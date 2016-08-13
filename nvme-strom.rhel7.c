/*
 * RHEL7 specific portion for the NVMe-Strom driver
 *
 * RHEL7 kernel does not have non-static function to enqueue NVME-SSD command
 * with asynchronous manner.
 * nvme_submit_sync_cmd() is a thin wrapper for nvme_submit_cmd(), but we
 * cannot avoid synchronize the caller's context. So, we partially copy the
 * code and structure from the kernel source. Once RHEL7 kernel updated its
 * implementation, we have to follow these update....
 */
#include <linux/kthread.h>


struct strom_dma_request {
	strom_dma_task	   *dtask;
	struct request	   *req;
	struct nvme_iod	   *iod;
};
typedef struct strom_dma_request	strom_dma_request;

struct async_cmd_info {
	struct kthread_work work;
	struct kthread_worker *worker;
	struct request *req;
	u32 result;
	int status;
	void *ctx;
};

/*
 * An NVM Express queue.  Each device has at least two (one for admin
 * commands and one for I/O commands).
 */
struct nvme_queue {
	struct device *q_dmadev;
	struct nvme_dev *dev;
	char irqname[24];   /* nvme4294967295-65535\0 */
	spinlock_t q_lock;
	struct nvme_command *sq_cmds;
	volatile struct nvme_completion *cqes;
	struct blk_mq_tags **tags;
	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;
	u32 __iomem *q_db;
	u16 q_depth;
	s16 cq_vector;
	u16 sq_head;
	u16 sq_tail;
	u16 cq_head;
	u16 qid;
	u8 cq_phase;
	u8 cqe_seen;
	struct async_cmd_info cmdinfo;
};

typedef void (*nvme_completion_fn)(struct nvme_queue *, void *,
								   struct nvme_completion *);

struct nvme_cmd_info {
	nvme_completion_fn fn;
	void *ctx;
	int aborted;
	struct nvme_queue *nvmeq;
	struct nvme_iod iod[0];
};

static void
nvme_callback_async_read_cmd(struct nvme_queue *nvmeq, void *ctx,
							 struct nvme_completion *cqe)
{
	strom_dma_request  *dma_req = (strom_dma_request *) ctx;
	int					dma_status = le16_to_cpup(&cqe->status) >> 1;
	u32					dma_result = le32_to_cpup(&cqe->result);

	/*
	 * FIXME: dma_status is one of NVME_SC_* (like NVME_SC_SUCCESS)
	 * We have to translate it to host understandable error code
	 */
	prDebug("DMA Req Completed status=%d result=%u", dma_status, dma_result);

	/* release resources and wake up waiter */
	__nvme_free_iod(nvmeq->dev, dma_req->iod);
	blk_mq_free_request(dma_req->req);
	strom_put_dma_task(dma_req->dtask, dma_status);
	kfree(dma_req);
}

/* -- copy from nvme-core.c -- */

/*
 * nvme_submit_cmd() - Copy a command into a queue and ring the doorbell
 * @nvmeq: The queue to use
 * @cmd: The command to send
 *
 * Safe to use from interrupt context
 */
static inline int
__nvme_submit_cmd(struct nvme_queue *nvmeq, struct nvme_command *cmd)
{
	u16 tail = nvmeq->sq_tail;

	memcpy(&nvmeq->sq_cmds[tail], cmd, sizeof(*cmd));
	if (++tail == nvmeq->q_depth)
		tail = 0;
	writel(tail, nvmeq->q_db);
	nvmeq->sq_tail = tail;

	return 0;
}

static inline int
nvme_submit_cmd(struct nvme_queue *nvmeq, struct nvme_command *cmd)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&nvmeq->q_lock, flags);
	ret = __nvme_submit_cmd(nvmeq, cmd);
	spin_unlock_irqrestore(&nvmeq->q_lock, flags);
	return ret;
}

static void
nvme_set_info(struct nvme_cmd_info *cmd, void *ctx, nvme_completion_fn handler)
{
	cmd->fn = handler;
	cmd->ctx = ctx;
	cmd->aborted = 0;
	blk_mq_start_request(blk_mq_rq_from_pdu(cmd));
}

/*
 * nvme_submit_io_cmd_async - It submits an I/O command of NVME-SSD, and then
 * returns to the caller immediately. Callback will put the strom_dma_task,
 * thus, strom_memcpy_ssd2gpu_wait() allows synchronization of DMA completion.
 */
static int
nvme_submit_async_read_cmd(strom_dma_task *dtask, struct nvme_iod *iod)
{
	struct nvme_ns		   *nvme_ns = dtask->nvme_ns;
	struct request		   *req;
	struct nvme_cmd_info   *cmd_rq;
	struct nvme_command		cmd;
	strom_dma_request	   *dma_req;
	size_t					length;
	int						prp_len;
	u16						control = 0;
	u32						dsmgmt = 0;
	u32						nblocks;
	u64						slba;
	int						retval = 0;

	Assert(dtask->blocksz_shift >= nvme_ns->lba_shift);
	/* setup scatter-gather list */
	length  = (dtask->nr_blocks << dtask->blocksz_shift);
	nblocks = (dtask->nr_blocks << (dtask->blocksz_shift -
									nvme_ns->lba_shift)) - 1;
	if (nblocks > 0xffff)
		return -EINVAL;
	prDebug("src_block=%zu start_sect=%zu nblocks=%u",
			(size_t)dtask->src_block,
			(size_t)dtask->start_sect,
			nblocks);
	slba = dtask->src_block << (dtask->blocksz_shift -
								nvme_ns->lba_shift);
	slba += dtask->start_sect;

	/* setup scatter-gather list */
	{
		int		i;

		prDebug("iod %p {private=%lu npages=%d offset=%d nents=%d length=%d}",
				iod, iod->private, iod->npages, iod->offset,
				iod->nents, iod->length);
		for (i=0; i < iod->nents; i++)
		{
			struct scatterlist *sg = &iod->sg[i];

			prDebug("sg[%d] {page_link=%ld offset=%u length=%u daddr=%p}",
					i, sg->page_link, sg->offset, sg->length, (void *)sg->dma_address);
		}
	}
	prp_len = __nvme_setup_prps(nvme_ns->dev, iod, length, GFP_KERNEL);
	if (prp_len != length)
		return -ENOMEM;
#if 1
	memset(&cmd, 0, sizeof(cmd));
	cmd.rw.opcode		= nvme_cmd_read;
	cmd.rw.flags		= 0;
	cmd.rw.nsid			= cpu_to_le32(nvme_ns->ns_id);
	cmd.rw.prp1			= cpu_to_le64(sg_dma_address(iod->sg));
	cmd.rw.prp2			= cpu_to_le64(iod->first_dma);
	cmd.rw.slba			= cpu_to_le64(slba);
	cmd.rw.length		= cpu_to_le16(nblocks);
	cmd.rw.control		= cpu_to_le16(control);
	cmd.rw.dsmgmt		= cpu_to_le32(dsmgmt);

	prDebug("cmd {prp1=%lx prp2=%lx slba=%lu len=%d}", cmd.rw.prp1, cmd.rw.prp2, cmd.rw.slba, cmd.rw.length);

	retval = __nvme_submit_io_cmd(nvme_ns->dev, nvme_ns, &cmd, NULL);

	prDebug("__nvme_submit_io_cmd = %d", retval);

//	__nvme_free_iod(nvme_ns->dev, iod);
#else
	/* submit an asynchronous command */
	dma_req = kzalloc(sizeof(strom_dma_request), GFP_KERNEL);
	if (!dma_req)
		return -ENOMEM;

	req = blk_mq_alloc_request(nvme_ns->queue,
							   WRITE,
							   GFP_KERNEL|__GFP_WAIT,
							   false);
	if (IS_ERR(req))
	{
		kfree(dma_req);
		return PTR_ERR(req);
	}
	dma_req->req = req;
	dma_req->iod = iod;
	dma_req->dtask = strom_get_dma_task(dtask);

	/* setup READ command */
	if (req->cmd_flags & REQ_FUA)
		control |= NVME_RW_FUA;
	if (req->cmd_flags & (REQ_FAILFAST_DEV | REQ_RAHEAD))
		control |= NVME_RW_LR;
	if (req->cmd_flags & REQ_RAHEAD)
		dsmgmt |= NVME_RW_DSM_FREQ_PREFETCH;

	memset(&cmd, 0, sizeof(struct nvme_command));
	cmd.rw.opcode		= nvme_cmd_read;
	cmd.rw.flags		= 0;	/* we use PRPs, rather than SGL */
	cmd.rw.command_id	= req->tag;
	cmd.rw.nsid			= cpu_to_le32(nvme_ns->ns_id);
	cmd.rw.prp1			= cpu_to_le64(sg_dma_address(iod->sg));
	cmd.rw.prp2			= cpu_to_le64(iod->first_dma);
	cmd.rw.metadata		= 0;	/* XXX integrity check, if needed */
	cmd.rw.slba			= cpu_to_le64(slba);
	cmd.rw.length		= cpu_to_le16(nblocks);
	cmd.rw.control		= cpu_to_le16(control);
	cmd.rw.dsmgmt		= cpu_to_le32(dsmgmt);
	/*
	 * 'reftag', 'apptag' and 'appmask' fields are used only when nvme-
	 * namespace is formatted to use end-to-end protection information.
	 * Linux kernel of RHEL7 does not use these fields.
	 */
	cmd_rq = blk_mq_rq_to_pdu(req);
	nvme_set_info(cmd_rq, dma_req, nvme_callback_async_read_cmd);
	nvme_submit_cmd(cmd_rq->nvmeq, &cmd);
#endif
	return retval;
}
