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
	struct request	   *req;
	strom_dma_task	   *dtask;
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
callback_ssd2gpu_memcpy(struct nvme_queue *nvmeq, void *ctx,
						struct nvme_completion *cqe)
{
	strom_dma_request  *dreq = (strom_dma_request *) ctx;
	strom_dma_task	   *dtask = dreq->dtask;
	int					dma_status = le16_to_cpup(&cqe->status) >> 1;
	u32					dma_result = le32_to_cpup(&cqe->result);

	/* update execution result, if error */
	if (dma_status != NVME_SC_SUCCESS)
	{
		spinlock_t	   *lock = &strom_dma_task_locks[dtask->hindex];
		unsigned long	flags;

		spin_lock_irqsave(lock, flags);
		if (dtask->dma_status == NVME_SC_SUCCESS)
		{
			dtask->dma_status = dma_status;
			dtask->dma_result = dma_result;
		}
		spin_unlock_irqrestore(lock, flags);
	}

	/* release resources and wake up waiter */
	blk_mq_free_request(dreq->req);
	strom_put_dma_task(dreq->dtask);
	kfree(dreq);
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

/*
 * nvme_submit_io_cmd_async - It submits an I/O command of NVME-SSD, and then
 * returns to the caller immediately. Callback will put the strom_dma_task,
 * thus, strom_memcpy_ssd2gpu_wait() allows synchronization of DMA completion.
 */
static int
nvme_submit_async_cmd(strom_dma_task *dtask, struct nvme_command *cmd)
{
	struct nvme_ns		   *nvme_ns = dtask->nvme_ns;
	struct request		   *req;
	struct nvme_cmd_info   *cmd_rq;
	strom_dma_request	   *dreq;

	dreq = kzalloc(sizeof(strom_dma_request), GFP_KERNEL);
	if (!dreq)
		return -ENOMEM;

	req = blk_mq_alloc_request(nvme_ns->queue,
							   WRITE,
							   GFP_KERNEL|__GFP_WAIT,
							   false);
	if (IS_ERR(req))
	{
		kfree(dreq);
		return PTR_ERR(req);
	}
	dreq->req = req;
	dreq->dtask = strom_get_dma_task(dtask);

	cmd_rq = blk_mq_rq_to_pdu(req);
	cmd_rq->fn = callback_ssd2gpu_memcpy;
	cmd_rq->ctx = dreq;
	cmd_rq->aborted = 0;
	blk_mq_start_request(blk_mq_rq_from_pdu(cmd_rq));

	cmd->common.command_id = req->tag;

	nvme_submit_cmd(cmd_rq->nvmeq, cmd);

	return 0;
}
