/* ----------------------------------------------------------------
 *
 * nvme-strom.h
 *
 * Definition of SSD-to-GPU stuff
 *
 * ----------------------------------------------------------------
 */
#ifndef NVME_STROM_H
#define NVME_STROM_H
#include <asm/ioctl.h>

enum {
	STROM_IOCTL__CHECK_FILE				= _IO('S',0x80),
	STROM_IOCTL__MAP_GPU_MEMORY			= _IO('S',0x81),
	STROM_IOCTL__UNMAP_GPU_MEMORY		= _IO('S',0x82),
	STROM_IOCTL__INFO_GPU_MEMORY		= _IO('S',0x83),
	STROM_IOCTL__MEMCPY_SSD2GPU			= _IO('S',0x84),
	STROM_IOCTL__MEMCPY_SSD2GPU_ASYNC	= _IO('S',0x85),
	STROM_IOCTL__MEMCPY_SSD2GPU_WAIT	= _IO('S',0x86),
	STROM_IOCTL__DEBUG					= _IO('S',0x87),
};

/* STROM_IOCTL__CHECK_FILE */
struct StromCmd__CheckFile
{
	int				fdesc;		/* in: file descriptor to be checked */
};
typedef struct StromCmd__CheckFile		StromCmd__CheckFile;

/* STROM_IOCTL__MAP_GPU_MEMORY */
struct StromCmd__MapGpuMemory
{
	unsigned long	handle;		/* out: handler of the mapped region */
	uint64_t		vaddress;	/* in: virtual address of the device memory */
	size_t			length;		/* in: length of the device memory */
};
typedef struct StromCmd__MapGpuMemory	StromCmd__MapGpuMemory;

/* STROM_IOCTL__UNMAP_GPU_MEMORY */
struct StromCmd__UnmapGpuMemory
{
	unsigned long	handle;		/* in: handler of the mapped region */
};
typedef struct StromCmd__UnmapGpuMemory	StromCmd__UnmapGpuMemory;

/* STROM_IOCTL__INFO_GPU_MEMORY */
struct StromCmd__InfoGpuMemory
{
	unsigned long	handle;		/* in: handler of the mapped region */
	uint32_t		nrooms;		/* in: length of the variable length array */
	uint32_t		version;	/* out: 'version' of p2p_page_table */
	uint32_t		page_size;	/* out: 'page_size' of p2p_page_table */
	uint32_t		entries;	/* out: 'entries' of p2p_page_table */
	uint64_t		physical_address[1];
};
typedef struct StromCmd__InfoGpuMemory	StromCmd__InfoGpuMemory;

/* STROM_IOCTL__MEMCPY_SSD2GPU and STROM_IOCTL__MEMCPY_SSD2GPU_ASYNC */
struct strom_dma_chunk
{
	unsigned int	length;		/* in: length of this chunk */
	char			source;		/* in: source of this chunk */
	union {						/*     'f': file, 'm': host memory */
		loff_t		file_pos;	/* in: file offset from the head */
		void	   *host_addr;	/* in: host memory address */
	} u;
};
typedef struct strom_dma_chunk	strom_dma_chunk;

struct StromCmd__MemCpySsdToGpu
{
	unsigned long	dma_task_id;/* out: ID of this DMA operation */
	unsigned long	handle;		/* in: handler of the mapped region */
	size_t			offset;		/* in: destination offset from the head of
								 *     this mapped region */
	int				fdesc;		/* in: file descriptor, if any. Or, -1 */
	int				nchunks;	/* in: number of the source chunks */
	strom_dma_chunk	chunks[1];	/* in: ...variable length array... */
};
typedef struct StromCmd__MemCpySsdToGpu	StromCmd__MemCpySsdToGpu;

/* STROM_IOCTL__MEMCPY_SSD2GPU_WAIT */
typedef struct
{
	unsigned long	dma_task_id;/* in: ID of the DMA operation to wait */
} StromCmd__MemCpySsdToGpuWait;

/* STROM_IOCTL_DEBUG */
typedef struct
{
	unsigned int	fdesc;		/* in: file descriptor */
} StromCmd__Debug;


#endif /* NVME_STROM_H */
