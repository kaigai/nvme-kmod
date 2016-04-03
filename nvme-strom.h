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
	STROM_IOCTL_CHECK_SUPPORTED		= _IO('S',0x80),
	STROM_IOCTL_PIN_GPU_MEMORY		= _IO('S',0x81),
	STROM_IOCTL_UNPIN_GPU_MEMORY	= _IO('S',0x82),
	STROM_IOCTL_DMA_SSD2GPU			= _IO('S',0x83),
	STROM_IOCTL_DEBUG				= _IO('S',0x99),
};

/* STROM_IOCTL_CHECK_SUPPORTED */
typedef struct
{
	unsigned int	fdesc;		/* in: file descriptor to be checked */
} StromCmd__CheckSupported;

/* STROM_IOCTL_PIN_GPU_MEMORY */
typedef struct
{
	uint64_t		address;	/* in: address of the device memory */
	size_t			length;		/* in: length of the device memory */
	unsigned long	handle;		/* out: identifier of this mapping */
} StromCmd__PinGpuMemory;

/* STROM_IOCTL_UNPIN_GPU_MEMORY */
typedef struct
{
	unsigned long	handle;		/* in: identifier to be unpinned */
} StromCmd__UnpinGpuMemory;

/* STROM_IOCTL_P2PDMA_SSD2GPU */
typedef struct
{
	unsigned long	handle;		/* in: handle of pinned gpu memory */
	size_t			offset;		/* in: destination offset of the GPU memory */
	unsigned int	fdesc;		/* in: file descriptor */
	unsigned int	n_chunks;	/* in: number of source chunks */
	struct {
		union {
			size_t	foffset;	/* in: file offset of this chunk */
			void   *vaddr;		/* in: host vaddress of this chunk */
		} u;
		long		length;		/* in: absolete length of this chunk.
								 *     positive means File -> GPU DMA
								 *     negative means Host -> GPU DMA */
	} chunks[1];				/* variable length */
} StromCmd__MemcpySsd2Gpu;

/* STROM_IOCTL_DEBUG */
typedef struct
{
	unsigned int	fdesc;		/* in: file descriptor */
} StromCmd__Debug;


#endif /* NVME_STROM_H */
