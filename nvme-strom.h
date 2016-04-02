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
	STROM_IOCTL_PIN_GPU_MEMORY		= _IO('S',0x80),
	STROM_IOCTL_UNPIN_GPU_MEMORY	= _IO('S',0x81),
};

/* STROM_IOCTL_PIN_GPU_MEMORY */
typedef struct strom_cmd_pin_gpu_memory_arg
{
	uint64_t		address;	/* in: address of the device memory */
	size_t			length;		/* in: length of the device memory */
	unsigned long	handle;		/* out: identifier of this mapping */
} StromCmdPinGpuMemory;

/* STROM_IOCTL_UNPIN_GPU_MEMORY */
typedef struct strom_cmd_unpin_gpu_memory_arg
{
	unsigned long	handle;		/* in: identifier to be unpinned */
} StromCmdUnpinGpuMemory;






#endif /* NVME_STROM_H */
