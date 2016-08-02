/* ----------------------------------------------------------------
 *
 * libnvme-strom.c
 *
 * Collection of routines to use 'nvme-strom' kernel module
 * --------
 * Copyright 2016 (C) KaiGai Kohei <kaigai@kaigai.gr.jp>
 * Copyright 2016 (C) The PG-Strom Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 * ----------------------------------------------------------------
 */
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "nvme-strom.h"

/*
 *
 *
 */
static int
nvme_strom_ioctl(int cmd, const void *arg)
{
	static __thread int fdesc_nvme_strom = -1;

	if (fdesc_nvme_strom < 0)
	{
		fdesc_nvme_strom = open("/proc/nvme-strom", O_RDONLY);
		if (fdesc_nvme_strom < 0)
		{
			fprintf(stderr, "failed to open \"/proc/nvme-strom\" : %m\n");
			return -1;
		}
	}
	return ioctl(fdesc_nvme_strom, cmd, arg);
}





#ifdef BUILD_AS_DRIVERTEST
#include <cuda.h>

#define offsetof(type, field)   ((long) &((type *)0)->field)

static void cuda_exit_on_error(CUresult rc, const char *apiname)
{
	if (rc != CUDA_SUCCESS)
	{
		const char *error_name;

		if (cuGetErrorName(rc, &error_name) != CUDA_SUCCESS)
			error_name = "unknown error";

		fprintf(stderr, "failed on %s: %s\n", apiname, error_name);
		exit(1);
	}
}

static int
drivertest_debug(void)
{
	StromCmd__Debug	uarg;
	int				retval;

	uarg.fdesc = -1;
	uarg.offset = 0;
	uarg.length = 0;

	retval = nvme_strom_ioctl(STROM_IOCTL__DEBUG, &uarg);
	printf("STROM_IOCTL__DEBUG() --> %d : %m\n", retval);

	return retval;
}

static void
drivertest_check_file(const char *filename, int fdesc)
{
	StromCmd__CheckFile uarg;
	int		rc;

	memset(&uarg, 0, sizeof(uarg));
	uarg.fdesc = fdesc;

	rc = nvme_strom_ioctl(STROM_IOCTL__CHECK_FILE, &uarg);
	printf("STROM_IOCTL__CHECK_FILE('%s') --> %d: %m\n",
		   filename, rc);
	if (rc)
		exit(rc);
}

static void
drivertest_map_gpumem(const char *filename, size_t file_size,
					  CUdeviceptr *p_devptr,
					  unsigned long *p_handle,
					  unsigned int *p_num_pages)
{
	StromCmd__MapGpuMemory uarg;
	CUdevice	cuda_device;
	CUcontext	cuda_context;
	CUdeviceptr	cuda_devptr;
	CUresult	rc;
	int			retval;

	rc = cuInit(0);
	cuda_exit_on_error(rc, "cuInit");

	rc = cuDeviceGet(&cuda_device, 0);
	cuda_exit_on_error(rc, "cuDeviceGet");

	rc = cuCtxCreate(&cuda_context, CU_CTX_SCHED_AUTO, cuda_device);
	cuda_exit_on_error(rc, "cuCtxCreate");

	rc = cuMemAlloc(&cuda_devptr, file_size);
	cuda_exit_on_error(rc, "cuMemAlloc");

	memset(&uarg, 0, sizeof(StromCmd__MapGpuMemory));
	uarg.vaddress = cuda_devptr;
	uarg.length = file_size;

	retval = nvme_strom_ioctl(STROM_IOCTL__MAP_GPU_MEMORY, &uarg);
	printf("STROM_IOCTL__MAP_GPU_MEMORY(%p, %lu, handle=%lx) --> %d: %m\n",
		   (void *)cuda_devptr, file_size, uarg.handle, retval);
	if (retval)
		exit(retval);

	*p_devptr = cuda_devptr;
	*p_handle = uarg.handle;
	*p_num_pages = uarg.gpu_npages;

}

static void
drivertest_print_gpumem(unsigned long handle, unsigned int num_pages)
{
	StromCmd__InfoGpuMemory *uarg;
	size_t	required;
	int		i, retval;

	required = offsetof(StromCmd__InfoGpuMemory, pages[num_pages]);
	uarg = malloc(required);
	if (!uarg)
	{
		fprintf(stderr, "out of memory: %m\n");
		exit(1);
	}
	memset(uarg, 0, required);
	uarg->handle = handle;
	uarg->nrooms = num_pages;

	retval = nvme_strom_ioctl(STROM_IOCTL__INFO_GPU_MEMORY, uarg);
	printf("STROM_IOCTL__INFO_GPU_MEMORY(handle=%lx) --> %d: %m\n",
		   handle, retval);
	if (retval)
		exit(retval);

	printf("Handle=%lx version=%u gpu_page_sz=%u\n",
		   handle, uarg->version, uarg->gpu_page_sz);
	for (i=0; i < uarg->nitems; i++)
	{
		printf("V:%016lx <--> P:%016lx\n",
			   (void *)uarg->pages[i].vaddr,
			   (void *)uarg->pages[i].paddr);
	}
	free(uarg);
}

static void
drivertest_unmap_gpumem(unsigned long handle)
{
	StromCmd__UnmapGpuMemory uarg;
	int		retval;

	uarg.handle = handle;
	retval = nvme_strom_ioctl(STROM_IOCTL__UNMAP_GPU_MEMORY, &uarg);
	printf("STROM_IOCTL__UNMAP_GPU_MEMORY(handle=%lx) = %d\n", handle, retval);
}

static void
drivertest_dma_gpumem(const char *filename, int fdesc, size_t file_size,
					  CUdeviceptr devptr, unsigned long handle)
{
	StromCmd__MemCpySsdToGpu uarg;
	char	   *src_buffer;
	void	   *dst_buffer;
	char	   *pos;
	ssize_t		retval;
	CUresult	rc;

	src_buffer = malloc(file_size);
	if (!src_buffer)
	{
		fprintf(stderr, "out of memory: %m\n");
		exit(1);
	}
	retval = read(fdesc, src_buffer, file_size);
	if (retval != file_size)
	{
		fprintf(stderr, "failed on read(2) %zu bytes read but %zu required\n",
				retval, file_size);
		exit(1);
	}

	rc = cuMemAllocHost(&dst_buffer, file_size);
	cuda_exit_on_error(rc, "cuMemAllocHost");

	/* src_buffer -> GPU RAM */
	uarg.handle = handle;
	uarg.offset = 0;
	uarg.fdesc = fdesc;
	uarg.nchunks = 1;
	uarg.chunks[0].fpos = 0;
	uarg.chunks[0].length = file_size;

	retval = nvme_strom_ioctl(STROM_IOCTL__MEMCPY_SSD2GPU, &uarg);
	printf("STROM_IOCTL__MEMCPY_SSD2GPU(%zu bytes) --> %d: %m\n",
		   file_size, retval);

	sleep(2);

	/* GPU RAM -> dst_buffer */
	rc = cuMemcpyDtoH(dst_buffer, devptr, file_size);
	cuda_exit_on_error(rc, "cuMemcpyDtoH");

	/* compare results */
	retval = memcmp(src_buffer, dst_buffer, file_size);
	printf("memcmp(src, dst, %zu) --> %d\n", file_size, retval);
//	write(0, dst_buffer, file_size);
}

/*
 * entrypoint of driver_test
 */
int main(int argc, char * const argv[])
{
	const char	   *filename;
	int				fdesc = -1;
	struct stat		stbuf;
	size_t			filesize;
	size_t			falign;
	CUdeviceptr		devptr;
	unsigned long	handle;
	unsigned int	num_pages;
	int				rc;

	if (argc != 2)
	{
		fprintf(stderr, "usage: %s (<filename>|-debug)\n", basename(argv[0]));
		return 1;
	}
	filename = argv[1];
	if (strcmp(filename, "-debug") == 0)
		return drivertest_debug();

	fdesc = open(filename, O_RDONLY);
	if (fdesc < 0)
	{
		fprintf(stderr, "failed to open \"%s\": %m\n", filename);
		return 1;
	}

	if (fstat(fdesc, &stbuf) != 0)
	{
		fprintf(stderr, "failed on fstat(\"%s\"): %m\n", filename);
		return 1;
	}
	filesize = (stbuf.st_size & ~(stbuf.st_blksize - 1));

	/* is this file supported? */
	drivertest_check_file(filename, fdesc);

	/* if supported, try to alloc device memory */
	drivertest_map_gpumem(filename, filesize,
						  &devptr, &handle, &num_pages);

	/* print device memory map information */
	drivertest_print_gpumem(handle, num_pages);

	/* kick DMA from file to device memory */
	drivertest_dma_gpumem(filename, fdesc, filesize,
						  devptr, handle);

	return 0;
}

#endif	/* BUILD_AS_DRIVERTEST */
