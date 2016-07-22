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

static int drivertest_map_gpumem(size_t required, int do_host_dma_test)
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

	rc = cuMemAlloc(&cuda_devptr, required);
	cuda_exit_on_error(rc, "cuMemAlloc");

	memset(&uarg, 0, sizeof(StromCmd__MapGpuMemory));
	uarg.vaddress = cuda_devptr;
	uarg.length = required;

	retval = nvme_strom_ioctl(STROM_IOCTL__MAP_GPU_MEMORY, &uarg);
	printf("STROM_IOCTL__MAP_GPU_MEMORY(%p, %lu) --> %d: %m\n",
		   (void *)cuda_devptr, required, retval);
	if (retval != 0)
		exit(1);

	printf("map handle = %lu\n", uarg.handle);

	system("cat /proc/nvme-strom");

	/*
	 * RAM->GPU DMA Test
	 */
	if (do_host_dma_test)
	{
		StromCmd__MemCpySsdToGpu dma_arg;
		char	   *src_buffer;
		void	   *dst_buffer;
		char	   *pos;

		src_buffer = malloc(required);
		if (!src_buffer)
		{
			fprintf(stderr, "out of memory: %m\n");
			exit(1);
		}
		rc = cuMemAllocHost(&dst_buffer, required);
		cuda_exit_on_error(rc, "cuMemAllocHost");

		/* fill up by random */
		srand(time(NULL));
		for (pos = src_buffer; pos < src_buffer + required; pos++)
			*pos = (char)rand();

		/* src_buffer -> GPU RAM */
		dma_arg.handle = uarg.handle;
		dma_arg.offset = 0;
		dma_arg.fdesc = -1;
		dma_arg.nchunks = 1;
		dma_arg.chunks[0].length = required;
		dma_arg.chunks[0].source = 'm';
		dma_arg.chunks[0].u.host_addr = src_buffer;

		retval = nvme_strom_ioctl(STROM_IOCTL__MEMCPY_SSD2GPU, &dma_arg);
		printf("STROM_IOCTL__MEMCPY_SSD2GPU(%zu bytes) --> %d: %m\n",
			   required, retval);

		/* GPU RAM -> dst_buffer */
		rc = cuMemcpyDtoH(dst_buffer, cuda_devptr, required);
		cuda_exit_on_error(rc, "cuMemcpyDtoH");

		/* compare results */
		retval = memcmp(src_buffer, dst_buffer, required);
		printf("memcmp(src, dst, %zu) --> %d\n", required, retval);
	}
	return 0;
}

static int drivertest_check_file(const char *filename, int fdesc)
{
	StromCmd__CheckFile uarg;
	int		rc;

	uarg.fdesc = fdesc;

	rc = nvme_strom_ioctl(STROM_IOCTL__CHECK_FILE, &uarg);
	printf("STROM_IOCTL__CHECK_FILE('%s') --> %d : %m\n", filename, rc);
	return rc;
}

static void drivertest_debug(const char *filename, int fdesc)
{
	StromCmd__Debug	uarg;
	struct stat		stbuf;
	int				rc;

	if (fstat(fdesc, &stbuf) != 0)
	{
		printf("failed on fstat(2): %m\n");
		return;
	}
	uarg.fdesc = fdesc;
	uarg.offset = 0;
	uarg.length = stbuf.st_size;

	rc = nvme_strom_ioctl(STROM_IOCTL__DEBUG, &uarg);
	printf("STROM_IOCTL__DEBUG('%s') --> %d : %m\n", filename, rc);
}

static int usage(char *argv0)
{
	fprintf(stderr, "usage: %s [options] <filename>\n",
			basename(argv0));
	return 1;
}

/*
 * entrypoint of driver_test
 */
int main(int argc, char * const argv[])
{
	int			c;
	int			do_check_supported = 0;
	int			do_host_dma_test = 0;
	long		required = -1;
	const char *filename = NULL;
	int			fdesc = -1;

	while ((c = getopt(argc, argv, "dm:ch")) >= 0)
	{
		switch (c)
		{
			case 'd':
				do_host_dma_test = 1;
				break;
			case 'm':
				required = atol(optarg);
				break;
			case 'c':
				do_check_supported = 1;
				break;
			case 'h':
			default:
				return usage(argv[0]);
		}
	}

	if (optind != argc)
	{
		if (optind + 1 != argc)
			return usage(argv[0]);
		filename = argv[optind];
		fdesc = open(filename, O_RDONLY);
		if (fdesc < 0)
		{
			fprintf(stderr, "failed to open \"%s\": %m\n", argv[optind]);
			return 1;
		}
	}

	if (required > 0)
		drivertest_map_gpumem(required, do_host_dma_test);
	if (fdesc >= 0)
	{
		if (do_check_supported)
			drivertest_check_file(filename, fdesc);
		else
			drivertest_debug(filename, fdesc);
		close(fdesc);
	}
	return 0;
}

#endif	/* BUILD_AS_DRIVERTEST */
