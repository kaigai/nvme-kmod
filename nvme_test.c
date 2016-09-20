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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <cuda.h>
#include "nvme_strom.h"

#define offsetof(type, field)   ((long) &((type *)0)->field)
#define Max(a,b)				((a) > (b) ? (a) : (b))
#define Min(a,b)				((a) < (b) ? (a) : (b))
#define WB_UNITSZ				(8192)

/* command line options */
static int		device_index = -1;
static int		num_chunks = 6;
static size_t	chunk_size = 32UL << 20;
static int		enable_checks = 0;
static int		print_mapping = 0;
static int		test_by_vfs = 0;
static size_t	vfs_io_size = 0;

static sem_t	buffer_sem;
static pthread_mutex_t	buffer_lock;

/*
 * nvme_strom_ioctl - entrypoint of NVME-Strom
 */
static int
nvme_strom_ioctl(int cmd, const void *arg)
{
	static __thread int fdesc_nvme_strom = -1;

	if (fdesc_nvme_strom < 0)
	{
		fdesc_nvme_strom = open(NVME_STROM_IOCTL_PATHNAME, O_RDONLY);
		if (fdesc_nvme_strom < 0)
		{
			fprintf(stderr, "failed to open \"%s\" : %m\n",
					NVME_STROM_IOCTL_PATHNAME);
			return -1;
		}
	}
	return ioctl(fdesc_nvme_strom, cmd, arg);
}

#define cuda_exit_on_error(__RC, __API_NAME)							\
	do {																\
		if ((__RC) != CUDA_SUCCESS)										\
		{																\
			const char *error_name;										\
																		\
			if (cuGetErrorName((__RC), &error_name) != CUDA_SUCCESS)	\
				error_name = "unknown error";							\
			fprintf(stderr, "%d: failed on %s: %s\n",					\
					__LINE__, __API_NAME, error_name);					\
			exit(1);													\
		}																\
	} while(0)

#define system_exit_on_error(__RC, __API_NAME)							\
	do {																\
		if ((__RC))														\
		{																\
			fprintf(stderr, "%d: failed on %s: %m\n",					\
					__LINE__, __API_NAME);								\
			exit(1);													\
		}																\
	} while(0)

static void
ioctl_check_file(const char *filename, int fdesc)
{
	StromCmd__CheckFile uarg;
	int		rc;

	memset(&uarg, 0, sizeof(uarg));
	uarg.fdesc = fdesc;

	rc = nvme_strom_ioctl(STROM_IOCTL__CHECK_FILE, &uarg);
	if (rc)
	{
		fprintf(stderr, "STROM_IOCTL__CHECK_FILE('%s') --> %d: %m\n",
				filename, rc);
		exit(1);
	}
}

static unsigned long
ioctl_map_gpu_memory(CUdeviceptr cuda_devptr, size_t buffer_size)
{
	StromCmd__MapGpuMemory uarg;
	int			retval;

	memset(&uarg, 0, sizeof(StromCmd__MapGpuMemory));
	uarg.vaddress = cuda_devptr;
	uarg.length = buffer_size;

	retval = nvme_strom_ioctl(STROM_IOCTL__MAP_GPU_MEMORY, &uarg);
	if (retval)
	{
		fprintf(stderr, "STROM_IOCTL__MAP_GPU_MEMORY(%p, %lu) --> %d: %m",
			   (void *)cuda_devptr, buffer_size, retval);
		exit(1);
	}
	return uarg.handle;
}

typedef struct
{
	int				fdesc;
	loff_t			fpos;
	size_t			flen;
	int				index;
	int				is_running;
	CUstream		cuda_stream;
	unsigned long	dma_task_id;
	void		   *src_buffer;
	void		   *dest_buffer;
} async_task;

static void
callback_dma_wait(CUstream cuda_stream, CUresult status, void *private)
{
	StromCmd__MemCpySsdToGpuWait	uarg;
	async_task	   *atask = private;
	int				rv;

	cuda_exit_on_error(status, "async_task");

	uarg.ntasks = 1;
	uarg.nwaits = 1;
	uarg.dma_task_id[0] = atask->dma_task_id;
	rv = nvme_strom_ioctl(STROM_IOCTL__MEMCPY_SSD2GPU_WAIT, &uarg);
	if (uarg.status)
		printf("async dma (id=%lu, status=%ld)\n",
			   uarg.nwaits > 0 ? uarg.dma_task_id[0] : 0,
			   uarg.status);
	system_exit_on_error(rv, "STROM_IOCTL__MEMCPY_SSD2GPU_WAIT");
}

static void
callback_release_atask(CUstream cuda_stream, CUresult status, void *private)
{
	async_task	   *atask = private;
	ssize_t			retval;
	size_t			count;

	/* Do we take a sanity check? */
	if (enable_checks)
	{
		if (test_by_vfs)
			count = atask->flen;
		else
		{
			retval = pread(atask->fdesc, atask->src_buffer,
						   atask->flen, atask->fpos);
			system_exit_on_error(retval < 0, "pread");
			count = retval;
		}

		if (memcmp(atask->src_buffer, atask->dest_buffer, count))
		{
			int		c, i, j, b = 0;

			while (((unsigned char *)atask->src_buffer)[b] ==
				   ((unsigned char *)atask->dest_buffer)[b])
				b++;
			b = (b > 32 ? (b & ~15) - 32 : 0);

			printf("memcmp failed (fpos=%zu):", atask->fpos);
			for (j=0; j < 12; j++)
			{
				for (i=0; i < 16; i++)
				{
					if (i % 16 == 0)
						printf("\nS +%08x:", j * 16 + i + b);
					else if (i % 8 == 0)
						printf(" ");
					c = ((unsigned char *)atask->src_buffer)[j * 16 + i + b];
					printf(" %02x", c);
				}

				for (i=0; i < 16; i++)
				{
					if (i % 16 == 0)
						printf("\nD +%08x:", j * 16 + i + b);
					else if (i % 8 == 0)
						printf(" ");
					c = ((unsigned char *)atask->dest_buffer)[j * 16 + i + b];
					printf(" %02x", c);
				}
			}
			putchar('\n');
			exit(1);
		}
	}
	pthread_mutex_lock(&buffer_lock);
	atask->is_running = 0;
	pthread_mutex_unlock(&buffer_lock);

	sem_post(&buffer_sem);
}

static async_task *
setup_async_tasks(int fdesc)
{
	async_task	   *async_tasks;
	CUresult		rc;
	int				i, rv;

	async_tasks = malloc(sizeof(async_task) * num_chunks);
	system_exit_on_error(!async_tasks, "malloc");

	rv = sem_init(&buffer_sem, 0, num_chunks);
	system_exit_on_error(rv, "sem_init");
	rv = pthread_mutex_init(&buffer_lock, NULL);
	system_exit_on_error(rv, "pthread_mutex_init");

	for (i=0; i < num_chunks; i++)
	{
		async_tasks[i].fdesc = dup(fdesc);
		system_exit_on_error(async_tasks[i].fdesc < 0, "dup");
		async_tasks[i].fpos  = 0;
		async_tasks[i].index = i;
		async_tasks[i].is_running = 0;
		rc = cuStreamCreate(&async_tasks[i].cuda_stream,
							CU_STREAM_DEFAULT);
		cuda_exit_on_error(rc, "cuStreamCreate");

		if (enable_checks || test_by_vfs)
		{
			rc = cuMemAllocHost(&async_tasks[i].src_buffer, chunk_size);
			cuda_exit_on_error(rc, "cuMemAllocHost");
		}
		else
			async_tasks[i].src_buffer = NULL;

		rc = cuMemAllocHost(&async_tasks[i].dest_buffer, chunk_size);
		cuda_exit_on_error(rc, "cuMemAllocHost");
	}
	return async_tasks;
}

static void
show_throughput(const char *filename, size_t file_size,
				struct timeval tv1, struct timeval tv2)
{
	long		time_ms;
	double		throughput;
	char		buf[256];
	int			ofs = 0;

	time_ms = ((tv2.tv_sec * 1000 + tv2.tv_usec / 1000) -
			   (tv1.tv_sec * 1000 + tv1.tv_usec / 1000));
	throughput = (double)file_size / ((double)time_ms / 1000.0);

	if (file_size < (4UL << 10))
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, "read: %zuBytes",
						file_size);
	else if (file_size < (4UL << 20))
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, "read: %.2fKB",
						(double)file_size / (double)(1UL << 10));
	else if (file_size < (4UL << 30))
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, "read: %.2fMB",
						(double)file_size / (double)(1UL << 20));
	else
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, "read: %.2fGB",
						(double)file_size / (double)(1UL << 30));

	if (time_ms < 4000UL)
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, ", time: %lums",
						time_ms);
	else
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, ", time: %.2fsec",
						(double)time_ms / 1000.0);

	if (throughput < (double)(4UL << 10))
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, ", throughput: %zuB/s",
						(size_t)throughput);
	else if (throughput < (double)(4UL << 20))
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, ", throughput: %.2fKB/s",
						throughput / (double)(1UL << 10));
	else if (throughput < (double)(4UL << 30))
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, ", throughput: %.2fMB/s",
						throughput / (double)(1UL << 20));
	else
		ofs += snprintf(buf+ofs, sizeof(buf)-ofs, ", throughput: %.2fGB/s",
						throughput / (double)(1UL << 30));

	printf("file: %s, %s\n", filename, buf);
}

static void
exec_test_by_strom(CUdeviceptr cuda_devptr, unsigned long handle,
				   const char *filename, int fdesc, size_t file_size)
{
	StromCmd__MemCpySsdToGpu uarg;
	async_task	   *async_tasks;
	CUresult		rc;
	int				j, rv;
	size_t			offset;
	struct timeval	tv1, tv2;

	async_tasks = setup_async_tasks(fdesc);
	gettimeofday(&tv1, NULL);
	for (offset=0; offset < file_size; offset += chunk_size)
	{
		async_task *atask = NULL;

		rv = sem_wait(&buffer_sem);
		system_exit_on_error(rv, "sem_wait");

		/* find out an available async_task */
		pthread_mutex_lock(&buffer_lock);
		for (j=0; j < num_chunks; j++)
		{
			atask = &async_tasks[j % num_chunks];
			if (!atask->is_running)
			{
				atask->is_running = 1;
				atask->fpos = offset;
				atask->flen = Min(file_size - offset, chunk_size);
				break;		/* found */
			}
		}
		if (j == num_chunks)
		{
			fprintf(stderr, "Bug? no free async_task but semaphore > 0\n");
			exit(1);
		}
		pthread_mutex_unlock(&buffer_lock);

		/* kick SSD-to-GPU DMA */
		memset(&uarg, 0, sizeof(uarg));
		uarg.handle           = handle;
		uarg.fdesc            = fdesc;
		uarg.nchunks          = 1;
		uarg.chunks[0].fpos   = atask->fpos;
		uarg.chunks[0].offset = atask->index * chunk_size;
		uarg.chunks[0].length = atask->flen;
		rv = nvme_strom_ioctl(STROM_IOCTL__MEMCPY_SSD2GPU_ASYNC, &uarg);
		system_exit_on_error(rv, "STROM_IOCTL__MEMCPY_SSD2GPU_ASYNC");
		atask->dma_task_id    = uarg.dma_task_id;
		atask->fpos           = offset;

		/* kick callback for synchronization */
		rc = cuStreamAddCallback(atask->cuda_stream,
								 callback_dma_wait, atask, 0);
		cuda_exit_on_error(rc, "cuStreamAddCallback");

		/* kick GPU-to-RAM DMA */
		if (enable_checks)
		{
			rc = cuMemcpyDtoHAsync(atask->dest_buffer,
								   cuda_devptr + atask->index * chunk_size,
								   chunk_size,
								   atask->cuda_stream);
			cuda_exit_on_error(rc, "cuMemcpyDtoHAsync");
		}

		/* kick callback to release atask */
		rc = cuStreamAddCallback(atask->cuda_stream,
								 callback_release_atask, atask, 0);
		cuda_exit_on_error(rc, "cuStreamAddCallback");
	}
	/* wait for completion of the asyncronous tasks */
	do {
		rv = sem_wait(&buffer_sem);
		system_exit_on_error(rv, "sem_wait");

		pthread_mutex_lock(&buffer_lock);
		for (j=0; j < num_chunks; j++)
		{
			async_task *atask = &async_tasks[j];
			if (atask->is_running)
				break;	/* here is still running task */
		}
		pthread_mutex_unlock(&buffer_lock);
	} while (j < num_chunks);
	gettimeofday(&tv2, NULL);
	show_throughput(filename, file_size, tv1, tv2);
}

static void
exec_test_by_vfs(CUdeviceptr cuda_devptr, unsigned long handle,
				 const char *filename, int fdesc, size_t file_size)
{
	async_task	   *async_tasks;
	CUresult		rc;
	int				j, rv;
	size_t			offset;
	size_t			pos;
	size_t			count;
	ssize_t			retval;
	struct timeval	tv1, tv2;

	async_tasks = setup_async_tasks(fdesc);
	gettimeofday(&tv1, NULL);
	for (offset=0; offset < file_size; offset += chunk_size)
	{
		async_task *atask = NULL;

		rv = sem_wait(&buffer_sem);
		system_exit_on_error(rv, "sem_wait");

		/* find out an available async_task */
		pthread_mutex_lock(&buffer_lock);
		for (j=0; j < num_chunks; j++)
		{
			atask = &async_tasks[j % num_chunks];
			if (!atask->is_running)
				break;		/* found */
		}
		if (j == num_chunks)
		{
			fprintf(stderr, "Bug? no free async_task but semaphore > 0\n");
			exit(1);
		}
		pthread_mutex_unlock(&buffer_lock);

		/* Load SSD-to-RAM */
		count = 0;
		for (pos=0; pos < chunk_size; pos += vfs_io_size)
		{
			retval = pread(fdesc, (char *)atask->src_buffer + pos,
						   vfs_io_size, offset + pos);
			system_exit_on_error(retval < 0, "pread");
			count += retval;
			if (retval < vfs_io_size)
				break;
		}
		if (count == 0)
			break;	/* EOF */

		atask->is_running = 1;
		atask->fpos = offset;
		atask->flen = count;

		/* Kick RAM-to-GPU DMA */
		rc = cuMemcpyHtoDAsync(cuda_devptr + atask->index * chunk_size,
							   atask->src_buffer, atask->flen,
							   atask->cuda_stream);
		cuda_exit_on_error(rc, "cuMemcpyHtoDAsync");

		/* Kick GPU-to-RAM DMA */
		if (enable_checks)
		{
			rc = cuMemcpyDtoHAsync(atask->dest_buffer,
								   cuda_devptr + atask->index * chunk_size,
								   atask->flen,
								   atask->cuda_stream);
			cuda_exit_on_error(rc, "cuMemcpyDtoHAsync");
		}
		/* Kick callback to release atask */
		rc = cuStreamAddCallback(atask->cuda_stream,
								 callback_release_atask, atask, 0);
		cuda_exit_on_error(rc, "cuStreamAddCallback");
	}
	/* wait for completion of the asyncronous tasks */
	do {
		rv = sem_wait(&buffer_sem);
		system_exit_on_error(rv, "sem_wait");

		pthread_mutex_lock(&buffer_lock);
		for (j=0; j < num_chunks; j++)
		{
			async_task *atask = &async_tasks[j];
			if (atask->is_running)
				break;  /* here is still running task */
		}
		pthread_mutex_unlock(&buffer_lock);
	} while (j < num_chunks);

	gettimeofday(&tv2, NULL);
	show_throughput(filename, file_size, tv1, tv2);
}

/*
 * ioctl_print_gpu_memory
 */
static int ioctl_print_gpu_memory(void)
{
	StromCmd__ListGpuMemory *cmd_list;
	StromCmd__InfoGpuMemory	*cmd_info;
	uint32_t		nrooms = 2000;
	int				i, j;

	/* get list of mapped memory handles */
	do {
		cmd_list = malloc(offsetof(StromCmd__ListGpuMemory,
								   handles[nrooms]));
		system_exit_on_error(!cmd_list, "malloc");
		cmd_list->nrooms = nrooms;
		cmd_list->nitems = 0;
		if (nvme_strom_ioctl(STROM_IOCTL__LIST_GPU_MEMORY, cmd_list))
		{
			if (errno != ENOBUFS)
				system_exit_on_error(errno, "STROM_IOCTL__LIST_GPU_MEMORY");
			assert(cmd_list->nitems > cmd_list->nrooms);
			nrooms = cmd_list->nitems + 100;	/* with some margin */
			free(cmd_list);
		}
	} while (errno != 0);

	/* get property for each mapped device memory */
	cmd_info = malloc(offsetof(StromCmd__InfoGpuMemory,
							   paddrs[nrooms]));
	system_exit_on_error(!cmd_info, "malloc");
	i = 0;
	while (i < cmd_list->nitems)
	{
		cmd_info->handle = cmd_list->handles[i];
		cmd_info->nrooms = nrooms;

		if (nvme_strom_ioctl(STROM_IOCTL__INFO_GPU_MEMORY, cmd_info))
		{
			if (errno == ENOENT)
			{
				i++;
				continue;
			}
			else if (errno != ENOBUFS)
				system_exit_on_error(errno, "STROM_IOCTL__INFO_GPU_MEMORY");
			assert(cmd_info->nitems > nrooms);
			nrooms = cmd_info->nitems + 100;
			free(cmd_info);
			cmd_info = malloc(offsetof(StromCmd__InfoGpuMemory,
									   paddrs[nrooms]));
			system_exit_on_error(!cmd_info, "malloc");
			continue;
		}
		else
		{
			printf("%s"
				   "Mapped GPU Memory (handle: 0x%016lx) %p - %p\n"
				   "GPU Page: version=%u, size=%u, n_entries=%u\n"
				   "Owner: uid=%u\n",
				   (i == 0 ? "" : "\n"),
				   cmd_info->handle,
				   (void *)(cmd_info->paddrs[0] +
							cmd_info->map_offset),
				   (void *)(cmd_info->paddrs[0] +
							cmd_info->map_offset + cmd_info->map_length),
				   cmd_info->version,
				   cmd_info->gpu_page_sz,
				   cmd_info->nitems,
				   cmd_info->owner);

			for (j=0; j < cmd_info->nitems; j++)
			{
				printf("+%08lx: %p - %p\n",
					   j * (size_t)cmd_info->gpu_page_sz,
					   (void *)(cmd_info->paddrs[j]),
					   (void *)(cmd_info->paddrs[j] + cmd_info->gpu_page_sz));
			}
		}
		i++;
	}
	return 0;
}

/*
 * usage
 */
static void usage(const char *cmdname)
{
	fprintf(stderr,
			"usage: %s [OPTIONS] <filename>\n"
			"    -d <device index>:        (default 0)\n"
			"    -n <num of chunks>:       (default 6)\n"
			"    -s <size of chunk in MB>: (default 32MB)\n"
			"    -c : Enables corruption check (default off)\n"
			"    -h : Print this message (default off)\n"
			"    -f (<i/o size in KB>): Test by VFS access (default off)\n"
			"    -p (<map handle>): Print property of mapped device memory\n",
			basename(strdup(cmdname)));
	exit(1);
}

/*
 * entrypoint of driver_test
 */
int main(int argc, char * const argv[])
{
	const char	   *filename = NULL;
	int				fdesc = -1;
	struct stat		stbuf;
	size_t			filesize;
	size_t			buffer_size;
	CUresult		rc;
	CUdevice		cuda_device;
	CUcontext		cuda_context;
	CUdeviceptr		cuda_devptr;
	unsigned long	mgmem_handle;
	char			devname[256];
	int				code;

	while ((code = getopt(argc, argv, "d:n:s:cpf::h")) >= 0)
	{
		switch (code)
		{
			case 'd':
				device_index = atoi(optarg);
				break;
			case 'n':		/* number of chunks */
				num_chunks = atoi(optarg);
				break;
			case 's':		/* size of chunks in MB */
				chunk_size = (size_t)atoi(optarg) << 20;
				break;
			case 'c':
				enable_checks = 1;
				break;
			case 'p':
				print_mapping = 1;
				break;
			case 'f':
				test_by_vfs = 1;
				if (optarg)
					vfs_io_size = (size_t)atoi(optarg) << 10;
				break;
			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}
	buffer_size = (size_t)chunk_size * num_chunks;

	/* dump the current device memory mapping */
	if (print_mapping)
		return ioctl_print_gpu_memory();

	if (optind + 1 == argc)
		filename = argv[optind];
	else
		usage(argv[0]);

	if (vfs_io_size == 0)
		vfs_io_size = chunk_size;
	else if (chunk_size % vfs_io_size != 0)
	{
		fprintf(stderr, "VFS I/O size (%zuKB) mismatch to ChunkSize (%zuMB)\n",
				vfs_io_size >> 10, chunk_size >> 20);
		return 1;
	}

	/* open the target file */
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
	ioctl_check_file(filename, fdesc);

	/* allocate and map device memory */
	rc = cuInit(0);
	cuda_exit_on_error(rc, "cuInit");

	if (device_index < 0)
	{
		int		count;

		rc = cuDeviceGetCount(&count);
		cuda_exit_on_error(rc, "cuDeviceGetCount");

		for (device_index = 0; device_index < count; device_index++)
		{
			rc = cuDeviceGet(&cuda_device, device_index);
			cuda_exit_on_error(rc, "cuDeviceGet");

			rc = cuDeviceGetName(devname, sizeof(devname), cuda_device);
			cuda_exit_on_error(rc, "cuDeviceGetName");

			if (strstr(devname, "Tesla") != NULL ||
				strstr(devname, "Quadro") != NULL)
				break;
		}
		if (device_index == count)
		{
			fprintf(stderr, "No Tesla or Quadro GPUs are installed\n");
			return 1;
		}
	}
	else
	{
		rc = cuDeviceGet(&cuda_device, device_index);
		cuda_exit_on_error(rc, "cuDeviceGet");

		rc = cuDeviceGetName(devname, sizeof(devname), cuda_device);
		cuda_exit_on_error(rc, "cuDeviceGetName");
	}

	/* print test scenario */
	printf("GPU[%d] %s - file: %s", device_index, devname, filename);
	if (filesize < (4UL << 10))
		printf(", i/o size: %zuB", filesize);
	else if (filesize < (4UL << 20))
		printf(", i/o size: %.2fKB", (double)filesize / (double)(1UL << 10));
	else if (filesize < (4UL << 30))
		printf(", i/o size: %.2fMB", (double)filesize / (double)(1UL << 20));
	else
		printf(", i/o size: %.2fGB", (double)filesize / (double)(1UL << 30));
	if (test_by_vfs)
		printf(" by VFS (i/o unitsz: %zuKB)", vfs_io_size >> 10);

	printf(", buffer %zuMB x %d\n",
		   chunk_size >> 20, num_chunks);

	rc = cuCtxCreate(&cuda_context, CU_CTX_SCHED_AUTO, cuda_device);
	cuda_exit_on_error(rc, "cuCtxCreate");

	rc = cuMemAlloc(&cuda_devptr, buffer_size);
	cuda_exit_on_error(rc, "cuMemAlloc");

	rc = cuMemsetD32(cuda_devptr, 0x41424344,
					 chunk_size * num_chunks / sizeof(int));
	cuda_exit_on_error(rc, "cuMemsetD32");

	mgmem_handle = ioctl_map_gpu_memory(cuda_devptr, buffer_size);

	/* test execution */
	if (test_by_vfs)
		exec_test_by_vfs(cuda_devptr, mgmem_handle,
						 filename, fdesc, filesize);
	else
		exec_test_by_strom(cuda_devptr, mgmem_handle,
						   filename, fdesc, filesize);
	return 0;
}
