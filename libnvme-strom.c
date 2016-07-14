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
	int			c, fdesc;
	int			do_check_supported = 0;
	const char *filename;

	while ((c = getopt(argc, argv, "ch")) >= 0)
	{
		switch (c)
		{
			case 'c':
				do_check_supported = 1;
				break;
			case 'h':
			default:
				return usage(argv[0]);
		}
	}

	if (optind + 1 != argc || !argv[optind])
		return usage(argv[0]);
	filename = argv[optind];


	fdesc = open(filename, O_RDONLY);
	if (fdesc < 0)
	{
		fprintf(stderr, "failed to open \"%s\" : %m\n", argv[optind]);
		return 1;
	}

	if (do_check_supported)
		drivertest_check_file(filename, fdesc);
	else
		drivertest_debug(filename, fdesc);
	
	close(fdesc);
	
	return 0;
}

#endif	/* BUILD_AS_DRIVERTEST */
