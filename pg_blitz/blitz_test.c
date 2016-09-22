/*
 * test_blitz.c
 *
 * Simple test program of the PG-Blitz kernel module
 *
 * Copyright 2016 (C) KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

static size_t		system_page_size;

static const char  *device_file_name = "/dev/pg_blitz0";
static int			device_file_desc = -1;
static char		   *device_file_mmap = NULL;

static loff_t		buffer_offset = 0;
static size_t		buffer_length = 16 << 20;	/* 16MB */


#define ERR_EXIT(cond, fmt, ...)							\
	do {													\
		if (cond)											\
		{													\
			fprintf(stderr, "%s:%d " fmt "\n",				\
					__FUNCTION__, __LINE__, ##__VA_ARGS__);	\
			exit(1);										\
		}													\
	} while(0)

static void usage(const char *argv0)
{
	fprintf(stderr,
			"usage: %s [OPTION] <filename>\n"
			"  -d <device file>     (default: /dev/pg_blitz0)\n"
			"  -l <map num pages>   (default: 16MB)\n"
			"  -o <map offset>      (default: 0)\n"
			"  -h                   print this message\n",
			basename(strdup(argv0)));
	exit(1);
}

int main(int argc, char *argv[])
{
	int		i, code;

	system_page_size = sysconf(_SC_PAGESIZE);

	while ((code = getopt(argc, argv, "d:l:o:h")) >= 0)
	{
		switch (code)
		{
			case 'd':
				device_file_name = strdup(optarg);
				ERR_EXIT(!device_file_name, "out of memory");
				break;
			case 'l':
				buffer_length = atol(optarg) * system_page_size;
				break;
			case 'o':
				buffer_offset = atol(optarg) * system_page_size;
				break;

			default:
				usage(argv[0]);
				break;
		}
	}

	device_file_desc = open(device_file_name, O_RDWR);
	ERR_EXIT(device_file_desc < 0,
			 "failed to open '%s': %m", device_file_name);

	device_file_mmap = mmap(NULL,
							buffer_length,
							PROT_READ | PROT_WRITE,
							MAP_SHARED,
							device_file_desc,
							buffer_offset);
	ERR_EXIT(device_file_mmap == (void *)(-1), "failed on mmap: %m");

	for (i=0; i < buffer_length / sizeof(int); i++)
	{
		((int *)device_file_mmap)[i] = i;
	}
	return 0;
}
