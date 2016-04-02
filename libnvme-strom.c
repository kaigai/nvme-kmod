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
#include "nvme-strom.h"












#ifdef BUILD_AS_DRIVERTEST

/*
 * entrypoint of driver_test
 */
int main(int argc, char * const argv[])
{
	int		c;

	while ((c = getopt(argc, argv, "h")) >= 0)
	{
		switch (c)
		{
			case 'h':
			default:
				fprintf(stderr, "usage: %s [options] <filename>\n",
						basename(argv[0]));
				return 1;
		}
	}
	
	
	
}

#endif	/* BUILD_AS_DRIVERTEST */
