/* ----------------------------------------------------------------
 *
 * pg_blitz.h
 *
 * Definition of PG-Blitz's special feature
 *
 * ----------------------------------------------------------------
 */
#ifndef PG_BLITZ_H
#define PG_BLITZ_H
#include <asm/ioctl.h>

enum {
	BLITZ_IOCTL__BUFFER_SIZE		= _IO('B',0x60),
	BLITZ_IOCTL__CHECK_FILE			= _IO('B',0x61),
	BLITZ_IOCTL__WRITE_FILE			= _IO('B',0x62),
	BLITZ_IOCTL__WRITE_FILE_ASYNC	= _IO('B',0x63),
	BLITZ_IOCTL__FLUSH_FILE			= _IO('B',0x64),
};

/* BLITZ_IOCTL__BUFFER_SIZE */
typedef struct BlitzCmd__BufferSize
{
	size_t		length;		/* out: total length of the kernel buffer */
} BlitzCmd__BufferSize;

/* BLITZ_IOCTL__CHECK_FILE */
typedef struct BlitzCmd__CheckFile
{
	int			fdesc;		/* in: file descriptor */
} BlitzCmd__CheckFile;

/* BLITZ_IOCTL__WRITE_FILE(_ASYNC) */
typedef struct BlitzCmd__WriteFile
{
	int			fdesc;		/* in: file descriptor */
	loff_t		fpos;		/* in: location on the file */
	size_t		length;		/* in: size to write */
	loff_t		offset;		/* in: offset from the DMA buffer */
	/*
	 * NOTE: all of the @fpos, @length, and @offset have to be aligned to
	 * the block size of the partition.
	 */
} BlitzCmd__WriteFile;

/* BLITZ_IOCTL__FLUSH_FILE */
typedef struct BlitzCmd__FlushFile
{
	int			fdesc;		/* in: file descriptor */
} BlitzCmd__FlushFile;

#endif	/* PG_BLITZ_H */
