/*TODO: license message*/


#include <common/fcntl.h>
#include <fs/debugout.h>
#include <syscall/mm.h>
#include <log.h>
#include <heap.h>


static int debugout_close(struct file *f)
{
	struct virtualfs_custom *mf = (struct virtualfs_custom *)f;

	kfree(f, sizeof(struct virtualfs_custom));
	return 0;
}

static size_t debugout_file_read(struct file *f, void *b, size_t count)
{
	return 0;
}

static size_t debugout_file_write(struct file *f, const void *b, size_t count)
{
	char buf[256];
	size_t allbytes = count;

	while (count > 0)
	{
		int to_write = min(sizeof(buf)-1, count);
		strncpy_s(buf, sizeof(buf), b, to_write);

		OutputDebugStringA(buf);
		count -= to_write;
		(char*)b += to_write;
	}

	return allbytes;
}


static int debugout_file_stat(struct file *f, struct newstat *buf)
{
	AcquireSRWLockShared(&f->rw_lock);
	struct virtualfs_custom *mf = (struct virtualfs_custom *)f;
	struct virtualfs_custom_desc *desc = (struct virtualfs_custom_desc *)mf->desc;
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IWGRP | S_IWOTH;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = desc->device;
	buf->st_size = 0;
	buf->st_blksize = PAGE_SIZE;
	buf->st_blocks = 0;
	buf->st_atime = 0;
	buf->st_atime_nsec = 0;
	buf->st_mtime = 0;
	buf->st_mtime_nsec = 0;
	buf->st_ctime = 0;
	buf->st_ctime_nsec = 0;
	ReleaseSRWLockShared(&f->rw_lock);
	return 0;
}


static const struct file_ops debugout_ops = {
	.close = debugout_close,
	.read = debugout_file_read,
	.write = debugout_file_write,
	.stat = debugout_file_stat,
};

struct file *debugout_file_alloc();

const struct virtualfs_custom_desc debugout_desc = VIRTUALFS_CUSTOM(mkdev(0, 1), debugout_file_alloc);

struct file *debugout_file_alloc()
{
	struct virtualfs_custom *f = (struct virtualfs_custom *)kmalloc(sizeof(struct virtualfs_custom));
	file_init(&f->base_file, &debugout_ops, O_LARGEFILE | O_RDONLY);
	virtualfs_init_custom(f, &debugout_desc);
	return (struct file *)f;
}

