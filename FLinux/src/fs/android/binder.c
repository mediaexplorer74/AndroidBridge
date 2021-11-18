/*TODO: license message*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <common/fcntl.h>


#include <syscall/mm.h>
#include <log.h>
#include <heap.h>

#include <common/reset_windef.h>

typedef int32_t __s32;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint8_t __u8;

#define BINDER_IPC_32BIT

#include <fs/android/binder.h>
#include <linux/binder.h> //must be last because of some windows headers colliding macros

#define BINDER_DEV mkdev(0, 51)


struct binder_file
{
	struct virtualfs_custom custom_file;
};

static int binder_close(struct file *f)
{
	struct binder_file *af = (struct binder_file *)f;

	kfree(f, sizeof(struct binder_file));
	return 0;
}


static size_t binder_file_read(struct file *f, void *b, size_t count)
{
	return count;
}

static size_t binder_file_write(struct file *f, const void *b, size_t count)
{
	struct binder_file *af = (struct binder_file *)f;

	return count;
}

static int binder_file_truncate(struct file *f, lx_loff_t length)
{
	struct binder_file *af = (struct binder_file *)f;

	return length;

}



static int binder_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct binder_file *af = (struct binder_file *)f;
	unsigned int size = _IOC_SIZE(cmd);
	int ret = 0;

	switch (cmd)
	{
	case BINDER_SET_MAX_THREADS:
		log_info("Binder BINDER_SET_MAX_THREADS: %d", *(int*)arg);
		break;
	case BINDER_VERSION:
		if (size != sizeof(struct binder_version)) {
			ret = -EINVAL;
			goto err;
		}
		((struct binder_version *)arg)->protocol_version = BINDER_CURRENT_PROTOCOL_VERSION;
		break;
	default:
		log_error("Unknown binder command %d", cmd);
		ret = -ENOTTY;
	}

err:

	return ret;
}

static int binder_file_stat(struct file *f, struct newstat *buf)
{
	AcquireSRWLockShared(&f->rw_lock);
	struct binder_file *af = (struct binder_file *)f;
	struct virtualfs_custom_desc *desc = (struct virtualfs_custom_desc *)af->custom_file.desc;
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = BINDER_DEV;
	buf->st_ino = 0;
	buf->st_mode = S_IWGRP | S_IWOTH | S_IFCHR;
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


size_t binder_pread(struct file *f, void *buf, size_t count, lx_loff_t offset)
{
	return count;
}

size_t binder_pwrite(struct file *f, const void *buf, size_t count, lx_loff_t offset)
{
	return count;
}


static const struct file_ops binder_ops = {
	.close = binder_close,
	.read = binder_file_read,
	.write = binder_file_write,
	.stat = binder_file_stat,
	.truncate = binder_file_truncate,
	.ioctl = binder_ioctl,
	.pread = binder_pread,
	.pwrite = binder_pwrite
};

struct file *binder_file_alloc();

const struct virtualfs_custom_desc binder_desc = VIRTUALFS_CUSTOM(BINDER_DEV, binder_file_alloc);

struct file *binder_file_alloc()
{
	struct binder_file *f = (struct binder_file *)kmalloc(sizeof(struct binder_file));
	memset(f, 0, sizeof(struct binder_file));
	file_init(&f->custom_file.base_file, &binder_ops, O_LARGEFILE | O_RDWR);
	virtualfs_init_custom(f, &binder_desc);
	return (struct file *)f;
}


