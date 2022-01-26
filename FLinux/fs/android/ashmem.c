/*TODO: license message*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <common/fcntl.h>


#include <syscall/mm.h>
#include <log.h>
#include <heap.h>

#include <common/reset_windef.h>
#include <fs/android/ashmem.h>
#include <linux/ashmem.h> //must be last because of some windows headers colliding macros

#define ASHMEM_NAME_PREFIX "dev/ashmem/"
#define ASHMEM_NAME_PREFIX_LEN (sizeof(ASHMEM_NAME_PREFIX) - 1)
#define ASHMEM_FULL_NAME_LEN (ASHMEM_NAME_LEN + ASHMEM_NAME_PREFIX_LEN) 

#define ASHMEM_DEV mkdev(0, 50)


struct ashmem_file
{
	struct virtualfs_custom custom_file;
	size_t size;
	char name[ASHMEM_FULL_NAME_LEN];
	unsigned long prot_mask;
};

static int ashmem_close(struct file *f)
{
	struct ashmem_file *af = (struct ashmem_file *)f;

	kfree(f, sizeof(struct ashmem_file));
	return 0;
}


static size_t ashmem_file_read(struct file *f, void *b, size_t count)
{
	return count;
}

static size_t ashmem_file_write(struct file *f, const void *b, size_t count)
{
	struct ashmem_file *af = (struct ashmem_file *)f;

	return count;
}

static int ashmem_file_truncate(struct file *f, lx_loff_t length)
{
	struct ashmem_file *af = (struct ashmem_file *)f;

	return length;

}

static int set_name(struct ashmem_file *af, void *buffer)
{
	int ret = 0;
	strcpy(af->name, buffer);
	log_debug("ashmem set_name %s", af->name);
	return ret;
}

static int get_name(struct ashmem_file *af, void *buffer)
{
	int ret = 0;
	strcpy(buffer, ASHMEM_NAME_PREFIX);
	strcpy((char*)buffer + ASHMEM_NAME_PREFIX_LEN, af->name);

	return ret;
}


static int ashmem_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct ashmem_file *af = (struct ashmem_file *)f;
	int ret = -ENOTTY;

	switch (cmd)
	{
	case ASHMEM_SET_NAME:
		ret = set_name(af, (void*)arg);
		break;
	case ASHMEM_GET_NAME:
		ret = get_name(af, (void*)arg);
		break;
	case ASHMEM_SET_SIZE:
		ret = 0;
		af->size = (size_t)arg;
		break;
	case ASHMEM_GET_SIZE:
		ret = af->size;
		break;
	case ASHMEM_SET_PROT_MASK:
		ret = 0;
		af->prot_mask = arg;
		break;
	case ASHMEM_GET_PROT_MASK:
		ret = af->prot_mask;
		break;
	case ASHMEM_PIN:
	case ASHMEM_UNPIN:
	case ASHMEM_GET_PIN_STATUS:
		ret = ASHMEM_NOT_PURGED;
		break;
	case ASHMEM_PURGE_ALL_CACHES:
		ret = -EPERM;
		break;

	default:
		log_error("Unknown ashmem command %d", cmd);
	}


	return ret;
}

static int ashmem_file_stat(struct file *f, struct newstat *buf)
{
	AcquireSRWLockShared(&f->rw_lock);
	struct ashmem_file *af = (struct ashmem_file *)f;
	struct virtualfs_custom_desc *desc = (struct virtualfs_custom_desc *)af->custom_file.desc;
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = ASHMEM_DEV;
	buf->st_ino = 0;
	buf->st_mode = S_IWGRP | S_IWOTH | S_IFCHR;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = desc->device;
	buf->st_size = af->size;
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

static int ashmem_getpath(struct file *f, char *buf)
{
	struct ashmem_file *af = (struct ashmem_file *)f;
	get_name(af, buf);
	return 0;
}

size_t ashmem_pread(struct file *f, void *buf, size_t count, lx_loff_t offset)
{
	return count;
}

size_t ashmem_pwrite(struct file *f, const void *buf, size_t count, lx_loff_t offset)
{
	return count;
}


static const struct file_ops ashmem_ops = {
	.close = ashmem_close,
	.read = ashmem_file_read,
	.write = ashmem_file_write,
	.stat = ashmem_file_stat,
	.truncate = ashmem_file_truncate,
	.ioctl = ashmem_ioctl,
	.getpath = ashmem_getpath,
	.pread = ashmem_pread,
	.pwrite = ashmem_pwrite
};

struct file *ashmem_file_alloc();

const struct virtualfs_custom_desc ashmem_desc = VIRTUALFS_CUSTOM(ASHMEM_DEV, ashmem_file_alloc);

struct file *ashmem_file_alloc()
{
	struct ashmem_file *f = (struct ashmem_file *)kmalloc(sizeof(struct ashmem_file));
	memset(f, 0, sizeof(struct ashmem_file));
	file_init(&f->custom_file.base_file, &ashmem_ops, O_LARGEFILE | O_RDWR);
	virtualfs_init_custom(f, &ashmem_desc);
	return (struct file *)f;
}


