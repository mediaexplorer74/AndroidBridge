/*TODO: license message*/


#include <common/fcntl.h>
#include <fs/android/propertyd.h>
#include <fs/socket.h>
#include <syscall/mm.h>
#include <log.h>
#include <heap.h>

#define PROP_NAME_MAX   32
#define PROP_VALUE_MAX  92

struct prop_msg
{
	unsigned cmd;
	char name[PROP_NAME_MAX];
	char value[PROP_VALUE_MAX];
};

struct property_cell
{
	char log_id;
};

struct propertyd_file
{
	struct socket_file socket;
	int cur_cell;
	struct property_cell cell;
};

static int propertyd_close(struct file *f)
{
	kfree(f, sizeof(struct propertyd_file));
	return 0;
}

static size_t propertyd_file_read(struct file *f, void *b, size_t count)
{
	return 0;
}

static size_t propertyd_file_write(struct file *f, const void *b, size_t count)
{
	struct propertyd_file *lf = (struct propertyd_file *)f;

	lf->cur_cell++;

	

	return count;
}


size_t propertyd_file_sendto(struct file *f, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, int addrlen)
{
	if (len == sizeof(struct prop_msg))
	{
		struct prop_msg* msg = buf;

		log_info("property cmd %d %s:%s", msg->cmd, msg->name, msg->value);

		return len;
	}

	return 0;
}

static int propertyd_file_stat(struct file *f, struct newstat *buf)
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


static const struct file_ops propertyd_ops = {
	.close = propertyd_close,
	.read = propertyd_file_read,
	.write = propertyd_file_write,
	.stat = propertyd_file_stat,
	.sendto = propertyd_file_sendto
};

struct file *propertyd_file_alloc();

const struct virtualfs_custom_desc propertyd_desc = VIRTUALFS_CUSTOM(mkdev(0, 1), propertyd_file_alloc);

struct file *propertyd_file_alloc()
{
	struct propertyd_file *f = (struct propertyd_file *)kmalloc(sizeof(struct propertyd_file));
	file_init(&f->socket.base_file, &propertyd_ops, O_LARGEFILE | O_RDWR);
	virtualfs_init_custom(f, &propertyd_desc);
	f->cur_cell = 0;
	return (struct file *)f;
}

