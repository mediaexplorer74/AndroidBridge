/*TODO: license message*/


#include <common/fcntl.h>
#include <fs/android/logd.h>
#include <fs/socket.h>
#include <syscall/mm.h>
#include <log.h>
#include <heap.h>

struct log_time { // Wire format
	uint32_t tv_sec;
	uint32_t tv_nsec;
};


/* Header Structure to logd, and second header for pstore */
#pragma pack(push,1)
typedef struct {
	unsigned char id;
	uint16_t tid;
	struct log_time realtime;
} android_log_header_t;
#pragma pack(pop)

struct log_cell
{
	char log_id;
	uint16_t tid;
	struct log_time realtime_ts;
	int priority;
	const char* tag;
	const char* msg;
};

struct logd_file
{
	struct socket_file socket;
	int cur_cell;
	struct log_cell cell;
};

static int logd_close(struct file *f)
{
	kfree(f, sizeof(struct logd_file));
	return 0;
}

static size_t logd_file_read(struct file *f, void *b, size_t count)
{
	return 0;
}

#define SET_LOG_CELL(__cell__)\
	if (sizeof(__cell__) == count)\
	{\
		memcpy(&__cell__, b, count);\
	}

static size_t logd_file_write(struct file *f, const void *b, size_t count)
{
	struct logd_file *lf = (struct logd_file *)f;

	lf->cur_cell++;

	if (lf->cur_cell == 1)
	{
		AcquireSRWLockShared(&f->rw_lock); // dont forget to release it when there is some error
		if (count == sizeof(android_log_header_t))
		{
			android_log_header_t* hdr = (android_log_header_t*)b;
			lf->cell.log_id = hdr->id;
			lf->cell.realtime_ts = hdr->realtime;
			lf->cell.tid = hdr->tid;
			lf->cur_cell += 2;
		}
		else
		{
			SET_LOG_CELL(lf->cell.log_id);
		}
	}
	else if (lf->cur_cell == 2)
	{
		SET_LOG_CELL(lf->cell.tid);
	}
	else if (lf->cur_cell == 3)
	{
		SET_LOG_CELL(lf->cell.realtime_ts);
	}
	else if (lf->cur_cell == 4)
	{
		SET_LOG_CELL(lf->cell.priority);
	}
	else if (lf->cur_cell == 5)
	{
		lf->cell.tag = b;
	}
	else if (lf->cur_cell == 6)
	{
		lf->cell.msg = b;

		char buf[1000];

		strcpy_s(buf, sizeof(buf), b);
		OutputDebugStringA(buf);

		lf->cur_cell = 0;
		ReleaseSRWLockShared(&f->rw_lock);
	}

	return count;
}


static int logd_file_stat(struct file *f, struct newstat *buf)
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


static const struct file_ops logd_ops = {
	.close = logd_close,
	.read = logd_file_read,
	.write = logd_file_write,
	.stat = logd_file_stat,
};

struct file *logd_file_alloc();

const struct virtualfs_custom_desc logd_desc = VIRTUALFS_CUSTOM(mkdev(0, 1), logd_file_alloc);

struct file *logd_file_alloc()
{
	struct logd_file *f = (struct logd_file *)kmalloc(sizeof(struct logd_file));
	file_init(&f->socket.base_file, &logd_ops, O_LARGEFILE | O_RDWR);
	virtualfs_init_custom(f, &logd_desc);
	f->cur_cell = 0;
	return (struct file *)f;
}

