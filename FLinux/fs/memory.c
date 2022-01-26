/*TODO: license message*/

#include <common/fcntl.h>
#include <fs/memory.h>
#include <syscall/mm.h>
#include <log.h>
#include <heap.h>

struct memory_file
{
	struct virtualfs_custom custom_file;
	void *buffer;
	size_t buffer_size;
	uint64_t size;
};



static int memory_close(struct file *f)
{
	struct memory_file *mf = (struct memory_file *)f;
	if(mf->buffer != NULL)
		kfree(mf->buffer, (mf->buffer_size));
		
	kfree(f, sizeof(struct memory_file));
	return 0;
}

static void extend_buffer(struct memory_file *mf, size_t min_size)
{
	if (mf->buffer_size >= min_size)
		return;

	void* new_buf =  mm_mmap(NULL, min_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
		INTERNAL_MAP_NORESET | INTERNAL_MAP_VIRTUALALLOC, NULL, 0);
	if (mf->buffer != NULL)
	{
		memcpy(new_buf, mf->buffer, mf->buffer_size);
		mm_munmap(mf->buffer, mf->buffer_size);
	}
	mf->buffer = new_buf;
	mf->buffer_size = min_size;

}

size_t memory_file_read(struct file *f, void *b, size_t count)
{
	struct memory_file *mf = (struct memory_file *)f;

	size_t to_read = min(count, mf->size);

	memcpy(b, mf->buffer, to_read);

	return to_read;
}

size_t memory_file_write(struct file *f, const void *b, size_t count)
{
	struct memory_file *mf = (struct memory_file *)f;

	return count;
}

int memory_file_truncate(struct file *f, lx_loff_t length)
{
	struct memory_file *mf = (struct memory_file *)f;

	if (mf->size == length)
		return 0;

	if (mf->size > length)
	{
		mf->size = length;
		return 0;
	}

	if (mf->buffer_size < length)
	{
		extend_buffer(mf, length);
		memset((char*)mf->buffer + mf->size, 0, length - mf->size);
	}

	mf->size = length;
	return 0;
}


static int memory_file_stat(struct file *f, struct newstat *buf)
{
	AcquireSRWLockShared(&f->rw_lock);
	struct memory_file *mf = (struct memory_file *)f;
	struct virtualfs_custom_desc *desc = (struct virtualfs_custom_desc *)mf->custom_file.desc;
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(0, 1);
	buf->st_ino = 0;
	buf->st_mode = S_IWGRP | S_IWOTH;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = desc->device;
	buf->st_size = mf->size;
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


static const struct file_ops memory_ops = {
	.close = memory_close,
	.read = memory_file_read,
	.write = memory_file_write,
	.stat = memory_file_stat,
	.pread = memory_file_read,
	.pwrite = memory_file_write,
	.truncate = memory_file_truncate
};

struct file *memory_file_alloc();

const struct virtualfs_custom_desc memory_desc = VIRTUALFS_CUSTOM(mkdev(0, 1), memory_file_alloc);

struct file *memory_file_alloc()
{
	struct memory_file *f = (struct memory_file *)kmalloc(sizeof(struct memory_file));
	memset(f, 0, sizeof(struct memory_file));
	file_init(&f->custom_file.base_file, &memory_ops, O_LARGEFILE | O_RDWR);
	virtualfs_init_custom(f, &memory_desc);
	return (struct file *)f;
}

