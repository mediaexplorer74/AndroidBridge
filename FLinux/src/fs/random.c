/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <windows.h>
#include <wincrypt.h>
#include <ntdll.h>
#include <log.h>
#include <common/reset_windef.h>

#include <common/errno.h>
#include <common/fcntl.h>
#include <syscall/syscall.h>


#include <fs/file.h>

#include <fs/virtual.h>
#include <linux/random.h>


struct random_file
{
	struct virtualfs_custom custom_file;
	struct rand_pool_info rnd_info;
};


DEFINE_SYSCALL(getrandom, void *, buf, size_t, buflen, unsigned int, flags)
{
	log_info("getrandom(%p, %d, %x)", buf, buflen, flags);
	if (!mm_check_write(buf, buflen))
		return -L_EFAULT;

	if (!NT_SUCCESS(BCryptGenRandom(NULL, buf, buflen, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
		return -L_EFAULT;

	return buflen;
}


static int random_close(struct file *f)
{
	struct random_file *af = (struct random_file *)f;

	kfree(f, sizeof(struct random_file));
	return 0;
}

static size_t random_read(int tag, void *buf, size_t count)
{
	if (!NT_SUCCESS(BCryptGenRandom(NULL, buf, count, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
		return 0;

	return count;
}

static size_t random_write(int tag, const void *buf, size_t count)
{
	return count;
}

static int random_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct random_file *rf = (struct random_file *)f;
	int ret = -ENOTTY;

	switch (cmd)
	{
	case RNDGETENTCNT:
		return rf->rnd_info.entropy_count;
		break;
	}

	return ret;
}

static int random_file_stat(struct file *f, struct newstat *buf)
{
	AcquireSRWLockShared(&f->rw_lock);
	struct random_file *af = (struct random_file *)f;
	struct virtualfs_custom_desc *desc = (struct virtualfs_custom_desc *)af->custom_file.desc;
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = mkdev(1, 9);
	buf->st_ino = 0;
	buf->st_mode = S_IWGRP | S_IWOTH | S_IFCHR;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = desc->device;
	buf->st_size = 4096;
	buf->st_blksize = 4096;
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

static const struct file_ops random_ops = {
	.read = random_read,
	.write = random_write,
	.ioctl = random_ioctl,
	.stat = random_file_stat,
	.close = random_close
};

struct virtualfs_char_desc random_desc = VIRTUALFS_CHAR(mkdev(1, 8), random_read, random_write);


struct file *random_file_alloc();

const struct virtualfs_custom_desc urandom_desc = VIRTUALFS_CUSTOM(mkdev(1, 9), random_file_alloc);

struct file *random_file_alloc()
{
	struct random_file *f = (struct random_file *)kmalloc(sizeof(struct random_file));
	memset(f, 0, sizeof(struct random_file));
	file_init(&f->custom_file.base_file, &random_ops, O_LARGEFILE | O_RDWR);
	virtualfs_init_custom(f, &urandom_desc);
	f->rnd_info.entropy_count = 1;
	return (struct file *)f;
}


//struct virtualfs_char_desc urandom_desc = VIRTUALFS_CHAR(mkdev(1, 9), random_read, random_write, random_ioctl);
