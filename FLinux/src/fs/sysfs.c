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

#include <fs/debugout.h>
#include <fs/sysfs.h>
#include <fs/virtual.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

static const struct virtualfs_directory_desc sysfs_kernel_debug_tracing =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("trace_marker", debugout_desc)
		VIRTUALFS_ENTRY_END()
	}
};

static const struct virtualfs_directory_desc sysfs_devices_system_cpu =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
	VIRTUALFS_ENTRY("cpu0", sysfs_devices_system_cpu)
	VIRTUALFS_ENTRY("cpu1", sysfs_devices_system_cpu)
	VIRTUALFS_ENTRY_END()
}
};

static const struct virtualfs_directory_desc sysfs_kernel_debug =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("tracing", sysfs_kernel_debug_tracing)
		VIRTUALFS_ENTRY_END()
	}
};


static const struct virtualfs_directory_desc sysfs_devices_system =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
	VIRTUALFS_ENTRY("cpu", sysfs_devices_system_cpu)
	VIRTUALFS_ENTRY_END()
}
};

static const struct virtualfs_directory_desc sysfs_kernel =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("debug", sysfs_kernel_debug)
		VIRTUALFS_ENTRY_END()
	}
};

static const struct virtualfs_directory_desc sysfs_devices =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
	VIRTUALFS_ENTRY("system", sysfs_devices_system)
	VIRTUALFS_ENTRY_END()
}
};

static const struct virtualfs_directory_desc sysfs =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("kernel", sysfs_kernel)
		VIRTUALFS_ENTRY("devices", sysfs_devices)
		VIRTUALFS_ENTRY_END()
	}
};

struct file_system *sysfs_alloc()
{
	return virtualfs_alloc("/sys", &sysfs);
}
