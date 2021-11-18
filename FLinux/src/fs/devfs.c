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

//#include <fs/console.h>
#include <fs/devfs.h>
#include <fs/dsp.h>
#include <fs/null.h>
#include <fs/random.h>
#include <fs/virtual.h>
#include <fs/zero.h>
#include <fs/memory.h>
#include <fs/android/logd.h>
#include <fs/android/propertyd.h>
#include <fs/android/ashmem.h>
#include <fs/android/binder.h>


static const struct virtualfs_directory_desc devfs_socket =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("logdw", logd_desc)
		VIRTUALFS_ENTRY("property_service", propertyd_desc)
		VIRTUALFS_ENTRY_END()
	}
};

static const struct virtualfs_directory_desc devfs_properties =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
	VIRTUALFS_ENTRY("u:object_r:dalvik_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:config_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("properties_serial", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:default_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:security_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:logd_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:system_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:debug_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:fingerprint_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:opengles_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:radio_noril_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:qemu_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:nfc_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:vold_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:restorecon_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:safemode_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:mmc_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:logpersistd_logging_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:device_logging_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:persist_debug_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:audio_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:shell_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:wifi_log_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:log_tag_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:log_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:dumpstate_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:debuggerd_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:bluetooth_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:pan_result_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:dhcp_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:ffs_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:powerctl_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:cppreopt_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:radio_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:system_radio_prop:s0", memory_desc)
	VIRTUALFS_ENTRY("u:object_r:net_radio_prop:s0", memory_desc)


	VIRTUALFS_ENTRY_END()
}
};

static const struct virtualfs_directory_desc devfs =
{
	.type = VIRTUALFS_TYPE_DIRECTORY,
	.entries = {
		VIRTUALFS_ENTRY("socket", devfs_socket)
		VIRTUALFS_ENTRY("dsp", dsp_desc)
		VIRTUALFS_ENTRY("null", null_desc)
		VIRTUALFS_ENTRY("zero", zero_desc)
		VIRTUALFS_ENTRY("random", random_desc)
		VIRTUALFS_ENTRY("urandom", urandom_desc)
#ifdef FLINUX_CONSOLE
		VIRTUALFS_ENTRY("console", console_desc)
		VIRTUALFS_ENTRY("tty", console_desc)
#endif
		VIRTUALFS_ENTRY("__properties__", devfs_properties)
		VIRTUALFS_ENTRY("ashmem", ashmem_desc)
		VIRTUALFS_ENTRY("binder", binder_desc)
		VIRTUALFS_ENTRY_END()
	}
};

struct file_system *devfs_alloc()
{
	return virtualfs_alloc("/dev", &devfs);
}
