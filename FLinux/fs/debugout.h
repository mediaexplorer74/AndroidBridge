/*TODO: license message*/

#pragma once

#include <fs/file.h>
#include <fs/virtual.h>

const struct virtualfs_custom_desc debugout_desc;


extern struct file *debugout_file_alloc();

