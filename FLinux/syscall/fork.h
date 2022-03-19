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

#pragma once
#if defined(_M_ARM)
#include "platform/arm/context.h"
#elif defined(_M_IX86)
#include "context.h"//"platform/x86/context.h"
#endif

extern void fork_init();


#ifdef _WIN64
extern int sys_clone_imp(struct syscall_context *context, unsigned long flags, void *child_stack, void *ptid, void *ctid);
#else
extern int sys_clone_imp(struct syscall_context *context, unsigned long flags, void *child_stack, void *ptid, int tls, void *ctid);
#endif

