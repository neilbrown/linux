/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_LIBCFS_H__
#define __LIBCFS_LIBCFS_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include <uapi/linux/lnet/libcfs_ioctl.h>
#include <linux/libcfs/libcfs_debug.h>
#include <linux/libcfs/libcfs_private.h>
#include <linux/libcfs/bitmap.h>
#include <linux/libcfs/libcfs_string.h>
#include <linux/libcfs/libcfs_hash.h>
#include <linux/libcfs/libcfs_fail.h>
typedef u32 cfs_cap_t;
#define cfs_cap_pack(cap) (cap)
#define cfs_cap_unpack(cap) (cap)
static inline cfs_cap_t cfs_curproc_cap_pack(void){return cfs_cap_pack(current_cap().cap[0]);}

#define LIBCFS_VERSION	"0.7.1"

/* Sparse annotations */
#if !defined(__must_hold)
# ifdef __CHECKER__
#  define __must_hold(x) __attribute__((context(x, 1, 1)))
# else	/* __CHECKER__ */
#  define __must_hold(x)
# endif /* !__CHECKER__ */
#endif /* !__must_hold */

typedef s32 timeout_t;

/* need both kernel and user-land acceptor */
#define LNET_ACCEPTOR_MIN_RESERVED_PORT    512
#define LNET_ACCEPTOR_MAX_RESERVED_PORT    1023

int libcfs_ioctl(unsigned int cmd, struct libcfs_ioctl_data *data);

extern struct workqueue_struct *cfs_rehash_wq;

struct lnet_debugfs_symlink_def {
	const char *name;
	const char *target;
};

void lnet_insert_debugfs(struct ctl_table *table);
void lnet_remove_debugfs(struct ctl_table *table);

/* helper for sysctl handlers */
int lprocfs_call_handler(void *data, int write, loff_t *ppos,
			 void __user *buffer, size_t *lenp,
			 int (*handler)(void *data, int write, loff_t pos,
					void __user *buffer, int len));
int debugfs_doint(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos);

/*
 * Memory
 */
#if BITS_PER_LONG == 32
/* limit to lowmem on 32-bit systems */
#define NUM_CACHEPAGES \
	min(totalram_pages(), 1UL << (30 - PAGE_SHIFT) * 3 / 4)
#else
#define NUM_CACHEPAGES totalram_pages()
#endif

#define wait_var_event_warning(var, condition, format, ...)		\
do {									\
	int counter = 4;						\
	might_sleep();							\
	if (condition)							\
		break;							\
	___wait_var_event(var, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			  if (schedule_timeout(HZ) == 0)\
				  CDEBUG(is_power_of_2(counter++) ?	\
					 D_WARNING : D_NET,		\
					 format, ## __VA_ARGS__)	\
		);							\
} while (0)

/* atomic-context safe vfree */
void libcfs_vfree_atomic(const void *addr);

/* interval tree */

#define interval_tree_root rb_root_cached
#define interval_tree_first rb_first_cached
#define INTERVAL_TREE_ROOT RB_ROOT_CACHED
#define INTERVAL_TREE_EMPTY(_root) RB_EMPTY_ROOT(&(_root)->rb_root)

#endif /* _LIBCFS_LIBCFS_H_ */
