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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre_lib.h
 *
 * Basic Lustre library routines.
 */

#ifndef _LUSTRE_LIB_H
#define _LUSTRE_LIB_H

/** \defgroup lib lib
 *
 * @{
 */

#include <linux/sched/signal.h>
#include <linux/sched/mm.h>

#include <linux/libcfs/libcfs.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <uapi/linux/lustre/lustre_ver.h>
#include <uapi/linux/lustre/lustre_cfg.h>

/* target.c */
struct ptlrpc_request;
struct obd_export;
struct lu_target;
#include <lustre_ha.h>
#include <lustre_net.h>

#define LI_POISON 0x5a5a5a5a
#if BITS_PER_LONG > 32
# define LL_POISON 0x5a5a5a5a5a5a5a5aL
#else
# define LL_POISON 0x5a5a5a5aL
#endif
#define LP_POISON ((void *)LL_POISON)

int target_pack_pool_reply(struct ptlrpc_request *req);
int do_set_info_async(struct obd_import *imp,
		      int opcode, int version,
		      size_t keylen, void *key,
		      size_t vallen, void *val,
		      struct ptlrpc_request_set *set);

void target_send_reply(struct ptlrpc_request *req, int rc, int fail_id);

#define LL_CDEBUG_PAGE(mask, page, fmt, arg...)				\
	CDEBUG(mask, "page %p map %p index %lu flags %lx count %u priv %0lx: " \
	       fmt, page, page->mapping, page->index, (long)page->flags, \
	       page_count(page), page_private(page), ## arg)

/** @} lib */

#endif /* _LUSTRE_LIB_H */
