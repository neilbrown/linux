// SPDX-License-Identifier: GPL-2.0
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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_inodebits.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

/**
 * This file contains implementation of IBITS lock type
 *
 * IBITS lock type contains a bit mask determining various properties of an
 * object. The meanings of specific bits are specific to the caller and are
 * opaque to LDLM code.
 *
 * Locks with intersecting bitmasks and conflicting lock modes (e.g.  LCK_PW)
 * are considered conflicting.  See the lock mode compatibility matrix
 * in lustre_dlm.h.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <lustre_dlm.h>
#include <obd_support.h>
#include <lustre_lib.h>
#include "ldlm_internal.h"

void ldlm_ibits_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				     union ldlm_policy_data *lpolicy)
{
	lpolicy->l_inodebits.bits = wpolicy->l_inodebits.bits;
}

void ldlm_ibits_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				     union ldlm_wire_policy_data *wpolicy)
{
	memset(wpolicy, 0, sizeof(*wpolicy));
	wpolicy->l_inodebits.bits = lpolicy->l_inodebits.bits;
	wpolicy->l_inodebits.li_gid = lpolicy->l_inodebits.li_gid;
}

/**
 * Attempt to convert already granted IBITS lock with several bits set to
 * a lock with less bits (downgrade).
 *
 * Such lock conversion is used to keep lock with non-blocking bits instead of
 * cancelling it, introduced for better support of DoM files.
 */
int ldlm_inodebits_drop(struct ldlm_lock *lock, u64 to_drop)
{
	check_res_locked(lock->l_resource);

	/* Just return if there are no conflicting bits */
	if ((lock->l_policy_data.l_inodebits.bits & to_drop) == 0) {
		LDLM_WARN(lock, "try to drop unset bits %#llx/%#llx",
			  lock->l_policy_data.l_inodebits.bits, to_drop);
		/* nothing to do */
		return 0;
	}

	/* remove lock from a skiplist and put in the new place
	 * according with new inodebits
	 */
	ldlm_resource_unlink_lock(lock);
	lock->l_policy_data.l_inodebits.bits &= ~to_drop;
	ldlm_grant_lock_with_skiplist(lock);
	return 0;
}
EXPORT_SYMBOL(ldlm_inodebits_drop);

/* convert single lock */
int ldlm_cli_inodebits_convert(struct ldlm_lock *lock,
			       enum ldlm_cancel_flags cancel_flags)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);
	struct ldlm_lock_desc ld = { { 0 } };
	u64 drop_bits, new_bits;
	u32 flags = 0;
	int rc;

	check_res_locked(lock->l_resource);

	/* Lock is being converted already */
	if (ldlm_is_converting(lock)) {
		if (!(cancel_flags & LCF_ASYNC)) {
			unlock_res_and_lock(lock);
			wait_event_idle(lock->l_waitq,
					is_lock_converted(lock));
			lock_res_and_lock(lock);
		}
		return 0;
	}

	/* lru_cancel may happen in parallel and call ldlm_cli_cancel_list()
	 * independently.
	 */
	if (ldlm_is_canceling(lock))
		return -EINVAL;

	/* no need in only local convert */
	if (lock->l_flags & (LDLM_FL_LOCAL_ONLY | LDLM_FL_CANCEL_ON_BLOCK))
		return -EINVAL;

	drop_bits = lock->l_policy_data.l_inodebits.cancel_bits;
	/* no cancel bits - means that caller needs full cancel */
	if (drop_bits == 0)
		return -EINVAL;

	new_bits = lock->l_policy_data.l_inodebits.bits & ~drop_bits;
	/* check if all lock bits are dropped, proceed with cancel */
	if (!new_bits)
		return -EINVAL;

	/* check if no dropped bits, consider this as successful convert
	 */
	if (lock->l_policy_data.l_inodebits.bits == new_bits)
		return 0;

	ldlm_set_converting(lock);
	/* Finally call cancel callback for remaining bits only.
	 * It is important to have converting flag during that
	 * so blocking_ast callback can distinguish convert from
	 * cancels.
	 */
	ld.l_policy_data.l_inodebits.cancel_bits = drop_bits;
	unlock_res_and_lock(lock);
	lock->l_blocking_ast(lock, &ld, lock->l_ast_data, LDLM_CB_CANCELING);
	/* now notify server about convert */
	rc = ldlm_cli_convert_req(lock, &flags, new_bits);
	lock_res_and_lock(lock);
	if (rc)
		goto full_cancel;

	/* Finally clear these bits in lock ibits */
	ldlm_inodebits_drop(lock, drop_bits);

	/* Being locked again check if lock was canceled, it is important
	 * to do and don't drop cbpending below
	 */
	if (ldlm_is_canceling(lock)) {
		rc = -EINVAL;
		goto full_cancel;
	}

	/* also check again if more bits to be cancelled appeared */
	if (drop_bits != lock->l_policy_data.l_inodebits.cancel_bits) {
		rc = -EAGAIN;
		goto clear_converting;
	}

	/* clear cbpending flag early, it is safe to match lock right after
	 * client convert because it is downgrade always.
	 */
	ldlm_clear_cbpending(lock);
	ldlm_clear_bl_ast(lock);
	spin_lock(&ns->ns_lock);
	if (list_empty(&lock->l_lru))
		ldlm_lock_add_to_lru_nolock(lock);
	spin_unlock(&ns->ns_lock);

	/* the job is done, zero the cancel_bits. If more conflicts appear,
	 * it will result in another cycle of ldlm_cli_inodebits_convert().
	 */
full_cancel:
	lock->l_policy_data.l_inodebits.cancel_bits = 0;
clear_converting:
	ldlm_clear_converting(lock);
	return rc;
}
