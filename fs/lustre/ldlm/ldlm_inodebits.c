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
int ldlm_cli_dropbits(struct ldlm_lock *lock, u64 drop_bits)
{
	struct lustre_handle lockh;
	u32 flags = 0;
	int rc;

	LASSERT(drop_bits);
	LASSERT(!lock->l_readers && !lock->l_writers);

	LDLM_DEBUG(lock, "client lock convert START");

	ldlm_lock2handle(lock, &lockh);
	lock_res_and_lock(lock);
	/* check if all bits are blocked */
	if (!(lock->l_policy_data.l_inodebits.bits & ~drop_bits)) {
		unlock_res_and_lock(lock);
		/* return error to continue with cancel */
		rc = -EINVAL;
		goto exit;
	}

	/* check if no common bits, consider this as successful convert */
	if (!(lock->l_policy_data.l_inodebits.bits & drop_bits)) {
		unlock_res_and_lock(lock);
		rc = 0;
		goto exit;
	}

	/* check if there is race with cancel */
	if (ldlm_is_canceling(lock) || ldlm_is_cancel(lock)) {
		unlock_res_and_lock(lock);
		rc = -EINVAL;
		goto exit;
	}

	/* clear cbpending flag early, it is safe to match lock right after
	 * client convert because it is downgrade always.
	 */
	ldlm_clear_cbpending(lock);
	ldlm_clear_bl_ast(lock);

	/* If lock is being converted already, check drop bits first */
	if (ldlm_is_converting(lock)) {
		/* raced lock convert, lock inodebits are remaining bits
		 * so check if they are conflicting with new convert or not.
		 */
		if (!(lock->l_policy_data.l_inodebits.bits & drop_bits)) {
			unlock_res_and_lock(lock);
			rc = 0;
			goto exit;
		}
		/* Otherwise drop new conflicting bits in new convert */
	}
	ldlm_set_converting(lock);
	/* from all bits of blocking lock leave only conflicting */
	drop_bits &= lock->l_policy_data.l_inodebits.bits;
	/* save them in cancel_bits, so l_blocking_ast will know
	 * which bits from the current lock were dropped.
	 */
	lock->l_policy_data.l_inodebits.cancel_bits = drop_bits;
	/* Finally clear these bits in lock ibits */
	ldlm_inodebits_drop(lock, drop_bits);
	unlock_res_and_lock(lock);
	/* Finally call cancel callback for remaining bits only.
	 * It is important to have converting flag during that
	 * so blocking_ast callback can distinguish convert from
	 * cancels.
	 */
	if (lock->l_blocking_ast)
		lock->l_blocking_ast(lock, NULL, lock->l_ast_data,
				     LDLM_CB_CANCELING);

	/* now notify server about convert */
	rc = ldlm_cli_convert(lock, &flags);
	if (rc) {
		lock_res_and_lock(lock);
		if (ldlm_is_converting(lock)) {
			ldlm_clear_converting(lock);
			ldlm_set_cbpending(lock);
			ldlm_set_bl_ast(lock);
		}
		unlock_res_and_lock(lock);
		goto exit;
	}

exit:
	LDLM_DEBUG(lock, "client lock convert END");
	return rc;
}
