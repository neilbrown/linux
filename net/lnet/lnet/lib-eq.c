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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/lnet/lib-eq.c
 *
 * Library level Event queue management routines
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/lnet/lib-lnet.h>

/**
 * Create an event queue that calls a @callback on each event.
 *
 * @callback	A handler function that runs when an event is deposited
 *		into the EQ. The constant value LNET_EQ_HANDLER_NONE can
 *		be used to indicate that no event handler is desired.
 *
 * Return:	On successful return, the newly created EQ is returned.
 *		On failure, an error code encoded with ERR_PTR() is returned.
 *		-EINVAL If an parameter is not valid.
 *		-ENOMEM If memory for the EQ can't be allocated.
 *
 * \see lnet_eq_handler_t for the discussion on EQ handler semantics.
 */
struct lnet_eq *
LNetEQAlloc(lnet_eq_handler_t callback)
{
	struct lnet_eq *eq;

	LASSERT(the_lnet.ln_refcount > 0);

	if (callback == LNET_EQ_HANDLER_NONE)
		return ERR_PTR(-EINVAL);

	eq = kzalloc(sizeof(*eq), GFP_NOFS);
	if (!eq)
		return ERR_PTR(-ENOMEM);

	eq->eq_callback = callback;

	eq->eq_refs = cfs_percpt_alloc(lnet_cpt_table(),
				       sizeof(*eq->eq_refs[0]));
	if (!eq->eq_refs)
		goto failed;

	return eq;

failed:

	if (eq->eq_refs)
		cfs_percpt_free(eq->eq_refs);

	kfree(eq);
	return ERR_PTR(-ENOMEM);
}
EXPORT_SYMBOL(LNetEQAlloc);

/**
 * Release the resources associated with an event queue if it's idle;
 * otherwise do nothing and it's up to the user to try again.
 *
 * @eq		The event queue to be released.
 *
 * Return:	0 If the EQ is not in use and freed.
 *		-EBUSY If the EQ is still in use by some MDs.
 */
int
LNetEQFree(struct lnet_eq *eq)
{
	int **refs = NULL;
	int *ref;
	int rc = 0;
	int i;

	LASSERT(the_lnet.ln_refcount > 0);

	lnet_res_lock(LNET_LOCK_EX);
	/*
	 * NB: hold lnet_eq_wait_lock for EQ link/unlink, so we can do
	 * both EQ lookup and poll event with only lnet_eq_wait_lock
	 */
	lnet_eq_wait_lock();

	cfs_percpt_for_each(ref, i, eq->eq_refs) {
		LASSERT(*ref >= 0);
		if (!*ref)
			continue;

		CDEBUG(D_NET, "Event equeue (%d: %d) busy on destroy.\n",
		       i, *ref);
		rc = -EBUSY;
		goto out;
	}

	/* stash for free after lock dropped */
	refs = eq->eq_refs;

	kfree(eq);
out:
	lnet_eq_wait_unlock();
	lnet_res_unlock(LNET_LOCK_EX);

	if (refs)
		cfs_percpt_free(refs);

	return rc;
}
EXPORT_SYMBOL(LNetEQFree);

void
lnet_eq_enqueue_event(struct lnet_eq *eq, struct lnet_event *ev)
{
	/* MUST called with resource lock hold but w/o lnet_eq_wait_lock */
	LASSERT(eq->eq_callback != LNET_EQ_HANDLER_NONE);
	eq->eq_callback(ev);
}
