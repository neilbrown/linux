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

	return eq;
}
EXPORT_SYMBOL(LNetEQAlloc);

/**
 * Release the resources associated with an event queue if it's idle;
 * otherwise do nothing and it's up to the user to try again.
 *
 * @eq		The event queue to be released.
 *
 * Return:	0
 */
int
LNetEQFree(struct lnet_eq *eq)
{
	kfree(eq);

	return 0;
}
EXPORT_SYMBOL(LNetEQFree);
