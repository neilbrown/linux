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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_lock.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <lustre_intent.h>
#include <lustre_swab.h>
#include <obd_class.h>
#include "ldlm_internal.h"

struct kmem_cache *ldlm_glimpse_work_kmem;

/* lock types */
char *ldlm_lockname[] = {
	[0]		= "--",
	[LCK_EX]	= "EX",
	[LCK_PW]	= "PW",
	[LCK_PR]	= "PR",
	[LCK_CW]	= "CW",
	[LCK_CR]	= "CR",
	[LCK_NL]	= "NL",
	[LCK_GROUP]	= "GROUP",
	[LCK_COS]	= "COS",
};
EXPORT_SYMBOL(ldlm_lockname);

static char *ldlm_typename[] = {
	[LDLM_PLAIN]	= "PLN",
	[LDLM_EXTENT]	= "EXT",
	[LDLM_FLOCK]	= "FLK",
	[LDLM_IBITS]	= "IBT",
};

static ldlm_policy_wire_to_local_t ldlm_policy_wire_to_local[] = {
	[LDLM_PLAIN - LDLM_MIN_TYPE]	= ldlm_plain_policy_wire_to_local,
	[LDLM_EXTENT - LDLM_MIN_TYPE]	= ldlm_extent_policy_wire_to_local,
	[LDLM_FLOCK - LDLM_MIN_TYPE]	= ldlm_flock_policy_wire_to_local,
	[LDLM_IBITS - LDLM_MIN_TYPE]	= ldlm_ibits_policy_wire_to_local,
};

static ldlm_policy_local_to_wire_t ldlm_policy_local_to_wire[] = {
	[LDLM_PLAIN - LDLM_MIN_TYPE]	= ldlm_plain_policy_local_to_wire,
	[LDLM_EXTENT - LDLM_MIN_TYPE]	= ldlm_extent_policy_local_to_wire,
	[LDLM_FLOCK - LDLM_MIN_TYPE]	= ldlm_flock_policy_local_to_wire,
	[LDLM_IBITS - LDLM_MIN_TYPE]	= ldlm_ibits_policy_local_to_wire,
};

/**
 * Converts lock policy from local format to on the wire lock_desc format
 */
static void ldlm_convert_policy_to_wire(enum ldlm_type type,
					const union ldlm_policy_data *lpolicy,
					union ldlm_wire_policy_data *wpolicy)
{
	ldlm_policy_local_to_wire_t convert;

	convert = ldlm_policy_local_to_wire[type - LDLM_MIN_TYPE];

	convert(lpolicy, wpolicy);
}

/**
 * Converts lock policy from on the wire lock_desc format to local format
 */
void ldlm_convert_policy_to_local(struct obd_export *exp, enum ldlm_type type,
				  const union ldlm_wire_policy_data *wpolicy,
				  union ldlm_policy_data *lpolicy)
{
	ldlm_policy_wire_to_local_t convert;

	convert = ldlm_policy_wire_to_local[type - LDLM_MIN_TYPE];

	convert(wpolicy, lpolicy);
}

const char *ldlm_it2str(enum ldlm_intent_flags it)
{
	switch (it) {
	case IT_OPEN:
		return "open";
	case IT_CREAT:
		return "creat";
	case (IT_OPEN | IT_CREAT):
		return "open|creat";
	case IT_READDIR:
		return "readdir";
	case IT_GETATTR:
		return "getattr";
	case IT_LOOKUP:
		return "lookup";
	case IT_GETXATTR:
		return "getxattr";
	case IT_LAYOUT:
		return "layout";
	default:
		CERROR("Unknown intent 0x%08x\n", it);
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL(ldlm_it2str);

/*
 * REFCOUNTED LOCK OBJECTS
 */

/**
 * Get a reference on a lock.
 *
 * Lock refcounts, during creation:
 *   - one special one for allocation, dec'd only once in destroy
 *   - one for being a lock that's in-use
 *   - one for the addref associated with a new lock
 */
struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock)
{
	refcount_inc(&lock->l_handle.h_ref);
	return lock;
}
EXPORT_SYMBOL(ldlm_lock_get);

static void lock_handle_free(struct rcu_head *rcu)
{
	struct ldlm_lock *lock = container_of(rcu, struct ldlm_lock,
					      l_handle.h_rcu);
	kmem_cache_free(ldlm_lock_slab, lock);
}

/**
 * Release lock reference.
 *
 * Also frees the lock if it was last reference.
 */
void ldlm_lock_put(struct ldlm_lock *lock)
{
	LASSERT(lock->l_resource != LP_POISON);
	LASSERT(refcount_read(&lock->l_handle.h_ref) > 0);
	if (refcount_dec_and_test(&lock->l_handle.h_ref)) {
		struct ldlm_resource *res;

		LDLM_DEBUG(lock,
			   "final lock_put on destroyed lock, freeing it.");

		res = lock->l_resource;
		LASSERT(ldlm_is_destroyed(lock));
		LASSERT(list_empty(&lock->l_res_link));
		LASSERT(list_empty(&lock->l_pending_chain));

		lprocfs_counter_decr(ldlm_res_to_ns(res)->ns_stats,
				     LDLM_NSS_LOCKS);
		lu_ref_del(&res->lr_reference, "lock", lock);
		ldlm_resource_putref(res);
		lock->l_resource = NULL;
		if (lock->l_export) {
			class_export_lock_put(lock->l_export, lock);
			lock->l_export = NULL;
		}

		kvfree(lock->l_lvb_data);

		lu_ref_fini(&lock->l_reference);
		call_rcu(&lock->l_handle.h_rcu, lock_handle_free);
	}
}
EXPORT_SYMBOL(ldlm_lock_put);

/**
 * Removes LDLM lock @lock from LRU. Assumes LRU is already locked.
 */
int ldlm_lock_remove_from_lru_nolock(struct ldlm_lock *lock)
{
	int rc = 0;

	if (!list_empty(&lock->l_lru)) {
		struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

		LASSERT(lock->l_resource->lr_type != LDLM_FLOCK);
		if (ns->ns_last_pos == &lock->l_lru)
			ns->ns_last_pos = lock->l_lru.prev;
		list_del_init(&lock->l_lru);
		LASSERT(ns->ns_nr_unused > 0);
		ns->ns_nr_unused--;
		rc = 1;
	}
	return rc;
}

/**
 * Removes LDLM lock @lock from LRU. Obtains the LRU lock first.
 *
 * If @last_use is non-zero, it will remove the lock from LRU only if
 * it matches lock's l_last_used.
 *
 * Return:	0 if @last_use is set, the lock is not in LRU list or
 *		@last_use doesn't match lock's l_last_used;
 *		otherwise, the lock hasn't been in the LRU list.
 *
 *		1 the lock was in LRU list and removed.
 */
int ldlm_lock_remove_from_lru_check(struct ldlm_lock *lock, ktime_t last_use)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);
	int rc = 0;

	spin_lock(&ns->ns_lock);
	if (!ktime_compare(last_use, ktime_set(0, 0)) ||
	    !ktime_compare(last_use, lock->l_last_used))
		rc = ldlm_lock_remove_from_lru_nolock(lock);
	spin_unlock(&ns->ns_lock);

	return rc;
}

/**
 * Adds LDLM lock @lock to namespace LRU. Assumes LRU is already locked.
 */
void ldlm_lock_add_to_lru_nolock(struct ldlm_lock *lock)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

	lock->l_last_used = ktime_get();
	LASSERT(list_empty(&lock->l_lru));
	LASSERT(lock->l_resource->lr_type != LDLM_FLOCK);
	list_add_tail(&lock->l_lru, &ns->ns_unused_list);
	LASSERT(ns->ns_nr_unused >= 0);
	ns->ns_nr_unused++;
}

/**
 * Adds LDLM lock @lock to namespace LRU. Obtains necessary LRU locks
 * first.
 */
static void ldlm_lock_add_to_lru(struct ldlm_lock *lock)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

	spin_lock(&ns->ns_lock);
	ldlm_lock_add_to_lru_nolock(lock);
	spin_unlock(&ns->ns_lock);
}

/**
 * Moves LDLM lock @lock that is already in namespace LRU to the tail of
 * the LRU. Performs necessary LRU locking
 */
static void ldlm_lock_touch_in_lru(struct ldlm_lock *lock)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

	spin_lock(&ns->ns_lock);
	if (!list_empty(&lock->l_lru)) {
		ldlm_lock_remove_from_lru_nolock(lock);
		ldlm_lock_add_to_lru_nolock(lock);
	}
	spin_unlock(&ns->ns_lock);
}

/**
 * Helper to destroy a locked lock.
 *
 * Used by ldlm_lock_destroy and ldlm_lock_destroy_nolock
 * Must be called with l_lock and lr_lock held.
 *
 * Does not actually free the lock data, but rather marks the lock as
 * destroyed by setting l_destroyed field in the lock to 1.  Destroys a
 * handle->lock association too, so that the lock can no longer be found
 * and removes the lock from LRU list.  Actual lock freeing occurs when
 * last lock reference goes away.
 *
 * Original comment (of some historical value):
 * This used to have a 'strict' flag, which recovery would use to mark an
 * in-use lock as needing-to-die.  Lest I am ever tempted to put it back, I
 * shall explain why it's gone: with the new hash table scheme, once you call
 * ldlm_lock_destroy, you can never drop your final references on this lock.
 * Because it's not in the hash table anymore.  -phil
 */
static int ldlm_lock_destroy_internal(struct ldlm_lock *lock)
{
	if (lock->l_readers || lock->l_writers) {
		LDLM_ERROR(lock, "lock still has references");
		LBUG();
	}

	if (!list_empty(&lock->l_res_link)) {
		LDLM_ERROR(lock, "lock still on resource");
		LBUG();
	}

	if (ldlm_is_destroyed(lock)) {
		LASSERT(list_empty(&lock->l_lru));
		return 0;
	}
	ldlm_set_destroyed(lock);

	ldlm_lock_remove_from_lru(lock);
	class_handle_unhash(&lock->l_handle);

	return 1;
}

/**
 * Destroys a LDLM lock @lock. Performs necessary locking first.
 */
static void ldlm_lock_destroy(struct ldlm_lock *lock)
{
	int first;

	lock_res_and_lock(lock);
	first = ldlm_lock_destroy_internal(lock);
	unlock_res_and_lock(lock);

	/* drop reference from hashtable only for first destroy */
	if (first) {
		lu_ref_del(&lock->l_reference, "hash", lock);
		LDLM_LOCK_RELEASE(lock);
	}
}

/**
 * Destroys a LDLM lock @lock that is already locked.
 */
void ldlm_lock_destroy_nolock(struct ldlm_lock *lock)
{
	int first;

	first = ldlm_lock_destroy_internal(lock);
	/* drop reference from hashtable only for first destroy */
	if (first) {
		lu_ref_del(&lock->l_reference, "hash", lock);
		LDLM_LOCK_RELEASE(lock);
	}
}

static const char lock_handle_owner[] = "ldlm";

/**
 *
 * Allocate and initialize new lock structure.
 *
 * usage: pass in a resource on which you have done ldlm_resource_get
 *	new lock will take over the refcount.
 * returns: lock with refcount 2 - one for current caller and one for remote
 */
static struct ldlm_lock *ldlm_lock_new(struct ldlm_resource *resource)
{
	struct ldlm_lock *lock;

	LASSERT(resource);

	lock = kmem_cache_zalloc(ldlm_lock_slab, GFP_NOFS);
	if (!lock)
		return NULL;

	lock->l_resource = resource;
	lu_ref_add(&resource->lr_reference, "lock", lock);

	refcount_set(&lock->l_handle.h_ref, 2);
	INIT_LIST_HEAD(&lock->l_res_link);
	INIT_LIST_HEAD(&lock->l_lru);
	INIT_LIST_HEAD(&lock->l_pending_chain);
	INIT_LIST_HEAD(&lock->l_bl_ast);
	INIT_LIST_HEAD(&lock->l_cp_ast);
	INIT_LIST_HEAD(&lock->l_rk_ast);
	init_waitqueue_head(&lock->l_waitq);
	lock->l_blocking_lock = NULL;
	INIT_LIST_HEAD(&lock->l_sl_mode);
	INIT_LIST_HEAD(&lock->l_sl_policy);
	RB_CLEAR_NODE(&lock->l_rb);

	lprocfs_counter_incr(ldlm_res_to_ns(resource)->ns_stats,
			     LDLM_NSS_LOCKS);
	INIT_HLIST_NODE(&lock->l_handle.h_link);
	class_handle_hash(&lock->l_handle, lock_handle_owner);

	lu_ref_init(&lock->l_reference);
	lu_ref_add(&lock->l_reference, "hash", lock);
	lock->l_callback_timestamp = 0;
	lock->l_activity = 0;

#if LUSTRE_TRACKS_LOCK_EXP_REFS
	INIT_LIST_HEAD(&lock->l_exp_refs_link);
	lock->l_exp_refs_nr = 0;
	lock->l_exp_refs_target = NULL;
#endif

	return lock;
}

/**
 * Moves LDLM lock @lock to another resource.
 * This is used on client when server returns some other lock than requested
 * (typically as a result of intent operation)
 */
int ldlm_lock_change_resource(struct ldlm_namespace *ns, struct ldlm_lock *lock,
			      const struct ldlm_res_id *new_resid)
{
	struct ldlm_resource *oldres;
	struct ldlm_resource *newres;
	int type;

	oldres = lock_res_and_lock(lock);
	if (memcmp(new_resid, &oldres->lr_name,
		   sizeof(oldres->lr_name)) == 0) {
		/* Nothing to do */
		unlock_res_and_lock(lock);
		return 0;
	}

	LASSERT(new_resid->name[0] != 0);

	/* This function assumes that the lock isn't on any lists */
	LASSERT(list_empty(&lock->l_res_link));

	type = oldres->lr_type;
	unlock_res_and_lock(lock);

	newres = ldlm_resource_get(ns, NULL, new_resid, type, 1);
	if (IS_ERR(newres))
		return PTR_ERR(newres);

	lu_ref_add(&newres->lr_reference, "lock", lock);
	/*
	 * To flip the lock from the old to the new resource, oldres
	 * and newres have to be locked. Resource spin-locks are taken
	 * in the memory address order to avoid dead-locks.
	 * As this is the only circumstance where ->l_resource
	 * can change, and this cannot race with itself, it is safe
	 * to access lock->l_resource without being careful about locking.
	 */
	oldres = lock->l_resource;
	if (oldres < newres) {
		lock_res(oldres);
		lock_res_nested(newres, LRT_NEW);
	} else {
		lock_res(newres);
		lock_res_nested(oldres, LRT_NEW);
	}
	LASSERT(memcmp(new_resid, &oldres->lr_name,
		       sizeof(oldres->lr_name)) != 0);
	rcu_assign_pointer(lock->l_resource, newres);
	unlock_res(oldres);
	unlock_res(newres);

	/* ...and the flowers are still standing! */
	lu_ref_del(&oldres->lr_reference, "lock", lock);
	ldlm_resource_putref(oldres);

	return 0;
}

/** \defgroup ldlm_handles LDLM HANDLES
 * Ways to get hold of locks without any addresses.
 * @{
 */

/**
 * Fills in handle for LDLM lock @lock into supplied @lockh
 * Does not take any references.
 */
void ldlm_lock2handle(const struct ldlm_lock *lock, struct lustre_handle *lockh)
{
	lockh->cookie = lock->l_handle.h_cookie;
}
EXPORT_SYMBOL(ldlm_lock2handle);

/**
 * Obtain a lock reference by handle.
 *
 * if @flags: atomically get the lock and set the flags.
 *	      Return NULL if flag already set
 */
struct ldlm_lock *__ldlm_handle2lock(const struct lustre_handle *handle,
				     u64 flags)
{
	struct ldlm_lock *lock;

	LASSERT(handle);

	if (!lustre_handle_is_used(handle))
		return NULL;

	lock = class_handle2object(handle->cookie, lock_handle_owner);
	if (!lock)
		return NULL;

	if (lock->l_export && lock->l_export->exp_failed) {
		CDEBUG(D_INFO, "lock export failed: lock %p, exp %p\n",
		       lock, lock->l_export);
		LDLM_LOCK_PUT(lock);
		return NULL;
	}

	/* It's unlikely but possible that someone marked the lock as
	 * destroyed after we did handle2object on it
	 */
	if (flags == 0 && !ldlm_is_destroyed(lock)) {
		lu_ref_add_atomic(&lock->l_reference, "handle", lock);
		return lock;
	}

	lock_res_and_lock(lock);

	LASSERT(lock->l_resource);

	lu_ref_add_atomic(&lock->l_reference, "handle", lock);
	if (unlikely(ldlm_is_destroyed(lock))) {
		unlock_res_and_lock(lock);
		CDEBUG(D_INFO, "lock already destroyed: lock %p\n", lock);
		LDLM_LOCK_PUT(lock);
		return NULL;
	}

	if (flags) {
		if (lock->l_flags & flags) {
			unlock_res_and_lock(lock);
			LDLM_LOCK_PUT(lock);
			return NULL;
		}

		lock->l_flags |= flags;
	}

	unlock_res_and_lock(lock);
	return lock;
}
EXPORT_SYMBOL(__ldlm_handle2lock);
/** @} ldlm_handles */

/**
 * Fill in "on the wire" representation for given LDLM lock into supplied
 * lock descriptor @desc structure.
 */
void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc)
{
	ldlm_res2desc(lock->l_resource, &desc->l_resource);
	desc->l_req_mode = lock->l_req_mode;
	desc->l_granted_mode = lock->l_granted_mode;
	ldlm_convert_policy_to_wire(lock->l_resource->lr_type,
				    &lock->l_policy_data,
				    &desc->l_policy_data);
}

/**
 * Add a lock to list of conflicting locks to send AST to.
 *
 * Only add if we have not sent a blocking AST to the lock yet.
 */
static void ldlm_add_bl_work_item(struct ldlm_lock *lock, struct ldlm_lock *new,
				  struct list_head *work_list)
{
	if (!ldlm_is_ast_sent(lock)) {
		LDLM_DEBUG(lock, "lock incompatible; sending blocking AST.");
		ldlm_set_ast_sent(lock);
		/* If the enqueuing client said so, tell the AST recipient to
		 * discard dirty data, rather than writing back.
		 */
		if (ldlm_is_ast_discard_data(new))
			ldlm_set_discard_data(lock);
		/* Lock can be converted from a blocking state back to granted
		 * after lock convert or COS downgrade but still be in an
		 * older bl_list because it is controlled only by
		 * ldlm_work_bl_ast_lock(), let it be processed there.
		 */
		if (list_empty(&lock->l_bl_ast)) {
			list_add(&lock->l_bl_ast, work_list);
			LDLM_LOCK_GET(lock);
		}
		LASSERT(!lock->l_blocking_lock);
		lock->l_blocking_lock = LDLM_LOCK_GET(new);
	}
}

/**
 * Add a lock to list of just granted locks to send completion AST to.
 */
static void ldlm_add_cp_work_item(struct ldlm_lock *lock,
				  struct list_head *work_list)
{
	if (!ldlm_is_cp_reqd(lock)) {
		ldlm_set_cp_reqd(lock);
		LDLM_DEBUG(lock, "lock granted; sending completion AST.");
		LASSERT(list_empty(&lock->l_cp_ast));
		list_add(&lock->l_cp_ast, work_list);
		LDLM_LOCK_GET(lock);
	}
}

/**
 * Aggregator function to add AST work items into a list. Determines
 * what sort of an AST work needs to be done and calls the proper
 * adding function.
 * Must be called with lr_lock held.
 */
static void ldlm_add_ast_work_item(struct ldlm_lock *lock,
				   struct ldlm_lock *new,
				   struct list_head *work_list)
{
	check_res_locked(lock->l_resource);
	if (new)
		ldlm_add_bl_work_item(lock, new, work_list);
	else
		ldlm_add_cp_work_item(lock, work_list);
}

/**
 * Add specified reader/writer reference to LDLM lock with handle @lockh.
 * r/w reference type is determined by @mode
 * Calls ldlm_lock_addref_internal.
 */
void ldlm_lock_addref(const struct lustre_handle *lockh, enum ldlm_mode mode)
{
	struct ldlm_lock *lock;

	lock = ldlm_handle2lock(lockh);
	LASSERTF(lock, "Non-existing lock: %llx\n", lockh->cookie);
	ldlm_lock_addref_internal(lock, mode);
	LDLM_LOCK_PUT(lock);
}
EXPORT_SYMBOL(ldlm_lock_addref);

/**
 * Helper function.
 * Add specified reader/writer reference to LDLM lock @lock.
 * r/w reference type is determined by @mode
 * Removes lock from LRU if it is there.
 * Assumes the LDLM lock is already locked.
 */
void ldlm_lock_addref_internal_nolock(struct ldlm_lock *lock,
				      enum ldlm_mode mode)
{
	ldlm_lock_remove_from_lru(lock);
	if (mode & (LCK_NL | LCK_CR | LCK_PR)) {
		lock->l_readers++;
		lu_ref_add_atomic(&lock->l_reference, "reader", lock);
	}
	if (mode & (LCK_EX | LCK_CW | LCK_PW | LCK_GROUP | LCK_COS)) {
		lock->l_writers++;
		lu_ref_add_atomic(&lock->l_reference, "writer", lock);
	}
	LDLM_LOCK_GET(lock);
	lu_ref_add_atomic(&lock->l_reference, "user", lock);
	LDLM_DEBUG(lock, "ldlm_lock_addref(%s)", ldlm_lockname[mode]);
}

/**
 * Attempts to add reader/writer reference to a lock with handle @lockh, and
 * fails if lock is already LDLM_FL_CBPENDING or destroyed.
 *
 * Return:	0 success, lock was addref-ed
 *		-EAGAIN lock is being canceled.
 */
int ldlm_lock_addref_try(const struct lustre_handle *lockh, enum ldlm_mode mode)
{
	struct ldlm_lock *lock;
	int result;

	result = -EAGAIN;
	lock = ldlm_handle2lock(lockh);
	if (lock) {
		lock_res_and_lock(lock);
		if (lock->l_readers != 0 || lock->l_writers != 0 ||
		    !ldlm_is_cbpending(lock)) {
			ldlm_lock_addref_internal_nolock(lock, mode);
			result = 0;
		}
		unlock_res_and_lock(lock);
		LDLM_LOCK_PUT(lock);
	}
	return result;
}
EXPORT_SYMBOL(ldlm_lock_addref_try);

/**
 * Add specified reader/writer reference to LDLM lock @lock.
 * Locks LDLM lock and calls ldlm_lock_addref_internal_nolock to do the work.
 * Only called for local locks.
 */
void ldlm_lock_addref_internal(struct ldlm_lock *lock, enum ldlm_mode mode)
{
	lock_res_and_lock(lock);
	ldlm_lock_addref_internal_nolock(lock, mode);
	unlock_res_and_lock(lock);
}

/**
 * Removes reader/writer reference for LDLM lock @lock.
 * Assumes LDLM lock is already locked.
 * only called in ldlm_flock_destroy and for local locks.
 * Does NOT add lock to LRU if no r/w references left to accommodate flock locks
 * that cannot be placed in LRU.
 */
void ldlm_lock_decref_internal_nolock(struct ldlm_lock *lock,
				      enum ldlm_mode mode)
{
	LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
	if (mode & (LCK_NL | LCK_CR | LCK_PR)) {
		LASSERT(lock->l_readers > 0);
		lu_ref_del(&lock->l_reference, "reader", lock);
		lock->l_readers--;
	}
	if (mode & (LCK_EX | LCK_CW | LCK_PW | LCK_GROUP | LCK_COS)) {
		LASSERT(lock->l_writers > 0);
		lu_ref_del(&lock->l_reference, "writer", lock);
		lock->l_writers--;
	}

	lu_ref_del(&lock->l_reference, "user", lock);
	LDLM_LOCK_RELEASE(lock);    /* matches the LDLM_LOCK_GET() in addref */
}

/**
 * Removes reader/writer reference for LDLM lock @lock.
 * Locks LDLM lock first.
 * If the lock is determined to be client lock on a client and r/w refcount
 * drops to zero and the lock is not blocked, the lock is added to LRU lock
 * on the namespace.
 * For blocked LDLM locks if r/w count drops to zero, blocking_ast is called.
 */
void ldlm_lock_decref_internal(struct ldlm_lock *lock, enum ldlm_mode mode)
{
	struct ldlm_namespace *ns;

	lock_res_and_lock(lock);

	ns = ldlm_lock_to_ns(lock);

	ldlm_lock_decref_internal_nolock(lock, mode);

	if ((ldlm_is_local(lock) || lock->l_req_mode == LCK_GROUP) &&
	    !lock->l_readers && !lock->l_writers) {
		/* If this is a local lock on a server namespace and this was
		 * the last reference, cancel the lock.
		 *
		 * Group locks are special:
		 * They must not go in LRU, but they are not called back
		 * like non-group locks, instead they are manually released.
		 * They have an l_writers reference which they keep until
		 * they are manually released, so we remove them when they have
		 * no more reader or writer references. - LU-6368
		 */
		ldlm_set_cbpending(lock);
	}

	if (!lock->l_readers && !lock->l_writers && ldlm_is_cbpending(lock)) {
		unsigned int mask = D_DLMTRACE;

		/* If we received a blocked AST and this was the last reference,
		 * run the callback.
		 */
		LDLM_DEBUG_LIMIT(mask, lock,
				 "final decref done on %sCBPENDING lock",
				 mask & D_WARNING ? "non-local " : "");

		LDLM_LOCK_GET(lock); /* dropped by bl thread */
		ldlm_lock_remove_from_lru(lock);
		unlock_res_and_lock(lock);

		if (ldlm_is_fail_loc(lock))
			OBD_RACE(OBD_FAIL_LDLM_CP_BL_RACE);

		if (ldlm_is_atomic_cb(lock) ||
		    ldlm_bl_to_thread_lock(ns, NULL, lock) != 0)
			ldlm_handle_bl_callback(ns, NULL, lock);
	} else if (!lock->l_readers && !lock->l_writers &&
		   !ldlm_is_no_lru(lock) && !ldlm_is_bl_ast(lock) &&
		   !ldlm_is_converting(lock)) {

		/* If this is a client-side namespace and this was the last
		 * reference, put it on the LRU.
		 */
		ldlm_lock_add_to_lru(lock);
		unlock_res_and_lock(lock);
		LDLM_DEBUG(lock, "add lock into lru list");

		if (ldlm_is_fail_loc(lock))
			OBD_RACE(OBD_FAIL_LDLM_CP_BL_RACE);

		ldlm_pool_recalc(&ns->ns_pool, true);
	} else {
		LDLM_DEBUG(lock, "do not add lock into lru list");
		unlock_res_and_lock(lock);
	}
}

/**
 * Decrease reader/writer refcount for LDLM lock with handle @lockh
 */
void ldlm_lock_decref(const struct lustre_handle *lockh, enum ldlm_mode mode)
{
	struct ldlm_lock *lock = __ldlm_handle2lock(lockh, 0);

	LASSERTF(lock, "Non-existing lock: %#llx\n", lockh->cookie);
	ldlm_lock_decref_internal(lock, mode);
	LDLM_LOCK_PUT(lock);
}
EXPORT_SYMBOL(ldlm_lock_decref);

/**
 * Decrease reader/writer refcount for LDLM lock with handle
 * @lockh and mark it for subsequent cancellation once r/w refcount
 * drops to zero instead of putting into LRU.
 */
void ldlm_lock_decref_and_cancel(const struct lustre_handle *lockh,
				 enum ldlm_mode mode)
{
	struct ldlm_lock *lock = __ldlm_handle2lock(lockh, 0);

	LASSERT(lock);

	LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
	lock_res_and_lock(lock);
	ldlm_set_cbpending(lock);
	unlock_res_and_lock(lock);
	ldlm_lock_decref_internal(lock, mode);
	LDLM_LOCK_PUT(lock);
}
EXPORT_SYMBOL(ldlm_lock_decref_and_cancel);

struct sl_insert_point {
	struct list_head *res_link;
	struct list_head *mode_link;
	struct list_head *policy_link;
};

/**
 * Finds a position to insert the new lock into granted lock list.
 *
 * Used for locks eligible for skiplist optimization.
 *
 * Parameters:
 *      queue [input]:  the granted list where search acts on;
 *      req [input]:    the lock whose position to be located;
 *      prev [output]:  positions within 3 lists to insert @req to
 * Return Value:
 *      filled @prev
 * NOTE: called by
 *  - ldlm_grant_lock_with_skiplist
 */
static void search_granted_lock(struct list_head *queue,
				struct ldlm_lock *req,
				struct sl_insert_point *prev)
{
	struct ldlm_lock *lock, *mode_end, *policy_end;

	list_for_each_entry(lock, queue, l_res_link) {
		mode_end = list_prev_entry(lock, l_sl_mode);

		if (lock->l_req_mode != req->l_req_mode) {
			/* jump to last lock of mode group */
			lock = mode_end;
			continue;
		}

		/* suitable mode group is found */
		if (lock->l_resource->lr_type == LDLM_PLAIN) {
			/* insert point is last lock of the mode group */
			prev->res_link = &mode_end->l_res_link;
			prev->mode_link = &mode_end->l_sl_mode;
			prev->policy_link = &req->l_sl_policy;
			return;
		}

		if (lock->l_resource->lr_type == LDLM_IBITS) {
			for (;;) {
				policy_end =
					list_prev_entry(lock, l_sl_policy);

				if (lock->l_policy_data.l_inodebits.bits ==
				    req->l_policy_data.l_inodebits.bits) {
					/* insert point is last lock of
					 * the policy group
					 */
					prev->res_link =
						&policy_end->l_res_link;
					prev->mode_link =
						&policy_end->l_sl_mode;
					prev->policy_link =
						&policy_end->l_sl_policy;
					return;
				}

				if (policy_end == mode_end)
					/* done with mode group */
					break;

				/* go to next policy group within mode group */
				lock = list_next_entry(policy_end, l_res_link);
			}  /* loop over policy groups within the mode group */

			/* insert point is last lock of the mode group,
			 * new policy group is started
			 */
			prev->res_link = &mode_end->l_res_link;
			prev->mode_link = &mode_end->l_sl_mode;
			prev->policy_link = &req->l_sl_policy;
			return;
		}

		LDLM_ERROR(lock, "is not LDLM_PLAIN or LDLM_IBITS lock");
		LBUG();
	}

	/* insert point is last lock on the queue,
	 * new mode group and new policy group are started
	 */
	prev->res_link = queue->prev;
	prev->mode_link = &req->l_sl_mode;
	prev->policy_link = &req->l_sl_policy;
}

/**
 * Add a lock into resource granted list after a position described by
 * @prev.
 */
static void ldlm_granted_list_add_lock(struct ldlm_lock *lock,
				       struct sl_insert_point *prev)
{
	struct ldlm_resource *res = lock->l_resource;

	check_res_locked(res);

	ldlm_resource_dump(D_INFO, res);
	LDLM_DEBUG(lock, "About to add lock:");

	if (ldlm_is_destroyed(lock)) {
		CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
		return;
	}

	LASSERT(list_empty(&lock->l_res_link));
	LASSERT(list_empty(&lock->l_sl_mode));
	LASSERT(list_empty(&lock->l_sl_policy));

	/*
	 * lock->link == prev->link means lock is first starting the group.
	 * Don't re-add to itself to suppress kernel warnings.
	 */
	if (&lock->l_res_link != prev->res_link)
		list_add(&lock->l_res_link, prev->res_link);
	if (&lock->l_sl_mode != prev->mode_link)
		list_add(&lock->l_sl_mode, prev->mode_link);
	if (&lock->l_sl_policy != prev->policy_link)
		list_add(&lock->l_sl_policy, prev->policy_link);
}

/**
 * Add a lock to granted list on a resource maintaining skiplist
 * correctness.
 */
void ldlm_grant_lock_with_skiplist(struct ldlm_lock *lock)
{
	struct sl_insert_point prev;

	LASSERT(ldlm_is_granted(lock));

	search_granted_lock(&lock->l_resource->lr_granted, lock, &prev);
	ldlm_granted_list_add_lock(lock, &prev);
}

/**
 * Perform lock granting bookkeeping.
 *
 * Includes putting the lock into granted list and updating lock mode.
 * NOTE: called by
 *  - ldlm_lock_enqueue
 *  - ldlm_reprocess_queue
 *  - ldlm_lock_convert
 *
 * must be called with lr_lock held
 */
void ldlm_grant_lock(struct ldlm_lock *lock, struct list_head *work_list)
{
	struct ldlm_resource *res = lock->l_resource;

	check_res_locked(res);

	lock->l_granted_mode = lock->l_req_mode;

	if (work_list && lock->l_completion_ast)
		ldlm_add_ast_work_item(lock, NULL, work_list);

	if (res->lr_type == LDLM_PLAIN || res->lr_type == LDLM_IBITS) {
		ldlm_grant_lock_with_skiplist(lock);
	} else if (res->lr_type == LDLM_EXTENT) {
		ldlm_extent_add_lock(res, lock);
	} else if (res->lr_type == LDLM_FLOCK) {
		/*
		 * We should not add locks to granted list in
		 * the following cases:
		 * - this is an UNLOCK but not a real lock;
		 * - this is a TEST lock;
		 * - this is a F_CANCELLK lock (async flock has req_mode == 0)
		 * - this is a deadlock (flock cannot be granted)
		 */
		if (!lock->l_req_mode || lock->l_req_mode == LCK_NL ||
		    ldlm_is_test_lock(lock) || ldlm_is_flock_deadlock(lock))
			return;
		ldlm_resource_add_lock(res, &res->lr_granted, lock);
	} else {
		LBUG();
	}

	ldlm_pool_add(&ldlm_res_to_ns(res)->ns_pool, lock);
}

/**
 * Check if the given @lock meets the criteria for a match.
 * A reference on the lock is taken if matched.
 *
 * @lock	test-against this lock
 * @data	parameters
 */
static bool lock_matches(struct ldlm_lock *lock, void *vdata)
{
	struct ldlm_match_data *data = vdata;
	union ldlm_policy_data *lpol = &lock->l_policy_data;
	enum ldlm_mode match = LCK_MINMODE;

	if (lock == data->lmd_old)
		return true;

	/*
	 * Check if this lock can be matched.
	 * Used by LU-2919(exclusive open) for open lease lock
	 */
	if (ldlm_is_excl(lock))
		return false;

	/*
	 * llite sometimes wants to match locks that will be
	 * canceled when their users drop, but we allow it to match
	 * if it passes in CBPENDING and the lock still has users.
	 * this is generally only going to be used by children
	 * whose parents already hold a lock so forward progress
	 * can still happen.
	 */
	if (ldlm_is_cbpending(lock) &&
	    !(data->lmd_flags & LDLM_FL_CBPENDING))
		return false;

	if (!(data->lmd_match & LDLM_MATCH_UNREF) && ldlm_is_cbpending(lock) &&
	    !lock->l_readers && !lock->l_writers)
		return false;

	if (!(lock->l_req_mode & *data->lmd_mode))
		return false;

	/* When we search for ast_data, we are not doing a traditional match,
	 * so we don't worry about IBITS or extent matching.
	 */
	if (data->lmd_match & (LDLM_MATCH_AST | LDLM_MATCH_AST_ANY)) {
		if (!lock->l_ast_data)
			return false;

		if (data->lmd_match & LDLM_MATCH_AST_ANY)
			goto matched;
	}

	match = lock->l_req_mode;

	switch (lock->l_resource->lr_type) {
	case LDLM_EXTENT:
		if (!(data->lmd_match & LDLM_MATCH_RIGHT) &&
		    (lpol->l_extent.start > data->lmd_policy->l_extent.start ||
		     lpol->l_extent.end < data->lmd_policy->l_extent.end))
			return false;

		if (unlikely(match == LCK_GROUP) &&
		    data->lmd_policy->l_extent.gid != LDLM_GID_ANY &&
		    lpol->l_extent.gid != data->lmd_policy->l_extent.gid)
			return false;
		break;
	case LDLM_IBITS:
		/*
		 * We match if we have existing lock with same or wider set
		 * of bits.
		 */
		if ((lpol->l_inodebits.bits &
		     data->lmd_policy->l_inodebits.bits) !=
		    data->lmd_policy->l_inodebits.bits)
			return false;

		if (unlikely(match == LCK_GROUP) &&
		    data->lmd_policy->l_inodebits.li_gid != LDLM_GID_ANY &&
		    lpol->l_inodebits.li_gid !=
		    data->lmd_policy->l_inodebits.li_gid)
			return false;
		break;
	default:
		break;
	}
	/*
	 * We match if we have existing lock with same or wider set
	 * of bits.
	 */
	if (!(data->lmd_match & LDLM_MATCH_UNREF) && LDLM_HAVE_MASK(lock, GONE))
		return false;

	if (!equi(data->lmd_flags & LDLM_FL_LOCAL_ONLY, ldlm_is_local(lock)))
		return false;

	/* Filter locks by skipping flags */
	if (data->lmd_skip_flags & lock->l_flags)
		return false;

matched:
	if (data->lmd_flags & LDLM_FL_TEST_LOCK) {
		LDLM_LOCK_GET(lock);
		ldlm_lock_touch_in_lru(lock);
	} else {
		ldlm_lock_addref_internal_nolock(lock, match);
	}

	*data->lmd_mode = match;
	data->lmd_lock = lock;

	return true;
}

/**
 * Search for a lock with given parameters in interval trees.
 *
 * @res		search for a lock in this resource
 * @data	parameters
 *
 * Return:	a referenced lock or NULL.
 */
struct ldlm_lock *search_itree(struct ldlm_resource *res,
			       struct ldlm_match_data *data)
{
	int idx;
	u64 end = data->lmd_policy->l_extent.end;

	data->lmd_lock = NULL;

	if (data->lmd_match & LDLM_MATCH_RIGHT)
		end = OBD_OBJECT_EOF;

	for (idx = 0; idx < LCK_MODE_NUM; idx++) {
		struct ldlm_interval_tree *tree = &res->lr_itree[idx];

		if (RB_EMPTY_ROOT(&tree->lit_root.rb_root))
			continue;

		if (!(tree->lit_mode & *data->lmd_mode))
			continue;

		ldlm_extent_search(&tree->lit_root,
				   data->lmd_policy->l_extent.start,
				   end,
				   lock_matches, data);
		if (data->lmd_lock)
			return data->lmd_lock;
	}

	return NULL;
}
EXPORT_SYMBOL(search_itree);

/*
 * Search for a lock with given properties in a queue.
 *
 * @queue	search for a lock in this queue
 * @data	parameters
 *
 * Return:	a referenced lock or NULL.
 */
static struct ldlm_lock *search_queue(struct list_head *queue,
				      struct ldlm_match_data *data)
{
	struct ldlm_lock *lock;

	data->lmd_lock = NULL;

	list_for_each_entry(lock, queue, l_res_link)
		if (lock_matches(lock, data))
			return data->lmd_lock;

	return NULL;
}

void ldlm_lock_fail_match_locked(struct ldlm_lock *lock)
{
	if ((lock->l_flags & LDLM_FL_FAIL_NOTIFIED) == 0) {
		lock->l_flags |= LDLM_FL_FAIL_NOTIFIED;
		wake_up_all(&lock->l_waitq);
	}
}

/**
 * Mark lock as "matchable" by OST.
 *
 * Used to prevent certain races in LOV/OSC where the lock is granted, but LVB
 * is not yet valid.
 * Assumes LDLM lock is already locked.
 */
void ldlm_lock_allow_match_locked(struct ldlm_lock *lock)
{
	ldlm_set_lvb_ready(lock);
	wake_up_all(&lock->l_waitq);
}
EXPORT_SYMBOL(ldlm_lock_allow_match_locked);

/**
 * Mark lock as "matchable" by OST.
 * Locks the lock and then \see ldlm_lock_allow_match_locked
 */
void ldlm_lock_allow_match(struct ldlm_lock *lock)
{
	lock_res_and_lock(lock);
	ldlm_lock_allow_match_locked(lock);
	unlock_res_and_lock(lock);
}
EXPORT_SYMBOL(ldlm_lock_allow_match);

/**
 * Attempt to find a lock with specified properties.
 *
 * Typically returns a reference to matched lock unless LDLM_FL_TEST_LOCK is
 * set in @flags
 *
 * Can be called in two ways:
 *
 * If 'ns' is NULL, then lockh describes an existing lock that we want to look
 * for a duplicate of.
 *
 * Otherwise, all of the fields must be filled in, to match against.
 *
 * If 'flags' contains LDLM_FL_LOCAL_ONLY, then only match local locks on the
 *     server (ie, connh is NULL)
 * If 'flags' contains LDLM_FL_BLOCK_GRANTED, then only locks on the granted
 *     list will be considered
 * If 'flags' contains LDLM_FL_CBPENDING, then locks that have been marked
 *     to be canceled can still be matched as long as they still have reader
 *     or writer referneces
 * If 'flags' contains LDLM_FL_TEST_LOCK, then don't actually reference a lock,
 *     just tell us if we would have matched.
 *
 * Return:	1 if it finds an already-existing lock that is compatible;
 *		in this case, lockh is filled in with a addref()ed lock
 *
 * We also check security context, and if that fails we simply return 0 (to
 * keep caller code unchanged), the context failure will be discovered by
 * caller sometime later.
 */
enum ldlm_mode ldlm_lock_match_with_skip(struct ldlm_namespace *ns,
					 u64 flags, u64 skip_flags,
					 const struct ldlm_res_id *res_id,
					 enum ldlm_type type,
					 union ldlm_policy_data *policy,
					 enum ldlm_mode mode,
					 struct lustre_handle *lockh,
					 enum ldlm_match_flags match_flags)
{
	struct ldlm_match_data data = {
		.lmd_old	= NULL,
		.lmd_lock	= NULL,
		.lmd_mode	= &mode,
		.lmd_policy	= policy,
		.lmd_flags	= flags,
		.lmd_skip_flags	= skip_flags,
		.lmd_match	= match_flags,
	};
	struct ldlm_resource *res;
	struct ldlm_lock *lock;
	int matched;

	if (!ns) {
		data.lmd_old = ldlm_handle2lock(lockh);
		LASSERT(data.lmd_old);

		ns = ldlm_lock_to_ns(data.lmd_old);
		res_id = &data.lmd_old->l_resource->lr_name;
		type = data.lmd_old->l_resource->lr_type;
		*data.lmd_mode = data.lmd_old->l_req_mode;
	}

	res = ldlm_resource_get(ns, NULL, res_id, type, 0);
	if (IS_ERR(res)) {
		LASSERT(!data.lmd_old);
		return 0;
	}

	LDLM_RESOURCE_ADDREF(res);
	lock_res(res);
	if (res->lr_type == LDLM_EXTENT)
		lock = search_itree(res, &data);
	else
		lock = search_queue(&res->lr_granted, &data);
	if (!lock && !(flags & LDLM_FL_BLOCK_GRANTED))
		lock = search_queue(&res->lr_waiting, &data);
	matched = lock ? mode : 0;
	unlock_res(res);
	LDLM_RESOURCE_DELREF(res);
	ldlm_resource_putref(res);

	if (lock) {
		ldlm_lock2handle(lock, lockh);
		if ((flags & LDLM_FL_LVB_READY) && !ldlm_is_lvb_ready(lock)) {
			u64 wait_flags = LDLM_FL_LVB_READY |
				LDLM_FL_DESTROYED | LDLM_FL_FAIL_NOTIFIED;

			if (lock->l_completion_ast) {
				int err = lock->l_completion_ast(lock,
							  LDLM_FL_WAIT_NOREPROC,
								 NULL);
				if (err) {
					matched = 0;
					goto out_fail_match;
				}
			}

			/* XXX FIXME see comment on CAN_MATCH in lustre_dlm.h */
			wait_event_idle_timeout(lock->l_waitq,
						lock->l_flags & wait_flags,
						obd_timeout * HZ);

			if (!ldlm_is_lvb_ready(lock)) {
				matched = 0;
				goto out_fail_match;
			}
		}

		/* check user's security context */
		if (lock->l_conn_export &&
		    sptlrpc_import_check_ctx(class_exp2cliimp(lock->l_conn_export))) {
			matched = 0;
			goto out_fail_match;
		}

		LDLM_DEBUG(lock, "matched (%llu %llu)",
			   (type == LDLM_PLAIN || type == LDLM_IBITS) ?
			   res_id->name[2] : policy->l_extent.start,
			   (type == LDLM_PLAIN || type == LDLM_IBITS) ?
			   res_id->name[3] : policy->l_extent.end);

out_fail_match:
		if (flags & LDLM_FL_TEST_LOCK)
			LDLM_LOCK_RELEASE(lock);
		else if (!matched)
			ldlm_lock_decref_internal(lock, mode);
	}

	/* less verbose for test-only */
	if (!matched && !(flags & LDLM_FL_TEST_LOCK)) {
		LDLM_DEBUG_NOLOCK("not matched ns %p type %u mode %u res %llu/%llu (%llu %llu)",
				  ns, type, mode, res_id->name[0],
				  res_id->name[1],
				  (type == LDLM_PLAIN || type == LDLM_IBITS) ?
				  res_id->name[2] : policy->l_extent.start,
				  (type == LDLM_PLAIN || type == LDLM_IBITS) ?
				  res_id->name[3] : policy->l_extent.end);
	}
	if (data.lmd_old)
		LDLM_LOCK_PUT(data.lmd_old);

	return matched;
}
EXPORT_SYMBOL(ldlm_lock_match_with_skip);

enum ldlm_mode ldlm_revalidate_lock_handle(const struct lustre_handle *lockh,
					   u64 *bits)
{
	struct ldlm_lock *lock;
	enum ldlm_mode mode = 0;

	lock = ldlm_handle2lock(lockh);
	if (lock) {
		lock_res_and_lock(lock);
		if (LDLM_HAVE_MASK(lock, GONE))
			goto out;

		if (ldlm_is_cbpending(lock) &&
		    lock->l_readers == 0 && lock->l_writers == 0)
			goto out;

		if (bits)
			*bits = lock->l_policy_data.l_inodebits.bits;
		mode = lock->l_granted_mode;
		ldlm_lock_addref_internal_nolock(lock, mode);
	}

out:
	if (lock) {
		unlock_res_and_lock(lock);
		LDLM_LOCK_PUT(lock);
	}
	return mode;
}
EXPORT_SYMBOL(ldlm_revalidate_lock_handle);

/** The caller must guarantee that the buffer is large enough. */
int ldlm_fill_lvb(struct ldlm_lock *lock, struct req_capsule *pill,
		  enum req_location loc, void *data, int size)
{
	void *lvb;

	LASSERT(data);
	LASSERT(size >= 0);

	switch (lock->l_lvb_type) {
	case LVB_T_OST:
		if (size == sizeof(struct ost_lvb)) {
			if (loc == RCL_CLIENT)
				lvb = req_capsule_client_swab_get(pill,
								  &RMF_DLM_LVB,
							lustre_swab_ost_lvb);
			else
				lvb = req_capsule_server_swab_get(pill,
								  &RMF_DLM_LVB,
							lustre_swab_ost_lvb);
			if (unlikely(!lvb)) {
				LDLM_ERROR(lock, "no LVB");
				return -EPROTO;
			}

			memcpy(data, lvb, size);
		} else if (size == sizeof(struct ost_lvb_v1)) {
			struct ost_lvb *olvb = data;

			if (loc == RCL_CLIENT)
				lvb = req_capsule_client_swab_get(pill,
								  &RMF_DLM_LVB,
								  lustre_swab_ost_lvb_v1);
			else
				lvb = req_capsule_server_sized_swab_get(pill,
						&RMF_DLM_LVB, size,
						lustre_swab_ost_lvb_v1);
			if (unlikely(!lvb)) {
				LDLM_ERROR(lock, "no LVB");
				return -EPROTO;
			}

			memcpy(data, lvb, size);
			olvb->lvb_mtime_ns = 0;
			olvb->lvb_atime_ns = 0;
			olvb->lvb_ctime_ns = 0;
		} else {
			LDLM_ERROR(lock, "Replied unexpected ost LVB size %d",
				   size);
			return -EINVAL;
		}
		break;
	case LVB_T_LQUOTA:
		if (size == sizeof(struct lquota_lvb)) {
			if (loc == RCL_CLIENT)
				lvb = req_capsule_client_swab_get(pill,
								  &RMF_DLM_LVB,
							lustre_swab_lquota_lvb);
			else
				lvb = req_capsule_server_swab_get(pill,
								  &RMF_DLM_LVB,
							lustre_swab_lquota_lvb);
			if (unlikely(!lvb)) {
				LDLM_ERROR(lock, "no LVB");
				return -EPROTO;
			}

			memcpy(data, lvb, size);
		} else {
			LDLM_ERROR(lock,
				   "Replied unexpected lquota LVB size %d",
				   size);
			return -EINVAL;
		}
		break;
	case LVB_T_LAYOUT:
		if (size == 0)
			break;

		if (loc == RCL_CLIENT)
			lvb = req_capsule_client_get(pill, &RMF_DLM_LVB);
		else
			lvb = req_capsule_server_get(pill, &RMF_DLM_LVB);
		if (unlikely(!lvb)) {
			LDLM_ERROR(lock, "no LVB");
			return -EPROTO;
		}

		memcpy(data, lvb, size);
		break;
	default:
		LDLM_ERROR(lock, "Unknown LVB type: %d", lock->l_lvb_type);
		libcfs_debug_dumpstack(NULL);
		return -EINVAL;
	}

	return 0;
}

/**
 * Create and fill in new LDLM lock with specified properties.
 * Returns a referenced lock
 */
struct ldlm_lock *ldlm_lock_create(struct ldlm_namespace *ns,
				   const struct ldlm_res_id *res_id,
				   enum ldlm_type type,
				   enum ldlm_mode mode,
				   const struct ldlm_callback_suite *cbs,
				   void *data, u32 lvb_len,
				   enum lvb_type lvb_type)
{
	struct ldlm_lock *lock;
	struct ldlm_resource *res;
	int rc;

	res = ldlm_resource_get(ns, NULL, res_id, type, 1);
	if (IS_ERR(res))
		return ERR_CAST(res);

	lock = ldlm_lock_new(res);
	if (!lock) {
		ldlm_resource_putref(res);
		return ERR_PTR(-ENOMEM);
	}

	lock->l_req_mode = mode;
	lock->l_ast_data = data;
	lock->l_pid = current->pid;
	if (cbs) {
		lock->l_blocking_ast = cbs->lcs_blocking;
		lock->l_completion_ast = cbs->lcs_completion;
		lock->l_glimpse_ast = cbs->lcs_glimpse;
	}

	if (lvb_len) {
		lock->l_lvb_len = lvb_len;
		lock->l_lvb_data = kvzalloc(lvb_len, GFP_NOFS);
		if (!lock->l_lvb_data) {
			rc = -ENOMEM;
			goto out;
		}
	}

	lock->l_lvb_type = lvb_type;
	if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_NEW_LOCK)) {
		rc = -ENOENT;
		goto out;
	}

	return lock;

out:
	ldlm_lock_destroy(lock);
	LDLM_LOCK_RELEASE(lock);
	return ERR_PTR(rc);
}

/**
 * Enqueue (request) a lock.
 * On the client this is called from ldlm_cli_enqueue_fini
 * after we already got an initial reply from the server with some status.
 *
 * Does not block. As a result of enqueue the lock would be put
 * into granted or waiting list.
 */
enum ldlm_error ldlm_lock_enqueue(const struct lu_env *env,
				  struct ldlm_namespace *ns,
				  struct ldlm_lock **lockp,
				  void *cookie, u64 *flags)
{
	struct ldlm_lock *lock = *lockp;
	struct ldlm_resource *res;

	res = lock_res_and_lock(lock);
	if (ldlm_is_granted(lock)) {
		/* The server returned a blocked lock, but it was granted
		 * before we got a chance to actually enqueue it.  We don't
		 * need to do anything else.
		 */
		*flags &= ~LDLM_FL_BLOCKED_MASK;
		goto out;
	}

	ldlm_resource_unlink_lock(lock);

	/* Some flags from the enqueue want to make it into the AST, via the
	 * lock's l_flags.
	 */
	if (*flags & LDLM_FL_AST_DISCARD_DATA)
		ldlm_set_ast_discard_data(lock);
	if (*flags & LDLM_FL_TEST_LOCK)
		ldlm_set_test_lock(lock);

	/*
	 * This distinction between local lock trees is very important; a client
	 * namespace only has information about locks taken by that client, and
	 * thus doesn't have enough information to decide for itself if it can
	 * be granted (below).  In this case, we do exactly what the server
	 * tells us to do, as dictated by the 'flags'.
	 */
	if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED))
		ldlm_resource_add_lock(res, &res->lr_waiting, lock);
	else
		ldlm_grant_lock(lock, NULL);

out:
	unlock_res_and_lock(lock);
	return ELDLM_OK;
}

/**
 * Process a call to completion AST callback for a lock in ast_work list
 */
static int
ldlm_work_cp_ast_lock(struct ptlrpc_request_set *rqset, void *opaq)
{
	struct ldlm_cb_set_arg *arg = opaq;
	int rc = 0;
	struct ldlm_lock *lock;
	ldlm_completion_callback completion_callback;

	if (list_empty(arg->list))
		return -ENOENT;

	lock = list_first_entry(arg->list, struct ldlm_lock, l_cp_ast);

	/* It's possible to receive a completion AST before we've set
	 * the l_completion_ast pointer: either because the AST arrived
	 * before the reply, or simply because there's a small race
	 * window between receiving the reply and finishing the local
	 * enqueue. (bug 842)
	 *
	 * This can't happen with the blocking_ast, however, because we
	 * will never call the local blocking_ast until we drop our
	 * reader/writer reference, which we won't do until we get the
	 * reply and finish enqueueing.
	 */

	/* nobody should touch l_cp_ast */
	lock_res_and_lock(lock);
	list_del_init(&lock->l_cp_ast);
	LASSERT(ldlm_is_cp_reqd(lock));
	/* save l_completion_ast since it can be changed by
	 * mds_intent_policy(), see bug 14225
	 */
	completion_callback = lock->l_completion_ast;
	ldlm_clear_cp_reqd(lock);
	unlock_res_and_lock(lock);

	if (completion_callback)
		rc = completion_callback(lock, 0, (void *)arg);
	LDLM_LOCK_RELEASE(lock);

	return rc;
}

/**
 * Process list of locks in need of ASTs being sent.
 *
 * Used on server to send multiple ASTs together instead of sending one by
 * one.
 */
int ldlm_run_ast_work(struct ldlm_namespace *ns, struct list_head *rpc_list,
		      enum ldlm_desc_ast_t ast_type)
{
	struct ldlm_cb_set_arg *arg;
	set_producer_func work_ast_lock;
	int rc;

	if (list_empty(rpc_list))
		return 0;

	arg = kzalloc(sizeof(*arg), GFP_NOFS);
	if (!arg)
		return -ENOMEM;

	atomic_set(&arg->restart, 0);
	arg->list = rpc_list;

	switch (ast_type) {
	case LDLM_WORK_CP_AST:
		arg->type = LDLM_CP_CALLBACK;
		work_ast_lock = ldlm_work_cp_ast_lock;
		break;
	default:
		LBUG();
	}

	/* We create a ptlrpc request set with flow control extension.
	 * This request set will use the work_ast_lock function to produce new
	 * requests and will send a new request each time one completes in order
	 * to keep the number of requests in flight to ns_max_parallel_ast
	 */
	arg->set = ptlrpc_prep_fcset(ns->ns_max_parallel_ast ? : UINT_MAX,
				     work_ast_lock, arg);
	if (!arg->set) {
		rc = -ENOMEM;
		goto out;
	}

	ptlrpc_set_wait(NULL, arg->set);
	ptlrpc_set_destroy(arg->set);

	rc = atomic_read(&arg->restart) ? -ERESTART : 0;
	goto out;
out:
	kfree(arg);
	return rc;
}

/**
 * Helper function to call blocking AST for LDLM lock @lock in a
 * "cancelling" mode.
 */
void ldlm_cancel_callback(struct ldlm_lock *lock)
{
	check_res_locked(lock->l_resource);
	if (!ldlm_is_cancel(lock)) {
		ldlm_set_cancel(lock);
		if (lock->l_blocking_ast) {
			unlock_res_and_lock(lock);
			lock->l_blocking_ast(lock, NULL, lock->l_ast_data,
					     LDLM_CB_CANCELING);
			lock_res_and_lock(lock);
		} else {
			LDLM_DEBUG(lock, "no blocking ast");
		}
		/* only canceller can set bl_done bit */
		ldlm_set_bl_done(lock);
		wake_up_all(&lock->l_waitq);
	} else if (!ldlm_is_bl_done(lock)) {
		/*
		 * The lock is guaranteed to have been canceled once
		 * returning from this function.
		 */
		unlock_res_and_lock(lock);
		wait_event_idle(lock->l_waitq, is_bl_done(lock));
		lock_res_and_lock(lock);
	}
}

/**
 * Remove skiplist-enabled LDLM lock @req from granted list
 */
void ldlm_unlink_lock_skiplist(struct ldlm_lock *req)
{
	if (req->l_resource->lr_type != LDLM_PLAIN &&
	    req->l_resource->lr_type != LDLM_IBITS)
		return;

	list_del_init(&req->l_sl_policy);
	list_del_init(&req->l_sl_mode);
}

/**
 * Attempts to cancel LDLM lock @lock that has no reader/writer references.
 */
void ldlm_lock_cancel(struct ldlm_lock *lock)
{
	struct ldlm_resource *res;
	struct ldlm_namespace *ns;

	res = lock_res_and_lock(lock);

	ns  = ldlm_res_to_ns(res);

	/* Please do not, no matter how tempting, remove this LBUG without
	 * talking to me first. -phik
	 */
	if (lock->l_readers || lock->l_writers) {
		LDLM_ERROR(lock, "lock still has references");
		unlock_res_and_lock(lock);
		LBUG();
	}

	/* Releases cancel callback. */
	ldlm_cancel_callback(lock);

	ldlm_resource_unlink_lock(lock);
	ldlm_lock_destroy_nolock(lock);

	if (ldlm_is_granted(lock))
		ldlm_pool_del(&ns->ns_pool, lock);

	/* Make sure we will not be called again for same lock what is possible
	 * if not to zero out lock->l_granted_mode
	 */
	lock->l_granted_mode = LCK_MINMODE;
	unlock_res_and_lock(lock);
}
EXPORT_SYMBOL(ldlm_lock_cancel);

/**
 * Set opaque data into the lock that only makes sense to upper layer.
 */
int ldlm_lock_set_data(const struct lustre_handle *lockh, void *data)
{
	struct ldlm_lock *lock = ldlm_handle2lock(lockh);
	int rc = -EINVAL;

	if (lock) {
		if (!lock->l_ast_data)
			lock->l_ast_data = data;
		if (lock->l_ast_data == data)
			rc = 0;
		LDLM_LOCK_PUT(lock);
	}
	return rc;
}
EXPORT_SYMBOL(ldlm_lock_set_data);

struct export_cl_data {
	const struct lu_env	*ecl_env;
	struct obd_export	*ecl_exp;
	int			ecl_loop;
};

/**
 * Print lock with lock handle @lockh description into debug log.
 *
 * Used when printing all locks on a resource for debug purposes.
 */
void ldlm_lock_dump_handle(int level, const struct lustre_handle *lockh)
{
	struct ldlm_lock *lock;

	if (!((libcfs_debug | D_ERROR) & level))
		return;

	lock = ldlm_handle2lock(lockh);
	if (!lock)
		return;

	LDLM_DEBUG_LIMIT(level, lock, "###");

	LDLM_LOCK_PUT(lock);
}
EXPORT_SYMBOL(ldlm_lock_dump_handle);

/**
 * Print lock information with custom message into debug log.
 * Helper function.
 */
void _ldlm_lock_debug(struct ldlm_lock *lock,
		      struct libcfs_debug_msg_data *msgdata,
		      const char *fmt, ...)
{
	struct obd_export *exp = lock->l_export;
	struct ldlm_resource *resource = NULL;
	char *nid = "local";
	va_list args;
	struct va_format vaf;

	rcu_read_lock();
	resource = rcu_dereference(lock->l_resource);
	if (resource && !atomic_inc_not_zero(&resource->lr_refcount))
		resource = NULL;
	rcu_read_unlock();

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	if (exp && exp->exp_connection) {
		nid = obd_export_nid2str(exp);
	} else if (exp && exp->exp_obd) {
		struct obd_import *imp = exp->exp_obd->u.cli.cl_import;

		nid = obd_import_nid2str(imp);
	}

	if (!resource) {
		libcfs_debug_msg(msgdata,
				 "%pV ns: \?\? lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s res: \?\? rrc=\?\? type: \?\?\? flags: %#llx nid: %s remote: %#llx expref: %d pid: %u timeout: %lld lvb_type: %d\n",
				 &vaf,
				 lock,
				 lock->l_handle.h_cookie,
				 refcount_read(&lock->l_handle.h_ref),
				 lock->l_readers, lock->l_writers,
				 ldlm_lockname[lock->l_granted_mode],
				 ldlm_lockname[lock->l_req_mode],
				 lock->l_flags, nid,
				 lock->l_remote_handle.cookie,
				 exp ? refcount_read(&exp->exp_handle.h_ref) : -99,
				 lock->l_pid, lock->l_callback_timestamp,
				 lock->l_lvb_type);
		va_end(args);
		return;
	}

	switch (resource->lr_type) {
	case LDLM_EXTENT:
		libcfs_debug_msg(msgdata,
				 "%pV ns: %s lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s res: " DLDLMRES " rrc: %d type: %s [%llu->%llu] (req %llu->%llu) gid %llu flags: %#llx nid: %s remote: %#llx expref: %d pid: %u timeout: %lld lvb_type: %d\n",
				 &vaf,
				 ldlm_lock_to_ns_name(lock), lock,
				 lock->l_handle.h_cookie,
				 refcount_read(&lock->l_handle.h_ref),
				 lock->l_readers, lock->l_writers,
				 ldlm_lockname[lock->l_granted_mode],
				 ldlm_lockname[lock->l_req_mode],
				 PLDLMRES(resource),
				 atomic_read(&resource->lr_refcount),
				 ldlm_typename[resource->lr_type],
				 lock->l_policy_data.l_extent.start,
				 lock->l_policy_data.l_extent.end,
				 lock->l_req_extent.start,
				 lock->l_req_extent.end,
				 lock->l_req_extent.gid,
				 lock->l_flags, nid,
				 lock->l_remote_handle.cookie,
				 exp ? refcount_read(&exp->exp_handle.h_ref) : -99,
				 lock->l_pid, lock->l_callback_timestamp,
				 lock->l_lvb_type);
		break;

	case LDLM_FLOCK:
		libcfs_debug_msg(msgdata,
				 "%pV ns: %s lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s res: " DLDLMRES " rrc: %d type: %s pid: %d [%llu->%llu] flags: %#llx nid: %s remote: %#llx expref: %d pid: %u timeout: %lld\n",
				 &vaf,
				 ldlm_lock_to_ns_name(lock), lock,
				 lock->l_handle.h_cookie,
				 refcount_read(&lock->l_handle.h_ref),
				 lock->l_readers, lock->l_writers,
				 ldlm_lockname[lock->l_granted_mode],
				 ldlm_lockname[lock->l_req_mode],
				 PLDLMRES(resource),
				 atomic_read(&resource->lr_refcount),
				 ldlm_typename[resource->lr_type],
				 lock->l_policy_data.l_flock.pid,
				 lock->l_policy_data.l_flock.start,
				 lock->l_policy_data.l_flock.end,
				 lock->l_flags, nid,
				 lock->l_remote_handle.cookie,
				 exp ? refcount_read(&exp->exp_handle.h_ref) : -99,
				 lock->l_pid, lock->l_callback_timestamp);
		break;

	case LDLM_IBITS:
		libcfs_debug_msg(msgdata,
				 "%pV ns: %s lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s res: " DLDLMRES " bits %#llx rrc: %d type: %s gid %llu flags: %#llx nid: %s remote: %#llx expref: %d pid: %u timeout: %lld lvb_type: %d\n",
				 &vaf,
				 ldlm_lock_to_ns_name(lock),
				 lock, lock->l_handle.h_cookie,
				 refcount_read(&lock->l_handle.h_ref),
				 lock->l_readers, lock->l_writers,
				 ldlm_lockname[lock->l_granted_mode],
				 ldlm_lockname[lock->l_req_mode],
				 PLDLMRES(resource),
				 lock->l_policy_data.l_inodebits.bits,
				 atomic_read(&resource->lr_refcount),
				 ldlm_typename[resource->lr_type],
				 lock->l_policy_data.l_inodebits.li_gid,
				 lock->l_flags, nid,
				 lock->l_remote_handle.cookie,
				 exp ? refcount_read(&exp->exp_handle.h_ref) : -99,
				 lock->l_pid, lock->l_callback_timestamp,
				 lock->l_lvb_type);
		break;

	default:
		libcfs_debug_msg(msgdata,
				 "%pV ns: %s lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s res: " DLDLMRES " rrc: %d type: %s flags: %#llx nid: %s remote: %#llx expref: %d pid: %u timeout: %lld lvb_type: %d\n",
				 &vaf,
				 ldlm_lock_to_ns_name(lock),
				 lock, lock->l_handle.h_cookie,
				 refcount_read(&lock->l_handle.h_ref),
				 lock->l_readers, lock->l_writers,
				 ldlm_lockname[lock->l_granted_mode],
				 ldlm_lockname[lock->l_req_mode],
				 PLDLMRES(resource),
				 atomic_read(&resource->lr_refcount),
				 ldlm_typename[resource->lr_type],
				 lock->l_flags, nid,
				 lock->l_remote_handle.cookie,
				 exp ? refcount_read(&exp->exp_handle.h_ref) : -99,
				 lock->l_pid, lock->l_callback_timestamp,
				 lock->l_lvb_type);
		break;
	}
	va_end(args);
	ldlm_resource_putref(resource);
}
EXPORT_SYMBOL(_ldlm_lock_debug);
