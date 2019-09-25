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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Client Lustre Page.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd_class.h>
#include <obd_support.h>
#include <linux/list.h>

#include <cl_object.h>
#include "cl_internal.h"

static void __cl_page_delete(const struct lu_env *env, struct cl_page *pg);

# define PASSERT(env, page, expr)					   \
	do {								   \
		if (unlikely(!(expr))) {				   \
			CL_PAGE_DEBUG(D_ERROR, (env), (page), #expr "\n"); \
			LASSERT(0);					   \
		}							   \
	} while (0)

/**
 * Internal version of cl_page_get().
 *
 * This function can be used to obtain initial reference to previously
 * unreferenced cached object. It can be called only if concurrent page
 * reclamation is somehow prevented, e.g., by keeping a lock on a VM page,
 * associated with @page.
 *
 * Use with care! Not exported.
 */
static void cl_page_get_trust(struct cl_page *page)
{
	LASSERT(refcount_read(&page->cp_ref) > 0);
	refcount_inc(&page->cp_ref);
}

/**
 * Returns a slice within a page, corresponding to the given layer in the
 * device stack.
 *
 * \see cl_lock_at()
 */
static const struct cl_page_slice *
cl_page_at_trusted(const struct cl_page *page,
		   const struct lu_device_type *dtype)
{
	const struct cl_page_slice *slice;

	list_for_each_entry(slice, &page->cp_layers, cpl_linkage) {
		if (slice->cpl_obj->co_lu.lo_dev->ld_type == dtype)
			return slice;
	}
	return NULL;
}

static void cl_page_free(const struct lu_env *env, struct cl_page *page,
			 struct pagevec *pvec)
{
	struct cl_object *obj = page->cp_obj;
	struct cl_page_slice *slice;

	PASSERT(env, page, list_empty(&page->cp_batch));
	PASSERT(env, page, !page->cp_owner);
	PASSERT(env, page, page->cp_state == CPS_FREEING);

	while ((slice = list_first_entry_or_null(&page->cp_layers,
						 struct cl_page_slice,
						 cpl_linkage)) != NULL) {
		list_del_init(page->cp_layers.next);
		if (unlikely(slice->cpl_ops->cpo_fini))
			slice->cpl_ops->cpo_fini(env, slice, pvec);
	}
	lu_object_ref_del_at(&obj->co_lu, &page->cp_obj_ref, "cl_page", page);
	cl_object_put(env, obj);
	lu_ref_fini(&page->cp_reference);
	kfree(page);
}

/**
 * Helper function updating page state. This is the only place in the code
 * where cl_page::cp_state field is mutated.
 */
static inline void cl_page_state_set_trust(struct cl_page *page,
					   enum cl_page_state state)
{
	/* bypass const. */
	*(enum cl_page_state *)&page->cp_state = state;
}

struct cl_page *cl_page_alloc(const struct lu_env *env,
			      struct cl_object *o, pgoff_t ind,
			      struct page *vmpage,
			      enum cl_page_type type)
{
	struct cl_page *page;
	struct cl_object *o2;

	page = kzalloc(cl_object_header(o)->coh_page_bufsize, GFP_NOFS);
	if (page) {
		int result = 0;

		refcount_set(&page->cp_ref, 1);
		page->cp_obj = o;
		cl_object_get(o);
		lu_object_ref_add_at(&o->co_lu, &page->cp_obj_ref, "cl_page",
				     page);
		page->cp_vmpage = vmpage;
		cl_page_state_set_trust(page, CPS_CACHED);
		page->cp_type = type;
		INIT_LIST_HEAD(&page->cp_layers);
		INIT_LIST_HEAD(&page->cp_batch);
		lu_ref_init(&page->cp_reference);
		cl_object_for_each(o2, o) {
			if (o2->co_ops->coo_page_init) {
				result = o2->co_ops->coo_page_init(env, o2,
								   page, ind);
				if (result != 0) {
					__cl_page_delete(env, page);
					cl_page_free(env, page, NULL);
					page = ERR_PTR(result);
					break;
				}
			}
		}
	} else {
		page = ERR_PTR(-ENOMEM);
	}
	return page;
}

/**
 * Returns a cl_page with index @idx at the object @o, and associated with
 * the VM page @vmpage.
 *
 * This is the main entry point into the cl_page caching interface. First, a
 * cache (implemented as a per-object radix tree) is consulted. If page is
 * found there, it is returned immediately. Otherwise new page is allocated
 * and returned. In any case, additional reference to page is acquired.
 *
 * \see cl_object_find(), cl_lock_find()
 */
struct cl_page *cl_page_find(const struct lu_env *env,
			     struct cl_object *o,
			     pgoff_t idx, struct page *vmpage,
			     enum cl_page_type type)
{
	struct cl_page *page = NULL;
	struct cl_object_header *hdr;

	LASSERT(type == CPT_CACHEABLE || type == CPT_TRANSIENT);
	might_sleep();

	hdr = cl_object_header(o);

	CDEBUG(D_PAGE, "%lu@" DFID " %p %lx %d\n",
	       idx, PFID(&hdr->coh_lu.loh_fid), vmpage, vmpage->private, type);
	/* fast path. */
	if (type == CPT_CACHEABLE) {
		/*
		 * vmpage lock is used to protect the child/parent
		 * relationship
		 */
		LASSERT(PageLocked(vmpage));
		/*
		 * cl_vmpage_page() can be called here without any locks as
		 *
		 *     - "vmpage" is locked (which prevents ->private from
		 *       concurrent updates), and
		 *
		 *     - "o" cannot be destroyed while current thread holds a
		 *       reference on it.
		 */
		page = cl_vmpage_page(vmpage, o);

		if (page)
			return page;
	}

	/* allocate and initialize cl_page */
	page = cl_page_alloc(env, o, idx, vmpage, type);
	return page;
}
EXPORT_SYMBOL(cl_page_find);

static inline int cl_page_invariant(const struct cl_page *pg)
{
	return cl_page_in_use_noref(pg);
}

static void __cl_page_state_set(const struct lu_env *env,
				struct cl_page *page, enum cl_page_state state)
{
	enum cl_page_state old;

	/*
	 * Matrix of allowed state transitions [old][new], for sanity
	 * checking.
	 */
	static const int allowed_transitions[CPS_NR][CPS_NR] = {
		[CPS_CACHED] = {
			[CPS_CACHED]	= 0,
			[CPS_OWNED]	= 1, /* io finds existing cached page */
			[CPS_PAGEIN]	= 0,
			[CPS_PAGEOUT]	= 1, /* write-out from the cache */
			[CPS_FREEING]	= 1, /* eviction on the memory pressure */
		},
		[CPS_OWNED] = {
			[CPS_CACHED]	= 1, /* release to the cache */
			[CPS_OWNED]	= 0,
			[CPS_PAGEIN]	= 1, /* start read immediately */
			[CPS_PAGEOUT]	= 1, /* start write immediately */
			[CPS_FREEING]	= 1, /* lock invalidation or truncate */
		},
		[CPS_PAGEIN] = {
			[CPS_CACHED]	= 1, /* io completion */
			[CPS_OWNED]	= 0,
			[CPS_PAGEIN]	= 0,
			[CPS_PAGEOUT]	= 0,
			[CPS_FREEING]	= 0,
		},
		[CPS_PAGEOUT] = {
			[CPS_CACHED]	= 1, /* io completion */
			[CPS_OWNED]	= 0,
			[CPS_PAGEIN]	= 0,
			[CPS_PAGEOUT]	= 0,
			[CPS_FREEING]	= 0,
		},
		[CPS_FREEING] = {
			[CPS_CACHED]	= 0,
			[CPS_OWNED]	= 0,
			[CPS_PAGEIN]	= 0,
			[CPS_PAGEOUT]	= 0,
			[CPS_FREEING]	= 0,
		}
	};

	old = page->cp_state;
	PASSERT(env, page, allowed_transitions[old][state]);
	CL_PAGE_HEADER(D_TRACE, env, page, "%d -> %d\n", old, state);
	PASSERT(env, page, page->cp_state == old);
	PASSERT(env, page, equi(state == CPS_OWNED, page->cp_owner));
	cl_page_state_set_trust(page, state);
}

static void cl_page_state_set(const struct lu_env *env,
			      struct cl_page *page, enum cl_page_state state)
{
	__cl_page_state_set(env, page, state);
}

/**
 * Acquires an additional reference to a page.
 *
 * This can be called only by caller already possessing a reference to
 * @page.
 *
 * \see cl_object_get(), cl_lock_get().
 */
void cl_page_get(struct cl_page *page)
{
	cl_page_get_trust(page);
}
EXPORT_SYMBOL(cl_page_get);

/**
 * Releases a reference to a page, use the pagevec to release the pages
 * in batch if provided.
 *
 * Users need to do a final pagevec_release() to release any trailing pages.
 */
void cl_pagevec_put(const struct lu_env *env, struct cl_page *page,
		  struct pagevec *pvec)
{
	CL_PAGE_HEADER(D_TRACE, env, page, "%d\n",
		       refcount_read(&page->cp_ref));

	if (refcount_dec_and_test(&page->cp_ref)) {
		LASSERT(page->cp_state == CPS_FREEING);

		LASSERT(refcount_read(&page->cp_ref) == 0);
		PASSERT(env, page, !page->cp_owner);
		PASSERT(env, page, list_empty(&page->cp_batch));
		/*
		 * Page is no longer reachable by other threads. Tear
		 * it down.
		 */
		cl_page_free(env, page, pvec);
	}
}
EXPORT_SYMBOL(cl_pagevec_put);

/**
 * Releases a reference to a page, wrapper to cl_pagevec_put
 *
 * When last reference is released, page is returned to the cache, unless it
 * is in cl_page_state::CPS_FREEING state, in which case it is immediately
 * destroyed.
 *
 * \see cl_object_put(), cl_lock_put().
 */
void cl_page_put(const struct lu_env *env, struct cl_page *page)
{
	cl_pagevec_put(env, page, NULL);
}
EXPORT_SYMBOL(cl_page_put);

/**
 * Returns a cl_page associated with a VM page, and given cl_object.
 */
struct cl_page *cl_vmpage_page(struct page *vmpage, struct cl_object *obj)
{
	struct cl_page *page;

	LASSERT(PageLocked(vmpage));

	/*
	 * NOTE: absence of races and liveness of data are guaranteed by page
	 *       lock on a "vmpage". That works because object destruction has
	 *       bottom-to-top pass.
	 */

	page = (struct cl_page *)vmpage->private;
	if (page) {
		cl_page_get_trust(page);
		LASSERT(page->cp_type == CPT_CACHEABLE);
	}
	return page;
}
EXPORT_SYMBOL(cl_vmpage_page);

const struct cl_page_slice *cl_page_at(const struct cl_page *page,
				       const struct lu_device_type *dtype)
{
	return cl_page_at_trusted(page, dtype);
}
EXPORT_SYMBOL(cl_page_at);

static void cl_page_owner_clear(struct cl_page *page)
{
	if (page->cp_owner) {
		LASSERT(page->cp_owner->ci_owned_nr > 0);
		page->cp_owner->ci_owned_nr--;
		page->cp_owner = NULL;
	}
}

static void cl_page_owner_set(struct cl_page *page)
{
	page->cp_owner->ci_owned_nr++;
}

void __cl_page_disown(const struct lu_env *env,
		     struct cl_io *io, struct cl_page *pg)
{
	const struct cl_page_slice *slice;
	enum cl_page_state state;

	state = pg->cp_state;
	cl_page_owner_clear(pg);

	if (state == CPS_OWNED)
		cl_page_state_set(env, pg, CPS_CACHED);
	/*
	 * Completion call-backs are executed in the bottom-up order, so that
	 * uppermost layer (llite), responsible for VFS/VM interaction runs
	 * last and can release locks safely.
	 */
	list_for_each_entry_reverse(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_disown)
			(*slice->cpl_ops->cpo_disown)(env, slice, io);
	}
}

/**
 * returns true, iff page is owned by the given io.
 */
int cl_page_is_owned(const struct cl_page *pg, const struct cl_io *io)
{
	struct cl_io *top = cl_io_top((struct cl_io *)io);

	LINVRNT(cl_object_same(pg->cp_obj, io->ci_obj));
	return pg->cp_state == CPS_OWNED && pg->cp_owner == top;
}
EXPORT_SYMBOL(cl_page_is_owned);

/**
 * Try to own a page by IO.
 *
 * Waits until page is in cl_page_state::CPS_CACHED state, and then switch it
 * into cl_page_state::CPS_OWNED state.
 *
 * \pre  !cl_page_is_owned(pg, io)
 * \post result == 0 iff cl_page_is_owned(pg, io)
 *
 * Return:	0 success
 *
 *		-ve failure, e.g., page was destroyed (and landed in
 *		cl_page_state::CPS_FREEING instead of
 *		cl_page_state::CPS_CACHED). or, page was owned by
 *		another thread, or in IO.
 *
 * \see cl_page_disown()
 * \see cl_page_operations::cpo_own()
 * \see cl_page_own_try()
 * \see cl_page_own
 */
static int __cl_page_own(const struct lu_env *env, struct cl_io *io,
			 struct cl_page *pg, int nonblock)
{
	const struct cl_page_slice *slice;
	int result = 0;

	io = cl_io_top(io);

	if (pg->cp_state == CPS_FREEING) {
		result = -ENOENT;
		goto out;
	}

	list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_own)
			result = (*slice->cpl_ops->cpo_own)(env, slice,
							    io, nonblock);
		if (result != 0)
			break;
	}
	if (result > 0)
		result = 0;

	if (result == 0) {
		PASSERT(env, pg, !pg->cp_owner);
		pg->cp_owner = cl_io_top(io);
		cl_page_owner_set(pg);
		if (pg->cp_state != CPS_FREEING) {
			cl_page_state_set(env, pg, CPS_OWNED);
		} else {
			__cl_page_disown(env, io, pg);
			result = -ENOENT;
		}
	}
out:
	return result;
}

/**
 * Own a page, might be blocked.
 *
 * \see __cl_page_own()
 */
int cl_page_own(const struct lu_env *env, struct cl_io *io, struct cl_page *pg)
{
	return __cl_page_own(env, io, pg, 0);
}
EXPORT_SYMBOL(cl_page_own);

/**
 * Nonblock version of cl_page_own().
 *
 * \see __cl_page_own()
 */
int cl_page_own_try(const struct lu_env *env, struct cl_io *io,
		    struct cl_page *pg)
{
	return __cl_page_own(env, io, pg, 1);
}
EXPORT_SYMBOL(cl_page_own_try);

/**
 * Assume page ownership.
 *
 * Called when page is already locked by the hosting VM.
 *
 * \pre !cl_page_is_owned(pg, io)
 * \post cl_page_is_owned(pg, io)
 *
 * \see cl_page_operations::cpo_assume()
 */
void cl_page_assume(const struct lu_env *env,
		    struct cl_io *io, struct cl_page *pg)
{
	const struct cl_page_slice *slice;

	io = cl_io_top(io);

	list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_assume)
			(*slice->cpl_ops->cpo_assume)(env, slice, io);
	}

	PASSERT(env, pg, !pg->cp_owner);
	pg->cp_owner = cl_io_top(io);
	cl_page_owner_set(pg);
	cl_page_state_set(env, pg, CPS_OWNED);
}
EXPORT_SYMBOL(cl_page_assume);

/**
 * Releases page ownership without unlocking the page.
 *
 * Moves page into cl_page_state::CPS_CACHED without releasing a lock on the
 * underlying VM page (as VM is supposed to do this itself).
 *
 * \pre   cl_page_is_owned(pg, io)
 * \post !cl_page_is_owned(pg, io)
 *
 * \see cl_page_assume()
 */
void cl_page_unassume(const struct lu_env *env,
		      struct cl_io *io, struct cl_page *pg)
{
	const struct cl_page_slice *slice;

	io = cl_io_top(io);
	cl_page_owner_clear(pg);
	cl_page_state_set(env, pg, CPS_CACHED);

	list_for_each_entry_reverse(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_unassume)
			(*slice->cpl_ops->cpo_unassume)(env, slice, io);
	}
}
EXPORT_SYMBOL(cl_page_unassume);

/**
 * Releases page ownership.
 *
 * Moves page into cl_page_state::CPS_CACHED.
 *
 * \pre   cl_page_is_owned(pg, io)
 * \post !cl_page_is_owned(pg, io)
 *
 * \see cl_page_own()
 * \see cl_page_operations::cpo_disown()
 */
void cl_page_disown(const struct lu_env *env,
		    struct cl_io *io, struct cl_page *pg)
{
	io = cl_io_top(io);
	__cl_page_disown(env, io, pg);
}
EXPORT_SYMBOL(cl_page_disown);

/**
 * Called when page is to be removed from the object, e.g., as a result of
 * truncate.
 *
 * Calls cl_page_operations::cpo_discard() top-to-bottom.
 *
 * \pre cl_page_is_owned(pg, io)
 *
 * \see cl_page_operations::cpo_discard()
 */
void cl_page_discard(const struct lu_env *env,
		     struct cl_io *io, struct cl_page *pg)
{
	const struct cl_page_slice *slice;

	list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_discard)
			(*slice->cpl_ops->cpo_discard)(env, slice, io);
	}
}
EXPORT_SYMBOL(cl_page_discard);

/**
 * Version of cl_page_delete() that can be called for not fully constructed
 * pages, e.g,. in a error handling cl_page_find()->__cl_page_delete()
 * path. Doesn't check page invariant.
 */
static void __cl_page_delete(const struct lu_env *env, struct cl_page *pg)
{
	const struct cl_page_slice *slice;

	PASSERT(env, pg, pg->cp_state != CPS_FREEING);

	/*
	 * Sever all ways to obtain new pointers to @pg.
	 */
	cl_page_owner_clear(pg);
	__cl_page_state_set(env, pg, CPS_FREEING);

	list_for_each_entry_reverse(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_delete)
			(*slice->cpl_ops->cpo_delete)(env, slice);
	}
}

/**
 * Called when a decision is made to throw page out of memory.
 *
 * Notifies all layers about page destruction by calling
 * cl_page_operations::cpo_delete() method top-to-bottom.
 *
 * Moves page into cl_page_state::CPS_FREEING state (this is the only place
 * where transition to this state happens).
 *
 * Eliminates all venues through which new references to the page can be
 * obtained:
 *
 *     - removes page from the radix trees,
 *
 *     - breaks linkage from VM page to cl_page.
 *
 * Once page reaches cl_page_state::CPS_FREEING, all remaining references will
 * drain after some time, at which point page will be recycled.
 *
 * \pre  VM page is locked
 * \post pg->cp_state == CPS_FREEING
 *
 * \see cl_page_operations::cpo_delete()
 */
void cl_page_delete(const struct lu_env *env, struct cl_page *pg)
{
	__cl_page_delete(env, pg);
}
EXPORT_SYMBOL(cl_page_delete);

/**
 * Marks page up-to-date.
 *
 * Call cl_page_operations::cpo_export() through all layers top-to-bottom. The
 * layer responsible for VM interaction has to mark/clear page as up-to-date
 * by the @uptodate argument.
 *
 * \see cl_page_operations::cpo_export()
 */
void cl_page_export(const struct lu_env *env, struct cl_page *pg, int uptodate)
{
	const struct cl_page_slice *slice;

	list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_export)
			(*slice->cpl_ops->cpo_export)(env, slice, uptodate);
	}
}
EXPORT_SYMBOL(cl_page_export);

/**
 * Returns true, if @pg is VM locked in a suitable sense by the calling
 * thread.
 */
int cl_page_is_vmlocked(const struct lu_env *env, const struct cl_page *pg)
{
	const struct cl_page_slice *slice;
	int result;

	slice = list_first_entry(&pg->cp_layers,
				 const struct cl_page_slice, cpl_linkage);
	PASSERT(env, pg, slice->cpl_ops->cpo_is_vmlocked);
	/*
	 * Call ->cpo_is_vmlocked() directly instead of going through
	 * CL_PAGE_INVOKE(), because cl_page_is_vmlocked() is used by
	 * cl_page_invariant().
	 */
	result = slice->cpl_ops->cpo_is_vmlocked(env, slice);
	PASSERT(env, pg, result == -EBUSY || result == -ENODATA);
	return result == -EBUSY;
}
EXPORT_SYMBOL(cl_page_is_vmlocked);

void cl_page_touch(const struct lu_env *env, const struct cl_page *pg,
		  size_t to)
{
	const struct cl_page_slice *slice;

	list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_page_touch)
			(*slice->cpl_ops->cpo_page_touch)(env, slice, to);
	}

}
EXPORT_SYMBOL(cl_page_touch);

static enum cl_page_state cl_req_type_state(enum cl_req_type crt)
{
	return crt == CRT_WRITE ? CPS_PAGEOUT : CPS_PAGEIN;
}

static void cl_page_io_start(const struct lu_env *env,
			     struct cl_page *pg, enum cl_req_type crt)
{
	/*
	 * Page is queued for IO, change its state.
	 */
	cl_page_owner_clear(pg);
	cl_page_state_set(env, pg, cl_req_type_state(crt));
}

/**
 * Prepares page for immediate transfer. cl_page_operations::cpo_prep() is
 * called top-to-bottom. Every layer either agrees to submit this page (by
 * returning 0), or requests to omit this page (by returning -EALREADY). Layer
 * handling interactions with the VM also has to inform VM that page is under
 * transfer now.
 */
int cl_page_prep(const struct lu_env *env, struct cl_io *io,
		 struct cl_page *pg, enum cl_req_type crt)
{
	const struct cl_page_slice *slice;
	int result = 0;

	/*
	 * XXX this has to be called bottom-to-top, so that llite can set up
	 * PG_writeback without risking other layers deciding to skip this
	 * page.
	 */
	if (crt >= CRT_NR)
		return -EINVAL;

	list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_own)
			result = (*slice->cpl_ops->io[crt].cpo_prep)(env, slice,
								     io);
		if (result != 0)
			break;
	}

	if (result >= 0) {
		result = 0;
		cl_page_io_start(env, pg, crt);
	}

	CL_PAGE_HEADER(D_TRACE, env, pg, "%d %d\n", crt, result);
	return result;
}
EXPORT_SYMBOL(cl_page_prep);

/**
 * Notify layers about transfer completion.
 *
 * Invoked by transfer sub-system (which is a part of osc) to notify layers
 * that a transfer, of which this page is a part of has completed.
 *
 * Completion call-backs are executed in the bottom-up order, so that
 * uppermost layer (llite), responsible for the VFS/VM interaction runs last
 * and can release locks safely.
 *
 * \pre  pg->cp_state == CPS_PAGEIN || pg->cp_state == CPS_PAGEOUT
 * \post pg->cp_state == CPS_CACHED
 *
 * \see cl_page_operations::cpo_completion()
 */
void cl_page_completion(const struct lu_env *env,
			struct cl_page *pg, enum cl_req_type crt, int ioret)
{
	struct cl_sync_io *anchor = pg->cp_sync_io;
	const struct cl_page_slice *slice;

	PASSERT(env, pg, crt < CRT_NR);
	PASSERT(env, pg, pg->cp_state == cl_req_type_state(crt));

	CL_PAGE_HEADER(D_TRACE, env, pg, "%d %d\n", crt, ioret);

	cl_page_state_set(env, pg, CPS_CACHED);
	if (crt >= CRT_NR)
		return;

	list_for_each_entry_reverse(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->io[crt].cpo_completion)
			(*slice->cpl_ops->io[crt].cpo_completion)(env, slice,
								  ioret);
	}

	if (anchor) {
		LASSERT(pg->cp_sync_io == anchor);
		pg->cp_sync_io = NULL;
		cl_sync_io_note(env, anchor, ioret);
	}
}
EXPORT_SYMBOL(cl_page_completion);

/**
 * Notify layers that transfer formation engine decided to yank this page from
 * the cache and to make it a part of a transfer.
 *
 * \pre  pg->cp_state == CPS_CACHED
 * \post pg->cp_state == CPS_PAGEIN || pg->cp_state == CPS_PAGEOUT
 *
 * \see cl_page_operations::cpo_make_ready()
 */
int cl_page_make_ready(const struct lu_env *env, struct cl_page *pg,
		       enum cl_req_type crt)
{
	const struct cl_page_slice *sli;
	int result = 0;

	if (crt >= CRT_NR)
		return -EINVAL;

	list_for_each_entry(sli, &pg->cp_layers, cpl_linkage) {
		if (sli->cpl_ops->io[crt].cpo_make_ready)
			result = (*sli->cpl_ops->io[crt].cpo_make_ready)(env,
									 sli);
		if (result != 0)
			break;
	}

	if (result >= 0) {
		PASSERT(env, pg, pg->cp_state == CPS_CACHED);
		cl_page_io_start(env, pg, crt);
		result = 0;
	}
	CL_PAGE_HEADER(D_TRACE, env, pg, "%d %d\n", crt, result);
	return result;
}
EXPORT_SYMBOL(cl_page_make_ready);

/**
 * Called if a pge is being written back by kernel's intention.
 *
 * \pre  cl_page_is_owned(pg, io)
 * \post ergo(result == 0, pg->cp_state == CPS_PAGEOUT)
 *
 * \see cl_page_operations::cpo_flush()
 */
int cl_page_flush(const struct lu_env *env, struct cl_io *io,
		  struct cl_page *pg)
{
	const struct cl_page_slice *slice;
	int result = 0;

	 list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_flush)
			result = (*slice->cpl_ops->cpo_flush)(env, slice, io);
		if (result != 0)
			break;
	}
	if (result > 0)
		result = 0;

	CL_PAGE_HEADER(D_TRACE, env, pg, "%d\n", result);
	return result;
}
EXPORT_SYMBOL(cl_page_flush);

/**
 * Tells transfer engine that only part of a page is to be transmitted.
 *
 * \see cl_page_operations::cpo_clip()
 */
void cl_page_clip(const struct lu_env *env, struct cl_page *pg,
		  int from, int to)
{
	const struct cl_page_slice *slice;

	CL_PAGE_HEADER(D_TRACE, env, pg, "%d %d\n", from, to);

	list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_clip)
			(*slice->cpl_ops->cpo_clip)(env, slice, from, to);
	}
}
EXPORT_SYMBOL(cl_page_clip);

/**
 * Prints human readable representation of @pg to the @f.
 */
void cl_page_header_print(const struct lu_env *env, void *cookie,
			  lu_printer_t printer, const struct cl_page *pg)
{
	(*printer)(env, cookie,
		   "page@%p[%d %p %d %d %p]\n",
		   pg, refcount_read(&pg->cp_ref), pg->cp_obj,
		   pg->cp_state, pg->cp_type,
		   pg->cp_owner);
}
EXPORT_SYMBOL(cl_page_header_print);

/**
 * Prints human readable representation of @pg to the @f.
 */
void cl_page_print(const struct lu_env *env, void *cookie,
		   lu_printer_t printer, const struct cl_page *pg)
{
	const struct cl_page_slice *slice;
	int result = 0;

	cl_page_header_print(env, cookie, printer, pg);

	list_for_each_entry(slice, &pg->cp_layers, cpl_linkage) {
		if (slice->cpl_ops->cpo_print)
			result = (*slice->cpl_ops->cpo_print)(env, slice,
							      cookie, printer);
		if (result != 0)
			break;
	}
	(*printer)(env, cookie, "end page@%p\n", pg);
}
EXPORT_SYMBOL(cl_page_print);

/**
 * Converts a byte offset within object @obj into a page index.
 */
loff_t cl_offset(const struct cl_object *obj, pgoff_t idx)
{
	/*
	 * XXX for now.
	 */
	return (loff_t)idx << PAGE_SHIFT;
}
EXPORT_SYMBOL(cl_offset);

/**
 * Converts a page index into a byte offset within object @obj.
 */
pgoff_t cl_index(const struct cl_object *obj, loff_t offset)
{
	/*
	 * XXX for now.
	 */
	return offset >> PAGE_SHIFT;
}
EXPORT_SYMBOL(cl_index);

size_t cl_page_size(const struct cl_object *obj)
{
	return 1UL << PAGE_SHIFT;
}
EXPORT_SYMBOL(cl_page_size);

/**
 * Adds page slice to the compound page.
 *
 * This is called by cl_object_operations::coo_page_init() methods to add a
 * per-layer state to the page. New state is added at the end of
 * cl_page::cp_layers list, that is, it is at the bottom of the stack.
 *
 * \see cl_lock_slice_add(), cl_req_slice_add(), cl_io_slice_add()
 */
void cl_page_slice_add(struct cl_page *page, struct cl_page_slice *slice,
		       struct cl_object *obj, pgoff_t index,
		       const struct cl_page_operations *ops)
{
	list_add_tail(&slice->cpl_linkage, &page->cp_layers);
	slice->cpl_obj = obj;
	slice->cpl_index = index;
	slice->cpl_ops = ops;
	slice->cpl_page = page;
}
EXPORT_SYMBOL(cl_page_slice_add);

/**
 * Allocate and initialize cl_cache, called by ll_init_sbi().
 */
struct cl_client_cache *cl_cache_init(unsigned long lru_page_max)
{
	struct cl_client_cache *cache = NULL;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache)
		return NULL;

	/* Initialize cache data */
	refcount_set(&cache->ccc_users, 1);
	cache->ccc_lru_max = lru_page_max;
	atomic_long_set(&cache->ccc_lru_left, lru_page_max);
	spin_lock_init(&cache->ccc_lru_lock);
	INIT_LIST_HEAD(&cache->ccc_lru);

	atomic_long_set(&cache->ccc_unstable_nr, 0);
	init_waitqueue_head(&cache->ccc_unstable_waitq);

	return cache;
}
EXPORT_SYMBOL(cl_cache_init);

/**
 * Increase cl_cache refcount
 */
void cl_cache_incref(struct cl_client_cache *cache)
{
	refcount_inc(&cache->ccc_users);
}
EXPORT_SYMBOL(cl_cache_incref);

/**
 * Decrease cl_cache refcount and free the cache if refcount=0.
 * Since llite, lov and osc all hold cl_cache refcount,
 * the free will not cause race. (LU-6173)
 */
void cl_cache_decref(struct cl_client_cache *cache)
{
	if (refcount_dec_and_test(&cache->ccc_users))
		kfree(cache);
}
EXPORT_SYMBOL(cl_cache_decref);
