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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/llog.c
 *
 * OST<->MDS recovery logging infrastructure.
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mikhail Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <linux/pid_namespace.h>
#include <linux/kthread.h>
#include <llog_swab.h>
#include <lustre_log.h>
#include <obd_support.h>
#include <obd_class.h>
#include "llog_internal.h"
/*
 * Allocate a new log or catalog handle
 * Used inside llog_open().
 */
static struct llog_handle *llog_alloc_handle(void)
{
	struct llog_handle *loghandle;

	loghandle = kzalloc(sizeof(*loghandle), GFP_NOFS);
	if (loghandle == NULL)
		return NULL;

	init_rwsem(&loghandle->lgh_lock);
	mutex_init(&loghandle->lgh_hdr_mutex);
	init_rwsem(&loghandle->lgh_last_sem);
	INIT_LIST_HEAD(&loghandle->u.phd.phd_entry);
	refcount_set(&loghandle->lgh_refcount, 1);

	return loghandle;
}

/*
 * Free llog handle and header data if exists. Used in llog_close() only
 */
static void llog_free_handle(struct llog_handle *loghandle)
{
	LASSERT(loghandle != NULL);

	/* failed llog_init_handle */
	if (loghandle->lgh_hdr == NULL)
		goto out;

	if (loghandle->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)
		LASSERT(list_empty(&loghandle->u.phd.phd_entry));
	else if (loghandle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)
		LASSERT(list_empty(&loghandle->u.chd.chd_head));
	kvfree(loghandle->lgh_hdr);
out:
	kfree(loghandle);
}

struct llog_handle *llog_handle_get(struct llog_handle *loghandle)
{
	if (refcount_inc_not_zero(&loghandle->lgh_refcount))
		return loghandle;
	return NULL;
}

int llog_handle_put(const struct lu_env *env, struct llog_handle *loghandle)
{
	int rc = 0;

	if (refcount_dec_and_test(&loghandle->lgh_refcount)) {
		const struct llog_operations *lop;

		rc = llog_handle2ops(loghandle, &lop);
		if (!rc) {
			if (lop->lop_close)
				rc = lop->lop_close(env, loghandle);
			else
				rc = -EOPNOTSUPP;
		}
		llog_free_handle(loghandle);
	}
	return rc;
}

int llog_read_header(const struct lu_env *env, struct llog_handle *handle,
		     const struct obd_uuid *uuid)
{
	const struct llog_operations *lop;
	int rc;

	rc = llog_handle2ops(handle, &lop);
	if (rc)
		return rc;

	if (lop->lop_read_header == NULL)
		return -EOPNOTSUPP;

	rc = lop->lop_read_header(env, handle);
	if (rc == LLOG_EEMPTY) {
		struct llog_log_hdr *llh = handle->lgh_hdr;

		/* lrh_len should be initialized in llog_init_handle */
		handle->lgh_last_idx = 0; /* header is record with index 0 */
		llh->llh_count = 1;         /* for the header record */
		llh->llh_hdr.lrh_type = LLOG_HDR_MAGIC;
		LASSERT(handle->lgh_ctxt->loc_chunk_size >=
						LLOG_MIN_CHUNK_SIZE);
		llh->llh_hdr.lrh_len = handle->lgh_ctxt->loc_chunk_size;
		llh->llh_hdr.lrh_index = 0;
		llh->llh_timestamp = ktime_get_real_seconds();
		if (uuid)
			memcpy(&llh->llh_tgtuuid, uuid,
			       sizeof(llh->llh_tgtuuid));
		llh->llh_bitmap_offset = offsetof(typeof(*llh), llh_bitmap);
		/* Since update llog header might also call this function,
		 * let's reset the bitmap to 0 here */
		memset(LLOG_HDR_BITMAP(llh), 0, llh->llh_hdr.lrh_len -
						llh->llh_bitmap_offset -
						sizeof(llh->llh_tail));
		set_bit_le(0, LLOG_HDR_BITMAP(llh));
		LLOG_HDR_TAIL(llh)->lrt_len = llh->llh_hdr.lrh_len;
		LLOG_HDR_TAIL(llh)->lrt_index = llh->llh_hdr.lrh_index;
		rc = 0;
	}
	return rc;
}
EXPORT_SYMBOL(llog_read_header);

int llog_init_handle(const struct lu_env *env, struct llog_handle *handle,
		     int flags, struct obd_uuid *uuid)
{
	struct llog_log_hdr	*llh;
	enum llog_flag		 fmt = flags & LLOG_F_EXT_MASK;
	int			 rc;
	int			chunk_size = handle->lgh_ctxt->loc_chunk_size;

	LASSERT(handle->lgh_hdr == NULL);

	LASSERT(chunk_size >= LLOG_MIN_CHUNK_SIZE);
	llh = kvzalloc(chunk_size, GFP_KERNEL);
	if (llh == NULL)
		return -ENOMEM;

	handle->lgh_hdr = llh;
	handle->lgh_hdr_size = chunk_size;
	/* first assign flags to use llog_client_ops */
	llh->llh_flags = flags;
	rc = llog_read_header(env, handle, uuid);
	if (rc == 0) {
		if (unlikely((llh->llh_flags & LLOG_F_IS_PLAIN &&
			      flags & LLOG_F_IS_CAT) ||
			     (llh->llh_flags & LLOG_F_IS_CAT &&
			      flags & LLOG_F_IS_PLAIN))) {
			CERROR("%s: llog type is %s but initializing %s\n",
			       handle->lgh_ctxt->loc_obd->obd_name,
			       llh->llh_flags & LLOG_F_IS_CAT ?
			       "catalog" : "plain",
			       flags & LLOG_F_IS_CAT ? "catalog" : "plain");
			rc = -EINVAL;
			goto out;
		} else if (llh->llh_flags &
			   (LLOG_F_IS_PLAIN | LLOG_F_IS_CAT)) {
			/*
			 * it is possible to open llog without specifying llog
			 * type so it is taken from llh_flags
			 */
			flags = llh->llh_flags;
		} else {
			/* for some reason the llh_flags has no type set */
			CERROR("llog type is not specified!\n");
			rc = -EINVAL;
			goto out;
		}
		if (unlikely(uuid &&
			     !obd_uuid_equals(uuid, &llh->llh_tgtuuid))) {
			CERROR("%s: llog uuid mismatch: %s/%s\n",
			       handle->lgh_ctxt->loc_obd->obd_name,
			       (char *)uuid->uuid,
			       (char *)llh->llh_tgtuuid.uuid);
			rc = -EEXIST;
			goto out;
		}
	}
	if (flags & LLOG_F_IS_CAT) {
		LASSERT(list_empty(&handle->u.chd.chd_head));
		INIT_LIST_HEAD(&handle->u.chd.chd_head);
		llh->llh_size = sizeof(struct llog_logid_rec);
		llh->llh_flags |= LLOG_F_IS_FIXSIZE;
	} else if (!(flags & LLOG_F_IS_PLAIN)) {
		CERROR("%s: unknown flags: %#x (expected %#x or %#x)\n",
		       handle->lgh_ctxt->loc_obd->obd_name,
		       flags, LLOG_F_IS_CAT, LLOG_F_IS_PLAIN);
		rc = -EINVAL;
	}
	llh->llh_flags |= fmt;
out:
	if (rc) {
		kvfree(llh);
		handle->lgh_hdr = NULL;
	}
	return rc;
}
EXPORT_SYMBOL(llog_init_handle);

static int llog_process_thread(void *arg)
{
	struct llog_process_info	*lpi = arg;
	struct llog_handle		*loghandle = lpi->lpi_loghandle;
	struct llog_log_hdr		*llh = loghandle->lgh_hdr;
	struct llog_process_cat_data	*cd  = lpi->lpi_catdata;
	char				*buf;
	size_t				 chunk_size;
	__u64				 cur_offset;
	int				 rc = 0, index = 1, last_index;
	int				 saved_index = 0;
	int				 last_called_index = 0;
	bool				 repeated = false;

	if (llh == NULL)
		return -EINVAL;

	cur_offset = chunk_size = llh->llh_hdr.lrh_len;
	/* expect chunk_size to be power of two */
	LASSERT(is_power_of_2(chunk_size));

	buf = kvzalloc(chunk_size, GFP_KERNEL);
	if (buf == NULL) {
		lpi->lpi_rc = -ENOMEM;
		return 0;
	}

	if (cd != NULL) {
		last_called_index = cd->lpcd_first_idx;
		index = cd->lpcd_first_idx + 1;
	}
	if (cd != NULL && cd->lpcd_last_idx)
		last_index = cd->lpcd_last_idx;
	else
		last_index = LLOG_HDR_BITMAP_SIZE(llh) - 1;

	while (rc == 0) {
		struct llog_rec_hdr *rec;
		off_t chunk_offset = 0;
		unsigned int buf_offset = 0;
		int	lh_last_idx;
		int	synced_idx = 0;

		/* skip records not set in bitmap */
		while (index <= last_index &&
		       !test_bit_le(index, LLOG_HDR_BITMAP(llh)))
			++index;

		/* There are no indices prior the last_index */
		if (index > last_index)
			break;

		CDEBUG(D_OTHER, "index: %d last_index %d\n", index,
		       last_index);

repeat:
		/* get the buf with our target record; avoid old garbage */
		memset(buf, 0, chunk_size);
		/* the record index for outdated chunk data */
		/* it is safe to process buffer until saved lgh_last_idx */
		lh_last_idx = LLOG_HDR_TAIL(llh)->lrt_index;
		rc = llog_next_block(lpi->lpi_env, loghandle, &saved_index,
				     index, &cur_offset, buf, chunk_size);
		if (repeated && rc)
			CDEBUG(D_OTHER, "cur_offset %llu, chunk_offset %llu,"
			       " buf_offset %u, rc = %d\n", cur_offset,
			       (__u64)chunk_offset, buf_offset, rc);
		/* we`ve tried to reread the chunk, but there is no
		 * new records */
		if (rc == -EIO && repeated && (chunk_offset + buf_offset) ==
		    cur_offset) {
			rc = 0;
			goto out;
		}
		if (rc != 0)
			goto out;

		/* NB: after llog_next_block() call the cur_offset is the
		 * offset of the next block after read one.
		 * The absolute offset of the current chunk is calculated
		 * from cur_offset value and stored in chunk_offset variable.
		 */
		if ((cur_offset & (chunk_size - 1)) != 0)
			chunk_offset = cur_offset & ~(chunk_size - 1);
		else
			chunk_offset = cur_offset - chunk_size;

		/* NB: when rec->lrh_len is accessed it is already swabbed
		 * since it is used at the "end" of the loop and the rec
		 * swabbing is done at the beginning of the loop. */
		for (rec = (struct llog_rec_hdr *)(buf + buf_offset);
		     (char *)rec < buf + chunk_size;
		     rec = llog_rec_hdr_next(rec)) {

			CDEBUG(D_OTHER, "processing rec 0x%p type %#x\n",
			       rec, rec->lrh_type);

			if (LLOG_REC_HDR_NEEDS_SWABBING(rec))
				lustre_swab_llog_rec(rec);

			CDEBUG(D_OTHER, "after swabbing, type=%#x idx=%d\n",
			       rec->lrh_type, rec->lrh_index);

			if (index == (synced_idx + 1) &&
			    synced_idx == LLOG_HDR_TAIL(llh)->lrt_index) {
				rc = 0;
				goto out;
			}

			if (OBD_FAIL_PRECHECK(OBD_FAIL_LLOG_PROCESS_TIMEOUT) &&
				cfs_fail_val == (unsigned int)
					(loghandle->lgh_id.lgl_oi.oi.oi_id &
					 0xFFFFFFFF)) {
				OBD_RACE(OBD_FAIL_LLOG_PROCESS_TIMEOUT);
			}

			/* the bitmap could be changed during processing
			 * records from the chunk. For wrapped catalog
			 * it means we can read deleted record and try to
			 * process it. Check this case and reread the chunk.
			 * It is safe to process to lh_last_idx, including
			 * lh_last_idx if it was synced. We can not do <=
			 * comparison, cause for wrapped catalog lgh_last_idx
			 * could be less than index. So we detect last index
			 * for processing as index == lh_last_idx+1. But when
			 * catalog is wrapped and full lgh_last_idx=llh_cat_idx,
			 * the first processing index is llh_cat_idx+1.The
			 * exception is !(lgh_last_idx == llh_cat_idx &&
			 * index == llh_cat_idx + 1), and after simplification
			 * it turns to
			 * lh_last_idx != LLOG_HDR_TAIL(llh)->lrt_index
			 * This exception is working for catalog only.
			 */

			if ((index == lh_last_idx && synced_idx != index) ||
			    (index == (lh_last_idx + 1) &&
			     lh_last_idx != LLOG_HDR_TAIL(llh)->lrt_index) ||
			    (rec->lrh_index == 0 && !repeated)) {

				/* save offset inside buffer for the re-read */
				buf_offset = (char *)rec - (char *)buf;
				cur_offset = chunk_offset;
				repeated = true;
				/* We need to be sure lgh_last_idx
				 * record was saved to disk
				 */
				down_read(&loghandle->lgh_last_sem);
				synced_idx = LLOG_HDR_TAIL(llh)->lrt_index;
				up_read(&loghandle->lgh_last_sem);
				CDEBUG(D_OTHER, "synced_idx: %d\n", synced_idx);
				goto repeat;

			}

			repeated = false;

			if (rec->lrh_len == 0 || rec->lrh_len > chunk_size) {
				CWARN("%s: invalid length %d in llog "DFID
				      "record for index %d/%d\n",
				       loghandle->lgh_ctxt->loc_obd->obd_name,
				       rec->lrh_len,
				       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
				       rec->lrh_index, index);

				rc = -EINVAL;
				goto out;
			}

			if (rec->lrh_index < index) {
				CDEBUG(D_OTHER, "skipping lrh_index %d\n",
				       rec->lrh_index);
				continue;
			}

			if (rec->lrh_index != index) {
				CERROR("%s: "DFID" Invalid record: index %u"
				       " but expected %u\n",
				       loghandle->lgh_ctxt->loc_obd->obd_name,
				       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
				       rec->lrh_index, index);
				rc = -ERANGE;
				goto out;
			}

			CDEBUG(D_OTHER,
			       "lrh_index: %d lrh_len: %d (%d remains)\n",
			       rec->lrh_index, rec->lrh_len,
			       (int)(buf + chunk_size - (char *)rec));

			/* lgh_cur_offset is used only at llog_test_3 */
			loghandle->lgh_cur_offset = (char *)rec - (char *)buf +
						    chunk_offset;

			/* if set, process the callback on this record */
			if (test_bit_le(index, LLOG_HDR_BITMAP(llh))) {
				CDEBUG((llh->llh_flags & LLOG_F_IS_CAT ?
					D_HA : D_OTHER),
				       "index: %d, lh_last_idx: %d "
				       "synced_idx: %d lgh_last_idx: %d\n",
				       index, lh_last_idx, synced_idx,
				       loghandle->lgh_last_idx);

				/* using lu_env for passing record offset to
				 * llog_write through various callbacks */
				rc = lpi->lpi_cb(lpi->lpi_env, loghandle, rec,
						 lpi->lpi_cbdata);
				last_called_index = index;

				if (rc)
					goto out;
				/* some stupid callbacks directly cancel records
				 * and delete llog. Check it and stop
				 * processing. */
				if (loghandle->lgh_hdr == NULL ||
				    loghandle->lgh_hdr->llh_count == 1) {
					rc = 0;
					goto out;
				}
			}
			/* exit if the last index is reached */
			if (index >= last_index) {
				rc = 0;
				goto out;
			}
			++index;
		}
	}

out:
	CDEBUG(D_HA, "stop processing %s "DOSTID":%x index %d count %d\n",
	       ((llh->llh_flags & LLOG_F_IS_CAT) ? "catalog" : "plain"),
	       POSTID(&loghandle->lgh_id.lgl_oi), loghandle->lgh_id.lgl_ogen,
	       index, llh->llh_count);

	if (cd != NULL)
		cd->lpcd_last_idx = last_called_index;
	kvfree(buf);
	lpi->lpi_rc = rc;
	return 0;
}

static int llog_process_thread_daemonize(void *arg)
{
	struct llog_process_info	*lpi = arg;
	struct lu_env			 env;
	int				 rc;
	struct nsproxy			*new_ns, *curr_ns = current->nsproxy;

	task_lock(lpi->lpi_reftask);
	new_ns = lpi->lpi_reftask->nsproxy;
	if (curr_ns != new_ns) {
		get_nsproxy(new_ns);

		current->nsproxy = new_ns;
		/* XXX: we should call put_nsproxy() instead of
		 * atomic_dec(&ns->count) directly. But put_nsproxy() cannot be
		 * used outside of the kernel itself, because it calls
		 * free_nsproxy() which is not exported by the kernel
		 * (defined in kernel/nsproxy.c) */
		if (curr_ns)
			atomic_dec(&curr_ns->count);
	}
	task_unlock(lpi->lpi_reftask);

	/* client env has no keys, tags is just 0 */
	rc = lu_env_init(&env, LCT_LOCAL | LCT_MG_THREAD);
	if (rc)
		goto out;
	lpi->lpi_env = &env;

	rc = llog_process_thread(arg);

	lu_env_fini(&env);
out:
	complete(&lpi->lpi_completion);
	return rc;
}

int llog_process_or_fork(const struct lu_env *env,
			 struct llog_handle *loghandle,
			 llog_cb_t cb, void *data, void *catdata, bool fork)
{
	struct llog_process_info *lpi;
	struct llog_process_data *d = data;
	struct llog_process_cat_data *cd = catdata;
	__u32 flags = loghandle->lgh_hdr->llh_flags;
	int rc;

	lpi = kzalloc(sizeof(*lpi), GFP_NOFS);
	if (lpi == NULL) {
		CERROR("cannot alloc pointer\n");
		return -ENOMEM;
	}
	lpi->lpi_loghandle = loghandle;
	lpi->lpi_cb        = cb;
	lpi->lpi_cbdata    = data;
	lpi->lpi_catdata   = catdata;

	CDEBUG(D_OTHER, "Processing "DFID" flags 0x%03x startcat %d startidx %d first_idx %d last_idx %d\n",
	       PFID(&loghandle->lgh_id.lgl_oi.oi_fid), flags,
	       (flags & LLOG_F_IS_CAT) && d ? d->lpd_startcat : -1,
	       (flags & LLOG_F_IS_CAT) && d ? d->lpd_startidx : -1,
	       cd ? cd->lpcd_first_idx : -1, cd ? cd->lpcd_last_idx : -1);
	if (fork) {
		struct task_struct *task;

		/* The new thread can't use parent env,
		 * init the new one in llog_process_thread_daemonize. */
		lpi->lpi_env = NULL;
		init_completion(&lpi->lpi_completion);
		/* take reference to current, so that
		 * llog_process_thread_daemonize() can use it to switch to
		 * namespace associated with current  */
		lpi->lpi_reftask = current;
		task = kthread_run(llog_process_thread_daemonize, lpi,
				   "llog_process_thread");
		if (IS_ERR(task)) {
			rc = PTR_ERR(task);
			CERROR("%s: cannot start thread: rc = %d\n",
			       loghandle->lgh_ctxt->loc_obd->obd_name, rc);
			goto out_lpi;
		}
		wait_for_completion(&lpi->lpi_completion);
	} else {
		lpi->lpi_env = env;
		llog_process_thread(lpi);
	}
	rc = lpi->lpi_rc;

out_lpi:
	kfree(lpi);
	return rc;
}
EXPORT_SYMBOL(llog_process_or_fork);

int llog_process(const struct lu_env *env, struct llog_handle *loghandle,
		 llog_cb_t cb, void *data, void *catdata)
{
	int rc;
	rc = llog_process_or_fork(env, loghandle, cb, data, catdata, true);
	return rc == LLOG_DEL_PLAIN ? 0 : rc;
}
EXPORT_SYMBOL(llog_process);

static inline const struct cred *llog_raise_resource(void)
{
	struct cred *cred = NULL;

	if (cap_raised(current_cap(), CAP_SYS_RESOURCE))
		return cred;

	cred = prepare_creds();
	if (!cred)
		return cred;

	cap_raise(cred->cap_effective, CAP_SYS_RESOURCE);
	return override_creds(cred);
}

static inline void llog_restore_resource(const struct cred *old_cred)
{
	if (old_cred)
		revert_creds(old_cred);
}

int llog_open(const struct lu_env *env, struct llog_ctxt *ctxt,
	      struct llog_handle **lgh, struct llog_logid *logid,
	      char *name, enum llog_open_param open_param)
{
	const struct cred *old_cred;
	int	 rc;

	LASSERT(ctxt);
	LASSERT(ctxt->loc_logops);

	if (ctxt->loc_logops->lop_open == NULL) {
		*lgh = NULL;
		return -EOPNOTSUPP;
	}

	*lgh = llog_alloc_handle();
	if (*lgh == NULL)
		return -ENOMEM;
	(*lgh)->lgh_ctxt = ctxt;
	(*lgh)->lgh_logops = ctxt->loc_logops;

	old_cred = llog_raise_resource();
	rc = ctxt->loc_logops->lop_open(env, *lgh, logid, name, open_param);
	llog_restore_resource(old_cred);
	if (rc) {
		llog_free_handle(*lgh);
		*lgh = NULL;
	}
	return rc;
}
EXPORT_SYMBOL(llog_open);

int llog_close(const struct lu_env *env, struct llog_handle *loghandle)
{
	return llog_handle_put(env, loghandle);
}
EXPORT_SYMBOL(llog_close);

