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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/llog_cat.c
 *
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <obd_class.h>

#include "llog_internal.h"

/* Open an existent log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 * We return a lock on the handle to ensure nobody yanks it from us.
 *
 * This takes extra reference on llog_handle via llog_handle_get() and require
 * this reference to be put by caller using llog_handle_put()
 */
static int llog_cat_id2handle(const struct lu_env *env,
			      struct llog_handle *cathandle,
			      struct llog_handle **res,
			      struct llog_logid *logid)
{
	struct llog_handle *loghandle;
	enum llog_flag fmt;
	int rc = 0;

	if (!cathandle)
		return -EBADF;

	fmt = cathandle->lgh_hdr->llh_flags & LLOG_F_EXT_MASK;
	down_write(&cathandle->lgh_lock);
	list_for_each_entry(loghandle, &cathandle->u.chd.chd_head,
			    u.phd.phd_entry) {
		struct llog_logid *cgl = &loghandle->lgh_id;

		if (ostid_id(&cgl->lgl_oi) == ostid_id(&logid->lgl_oi) &&
		    ostid_seq(&cgl->lgl_oi) == ostid_seq(&logid->lgl_oi)) {
			if (cgl->lgl_ogen != logid->lgl_ogen) {
				CWARN("%s: log " DFID " generation %x != %x\n",
				      loghandle->lgh_ctxt->loc_obd->obd_name,
				      PFID(&logid->lgl_oi.oi_fid),
				      cgl->lgl_ogen, logid->lgl_ogen);
				continue;
			}
			*res = llog_handle_get(loghandle);
			if (!*res) {
				CERROR("%s: log "DFID" refcount is zero!\n",
				       loghandle->lgh_ctxt->loc_obd->obd_name,
				       PFID(&logid->lgl_oi.oi_fid));
				continue;
			}
			loghandle->u.phd.phd_cat_handle = cathandle;
			up_write(&cathandle->lgh_lock);
			return rc;
		}
	}
	up_write(&cathandle->lgh_lock);

	rc = llog_open(env, cathandle->lgh_ctxt, &loghandle, logid, NULL,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		CERROR("%s: error opening log id " DFID ":%x: rc = %d\n",
		       cathandle->lgh_ctxt->loc_obd->obd_name,
		       PFID(&logid->lgl_oi.oi_fid), logid->lgl_ogen, rc);
		return rc;
	}

	rc = llog_init_handle(env, loghandle, fmt | LLOG_F_IS_PLAIN, NULL);
	if (rc < 0) {
		llog_close(env, loghandle);
		*res = NULL;
		return rc;
	}

	*res = llog_handle_get(loghandle);
	LASSERT(*res);
	down_write(&cathandle->lgh_lock);
	list_add_tail(&loghandle->u.phd.phd_entry, &cathandle->u.chd.chd_head);
	up_write(&cathandle->lgh_lock);

	loghandle->u.phd.phd_cat_handle = cathandle;
	loghandle->u.phd.phd_cookie.lgc_lgl = cathandle->lgh_id;
	loghandle->u.phd.phd_cookie.lgc_index =
				loghandle->lgh_hdr->llh_cat_idx;
	return 0;
}

int llog_cat_close(const struct lu_env *env, struct llog_handle *cathandle)
{
	struct llog_handle *loghandle, *n;

	list_for_each_entry_safe(loghandle, n, &cathandle->u.chd.chd_head,
				 u.phd.phd_entry) {
		/* unlink open-not-created llogs */
		list_del_init(&loghandle->u.phd.phd_entry);
		llog_close(env, loghandle);
	}

	return 0;
}
EXPORT_SYMBOL(llog_cat_close);

static int llog_cat_process_common(const struct lu_env *env,
				   struct llog_handle *cat_llh,
				   struct llog_rec_hdr *rec,
				   struct llog_handle **llhp)
{
	struct llog_logid_rec *lir = container_of(rec, typeof(*lir), lid_hdr);
	int rc;

	if (rec->lrh_type != le32_to_cpu(LLOG_LOGID_MAGIC)) {
		rc = -EINVAL;
		CWARN("%s: invalid record in catalog " DFID ":%x: rc = %d\n",
		      cat_llh->lgh_ctxt->loc_obd->obd_name,
		      PFID(&cat_llh->lgh_id.lgl_oi.oi_fid),
		      cat_llh->lgh_id.lgl_ogen, rc);

		return rc;
	}
	CDEBUG(D_HA,
	       "processing log " DFID ":%x at index %u of catalog " DFID "\n",
	       PFID(&lir->lid_id.lgl_oi.oi_fid), lir->lid_id.lgl_ogen,
	       le32_to_cpu(rec->lrh_index),
	       PFID(&cat_llh->lgh_id.lgl_oi.oi_fid));

	rc = llog_cat_id2handle(env, cat_llh, llhp, &lir->lid_id);
	if (rc) {
		CWARN("%s: can't find llog handle " DFID ":%x: rc = %d\n",
		      cat_llh->lgh_ctxt->loc_obd->obd_name,
		      PFID(&lir->lid_id.lgl_oi.oi_fid),
		      lir->lid_id.lgl_ogen, rc);

		return rc;
	}

	return rc;
}

static int llog_cat_process_cb(const struct lu_env *env,
			       struct llog_handle *cat_llh,
			       struct llog_rec_hdr *rec, void *data)
{
	struct llog_process_data *d = data;
	struct llog_handle *llh = NULL;
	int rc;

	rc = llog_cat_process_common(env, cat_llh, rec, &llh);
	if (rc)
		goto out;

	if (rec->lrh_index < d->lpd_startcat)
		/* Skip processing of the logs until startcat */
		rc = 0;
	else if (d->lpd_startidx > 0) {
		struct llog_process_cat_data cd;

		cd.lpcd_first_idx = d->lpd_startidx;
		cd.lpcd_last_idx = 0;
		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  &cd, false);
		/* Continue processing the next log from idx 0 */
		d->lpd_startidx = 0;
	} else {
		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  NULL, false);
	}

out:
	llog_handle_put(env, llh);

	return rc;
}

static int llog_cat_process_or_fork(const struct lu_env *env,
				    struct llog_handle *cat_llh,
				    llog_cb_t cat_cb, llog_cb_t cb,
				    void *data, int startcat,
				    int startidx, bool fork)
{
	struct llog_process_data d;
	struct llog_log_hdr *llh = cat_llh->lgh_hdr;
	int rc;

	LASSERT(llh->llh_flags & LLOG_F_IS_CAT);
	d.lpd_data = data;
	d.lpd_cb = cb;
	d.lpd_startcat = (startcat == LLOG_CAT_FIRST ? 0 : startcat);
	d.lpd_startidx = startidx;

	if (llh->llh_cat_idx > cat_llh->lgh_last_idx) {
		struct llog_process_cat_data cd;

		CWARN("%s: catlog " DFID " crosses index zero\n",
		      cat_llh->lgh_ctxt->loc_obd->obd_name,
		      PFID(&cat_llh->lgh_id.lgl_oi.oi_fid));
		/*startcat = 0 is default value for general processing */
		if ((startcat != LLOG_CAT_FIRST &&
		    startcat >= llh->llh_cat_idx) || !startcat) {
			/* processing the catalog part at the end */
			cd.lpcd_first_idx = (startcat ? startcat :
					     llh->llh_cat_idx);
			cd.lpcd_last_idx = 0;
			rc = llog_process_or_fork(env, cat_llh, cat_cb,
						  &d, &cd, fork);
			/* Reset the startcat because it has already reached
			 * catalog bottom.
			 */
			startcat = 0;
			d.lpd_startcat = 0;
			if (rc != 0)
				return rc;
		}
		/* processing the catalog part at the beginning */
		cd.lpcd_first_idx = (startcat == LLOG_CAT_FIRST) ? 0 : startcat;
		/* Note, the processing will stop at the lgh_last_idx value,
		 * and it could be increased during processing. So records
		 * between current lgh_last_idx and lgh_last_idx in future
		 * would left unprocessed.
		 */
		cd.lpcd_last_idx = cat_llh->lgh_last_idx;
		rc = llog_process_or_fork(env, cat_llh, cat_cb, &d, &cd, fork);
	} else {
		rc = llog_process_or_fork(env, cat_llh, cat_cb, &d, NULL, fork);
	}

	return rc;
}

int llog_cat_process(const struct lu_env *env, struct llog_handle *cat_llh,
		     llog_cb_t cb, void *data, int startcat, int startidx)
{
	return llog_cat_process_or_fork(env, cat_llh, llog_cat_process_cb, cb,
					data, startcat, startidx, false);
}
EXPORT_SYMBOL(llog_cat_process);
