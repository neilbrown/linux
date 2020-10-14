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
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ptlrpc/pinger.c
 *
 * Portal-RPC reconnection and replay operations, for use in recovery.
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <obd_support.h>
#include <obd_class.h>
#include <linux/libcfs/libcfs_cpu.h>
#include "ptlrpc_internal.h"

struct mutex pinger_mutex;
static LIST_HEAD(pinger_imports);

struct ptlrpc_request *
ptlrpc_prep_ping(struct obd_import *imp)
{
	struct ptlrpc_request *req;

	req = ptlrpc_request_alloc_pack(imp, &RQF_OBD_PING,
					LUSTRE_OBD_VERSION, OBD_PING);
	if (req) {
		ptlrpc_request_set_replen(req);
		req->rq_no_resend = 1;
		req->rq_no_delay = 1;
	}
	return req;
}

int ptlrpc_obd_ping(struct obd_device *obd)
{
	int rc;
	struct ptlrpc_request *req;

	req = ptlrpc_prep_ping(obd->u.cli.cl_import);
	if (!req)
		return -ENOMEM;

	req->rq_send_state = LUSTRE_IMP_FULL;

	rc = ptlrpc_queue_wait(req);

	ptlrpc_req_finished(req);

	return rc;
}
EXPORT_SYMBOL(ptlrpc_obd_ping);

static bool ptlrpc_check_import_is_idle(struct obd_import *imp)
{
	struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
	time64_t now;

	if (!imp->imp_idle_timeout)
		return false;
	if (atomic_read(&imp->imp_reqs) > 0)
		return false;

	/* any lock increases ns_bref being a resource holder */
	if (ns && atomic_read(&ns->ns_bref) > 0)
		return false;

	now = ktime_get_real_seconds();
	if (now - imp->imp_last_reply_time < imp->imp_idle_timeout)
		return false;

	return true;
}

static int ptlrpc_ping(struct obd_import *imp)
{
	struct ptlrpc_request *req;

	if (ptlrpc_check_import_is_idle(imp))
		return ptlrpc_disconnect_and_idle_import(imp);

	req = ptlrpc_prep_ping(imp);
	if (!req) {
		CERROR("OOM trying to ping %s->%s\n",
		       imp->imp_obd->obd_uuid.uuid,
		       obd2cli_tgt(imp->imp_obd));
		return -ENOMEM;
	}

	DEBUG_REQ(D_INFO, req, "pinging %s->%s",
		  imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
	ptlrpcd_add_req(req);

	return 0;
}

static void ptlrpc_update_next_ping(struct obd_import *imp, int soon)
{
	time64_t time = soon ? PING_INTERVAL_SHORT : PING_INTERVAL;

	if (imp->imp_state == LUSTRE_IMP_DISCON) {
		time64_t dtime = max_t(time64_t, CONNECTION_SWITCH_MIN,
				  AT_OFF ? 0 :
				  at_get(&imp->imp_at.iat_net_latency));
		time = min(time, dtime);
	}
	imp->imp_next_ping = ktime_get_seconds() + time;
}

static inline int imp_is_deactive(struct obd_import *imp)
{
	return (imp->imp_deactive ||
		OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_IMP_DEACTIVE));
}

static inline time64_t ptlrpc_next_reconnect(struct obd_import *imp)
{
	if (imp->imp_server_timeout)
		return ktime_get_seconds() + (obd_timeout >> 1);
	else
		return ktime_get_seconds() + obd_timeout;
}

static time64_t pinger_check_timeout(time64_t time)
{
	time64_t timeout = PING_INTERVAL;

	return time + timeout - ktime_get_seconds();
}

static bool ir_up;

void ptlrpc_pinger_ir_up(void)
{
	CDEBUG(D_HA, "IR up\n");
	ir_up = true;
}
EXPORT_SYMBOL(ptlrpc_pinger_ir_up);

void ptlrpc_pinger_ir_down(void)
{
	CDEBUG(D_HA, "IR down\n");
	ir_up = false;
}
EXPORT_SYMBOL(ptlrpc_pinger_ir_down);

static void ptlrpc_pinger_process_import(struct obd_import *imp,
					 time64_t this_ping)
{
	int level;
	int force;
	int force_next;
	int suppress;

	spin_lock(&imp->imp_lock);

	level = imp->imp_state;
	force = imp->imp_force_verify;
	force_next = imp->imp_force_next_verify;
	/*
	 * This will be used below only if the import is "FULL".
	 */
	suppress = ir_up && OCD_HAS_FLAG(&imp->imp_connect_data, PINGLESS);

	imp->imp_force_verify = 0;

	if (imp->imp_next_ping - 5 >= this_ping && !force) {
		spin_unlock(&imp->imp_lock);
		return;
	}

	imp->imp_force_next_verify = 0;

	CDEBUG(level == LUSTRE_IMP_FULL ? D_INFO : D_HA,
	       "%s->%s: level %s/%u force %u force_next %u deactive %u pingable %u suppress %u\n",
	       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd),
	       ptlrpc_import_state_name(level), level, force, force_next,
	       imp->imp_deactive, imp->imp_pingable, suppress);

	if (level == LUSTRE_IMP_DISCON && !imp_is_deactive(imp)) {
		/* wait for a while before trying recovery again */
		imp->imp_next_ping = ptlrpc_next_reconnect(imp);
		spin_unlock(&imp->imp_lock);
		if (!imp->imp_no_pinger_recover ||
		    imp->imp_connect_error == -EAGAIN)
			ptlrpc_initiate_recovery(imp);
	} else if (level != LUSTRE_IMP_FULL || imp->imp_obd->obd_no_recov ||
		   imp_is_deactive(imp)) {
		CDEBUG(D_HA,
		       "%s->%s: not pinging (in recovery or recovery disabled: %s)\n",
		       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd),
		       ptlrpc_import_state_name(level));
		if (force)
			imp->imp_force_verify = 1;
		spin_unlock(&imp->imp_lock);
	} else if ((imp->imp_pingable && !suppress) || force_next || force) {
		spin_unlock(&imp->imp_lock);
		ptlrpc_ping(imp);
	} else {
		spin_unlock(&imp->imp_lock);
	}
}

static struct workqueue_struct *pinger_wq;
static void ptlrpc_pinger_main(struct work_struct *ws);
static DECLARE_DELAYED_WORK(ping_work, ptlrpc_pinger_main);

static void ptlrpc_pinger_main(struct work_struct *ws)
{
	time64_t this_ping, time_after_ping, time_to_next_wake;
	struct obd_import *imp;

	do {
		this_ping = ktime_get_seconds();

		mutex_lock(&pinger_mutex);
		list_for_each_entry(imp, &pinger_imports, imp_pinger_chain) {
			ptlrpc_pinger_process_import(imp, this_ping);
			/* obd_timeout might have changed */
			if (imp->imp_pingable && imp->imp_next_ping &&
			    imp->imp_next_ping > this_ping + PING_INTERVAL)
				ptlrpc_update_next_ping(imp, 0);
		}
		mutex_unlock(&pinger_mutex);

		time_after_ping = ktime_get_seconds();

		if ((time_after_ping - this_ping - 3) > PING_INTERVAL)
			CDEBUG(D_HA, "long time to ping: %lld, %lld\n",
			       this_ping, time_after_ping);

		/* Wait until the next ping time, or until we're stopped. */
		time_to_next_wake = pinger_check_timeout(this_ping);
		/* The ping sent by ptlrpc_send_rpc may get sent out
		 * say .01 second after this.
		 * ptlrpc_pinger_sending_on_import will then set the
		 * next ping time to next_ping + .01 sec, which means
		 * we will SKIP the next ping at next_ping, and the
		 * ping will get sent 2 timeouts from now!  Beware.
		 */
		CDEBUG(D_INFO, "next wakeup in %lld (%lld)\n",
		       time_to_next_wake,
		       this_ping + PING_INTERVAL);
	} while (time_to_next_wake <= 0);

	queue_delayed_work(pinger_wq, &ping_work,
			   round_jiffies_up_relative(time_to_next_wake));
}

int ptlrpc_start_pinger(void)
{
	if (pinger_wq)
		return -EALREADY;

	pinger_wq = cfs_cpt_bind_workqueue("ptlrpc_pinger",
				    cfs_cpt_tab,
					   0, CFS_CPT_ANY | WQ_MEM_RECLAIM, 1);
	if (IS_ERR(pinger_wq)) {
		CERROR("cannot start pinger workqueue\n");
		return PTR_ERR(pinger_wq);
	}

	queue_delayed_work(pinger_wq, &ping_work, 0);
	return 0;
}

int ptlrpc_stop_pinger(void)
{
	int rc = 0;

	if (!pinger_wq)
		return -EALREADY;

	cancel_delayed_work_sync(&ping_work);
	destroy_workqueue(pinger_wq);
	pinger_wq = NULL;

	return rc;
}

void ptlrpc_pinger_sending_on_import(struct obd_import *imp)
{
	ptlrpc_update_next_ping(imp, 0);
}

void ptlrpc_pinger_commit_expected(struct obd_import *imp)
{
	ptlrpc_update_next_ping(imp, 1);
	assert_spin_locked(&imp->imp_lock);
	/*
	 * Avoid reading stale imp_connect_data.  When not sure if pings are
	 * expected or not on next connection, we assume they are not and force
	 * one anyway to guarantee the chance of updating
	 * imp_peer_committed_transno.
	 */
	if (imp->imp_state != LUSTRE_IMP_FULL ||
	    OCD_HAS_FLAG(&imp->imp_connect_data, PINGLESS))
		imp->imp_force_next_verify = 1;
}

int ptlrpc_pinger_add_import(struct obd_import *imp)
{
	if (!list_empty(&imp->imp_pinger_chain))
		return -EALREADY;

	mutex_lock(&pinger_mutex);
	CDEBUG(D_HA, "adding pingable import %s->%s\n",
	       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
	/* if we add to pinger we want recovery on this import */
	imp->imp_obd->obd_no_recov = 0;
	ptlrpc_update_next_ping(imp, 0);
	/* XXX sort, blah blah */
	list_add_tail(&imp->imp_pinger_chain, &pinger_imports);
	class_import_get(imp);

	ptlrpc_pinger_wake_up();
	mutex_unlock(&pinger_mutex);

	return 0;
}
EXPORT_SYMBOL(ptlrpc_pinger_add_import);

int ptlrpc_pinger_del_import(struct obd_import *imp)
{
	if (list_empty(&imp->imp_pinger_chain))
		return -ENOENT;

	mutex_lock(&pinger_mutex);
	list_del_init(&imp->imp_pinger_chain);
	CDEBUG(D_HA, "removing pingable import %s->%s\n",
	       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
	/* if we remove from pinger we don't want recovery on this import */
	imp->imp_obd->obd_no_recov = 1;
	class_import_put(imp);
	mutex_unlock(&pinger_mutex);
	return 0;
}
EXPORT_SYMBOL(ptlrpc_pinger_del_import);

void ptlrpc_pinger_wake_up(void)
{
	mod_delayed_work(pinger_wq, &ping_work, 0);
}
