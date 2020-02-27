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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 *
 * Copyright 2017 Cray Inc, all rights reserved.
 * Author: Ben Evans.
 *
 */

#define DEBUG_SUBSYSTEM S_RPC
#include <linux/ctype.h>
#include <linux/user_namespace.h>
#ifdef HAVE_UIDGID_HEADER
#include <linux/uidgid.h>
#endif
#include <linux/utsname.h>

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>

char obd_jobid_var[JOBSTATS_JOBID_VAR_MAX_LEN + 1] = JOBSTATS_DISABLE;
char obd_jobid_name[LUSTRE_JOBID_SIZE] = "%e.%u";

/*
 * Jobid can be set for a session (see setsid(2)) by writing to
 * a sysfs file from any process in that session.
 * The jobids are stored in a hash table indexed by the relevant
 * struct pid.  We periodically look for entries where the pid has
 * no PIDTYPE_SID tasks any more, and prune them.  This happens within
 * 5 seconds of a jobid being added, and every 5 minutes when jobids exist,
 * but none are added.
 */
#define JOBID_EXPEDITED_CLEAN	(5)
#define JOBID_BACKGROUND_CLEAN	(5 * 60)

struct session_jobid {
	struct pid		*sj_session;
	struct rhash_head	sj_linkage;
	struct rcu_head		sj_rcu;
	char			sj_jobid[1];
};

static const struct rhashtable_params jobid_params = {
	.key_len	= sizeof(struct pid *),
	.key_offset	= offsetof(struct session_jobid, sj_session),
	.head_offset	= offsetof(struct session_jobid, sj_linkage),
};

static struct rhashtable session_jobids;

/*
 * jobid_current must be called with rcu_read_lock held.
 * if it returns non-NULL, the string can only be used
 * until rcu_read_unlock is called.
 */
char *jobid_current(void)
{
	struct pid *sid = task_session(current);
	struct session_jobid *sj;

	sj = rhashtable_lookup_fast(&session_jobids, &sid, jobid_params);
	if (sj)
		return sj->sj_jobid;
	return NULL;
}

static void jobid_prune_expedite(void);
/*
 * jobid_set_current will try to add a new entry
 * to the table.  If one exists with the same key, the
 * jobid will be replaced
 */
int jobid_set_current(char *jobid)
{
	struct pid *sid;
	struct session_jobid *sj, *origsj;
	int ret;
	int len = strlen(jobid);

	sj = kmalloc(sizeof(*sj) + len, GFP_KERNEL);
	if (!sj)
		return -ENOMEM;
	rcu_read_lock();
	sid = task_session(current);
	sj->sj_session = get_pid(sid);
	strncpy(sj->sj_jobid, jobid, len+1);
	origsj = rhashtable_lookup_get_insert_fast(&session_jobids,
						   &sj->sj_linkage,
						   jobid_params);
	if (!origsj) {
		/* successful insert */
		rcu_read_unlock();
		jobid_prune_expedite();
		return 0;
	}

	if (IS_ERR(origsj)) {
		put_pid(sj->sj_session);
		kfree(sj);
		rcu_read_unlock();
		return PTR_ERR(origsj);
	}
	ret = rhashtable_replace_fast(&session_jobids,
				      &origsj->sj_linkage,
				      &sj->sj_linkage,
				      jobid_params);
	if (ret) {
		put_pid(sj->sj_session);
		kfree(sj);
		rcu_read_unlock();
		return ret;
	}
	put_pid(origsj->sj_session);
	rcu_read_unlock();
	kfree_rcu(origsj, sj_rcu);
	jobid_prune_expedite();

	return 0;
}

static void jobid_free(void *vsj, void *arg)
{
	struct session_jobid *sj = vsj;

	put_pid(sj->sj_session);
	kfree(sj);
}

static void jobid_prune(struct work_struct *work);
static DECLARE_DELAYED_WORK(jobid_prune_work, jobid_prune);
static int jobid_prune_expedited;
static void jobid_prune(struct work_struct *work)
{
	int remaining = 0;
	struct rhashtable_iter iter;
	struct session_jobid *sj;

	jobid_prune_expedited = 0;
	rhashtable_walk_enter(&session_jobids, &iter);
	rhashtable_walk_start(&iter);
	while ((sj = rhashtable_walk_next(&iter)) != NULL) {
		if (!hlist_empty(&sj->sj_session->tasks[PIDTYPE_SID])) {
			remaining++;
			continue;
		}
		if (rhashtable_remove_fast(&session_jobids,
					   &sj->sj_linkage,
					   jobid_params) == 0) {
			put_pid(sj->sj_session);
			kfree_rcu(sj, sj_rcu);
		}
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	if (remaining)
		schedule_delayed_work(&jobid_prune_work,
				      JOBID_BACKGROUND_CLEAN * HZ);
}

static void jobid_prune_expedite(void)
{
	if (!jobid_prune_expedited) {
		jobid_prune_expedited = 1;
		mod_delayed_work(system_wq, &jobid_prune_work,
				 JOBID_EXPEDITED_CLEAN * HZ);
	}
}

/* Get jobid of current process from stored variable or calculate
 * it from pid and user_id.
 *
 * Historically this was also done by reading the environment variable
 * stored in between the "env_start" & "env_end" of task struct.
 * This is now deprecated.
 */

/*
 * jobid_interpret_string()
 *
 * Interpret the jobfmt string to expand specified fields, like coredumps do:
 *   %e = executable
 *   %g = gid
 *   %h = hostname
 *   %j = jobid from environment
 *   %p = pid
 *   %u = uid
 *
 * Unknown escape strings are dropped.  Other characters are copied through,
 * excluding whitespace (to avoid making jobid parsing difficult).
 *
 * Return: -EOVERFLOW if the expanded string does not fit within @joblen
 *         0 for success
 */
static int jobid_interpret_string(const char *jobfmt, char *jobid,
				  ssize_t joblen)
{
	char c;

	while ((c = *jobfmt++) && joblen > 1) {
		char f;
		int l;

		if (isspace(c)) /* Don't allow embedded spaces */
			continue;

		if (c != '%') {
			*jobid = c;
			joblen--;
			jobid++;
			continue;
		}

		switch ((f = *jobfmt++)) {
		case 'e': /* executable name */
			l = snprintf(jobid, joblen, "%s", current->comm);
			break;
		case 'g': /* group ID */
			l = snprintf(jobid, joblen, "%u",
				     from_kgid(&init_user_ns, current_fsgid()));
			break;
		case 'h': /* hostname */
			l = snprintf(jobid, joblen, "%s",
				     init_utsname()->nodename);
			break;
		case 'j': /* jobid requested by process
			   * - currently not supported
			   */
			l = snprintf(jobid, joblen, "%s", "jobid");
			break;
		case 'p': /* process ID */
			l = snprintf(jobid, joblen, "%u", current->pid);
			break;
		case 'u': /* user ID */
			l = snprintf(jobid, joblen, "%u",
				     from_kuid(&init_user_ns, current_fsuid()));
			break;
		case '\0': /* '%' at end of format string */
			l = 0;
			goto out;
		default: /* drop unknown %x format strings */
			l = 0;
			break;
		}
		jobid += l;
		joblen -= l;
	}
	/*
	 * This points at the end of the buffer, so long as jobid is always
	 * incremented the same amount as joblen is decremented.
	 */
out:
	jobid[joblen - 1] = '\0';

	return joblen < 0 ? -EOVERFLOW : 0;
}

/**
 * Generate the job identifier string for this process for tracking purposes.
 *
 * Fill in @jobid string based on the value of obd_jobid_var:
 * JOBSTATS_DISABLE:	  none
 * JOBSTATS_NODELOCAL:	  content of obd_jobid_name (jobid_interpret_string())
 * JOBSTATS_PROCNAME_UID: process name/UID
 * JOBSTATS_SESSION	  per-session value set by
 *			  /sys/fs/lustre/jobid_this_session
 *
 * Return -ve error number, 0 on success.
 */
int lustre_get_jobid(char *jobid, size_t joblen)
{
	char tmp_jobid[LUSTRE_JOBID_SIZE] = "";

	if (unlikely(joblen < 2)) {
		if (joblen == 1)
			jobid[0] = '\0';
		return -EINVAL;
	}

	/* Jobstats isn't enabled */
	if (strcmp(obd_jobid_var, JOBSTATS_DISABLE) == 0)
		goto out_cache_jobid;

	/* Whole node dedicated to single job */
	if (strcmp(obd_jobid_var, JOBSTATS_NODELOCAL) == 0) {
		int rc2 = jobid_interpret_string(obd_jobid_name,
						 tmp_jobid, joblen);
		if (!rc2)
			goto out_cache_jobid;
	}

	/* Use process name + fsuid as jobid */
	if (strcmp(obd_jobid_var, JOBSTATS_PROCNAME_UID) == 0) {
		snprintf(tmp_jobid, LUSTRE_JOBID_SIZE, "%s.%u",
			 current->comm,
			 from_kuid(&init_user_ns, current_fsuid()));
		goto out_cache_jobid;
	}

	if (strcmp(obd_jobid_var, JOBSTATS_SESSION) == 0) {
		char *jid;

		rcu_read_lock();
		jid = jobid_current();
		if (jid)
			strlcpy(jobid, jid, sizeof(jobid));
		rcu_read_unlock();
		goto out_cache_jobid;
	}

	return -ENOENT;

out_cache_jobid:
	/* Only replace the job ID if it changed. */
	if (strcmp(jobid, tmp_jobid) != 0)
		strcpy(jobid, tmp_jobid);

	return 0;
}
EXPORT_SYMBOL(lustre_get_jobid);

int jobid_cache_init(void)
{
	return rhashtable_init(&session_jobids, &jobid_params);
}

void jobid_cache_fini(void)
{
	cancel_delayed_work_sync(&jobid_prune_work);

	rhashtable_free_and_destroy(&session_jobids, jobid_free, NULL);
}
