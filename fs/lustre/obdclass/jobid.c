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

int lustre_get_jobid(char *jobid, size_t joblen)
{
	char tmp_jobid[LUSTRE_JOBID_SIZE] = "";

	/* Jobstats isn't enabled */
	if (strcmp(obd_jobid_var, JOBSTATS_DISABLE) == 0)
		goto out_cache_jobid;

	/* Use process name + fsuid as jobid */
	if (strcmp(obd_jobid_var, JOBSTATS_PROCNAME_UID) == 0) {
		snprintf(tmp_jobid, LUSTRE_JOBID_SIZE, "%s.%u",
			 current->comm,
			 from_kuid(&init_user_ns, current_fsuid()));
		goto out_cache_jobid;
	}

	/* Whole node dedicated to single job */
	if (strcmp(obd_jobid_var, JOBSTATS_NODELOCAL) == 0) {
		int rc2 = jobid_interpret_string(obd_jobid_name,
						 tmp_jobid, joblen);
		if (!rc2)
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
