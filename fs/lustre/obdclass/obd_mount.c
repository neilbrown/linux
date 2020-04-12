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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/obd_mount.c
 *
 * Client mount routines
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS
#define D_MOUNT (D_SUPER | D_CONFIG/*|D_WARNING */)
#define PRINT_CMD CDEBUG

#include <linux/random.h>
#include <obd.h>
#include <obd_class.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_log.h>
#include <lustre_disk.h>
#include <uapi/linux/lustre/lustre_param.h>

/**************** config llog ********************/

/** Get a config log from the MGS and process it.
 * This func is called for both clients and servers.
 * Continue to process new statements appended to the logs
 * (whenever the config lock is revoked) until lustre_end_log
 * is called.
 * @sb:		The superblock is used by the MGC to write to the local copy of
 *		the config log
 * @logname:	The name of the llog to replicate from the MGS
 * @cfg:	Since the same mgc may be used to follow multiple config logs
 *		(e.g. ost1, ost2, client), the config_llog_instance keeps the
 *		state for this log, and is added to the mgc's list of logs to
 *		follow.
 */
int lustre_process_log(struct super_block *sb, char *logname,
		       struct config_llog_instance *cfg)
{
	struct lustre_cfg *lcfg;
	struct lustre_cfg_bufs *bufs;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *mgc = lsi->lsi_mgc;
	int rc;

	LASSERT(mgc);
	LASSERT(cfg);

	bufs = kzalloc(sizeof(*bufs), GFP_NOFS);
	if (!bufs)
		return -ENOMEM;

	/* mgc_process_config */
	lustre_cfg_bufs_reset(bufs, mgc->obd_name);
	lustre_cfg_bufs_set_string(bufs, 1, logname);
	lustre_cfg_bufs_set(bufs, 2, cfg, sizeof(*cfg));
	lustre_cfg_bufs_set(bufs, 3, &sb, sizeof(sb));
	lcfg = kzalloc(lustre_cfg_len(bufs->lcfg_bufcount, bufs->lcfg_buflen),
		       GFP_NOFS);
	if (!lcfg) {
		rc = -ENOMEM;
		goto out;
	}
	lustre_cfg_init(lcfg, LCFG_LOG_START, bufs);

	rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
	kfree(lcfg);
out:
	kfree(bufs);

	if (rc == -EINVAL)
		LCONSOLE_ERROR_MSG(0x15b, "%s: The configuration from log '%s' failed from the MGS (%d).  Make sure this client and the MGS are running compatible versions of Lustre.\n",
				   mgc->obd_name, logname, rc);

	else if (rc)
		LCONSOLE_ERROR_MSG(0x15c, "%s: The configuration from log '%s' failed (%d). This may be the result of communication errors between this node and the MGS, a bad configuration, or other errors. See the syslog for more information.\n",
				   mgc->obd_name, logname,
				   rc);

	/* class_obd_list(); */
	return rc;
}
EXPORT_SYMBOL(lustre_process_log);

/* Stop watching this config log for updates */
int lustre_end_log(struct super_block *sb, char *logname,
		   struct config_llog_instance *cfg)
{
	struct lustre_cfg *lcfg;
	struct lustre_cfg_bufs bufs;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *mgc = lsi->lsi_mgc;
	int rc;

	if (!mgc)
		return -ENOENT;

	/* mgc_process_config */
	lustre_cfg_bufs_reset(&bufs, mgc->obd_name);
	lustre_cfg_bufs_set_string(&bufs, 1, logname);
	if (cfg)
		lustre_cfg_bufs_set(&bufs, 2, cfg, sizeof(*cfg));
	lcfg = kzalloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen),
		       GFP_NOFS);
	if (!lcfg)
		return -ENOMEM;
	lustre_cfg_init(lcfg, LCFG_LOG_END, &bufs);

	rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
	kfree(lcfg);
	return rc;
}
EXPORT_SYMBOL(lustre_end_log);

/**************** obd start *******************/

/** lustre_cfg_bufs are a holdover from 1.4; we can still set these up from
 * lctl (and do for echo cli/srv.
 */
static int do_lcfg(char *cfgname, lnet_nid_t nid, int cmd,
		   char *s1, char *s2, char *s3, char *s4)
{
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg = NULL;
	int rc;

	CDEBUG(D_TRACE, "lcfg %s %#x %s %s %s %s\n", cfgname,
	       cmd, s1, s2, s3, s4);

	lustre_cfg_bufs_reset(&bufs, cfgname);
	if (s1)
		lustre_cfg_bufs_set_string(&bufs, 1, s1);
	if (s2)
		lustre_cfg_bufs_set_string(&bufs, 2, s2);
	if (s3)
		lustre_cfg_bufs_set_string(&bufs, 3, s3);
	if (s4)
		lustre_cfg_bufs_set_string(&bufs, 4, s4);

	lcfg = kzalloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen),
		       GFP_NOFS);
	if (!lcfg)
		return -ENOMEM;
	lustre_cfg_init(lcfg, cmd, &bufs);
	lcfg->lcfg_nid = nid;
	rc = class_process_config(lcfg);
	kfree(lcfg);
	return rc;
}

/** Call class_attach and class_setup.  These methods in turn call
 * obd type-specific methods.
 */
static int lustre_start_simple(char *obdname, char *type, char *uuid,
			       char *s1, char *s2, char *s3, char *s4)
{
	int rc;

	CDEBUG(D_MOUNT, "Starting obd %s (typ=%s)\n", obdname, type);

	rc = do_lcfg(obdname, 0, LCFG_ATTACH, type, uuid, NULL, NULL);
	if (rc) {
		CERROR("%s attach error %d\n", obdname, rc);
		return rc;
	}
	rc = do_lcfg(obdname, 0, LCFG_SETUP, s1, s2, s3, s4);
	if (rc) {
		CERROR("%s setup error %d\n", obdname, rc);
		do_lcfg(obdname, 0, LCFG_DETACH, NULL, NULL, NULL, NULL);
	}
	return rc;
}

static DEFINE_MUTEX(mgc_start_lock);

/** Set up a mgc obd to process startup logs
 *
 * @sb:		super block of the mgc obd
 *
 * Returns:	0 success, otherwise error code
 */
int lustre_start_mgc(struct super_block *sb)
{
	struct obd_connect_data *data = NULL;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *obd;
	struct obd_export *exp;
	struct obd_uuid *uuid = NULL;
	uuid_t uuidc;
	lnet_nid_t nid;
	char nidstr[LNET_NIDSTR_SIZE];
	char *mgcname = NULL, *niduuid = NULL, *mgssec = NULL;
	char *ptr;
	int rc = 0, i = 0, j;

	LASSERT(lsi->lsi_lmd);

	/* Use nids from mount line: uml1,1@elan:uml2,2@elan:/lustre */
	ptr = lsi->lsi_lmd->lmd_dev;
	if (class_parse_nid(ptr, &nid, &ptr) == 0)
		i++;
	if (i == 0) {
		CERROR("No valid MGS nids found.\n");
		return -EINVAL;
	}

	mutex_lock(&mgc_start_lock);

	libcfs_nid2str_r(nid, nidstr, sizeof(nidstr));
	mgcname = kasprintf(GFP_NOFS,
			    "%s%s", LUSTRE_MGC_OBDNAME, nidstr);
	niduuid = kasprintf(GFP_NOFS, "%s_%x", mgcname, 0);
	if (!mgcname || !niduuid) {
		rc = -ENOMEM;
		goto out_free;
	}

	mgssec = lsi->lsi_lmd->lmd_mgssec ? lsi->lsi_lmd->lmd_mgssec : "";

	data = kzalloc(sizeof(*data), GFP_NOFS);
	if (!data) {
		rc = -ENOMEM;
		goto out_free;
	}

	obd = class_name2obd(mgcname);
	if (obd && !obd->obd_stopping) {
		int recov_bk;

		rc = obd_set_info_async(NULL, obd->obd_self_export,
					strlen(KEY_MGSSEC), KEY_MGSSEC,
					strlen(mgssec), mgssec, NULL);
		if (rc)
			goto out_free;

		/* Re-using an existing MGC */
		atomic_inc(&obd->u.cli.cl_mgc_refcount);

		/* IR compatibility check, only for clients */
		if (lmd_is_client(lsi->lsi_lmd)) {
			int has_ir;
			int vallen = sizeof(*data);
			u32 *flags = &lsi->lsi_lmd->lmd_flags;

			rc = obd_get_info(NULL, obd->obd_self_export,
					  strlen(KEY_CONN_DATA), KEY_CONN_DATA,
					  &vallen, data);
			LASSERT(rc == 0);
			has_ir = OCD_HAS_FLAG(data, IMP_RECOV);
			if (has_ir ^ !(*flags & LMD_FLG_NOIR)) {
				/* LMD_FLG_NOIR is for test purpose only */
				LCONSOLE_WARN(
					"Trying to mount a client with IR setting not compatible with current mgc. Force to use current mgc setting that is IR %s.\n",
					has_ir ? "enabled" : "disabled");
				if (has_ir)
					*flags &= ~LMD_FLG_NOIR;
				else
					*flags |= LMD_FLG_NOIR;
			}
		}

		recov_bk = 0;

		/* Try all connections, but only once (again).
		 * We don't want to block another target from starting
		 * (using its local copy of the log), but we do want to connect
		 * if at all possible.
		 */
		recov_bk++;
		CDEBUG(D_MOUNT, "%s: Set MGC reconnect %d\n", mgcname,
		       recov_bk);
		rc = obd_set_info_async(NULL, obd->obd_self_export,
					sizeof(KEY_INIT_RECOV_BACKUP),
					KEY_INIT_RECOV_BACKUP,
					sizeof(recov_bk), &recov_bk, NULL);
		rc = 0;
		goto out;
	}

	CDEBUG(D_MOUNT, "Start MGC '%s'\n", mgcname);

	/* Add the primary nids for the MGS */
	i = 0;
	/* Use nids from mount line: uml1,1@elan:uml2,2@elan:/lustre */
	ptr = lsi->lsi_lmd->lmd_dev;
	while (class_parse_nid(ptr, &nid, &ptr) == 0) {
		rc = do_lcfg(mgcname, nid,
			     LCFG_ADD_UUID, niduuid, NULL, NULL, NULL);
		if (!rc)
			i++;
		/* Stop at the first failover nid */
		if (*ptr == ':')
			break;
	}
	if (i == 0) {
		CERROR("No valid MGS nids found.\n");
		rc = -EINVAL;
		goto out_free;
	}
	lsi->lsi_lmd->lmd_mgs_failnodes = 1;

	/* Random uuid for MGC allows easier reconnects */
	uuid = kzalloc(sizeof(*uuid), GFP_NOFS);
	if (!uuid) {
		rc = -ENOMEM;
		goto out_free;
	}

	generate_random_uuid(uuidc.b);
	snprintf(uuid->uuid, sizeof(*uuid), "%pU", uuidc.b);

	/* Start the MGC */
	rc = lustre_start_simple(mgcname, LUSTRE_MGC_NAME,
				 (char *)uuid->uuid, LUSTRE_MGS_OBDNAME,
				 niduuid, NULL, NULL);
	if (rc)
		goto out_free;

	/* Add any failover MGS nids */
	i = 1;
	while (ptr && ((*ptr == ':' ||
			class_find_param(ptr, PARAM_MGSNODE, &ptr) == 0))) {
		/* New failover node */
		sprintf(niduuid, "%s_%x", mgcname, i);
		j = 0;
		while (class_parse_nid_quiet(ptr, &nid, &ptr) == 0) {
			rc = do_lcfg(mgcname, nid, LCFG_ADD_UUID, niduuid,
				     NULL, NULL, NULL);
			if (!rc)
				++j;
			if (*ptr == ':')
				break;
		}
		if (j > 0) {
			rc = do_lcfg(mgcname, 0, LCFG_ADD_CONN,
				     niduuid, NULL, NULL, NULL);
			if (!rc)
				i++;
		} else {
			/* at ":/fsname" */
			break;
		}
	}
	lsi->lsi_lmd->lmd_mgs_failnodes = i;

	obd = class_name2obd(mgcname);
	if (!obd) {
		CERROR("Can't find mgcobd %s\n", mgcname);
		rc = -ENOTCONN;
		goto out_free;
	}

	rc = obd_set_info_async(NULL, obd->obd_self_export,
				strlen(KEY_MGSSEC), KEY_MGSSEC,
				strlen(mgssec), mgssec, NULL);
	if (rc)
		goto out_free;

	/* Keep a refcount of servers/clients who started with "mount",
	 * so we know when we can get rid of the mgc.
	 */
	atomic_set(&obd->u.cli.cl_mgc_refcount, 1);

	/* We connect to the MGS at setup, and don't disconnect until cleanup */
	data->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_AT |
				  OBD_CONNECT_FULL20 | OBD_CONNECT_IMP_RECOV |
				  OBD_CONNECT_LVB_TYPE | OBD_CONNECT_BULK_MBITS;

	if (lmd_is_client(lsi->lsi_lmd) &&
	    lsi->lsi_lmd->lmd_flags & LMD_FLG_NOIR)
		data->ocd_connect_flags &= ~OBD_CONNECT_IMP_RECOV;
	data->ocd_version = LUSTRE_VERSION_CODE;
	rc = obd_connect(NULL, &exp, obd, uuid, data, NULL);
	if (rc) {
		CERROR("connect failed %d\n", rc);
		goto out;
	}

	obd->u.cli.cl_mgc_mgsexp = exp;

out:
	/* Keep the mgc info in the sb. Note that many lsi's can point
	 * to the same mgc.
	 */
	lsi->lsi_mgc = obd;
out_free:
	mutex_unlock(&mgc_start_lock);

	kfree(uuid);
	kfree(data);
	kfree(mgcname);
	kfree(niduuid);
	return rc;
}
EXPORT_SYMBOL(lustre_start_mgc);

static int lustre_stop_mgc(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *obd;
	char *niduuid = NULL, *ptr = NULL;
	int i, rc = 0, len = 0;

	if (!lsi)
		return -ENOENT;
	obd = lsi->lsi_mgc;
	if (!obd)
		return -ENOENT;
	lsi->lsi_mgc = NULL;

	mutex_lock(&mgc_start_lock);
	LASSERT(atomic_read(&obd->u.cli.cl_mgc_refcount) > 0);
	if (!atomic_dec_and_test(&obd->u.cli.cl_mgc_refcount)) {
		/* This is not fatal, every client that stops
		 * will call in here.
		 */
		CDEBUG(D_MOUNT, "mgc still has %d references.\n",
		       atomic_read(&obd->u.cli.cl_mgc_refcount));
		rc = -EBUSY;
		goto out;
	}

	/* The MGC has no recoverable data in any case.
	 * force shutdown set in umount_begin
	 */
	obd->obd_no_recov = 1;

	if (obd->u.cli.cl_mgc_mgsexp) {
		/* An error is not fatal, if we are unable to send the
		 * disconnect mgs ping evictor cleans up the export
		 */
		rc = obd_disconnect(obd->u.cli.cl_mgc_mgsexp);
		if (rc)
			CDEBUG(D_MOUNT, "disconnect failed %d\n", rc);
	}

	/* Save the obdname for cleaning the nid uuids, which are obdname_XX */
	len = strlen(obd->obd_name) + 6;
	niduuid = kzalloc(len, GFP_NOFS);
	if (niduuid) {
		strcpy(niduuid, obd->obd_name);
		ptr = niduuid + strlen(niduuid);
	}

	rc = class_manual_cleanup(obd);
	if (rc)
		goto out;

	/* Clean the nid uuids */
	if (!niduuid) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < lsi->lsi_lmd->lmd_mgs_failnodes; i++) {
		sprintf(ptr, "_%x", i);
		rc = do_lcfg(LUSTRE_MGC_OBDNAME, 0, LCFG_DEL_UUID,
			     niduuid, NULL, NULL, NULL);
		if (rc)
			CERROR("del MDC UUID %s failed: rc = %d\n",
			       niduuid, rc);
	}
out:
	kfree(niduuid);

	/* class_import_put will get rid of the additional connections */
	mutex_unlock(&mgc_start_lock);
	return rc;
}

/***************** lustre superblock **************/

struct lustre_sb_info *lustre_init_lsi(struct super_block *sb)
{
	struct lustre_sb_info *lsi;

	lsi = kzalloc(sizeof(*lsi), GFP_NOFS);
	if (!lsi)
		return NULL;
	lsi->lsi_lmd = kzalloc(sizeof(*lsi->lsi_lmd), GFP_NOFS);
	if (!lsi->lsi_lmd) {
		kfree(lsi);
		return NULL;
	}

	s2lsi_nocast(sb) = lsi;
	/* we take 1 extra ref for our setup */
	atomic_set(&lsi->lsi_mounts, 1);

	/* Default umount style */
	lsi->lsi_flags = LSI_UMOUNT_FAILOVER;

	return lsi;
}
EXPORT_SYMBOL(lustre_init_lsi);

static int lustre_free_lsi(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);

	CDEBUG(D_MOUNT, "Freeing lsi %p\n", lsi);

	/* someone didn't call server_put_mount. */
	LASSERT(atomic_read(&lsi->lsi_mounts) == 0);

	if (lsi->lsi_lmd) {
		kfree(lsi->lsi_lmd->lmd_dev);
		kfree(lsi->lsi_lmd->lmd_profile);
		kfree(lsi->lsi_lmd->lmd_fileset);
		kfree(lsi->lsi_lmd->lmd_mgssec);
		kfree(lsi->lsi_lmd->lmd_opts);
		kfree(lsi->lsi_lmd->lmd_exclude);
		kfree(lsi->lsi_lmd->lmd_mgs);
		kfree(lsi->lsi_lmd->lmd_osd_type);
		kfree(lsi->lsi_lmd->lmd_params);
		kfree(lsi->lsi_lmd->lmd_nidnet);

		kfree(lsi->lsi_lmd);
	}

	LASSERT(!lsi->lsi_llsbi);
	kfree(lsi);
	s2lsi_nocast(sb) = NULL;

	return 0;
}

/* The lsi has one reference for every server that is using the disk -
 * e.g. MDT, MGS, and potentially MGC
 */
int lustre_put_lsi(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);

	CDEBUG(D_MOUNT, "put %p %d\n", sb, atomic_read(&lsi->lsi_mounts));
	if (atomic_dec_and_test(&lsi->lsi_mounts)) {
		lustre_free_lsi(sb);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL(lustre_put_lsi);

/*** SERVER NAME ***
 * <FSNAME><SEPARATOR><TYPE><INDEX>
 * FSNAME is between 1 and 8 characters (inclusive).
 *	Excluded characters are '/' and ':'
 * SEPARATOR is either ':' or '-'
 * TYPE: "OST", "MDT", etc.
 * INDEX: Hex representation of the index
 */

/** Get the fsname ("lustre") from the server name ("lustre-OST003F").
 *
 * @svname:	server name including type and index
 * @fsname:	Buffer to copy filesystem name prefix into.
 *		Must have at least 'strlen(fsname) + 1' chars.
 * @endptr:	if endptr isn't NULL it is set to end of fsname
 *
 * Returns:	rc < 0  on error
 */
int server_name2fsname(const char *svname, char *fsname,
		       const char **endptr)
{
	const char *dash;

	dash = svname + strnlen(svname, LUSTRE_MAXFSNAME);
	for (; dash > svname && *dash != '-' && *dash != ':'; dash--)
		;
	if (dash == svname)
		return -EINVAL;

	if (fsname) {
		strncpy(fsname, svname, dash - svname);
		fsname[dash - svname] = '\0';
	}

	if (endptr)
		*endptr = dash;

	return 0;
}
EXPORT_SYMBOL(server_name2fsname);

/* Get the index from the obd name.
 *  rc = server type, or
 * rc < 0  on error
 * if endptr isn't NULL it is set to end of name
 */
static int server_name2index(const char *svname, u32 *idx,
			     const char **endptr)
{
	unsigned long index;
	int rc;
	const char *dash;

	/* We use server_name2fsname() just for parsing */
	rc = server_name2fsname(svname, NULL, &dash);
	if (rc != 0)
		return rc;

	dash++;

	if (strncmp(dash, "MDT", 3) == 0)
		rc = LDD_F_SV_TYPE_MDT;
	else if (strncmp(dash, "OST", 3) == 0)
		rc = LDD_F_SV_TYPE_OST;
	else
		return -EINVAL;

	dash += 3;

	if (strncmp(dash, "all", 3) == 0) {
		if (endptr)
			*endptr = dash + 3;
		return rc | LDD_F_SV_ALL;
	}

	index = simple_strtoul(dash, (char **)endptr, 16);
	if (idx)
		*idx = index;

	/* Account for -mdc after index that is possible when specifying mdt */
	if (endptr && strncmp(LUSTRE_MDC_NAME, *endptr + 1,
			      sizeof(LUSTRE_MDC_NAME) - 1) == 0)
		*endptr += sizeof(LUSTRE_MDC_NAME);

	return rc;
}

/*************** mount common between server and client ***************/

/* Common umount */
int lustre_common_put_super(struct super_block *sb)
{
	int rc;

	CDEBUG(D_MOUNT, "dropping sb %p\n", sb);

	/* Drop a ref to the MGC */
	rc = lustre_stop_mgc(sb);
	if (rc && (rc != -ENOENT)) {
		if (rc != -EBUSY) {
			CERROR("Can't stop MGC: %d\n", rc);
			return rc;
		}
		/* BUSY just means that there's some other obd that
		 * needs the mgc.  Let him clean it up.
		 */
		CDEBUG(D_MOUNT, "MGC still in use\n");
	}
	/* Drop a ref to the mounted disk */
	lustre_put_lsi(sb);
	return rc;
}
EXPORT_SYMBOL(lustre_common_put_super);

static void lmd_print(struct lustre_mount_data *lmd)
{
	int i;

	PRINT_CMD(D_MOUNT, "  mount data:\n");
	if (lmd_is_client(lmd))
		PRINT_CMD(D_MOUNT, "profile: %s\n", lmd->lmd_profile);
	PRINT_CMD(D_MOUNT, "device:  %s\n", lmd->lmd_dev);
	PRINT_CMD(D_MOUNT, "flags:   %x\n", lmd->lmd_flags);

	if (lmd->lmd_opts)
		PRINT_CMD(D_MOUNT, "options: %s\n", lmd->lmd_opts);

	if (lmd->lmd_recovery_time_soft)
		PRINT_CMD(D_MOUNT, "recovery time soft: %d\n",
			  lmd->lmd_recovery_time_soft);

	if (lmd->lmd_recovery_time_hard)
		PRINT_CMD(D_MOUNT, "recovery time hard: %d\n",
			  lmd->lmd_recovery_time_hard);

	for (i = 0; i < lmd->lmd_exclude_count; i++) {
		PRINT_CMD(D_MOUNT, "exclude %d:  OST%04x\n", i,
			  lmd->lmd_exclude[i]);
	}
}

/* Is this server on the exclusion list */
int lustre_check_exclusion(struct super_block *sb, char *svname)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct lustre_mount_data *lmd = lsi->lsi_lmd;
	u32 index;
	int i, rc;

	rc = server_name2index(svname, &index, NULL);
	if (rc != LDD_F_SV_TYPE_OST)
		/* Only exclude OSTs */
		return 0;

	CDEBUG(D_MOUNT, "Check exclusion %s (%d) in %d of %s\n", svname,
	       index, lmd->lmd_exclude_count, lmd->lmd_dev);

	for (i = 0; i < lmd->lmd_exclude_count; i++) {
		if (index == lmd->lmd_exclude[i]) {
			CWARN("Excluding %s (on exclusion list)\n", svname);
			return 1;
		}
	}
	return 0;
}

/* mount -v  -o exclude=lustre-OST0001:lustre-OST0002 -t lustre ... */
static int lmd_make_exclusion(struct lustre_mount_data *lmd, const char *ptr)
{
	const char *s1 = ptr, *s2;
	u32 index = 0, *exclude_list;
	int rc = 0, devmax;

	/* The shortest an ost name can be is 8 chars: -OST0000.
	 * We don't actually know the fsname at this time, so in fact
	 * a user could specify any fsname.
	 */
	devmax = strlen(ptr) / 8 + 1;

	/* temp storage until we figure out how many we have */
	exclude_list = kcalloc(devmax, sizeof(index), GFP_NOFS);
	if (!exclude_list)
		return -ENOMEM;

	/* we enter this fn pointing at the '=' */
	while (*s1 && *s1 != ' ' && *s1 != ',') {
		s1++;
		rc = server_name2index(s1, &index, &s2);
		if (rc < 0) {
			CERROR("Can't parse server name '%s': rc = %d\n",
			       s1, rc);
			break;
		}
		if (rc == LDD_F_SV_TYPE_OST)
			exclude_list[lmd->lmd_exclude_count++] = index;
		else
			CDEBUG(D_MOUNT, "ignoring exclude %.*s: type = %#x\n",
			       (uint)(s2 - s1), s1, rc);
		s1 = s2;
		/* now we are pointing at ':' (next exclude)
		 * or ',' (end of excludes)
		 */
		if (lmd->lmd_exclude_count >= devmax)
			break;
	}
	if (rc >= 0) /* non-err */
		rc = 0;

	if (lmd->lmd_exclude_count) {
		/* permanent, freed in lustre_free_lsi */
		lmd->lmd_exclude = kcalloc(lmd->lmd_exclude_count,
					   sizeof(index), GFP_NOFS);
		if (lmd->lmd_exclude) {
			memcpy(lmd->lmd_exclude, exclude_list,
			       sizeof(index) * lmd->lmd_exclude_count);
		} else {
			rc = -ENOMEM;
			lmd->lmd_exclude_count = 0;
		}
	}
	kfree(exclude_list);
	return rc;
}

static int lmd_parse_mgssec(struct lustre_mount_data *lmd, char *ptr)
{
	char *tail;
	int length;

	kfree(lmd->lmd_mgssec);
	lmd->lmd_mgssec = NULL;

	tail = strchr(ptr, ',');
	if (!tail)
		length = strlen(ptr);
	else
		length = tail - ptr;

	lmd->lmd_mgssec = kzalloc(length + 1, GFP_NOFS);
	if (!lmd->lmd_mgssec)
		return -ENOMEM;

	memcpy(lmd->lmd_mgssec, ptr, length);
	lmd->lmd_mgssec[length] = '\0';
	return 0;
}

static int lmd_parse_network(struct lustre_mount_data *lmd, char *ptr)
{
	char *tail;
	int length;

	kfree(lmd->lmd_nidnet);
	lmd->lmd_nidnet = NULL;

	tail = strchr(ptr, ',');
	if (!tail)
		length = strlen(ptr);
	else
		length = tail - ptr;

	lmd->lmd_nidnet = kstrndup(ptr, length, GFP_KERNEL);
	if (!lmd->lmd_nidnet)
		return -ENOMEM;

	return 0;
}

static int lmd_parse_string(char **handle, char *ptr)
{
	char *tail;
	int length;

	if (!handle || !ptr)
		return -EINVAL;

	kfree(*handle);
	*handle = NULL;

	tail = strchr(ptr, ',');
	if (!tail)
		length = strlen(ptr);
	else
		length = tail - ptr;

	*handle = kzalloc(length + 1, GFP_NOFS);
	if (!*handle)
		return -ENOMEM;

	memcpy(*handle, ptr, length);
	(*handle)[length] = '\0';

	return 0;
}

/* Collect multiple values for mgsnid specifiers */
static int lmd_parse_mgs(struct lustre_mount_data *lmd, char **ptr)
{
	lnet_nid_t nid;
	char *tail = *ptr;
	char *mgsnid;
	int length;
	int oldlen = 0;

	/* Find end of nidlist */
	while (class_parse_nid_quiet(tail, &nid, &tail) == 0)
		;
	length = tail - *ptr;
	if (length == 0) {
		LCONSOLE_ERROR_MSG(0x159, "Can't parse NID '%s'\n", *ptr);
		return -EINVAL;
	}

	if (lmd->lmd_mgs)
		oldlen = strlen(lmd->lmd_mgs) + 1;

	mgsnid = kzalloc(oldlen + length + 1, GFP_NOFS);
	if (!mgsnid)
		return -ENOMEM;

	if (lmd->lmd_mgs) {
		/* Multiple mgsnid= are taken to mean failover locations */
		memcpy(mgsnid, lmd->lmd_mgs, oldlen);
		mgsnid[oldlen - 1] = ':';
		kfree(lmd->lmd_mgs);
	}
	memcpy(mgsnid + oldlen, *ptr, length);
	mgsnid[oldlen + length] = '\0';
	lmd->lmd_mgs = mgsnid;
	*ptr = tail;

	return 0;
}

/**
 * Find the first delimiter (comma or colon) from the specified @buf and
 * make @*endh point to the string starting with the delimiter. The commas
 * in expression list [...] will be skipped.
 *
 * @buf		a delimiter-separated string
 * @endh	a pointer to a pointer that will point to the string
 *		starting with the delimiter
 *
 * Returns:	true if delimiter is found, false if delimiter is not found
 */
static bool lmd_find_delimiter(char *buf, char **endh)
{
	char *c = buf;
	size_t pos;
	bool found;

	if (!buf)
		return false;
try_again:
	if (*c == ',' || *c == ':')
		return true;

	pos = strcspn(c, "[:,]");
	if (!pos)
		return false;

	/* Not a valid mount string */
	if (*c == ']') {
		CWARN("invalid mount string format\n");
		return false;
	}

	c += pos;
	if (*c == '[') {
		c = strchr(c, ']');

		/* invalid mount string */
		if (!c) {
			CWARN("invalid mount string format\n");
			return false;
		}
		c++;
		goto try_again;
	}

	found = *c != '\0';
	if (found && endh)
		*endh = c;

	return found;
}

/**
 * Find the first valid string delimited by comma or colon from the specified
 * @buf and parse it to see whether it's a valid nid list. If yes, @*endh
 * will point to the next string starting with the delimiter.
 *
 * @buf:	a delimiter-separated string
 * @endh:	a pointer to a pointer that will point to the string
 *		starting with the delimiter
 *
 * Returns:	0	if the string is a valid nid list
 *		1	if the string is not a valid nid list
 */
static int lmd_parse_nidlist(char *buf, char **endh)
{
	LIST_HEAD(nidlist);
	char *endp = buf;
	int rc = 0;
	char tmp;

	if (!buf)
		return 1;
	while (*buf == ',' || *buf == ':')
		buf++;
	if (*buf == ' ' || *buf == '/' || *buf == '\0')
		return 1;

	if (!lmd_find_delimiter(buf, &endp))
		endp = buf + strlen(buf);

	tmp = *endp;
	*endp = '\0';

	if (cfs_parse_nidlist(buf, strlen(buf), &nidlist) <= 0)
		rc = 1;
	cfs_free_nidlist(&nidlist);

	*endp = tmp;
	if (rc)
		return rc;
	if (endh)
		*endh = endp;
	return 0;
}

/** Parse mount line options
 * e.g. mount -v -t lustre -o abort_recov uml1:uml2:/lustre-client /mnt/lustre
 * dev is passed as device=uml1:/lustre by mount.lustre
 */
int lmd_parse(char *options, struct lustre_mount_data *lmd)
{
	char *s1, *s2, *devname = NULL;
	struct lustre_mount_data *raw = (struct lustre_mount_data *)options;
	int rc = 0;

	LASSERT(lmd);
	if (!options) {
		LCONSOLE_ERROR_MSG(0x162, "Missing mount data: check that /sbin/mount.lustre is installed.\n");
		return -EINVAL;
	}

	/* Options should be a string - try to detect old lmd data */
	if ((raw->lmd_magic & 0xffffff00) == (LMD_MAGIC & 0xffffff00)) {
		LCONSOLE_ERROR_MSG(0x163, "You're using an old version of /sbin/mount.lustre.  Please install version %s\n",
				   LUSTRE_VERSION_STRING);
		return -EINVAL;
	}
	lmd->lmd_magic = LMD_MAGIC;

	lmd->lmd_params = kzalloc(LMD_PARAMS_MAXLEN, GFP_NOFS);
	if (!lmd->lmd_params)
		return -ENOMEM;
	lmd->lmd_params[0] = '\0';

	/* Set default flags here */

	s1 = options;
	while (*s1) {
		int clear = 0;
		int time_min = OBD_RECOVERY_TIME_MIN;
		char *s3;

		/* Skip whitespace and extra commas */
		while (*s1 == ' ' || *s1 == ',')
			s1++;
		s3 = s1;

		/* Client options are parsed in ll_options: eg. flock,
		 * user_xattr, acl
		 */

		/* Parse non-ldiskfs options here. Rather than modifying
		 * ldiskfs, we just zero these out here
		 */
		if (strncmp(s1, "abort_recov", 11) == 0) {
			lmd->lmd_flags |= LMD_FLG_ABORT_RECOV;
			clear++;
		} else if (strncmp(s1, "abort_recov_mdt", 15) == 0) {
			lmd->lmd_flags |= LMD_FLG_ABORT_RECOV_MDT;
			clear++;
		} else if (strncmp(s1, "recovery_time_soft=", 19) == 0) {
			lmd->lmd_recovery_time_soft = max_t(int,
				simple_strtoul(s1 + 19, NULL, 10), time_min);
			clear++;
		} else if (strncmp(s1, "recovery_time_hard=", 19) == 0) {
			lmd->lmd_recovery_time_hard = max_t(int,
				simple_strtoul(s1 + 19, NULL, 10), time_min);
			clear++;
		} else if (strncmp(s1, "no_precreate", 12) == 0) {
			lmd->lmd_flags |= LMD_FLG_NO_PRECREATE;
			clear++;
		} else if (strncmp(s1, "noir", 4) == 0) {
			lmd->lmd_flags |= LMD_FLG_NOIR; /* test purpose only. */
			clear++;
		} else if (strncmp(s1, "nosvc", 5) == 0) {
			lmd->lmd_flags |= LMD_FLG_NOSVC;
			clear++;
		} else if (strncmp(s1, "nomgs", 5) == 0) {
			lmd->lmd_flags |= LMD_FLG_NOMGS;
			clear++;
		} else if (strncmp(s1, "noscrub", 7) == 0) {
			lmd->lmd_flags |= LMD_FLG_NOSCRUB;
			clear++;
		} else if (strncmp(s1, PARAM_MGSNODE,
				   sizeof(PARAM_MGSNODE) - 1) == 0) {
			s2 = s1 + sizeof(PARAM_MGSNODE) - 1;
			/* Assume the next mount opt is the first
			 * invalid nid we get to.
			 */
			rc = lmd_parse_mgs(lmd, &s2);
			if (rc)
				goto invalid;
			clear++;
		} else if (strncmp(s1, "writeconf", 9) == 0) {
			lmd->lmd_flags |= LMD_FLG_WRITECONF;
			clear++;
		} else if (strncmp(s1, "update", 6) == 0) {
			lmd->lmd_flags |= LMD_FLG_UPDATE;
			clear++;
		} else if (strncmp(s1, "virgin", 6) == 0) {
			lmd->lmd_flags |= LMD_FLG_VIRGIN;
			clear++;
		} else if (strncmp(s1, "noprimnode", 10) == 0) {
			lmd->lmd_flags |= LMD_FLG_NO_PRIMNODE;
			clear++;
		} else if (strncmp(s1, "mgssec=", 7) == 0) {
			rc = lmd_parse_mgssec(lmd, s1 + 7);
			if (rc)
				goto invalid;
			s3 = s2;
			clear++;
		/* ost exclusion list */
		} else if (strncmp(s1, "exclude=", 8) == 0) {
			rc = lmd_make_exclusion(lmd, s1 + 7);
			if (rc)
				goto invalid;
			clear++;
		} else if (strncmp(s1, "mgs", 3) == 0) {
			/* We are an MGS */
			lmd->lmd_flags |= LMD_FLG_MGS;
			clear++;
		} else if (strncmp(s1, "svname=", 7) == 0) {
			rc = lmd_parse_string(&lmd->lmd_profile, s1 + 7);
			if (rc)
				goto invalid;
			clear++;
		} else if (strncmp(s1, "param=", 6) == 0) {
			size_t length, params_length;
			char *tail = s1;

			if (lmd_find_delimiter(s1 + 6, &tail)) {
				char *param_str = tail + 1;
				int supplementary = 1;

				while (!lmd_parse_nidlist(param_str,
							  &param_str))
					supplementary = 0;
				length = param_str - s1 - supplementary;
			} else {
				length = strlen(s1);
			}
			length -= 6;
			params_length = strlen(lmd->lmd_params);
			if (params_length + length + 1 >= LMD_PARAMS_MAXLEN)
				return -E2BIG;
			strncat(lmd->lmd_params, s1 + 6, length);
			lmd->lmd_params[params_length + length] = '\0';
			strlcat(lmd->lmd_params, " ", LMD_PARAMS_MAXLEN);
			s3 = s1 + 6 + length;
			clear++;
		} else if (strncmp(s1, "localrecov", 10) == 0) {
			lmd->lmd_flags |= LMD_FLG_LOCAL_RECOV;
			clear++;
		} else if (strncmp(s1, "osd=", 4) == 0) {
			rc = lmd_parse_string(&lmd->lmd_osd_type, s1 + 4);
			if (rc)
				goto invalid;
			clear++;
		}
		/* Linux 2.4 doesn't pass the device, so we stuck it at the
		 * end of the options.
		 */
		else if (strncmp(s1, "device=", 7) == 0) {
			devname = s1 + 7;
			/* terminate options right before device.  device
			 * must be the last one.
			 */
			*s1 = '\0';
			break;
		} else if (strncmp(s1, "network=", 8) == 0) {
			rc = lmd_parse_network(lmd, s1 + 8);
			if (rc)
				goto invalid;

			/* check if LNet dynamic peer discovery is activated */
			if (LNetGetPeerDiscoveryStatus()) {
				CERROR("LNet Dynamic Peer Discovery is enabled on this node. 'network' mount option cannot be taken into account.\n");
				goto invalid;
			}

			clear++;
		}

		/* Find next opt */
		s2 = strchr(s1, ',');
		if (!s2) {
			if (clear)
				*s1 = '\0';
			break;
		}
		s2++;
		if (clear)
			memmove(s1, s2, strlen(s2) + 1);
		else
			s1 = s2;
	}

	if (!devname) {
		LCONSOLE_ERROR_MSG(0x164,
				   "Can't find the device name (need mount option 'device=...')\n");
		goto invalid;
	}

	s1 = strstr(devname, ":/");
	if (s1) {
		++s1;
		lmd->lmd_flags |= LMD_FLG_CLIENT;
		/* Remove leading /s from fsname */
		while (*++s1 == '/')
			;
		s2 = strchrnul(s1, '/');
		/* Freed in lustre_free_lsi */
		lmd->lmd_profile = kasprintf(GFP_KERNEL, "%.*s-client",
					     (int)(s2 - s1), s1);
		if (!lmd->lmd_profile)
			return -ENOMEM;

		s1 = s2;
		s2 = s1 + strlen(s1) - 1;
		/* Remove padding /s from fileset */
		while (*s2 == '/')
			s2--;
		if (s2 > s1) {
			lmd->lmd_fileset = kstrndup(s1, s2 - s1 + 1,
						    GFP_KERNEL);
			if (!lmd->lmd_fileset)
				return -ENOMEM;
		}
	} else {
		/* server mount */
		if (lmd->lmd_nidnet) {
			/* 'network=' mount option forbidden for server */
			kfree(lmd->lmd_nidnet);
			lmd->lmd_nidnet = NULL;
			rc = -EINVAL;
			CERROR("%s: option 'network=' not allowed for Lustre servers: rc = %d\n",
			       devname, rc);
			return rc;
		}
	}

	/* Freed in lustre_free_lsi */
	lmd->lmd_dev = kstrdup(devname, GFP_KERNEL);
	if (!lmd->lmd_dev)
		return -ENOMEM;

	/* Save mount options */
	s1 = options + strlen(options) - 1;
	while (s1 >= options && (*s1 == ',' || *s1 == ' '))
		*s1-- = 0;
	if (*options != 0) {
		/* Freed in lustre_free_lsi */
		lmd->lmd_opts = kstrdup(options, GFP_KERNEL);
		if (!lmd->lmd_opts)
			return -ENOMEM;
	}

	lmd_print(lmd);
	lmd->lmd_magic = LMD_MAGIC;

	return rc;

invalid:
	CERROR("Bad mount options %s\n", options);
	return -EINVAL;
}
EXPORT_SYMBOL(lmd_parse);
