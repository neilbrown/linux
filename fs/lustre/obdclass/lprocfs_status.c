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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/lprocfs_status.c
 *
 * Author: Hariharan Thantry <thantry@users.sourceforge.net>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/uaccess.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>

static const char * const obd_connect_names[] = {
	/* flags names */
	"read_only",
	"lov_index",
	"connect_from_mds",
	"write_grant",
	"server_lock",
	"version",
	"request_portal",
	"acl",
	"xattr",
	"create_on_write",
	"truncate_lock",
	"initial_transno",
	"inode_bit_locks",
	"join_file(obsolete)",
	"getattr_by_fid",
	"no_oh_for_devices",
	"remote_client",
	"remote_client_by_force",
	"max_byte_per_rpc",
	"64bit_qdata",
	"mds_capability",
	"oss_capability",
	"early_lock_cancel",
	"som",
	"adaptive_timeouts",
	"lru_resize",
	"mds_mds_connection",
	"real_conn",
	"change_qunit_size",
	"alt_checksum_algorithm",
	"fid_is_enabled",
	"version_recovery",
	"pools",
	"grant_shrink",
	"skip_orphan",
	"large_ea",
	"full20",
	"layout_lock",
	"64bithash",
	"object_max_bytes",
	"imp_recov",
	"jobstats",
	"umask",
	"einprogress",
	"grant_param",
	"flock_owner",
	"lvb_type",
	"nanoseconds_times",
	"lightweight_conn",
	"short_io",
	"pingless",
	"flock_deadlock",
	"disp_stripe",
	"open_by_fid",
	"lfsck",
	"unknown",
	"unlink_close",
	"multi_mod_rpcs",
	"dir_stripe",
	"subtree",
	"lockahead",
	"bulk_mbits",
	"compact_obdo",
	"second_flags",
	/* flags2 names */
	"file_secctx",	/* 0x01 */
	"lockaheadv2",	/* 0x02 */
	"dir_migrate",	/* 0x04 */
	"sum_statfs",	/* 0x08 */
	"overstriping",	/* 0x10 */
	"flr",		/* 0x20 */
	"wbc",		/* 0x40 */
	"lock_convert",	/* 0x80 */
	"archive_id_array",	/* 0x100 */
	"increasing_xid",	/* 0x200 */
	"selinux_policy",	/* 0x400 */
	"lsom",			/* 0x800 */
	"pcc",			/* 0x1000 */
	"crush",		/* 0x2000 */
	"async_discard",	/* 0x4000 */
	"client_encryption",	/* 0x8000 */
	"fidmap",		/* 0x10000 */
	"getattr_pfid",		/* 0x20000 */
	"lseek",		/* 0x40000 */
	NULL
};

int obd_connect_flags2str(char *page, int count, u64 flags, u64 flags2,
			  const char *sep)
{
	u64 mask;
	int i, ret = 0;

	BUILD_BUG_ON(ARRAY_SIZE(obd_connect_names) < 65);

	for (i = 0, mask = 1; i < 64; i++, mask <<= 1) {
		if (flags & mask)
			ret += snprintf(page + ret, count - ret, "%s%s",
					ret ? sep : "", obd_connect_names[i]);
	}

	if (!(flags & OBD_CONNECT_FLAGS2) || flags2 == 0)
		return ret;

	for (i = 64, mask = 1; obd_connect_names[i]; i++, mask <<= 1) {
		if (flags2 & mask)
			ret += snprintf(page + ret, count - ret, "%s%s",
					ret ? sep : "", obd_connect_names[i]);
	}

	if (flags2 & ~(mask - 1))
		ret += snprintf(page + ret, count - ret,
				"%sunknown2_%#llx",
				ret ? sep : "", flags2 & ~(mask - 1));

	return ret;
}
EXPORT_SYMBOL(obd_connect_flags2str);

static void obd_connect_data_seqprint(struct seq_file *m,
				      struct obd_connect_data *ocd)
{
	u64 flags;

	LASSERT(ocd);
	flags = ocd->ocd_connect_flags;

	seq_printf(m, "    connect_data:\n"
		   "       flags: %llx\n"
		   "       instance: %u\n",
		   ocd->ocd_connect_flags,
		   ocd->ocd_instance);
	if (flags & OBD_CONNECT_VERSION)
		seq_printf(m, "       target_version: %u.%u.%u.%u\n",
			   OBD_OCD_VERSION_MAJOR(ocd->ocd_version),
			   OBD_OCD_VERSION_MINOR(ocd->ocd_version),
			   OBD_OCD_VERSION_PATCH(ocd->ocd_version),
			   OBD_OCD_VERSION_FIX(ocd->ocd_version));
	if (flags & OBD_CONNECT_MDS)
		seq_printf(m, "       mdt_index: %d\n", ocd->ocd_group);
	if (flags & OBD_CONNECT_GRANT)
		seq_printf(m, "       initial_grant: %d\n", ocd->ocd_grant);
	if (flags & OBD_CONNECT_INDEX)
		seq_printf(m, "       target_index: %u\n", ocd->ocd_index);
	if (flags & OBD_CONNECT_BRW_SIZE)
		seq_printf(m, "       max_brw_size: %d\n", ocd->ocd_brw_size);
	if (flags & OBD_CONNECT_IBITS)
		seq_printf(m, "       ibits_known: %llx\n",
			   ocd->ocd_ibits_known);
	if (flags & OBD_CONNECT_GRANT_PARAM)
		seq_printf(m, "       grant_block_size: %d\n"
			   "       grant_inode_size: %d\n"
			   "       grant_max_extent_size: %d\n"
			   "       grant_extent_tax: %d\n",
			   1 << ocd->ocd_grant_blkbits,
			   1 << ocd->ocd_grant_inobits,
			   ocd->ocd_grant_max_blks << ocd->ocd_grant_blkbits,
			   ocd->ocd_grant_tax_kb << 10);
	if (flags & OBD_CONNECT_TRANSNO)
		seq_printf(m, "       first_transno: %llx\n",
			   ocd->ocd_transno);
	if (flags & OBD_CONNECT_CKSUM)
		seq_printf(m, "       cksum_types: %#x\n",
			   ocd->ocd_cksum_types);
	if (flags & OBD_CONNECT_MAX_EASIZE)
		seq_printf(m, "       max_easize: %d\n", ocd->ocd_max_easize);
	if (flags & OBD_CONNECT_MAXBYTES)
		seq_printf(m, "       max_object_bytes: %llx\n",
			   ocd->ocd_maxbytes);
	if (flags & OBD_CONNECT_MULTIMODRPCS)
		seq_printf(m, "       max_mod_rpcs: %hu\n",
			   ocd->ocd_maxmodrpcs);
}

/**
 * string_to_size - convert ASCII string representing a numerical
 *		    value with optional units to 64-bit binary value
 *
 * @size:	The numerical value extract out of @buffer
 * @buffer:	passed in string to parse
 * @count:	length of the @buffer
 *
 * This function returns a 64-bit binary value if @buffer contains a valid
 * numerical string. The string is parsed to 3 significant figures after
 * the decimal point. Support the string containing an optional units at
 * the end which can be base 2 or base 10 in value. If no units are given
 * the string is assumed to just a numerical value.
 *
 * Returns:	@count if the string is successfully parsed,
 *		-errno on invalid input strings. Error values:
 *
 *  - ``-EINVAL``: @buffer is not a proper numerical string
 *  - ``-EOVERFLOW``: results does not fit into 64 bits.
 *  - ``-E2BIG ``: @buffer is too large (not a valid number)
 */
int string_to_size(u64 *size, const char *buffer, size_t count)
{
	/* For string_get_size() it can support values above exabytes,
	 * (ZiB, YiB) due to breaking the return value into a size and
	 * bulk size to avoid 64 bit overflow. We don't break the size
	 * up into block size units so we don't support ZiB or YiB.
	 */
	static const char *const units_10[] = {
		"kB", "MB", "GB", "TB", "PB", "EB",
	};
	static const char *const units_2[] = {
		"K",  "M",  "G",  "T",  "P",  "E",
	};
	static const char *const *const units_str[] = {
		[STRING_UNITS_2] = units_2,
		[STRING_UNITS_10] = units_10,
	};
	static const unsigned int coeff[] = {
		[STRING_UNITS_10] = 1000,
		[STRING_UNITS_2] = 1024,
	};
	enum string_size_units unit = STRING_UNITS_2;
	u64 whole, blk_size = 1;
	char kernbuf[22], *end;
	size_t len = count;
	int rc;
	int i;

	if (count >= sizeof(kernbuf)) {
		CERROR("count %zd > buffer %zd\n", count, sizeof(kernbuf));
		return -E2BIG;
	}

	*size = 0;
	/* The "iB" suffix is optionally allowed for indicating base-2 numbers.
	 * If suffix is only "B" and not "iB" then we treat it as base-10.
	 */
	end = strstr(buffer, "B");
	if (end && *(end - 1) != 'i')
		unit = STRING_UNITS_10;

	i = unit == STRING_UNITS_2 ? ARRAY_SIZE(units_2) - 1 :
				     ARRAY_SIZE(units_10) - 1;
	do {
		end = strnstr(buffer, units_str[unit][i], count);
		if (end) {
			for (; i >= 0; i--)
				blk_size *= coeff[unit];
			len = end - buffer;
			break;
		}
	} while (i--);

	/* as 'B' is a substring of all units, we need to handle it
	 * separately.
	 */
	if (!end) {
		/* 'B' is only acceptable letter at this point */
		end = strnchr(buffer, count, 'B');
		if (end) {
			len = end - buffer;

			if (count - len > 2 ||
			    (count - len == 2 && strcmp(end, "B\n") != 0)) {
				CDEBUG(D_INFO, "unknown suffix '%s'\n", buffer);
				return -EINVAL;
			}
		}
		/* kstrtoull will error out if it has non digits */
		goto numbers_only;
	}

	end = strnchr(buffer, count, '.');
	if (end) {
		/* need to limit 3 decimal places */
		char rem[4] = "000";
		u64 frac = 0;
		size_t off;

		len = end - buffer;
		end++;

		/* limit to 3 decimal points */
		off = min_t(size_t, 3, strspn(end, "0123456789"));
		/* need to limit frac_d to a u32 */
		memcpy(rem, end, off);
		rc = kstrtoull(rem, 10, &frac);
		if (rc)
			return rc;

		if (fls64(frac) + fls64(blk_size) - 1 > 64)
			return -EOVERFLOW;

		frac *= blk_size;
		do_div(frac, 1000);
		*size += frac;
	}
numbers_only:
	snprintf(kernbuf, sizeof(kernbuf), "%.*s", (int)len, buffer);
	rc = kstrtoull(kernbuf, 10, &whole);
	if (rc)
		return rc;

	if (whole != 0 && fls64(whole) + fls64(blk_size) - 1 > 64)
		return -EOVERFLOW;

	*size += whole * blk_size;

	return count;
}
EXPORT_SYMBOL(string_to_size);

/**
 * sysfs_memparse - parse a ASCII string to 64-bit binary value,
 *		    with optional units
 *
 * @buffer:	kernel pointer to input string
 * @count:	number of bytes in the input @buffer
 * @val:	(output) binary value returned to caller
 * @defunit:	default unit suffix to use if none is provided
 *
 * Parses a string into a number. The number stored at @buffer is
 * potentially suffixed with K, M, G, T, P, E. Besides these other
 * valid suffix units are shown in the string_to_size() function.
 * If the string lacks a suffix then the defunit is used. The defunit
 * should be given as a binary unit (e.g. MiB) as that is the standard
 * for tunables in Lustre. If no unit suffix is given (e.g. 'G'), then
 * it is assumed to be in binary units.
 *
 * Returns:	0 on success or -errno on failure.
 */
int sysfs_memparse(const char *buffer, size_t count, u64 *val,
		   const char *defunit)
{
	const char *param = buffer;
	char tmp_buf[23];
	int rc;

	count = strlen(buffer);
	while (count > 0 && isspace(buffer[count - 1]))
		count--;

	if (!count)
		return -EINVAL;

	/* If there isn't already a unit on this value, append @defunit.
	 * Units of 'B' don't affect the value, so don't bother adding.
	 */
	if (!isalpha(buffer[count - 1]) && defunit[0] != 'B') {
		if (count + 3 >= sizeof(tmp_buf)) {
			CERROR("count %zd > size %zd\n", count, count + 1);
			return -E2BIG;
		}

		scnprintf(tmp_buf, sizeof(tmp_buf), "%.*s%s", (int)count,
			  buffer, defunit);
		param = tmp_buf;
		count = strlen(param);
	}

	rc = string_to_size(val, param, count);

	return rc < 0 ? rc : 0;
}
EXPORT_SYMBOL(sysfs_memparse);

int lprocfs_read_frac_helper(char *buffer, unsigned long count, long val,
			     int mult)
{
	long decimal_val, frac_val;
	int prtn;

	if (count < 10)
		return -EINVAL;

	decimal_val = val / mult;
	prtn = snprintf(buffer, count, "%ld", decimal_val);
	frac_val = val % mult;

	if (prtn < (count - 4) && frac_val > 0) {
		long temp_frac;
		int i, temp_mult = 1, frac_bits = 0;

		temp_frac = frac_val * 10;
		buffer[prtn++] = '.';
		while (frac_bits < 2 && (temp_frac / mult) < 1) {
			/* only reserved 2 bits fraction */
			buffer[prtn++] = '0';
			temp_frac *= 10;
			frac_bits++;
		}
		/*
		 * Need to think these cases :
		 *      1. #echo x.00 > /sys/xxx       output result : x
		 *      2. #echo x.0x > /sys/xxx       output result : x.0x
		 *      3. #echo x.x0 > /sys/xxx       output result : x.x
		 *      4. #echo x.xx > /sys/xxx       output result : x.xx
		 *      Only reserved 2 bits fraction.
		 */
		for (i = 0; i < (5 - prtn); i++)
			temp_mult *= 10;

		frac_bits = min((int)count - prtn, 3 - frac_bits);
		prtn += snprintf(buffer + prtn, frac_bits, "%ld",
				 frac_val * temp_mult / mult);

		prtn--;
		while (buffer[prtn] < '1' || buffer[prtn] > '9') {
			prtn--;
			if (buffer[prtn] == '.') {
				prtn--;
				break;
			}
		}
		prtn++;
	}
	buffer[prtn++] = '\n';
	return prtn;
}
EXPORT_SYMBOL(lprocfs_read_frac_helper);

int lprocfs_write_frac_helper(const char __user *buffer, unsigned long count,
			      int *val, int mult)
{
	char kernbuf[20], *end, *pbuf;

	if (count > (sizeof(kernbuf) - 1))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;

	kernbuf[count] = '\0';
	pbuf = kernbuf;
	if (*pbuf == '-') {
		mult = -mult;
		pbuf++;
	}

	*val = (int)simple_strtoul(pbuf, &end, 10) * mult;
	if (pbuf == end)
		return -EINVAL;

	if (end && *end == '.') {
		int temp_val, pow = 1;
		int i;

		pbuf = end + 1;
		if (strlen(pbuf) > 5)
			pbuf[5] = '\0'; /*only allow 5bits fractional*/

		temp_val = (int)simple_strtoul(pbuf, &end, 10) * mult;

		if (pbuf < end) {
			for (i = 0; i < (end - pbuf); i++)
				pow *= 10;

			*val += temp_val / pow;
		}
	}
	return 0;
}
EXPORT_SYMBOL(lprocfs_write_frac_helper);

static int lprocfs_no_percpu_stats;
module_param(lprocfs_no_percpu_stats, int, 0644);
MODULE_PARM_DESC(lprocfs_no_percpu_stats, "Do not alloc percpu data for lprocfs stats");

/* lprocfs API calls */

static const struct file_operations ldebugfs_empty_ops = { };

void ldebugfs_add_vars(struct dentry *parent, struct ldebugfs_vars *list,
		       void *data)
{
	if (IS_ERR_OR_NULL(parent) || IS_ERR_OR_NULL(list))
		return;

	while (list->name) {
		umode_t mode = 0;

		if (list->proc_mode != 0000) {
			mode = list->proc_mode;
		} else if (list->fops) {
			if (list->fops->read)
				mode = 0444;
			if (list->fops->write)
				mode |= 0200;
		}
		debugfs_create_file(list->name, mode, parent,
				    list->data ?: data,
				    list->fops ?: &ldebugfs_empty_ops);
		list++;
	}
}
EXPORT_SYMBOL_GPL(ldebugfs_add_vars);

static const struct file_operations lprocfs_empty_ops = { };

/* Generic callbacks */
static ssize_t uuid_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%s\n", obd->obd_uuid.uuid);
}
LUSTRE_RO_ATTR(uuid);

static ssize_t blocksize_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS,
			OBD_STATFS_NODELAY);
	if (!rc)
		return sprintf(buf, "%u\n", osfs.os_bsize);

	return rc;
}
LUSTRE_RO_ATTR(blocksize);

static ssize_t kbytestotal_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS,
			OBD_STATFS_NODELAY);
	if (!rc) {
		u32 blk_size = osfs.os_bsize >> 10;
		u64 result = osfs.os_blocks;

		result *= rounddown_pow_of_two(blk_size ?: 1);
		return sprintf(buf, "%llu\n", result);
	}

	return rc;
}
LUSTRE_RO_ATTR(kbytestotal);

static ssize_t kbytesfree_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS,
			OBD_STATFS_NODELAY);
	if (!rc) {
		u32 blk_size = osfs.os_bsize >> 10;
		u64 result = osfs.os_bfree;

		result *= rounddown_pow_of_two(blk_size ?: 1);

		return sprintf(buf, "%llu\n", result);
	}

	return rc;
}
LUSTRE_RO_ATTR(kbytesfree);

static ssize_t kbytesavail_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS,
			OBD_STATFS_NODELAY);
	if (!rc) {
		u32 blk_size = osfs.os_bsize >> 10;
		u64 result = osfs.os_bavail;

		result *= rounddown_pow_of_two(blk_size ?: 1);

		return sprintf(buf, "%llu\n", result);
	}

	return rc;
}
LUSTRE_RO_ATTR(kbytesavail);

static ssize_t filestotal_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS,
			OBD_STATFS_NODELAY);
	if (!rc)
		return sprintf(buf, "%llu\n", osfs.os_files);

	return rc;
}
LUSTRE_RO_ATTR(filestotal);

static ssize_t filesfree_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS,
			OBD_STATFS_NODELAY);
	if (!rc)
		return sprintf(buf, "%llu\n", osfs.os_ffree);

	return rc;
}
LUSTRE_RO_ATTR(filesfree);

ssize_t conn_uuid_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ptlrpc_connection *conn;
	struct obd_import *imp;
	ssize_t count;

	with_imp_locked(obd, imp, count) {
		conn = imp->imp_connection;
		if (conn)
			count = sprintf(buf, "%s\n", conn->c_remote_uuid.uuid);
		else
			count = sprintf(buf, "%s\n", "<none>");
	}
	return count;
}
EXPORT_SYMBOL(conn_uuid_show);

int ldebugfs_server_uuid_seq_read(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_import *imp;
	const char *imp_state_name = NULL;
	int rc;

	LASSERT(obd);
	with_imp_locked(obd, imp, rc) {
		imp_state_name = ptlrpc_import_state_name(imp->imp_state);
		seq_printf(m, "%s\t%s%s\n",
			   obd2cli_tgt(obd), imp_state_name,
			   imp->imp_deactive ? "\tDEACTIVATED" : "");

	}

	return rc;
}
EXPORT_SYMBOL(ldebugfs_server_uuid_seq_read);

/**
 * Lock statistics structure for access, possibly only on this CPU.
 *
 * The statistics struct may be allocated with per-CPU structures for
 * efficient concurrent update (usually only on server-wide stats), or
 * as a single global struct (e.g. for per-client or per-job statistics),
 * so the required locking depends on the type of structure allocated.
 *
 * For per-CPU statistics, pin the thread to the current cpuid so that
 * will only access the statistics for that CPU.  If the stats structure
 * for the current CPU has not been allocated (or previously freed),
 * allocate it now.  The per-CPU statistics do not need locking since
 * the thread is pinned to the CPU during update.
 *
 * For global statistics, lock the stats structure to prevent concurrent update.
 *
 * @stats:	statistics structure to lock
 * @opc:	type of operation:
 *		LPROCFS_GET_SMP_ID: "lock" and return current CPU index
 *				    for incrementing statistics for that CPU
 *		LPROCFS_GET_NUM_CPU: "lock" and return number of used
 *				     CPU indices to iterate over all indices
 * @flags:	CPU interrupt saved state for IRQ-safe locking
 *
 * Returns:	cpuid of current thread or number of allocated structs
 *		negative on error (only for opc LPROCFS_GET_SMP_ID +
 *				   per-CPU stats)
 */
int lprocfs_stats_lock(struct lprocfs_stats *stats,
		       enum lprocfs_stats_lock_ops opc,
		       unsigned long *flags)
{
	if (stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU) {
		if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE)
			spin_lock_irqsave(&stats->ls_lock, *flags);
		else
			spin_lock(&stats->ls_lock);
		return opc == LPROCFS_GET_NUM_CPU ? 1 : 0;
	}

	switch (opc) {
	case LPROCFS_GET_SMP_ID: {
		unsigned int cpuid = get_cpu();

		if (unlikely(!stats->ls_percpu[cpuid])) {
			int rc = lprocfs_stats_alloc_one(stats, cpuid);

			if (rc < 0) {
				put_cpu();
				return rc;
			}
		}
		return cpuid;
	}
	case LPROCFS_GET_NUM_CPU:
		return stats->ls_biggest_alloc_num;
	default:
		LBUG();
	}
}

/**
 * Unlock statistics structure after access.
 *
 * Unlock the lock acquired via lprocfs_stats_lock() for global statistics,
 * or unpin this thread from the current cpuid for per-CPU statistics.
 *
 * This function must be called using the same arguments as used when calling
 * lprocfs_stats_lock() so that the correct operation can be performed.
 *
 * @stats:	statistics structure to unlock
 * @opc:	type of operation (current cpuid or number of structs)
 * @flags:	CPU interrupt saved state for IRQ-safe locking
 */
void lprocfs_stats_unlock(struct lprocfs_stats *stats,
			  enum lprocfs_stats_lock_ops opc,
			  unsigned long *flags)
{
	if (stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU) {
		if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE)
			spin_unlock_irqrestore(&stats->ls_lock, *flags);
		else
			spin_unlock(&stats->ls_lock);
	} else if (opc == LPROCFS_GET_SMP_ID) {
		put_cpu();
	}
}

/** add up per-cpu counters */
void lprocfs_stats_collect(struct lprocfs_stats *stats, int idx,
			   struct lprocfs_counter *cnt)
{
	unsigned int num_entry;
	struct lprocfs_counter *percpu_cntr;
	int i;
	unsigned long flags = 0;

	memset(cnt, 0, sizeof(*cnt));

	if (!stats) {
		/* set count to 1 to avoid divide-by-zero errs in callers */
		cnt->lc_count = 1;
		return;
	}

	cnt->lc_min = LC_MIN_INIT;

	num_entry = lprocfs_stats_lock(stats, LPROCFS_GET_NUM_CPU, &flags);

	for (i = 0; i < num_entry; i++) {
		if (!stats->ls_percpu[i])
			continue;
		percpu_cntr = lprocfs_stats_counter_get(stats, i, idx);

		cnt->lc_count += percpu_cntr->lc_count;
		cnt->lc_sum += percpu_cntr->lc_sum;
		if (percpu_cntr->lc_min < cnt->lc_min)
			cnt->lc_min = percpu_cntr->lc_min;
		if (percpu_cntr->lc_max > cnt->lc_max)
			cnt->lc_max = percpu_cntr->lc_max;
		cnt->lc_sumsquare += percpu_cntr->lc_sumsquare;
	}

	lprocfs_stats_unlock(stats, LPROCFS_GET_NUM_CPU, &flags);
}

/**
 * Append a space separated list of current set flags to str.
 */
#define flag2str(flag, first)						\
	do {								\
		if (imp->imp_##flag)					\
			seq_printf(m, "%s" #flag, first ? "" : ", ");	\
	} while (0)
static int obd_import_flags2str(struct obd_import *imp, struct seq_file *m)
{
	bool first = true;

	if (imp->imp_obd->obd_no_recov) {
		seq_puts(m, "no_recov");
		first = false;
	}

	flag2str(invalid, first);
	first = false;
	flag2str(deactive, first);
	flag2str(replayable, first);
	flag2str(pingable, first);
	return 0;
}

#undef flags2str

static void obd_connect_seq_flags2str(struct seq_file *m, u64 flags,
				      u64 flags2, const char *sep)
{
	u64 mask;
	int i;
	bool first = true;

	for (i = 0, mask = 1; i < 64; i++, mask <<= 1) {
		if (flags & mask) {
			seq_printf(m, "%s%s",
				   first ? "" : sep, obd_connect_names[i]);
			first = false;
		}
	}

	if (flags & ~(mask - 1)) {
		seq_printf(m, "%sunknown flags %#llx",
			   first ? "" : sep, flags & ~(mask - 1));
		first = false;
	}

	if (!(flags & OBD_CONNECT_FLAGS2) || flags2 == 0)
		return;

	for (i = 64, mask = 1; obd_connect_names[i]; i++, mask <<= 1) {
		if (flags2 & mask) {
			seq_printf(m, "%s%s",
				   first ? "" : sep, obd_connect_names[i]);
			first = false;
		}
	}

	if (flags2 & ~(mask - 1)) {
		seq_printf(m, "%sunknown2_%#llx",
			   first ? "" : sep, flags2 & ~(mask - 1));
		first = false;
	}
}

int ldebugfs_import_seq_read(struct seq_file *m, void *data)
{
	char nidstr[LNET_NIDSTR_SIZE];
	struct lprocfs_counter ret;
	struct lprocfs_counter_header *header;
	struct obd_device *obd = data;
	struct obd_import *imp;
	struct obd_import_conn *conn;
	struct obd_connect_data *ocd;
	int j;
	int k;
	int rw = 0;
	int rc;

	LASSERT(obd);

	with_imp_locked(obd, imp, rc) {
		ocd = &imp->imp_connect_data;

		seq_printf(m, "import:\n"
			   "    name: %s\n"
			   "    target: %s\n"
			   "    state: %s\n"
			   "    instance: %u\n"
			   "    connect_flags: [ ",
			   obd->obd_name,
			   obd2cli_tgt(obd),
			   ptlrpc_import_state_name(imp->imp_state),
			   imp->imp_connect_data.ocd_instance);
		obd_connect_seq_flags2str(m, imp->imp_connect_data.ocd_connect_flags,
					  imp->imp_connect_data.ocd_connect_flags2,
					  ", ");
		seq_puts(m, " ]\n");
		obd_connect_data_seqprint(m, ocd);
		seq_puts(m, "    import_flags: [ ");
		obd_import_flags2str(imp, m);

		seq_puts(m,
			 " ]\n"
			 "    connection:\n"
			 "       failover_nids: [ ");
		spin_lock(&imp->imp_lock);
		j = 0;
		list_for_each_entry(conn, &imp->imp_conn_list, oic_item) {
			libcfs_nid2str_r(conn->oic_conn->c_peer.nid,
					 nidstr, sizeof(nidstr));
			seq_printf(m, "%s%s", j ? ", " : "", nidstr);
			j++;
		}
		if (imp->imp_connection)
			libcfs_nid2str_r(imp->imp_connection->c_peer.nid,
					 nidstr, sizeof(nidstr));
		else
			strncpy(nidstr, "<none>", sizeof(nidstr));
		seq_printf(m,
			   " ]\n"
			   "       current_connection: %s\n"
			   "       connection_attempts: %u\n"
			   "       generation: %u\n"
			   "       in-progress_invalidations: %u\n"
		   "       idle: %lld sec\n",
			   nidstr,
			   imp->imp_conn_cnt,
			   imp->imp_generation,
			   atomic_read(&imp->imp_inval_count),
		   ktime_get_real_seconds() - imp->imp_last_reply_time);
		spin_unlock(&imp->imp_lock);

		if (!obd->obd_svc_stats)
			goto out_climp;

		header = &obd->obd_svc_stats->ls_cnt_header[PTLRPC_REQWAIT_CNTR];
		lprocfs_stats_collect(obd->obd_svc_stats, PTLRPC_REQWAIT_CNTR, &ret);
		if (ret.lc_count != 0)
		ret.lc_sum = div64_s64(ret.lc_sum, ret.lc_count);
	else
		ret.lc_sum = 0;
	seq_printf(m,
		   "    rpcs:\n"
			   "       inflight: %u\n"
			   "       unregistering: %u\n"
			   "       timeouts: %u\n"
			   "       avg_waittime: %llu %s\n",
			   atomic_read(&imp->imp_inflight),
			   atomic_read(&imp->imp_unregistering),
			   atomic_read(&imp->imp_timeouts),
			   ret.lc_sum, header->lc_units);

		k = 0;
		for (j = 0; j < IMP_AT_MAX_PORTALS; j++) {
			if (imp->imp_at.iat_portal[j] == 0)
				break;
			k = max_t(unsigned int, k,
				  at_get(&imp->imp_at.iat_service_estimate[j]));
		}
		seq_printf(m,
			   "    service_estimates:\n"
			   "       services: %u sec\n"
			   "       network: %d sec\n",
			   k,
			   at_get(&imp->imp_at.iat_net_latency));

		seq_printf(m,
			   "    transactions:\n"
			   "       last_replay: %llu\n"
			   "       peer_committed: %llu\n"
			   "       last_checked: %llu\n",
			   imp->imp_last_replay_transno,
			   imp->imp_peer_committed_transno,
			   imp->imp_last_transno_checked);

		/* avg data rates */
		for (rw = 0; rw <= 1; rw++) {
			lprocfs_stats_collect(obd->obd_svc_stats,
					      PTLRPC_LAST_CNTR + BRW_READ_BYTES + rw,
					      &ret);
			if (ret.lc_sum > 0 && ret.lc_count > 0) {
			ret.lc_sum = div64_s64(ret.lc_sum, ret.lc_count);
			seq_printf(m,
				   "    %s_data_averages:\n"
					   "       bytes_per_rpc: %llu\n",
					   rw ? "write" : "read",
					   ret.lc_sum);
			}
			k = (int)ret.lc_sum;
			j = opcode_offset(OST_READ + rw) + EXTRA_MAX_OPCODES;
			header = &obd->obd_svc_stats->ls_cnt_header[j];
			lprocfs_stats_collect(obd->obd_svc_stats, j, &ret);
			if (ret.lc_sum > 0 && ret.lc_count != 0) {
			ret.lc_sum = div64_s64(ret.lc_sum, ret.lc_count);
			seq_printf(m,
				   "       %s_per_rpc: %llu\n",
					   header->lc_units, ret.lc_sum);
				j = (int)ret.lc_sum;
				if (j > 0)
					seq_printf(m,
						   "       MB_per_sec: %u.%.02u\n",
						   k / j, (100 * k / j) % 100);
			}
		}

	out_climp:
		;
	}

	return rc;
}
EXPORT_SYMBOL(ldebugfs_import_seq_read);

int ldebugfs_state_seq_read(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_import *imp;
	int j, k, rc;

	LASSERT(obd);
	with_imp_locked(obd, imp, rc) {
		seq_printf(m, "current_state: %s\n",
			   ptlrpc_import_state_name(imp->imp_state));
		seq_puts(m, "state_history:\n");
		k = imp->imp_state_hist_idx;
		for (j = 0; j < IMP_STATE_HIST_LEN; j++) {
			struct import_state_hist *ish =
				&imp->imp_state_hist[(k + j) %
						     IMP_STATE_HIST_LEN];
			if (ish->ish_state == 0)
				continue;
			seq_printf(m, " - [ %lld, %s ]\n", (s64)ish->ish_time,
				   ptlrpc_import_state_name(ish->ish_state));
		}

	}

	return rc;
}
EXPORT_SYMBOL(ldebugfs_state_seq_read);

int lprocfs_at_hist_helper(struct seq_file *m, struct adaptive_timeout *at)
{
	int i;

	for (i = 0; i < AT_BINS; i++)
		seq_printf(m, "%3u ", at->at_hist[i]);
	seq_puts(m, "\n");
	return 0;
}
EXPORT_SYMBOL(lprocfs_at_hist_helper);

/* See also ptlrpc_lprocfs_rd_timeouts */
int ldebugfs_timeouts_seq_read(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_import *imp;
	timeout_t cur_timeout, worst_timeout;
	time64_t now, worst_timestamp;
	int i, rc;

	LASSERT(obd);
	with_imp_locked(obd, imp, rc) {
		now = ktime_get_real_seconds();

		/* Some network health info for kicks */
		seq_printf(m, "%-10s : %lld, %llds ago\n",
			   "last reply", (s64)imp->imp_last_reply_time,
			   (s64)(now - imp->imp_last_reply_time));

		cur_timeout = at_get(&imp->imp_at.iat_net_latency);
		worst_timeout =
			imp->imp_at.iat_net_latency.at_worst_timeout_ever;
		worst_timestamp =
			imp->imp_at.iat_net_latency.at_worst_timestamp;
		seq_printf(m,
			   "%-10s : cur %3u  worst %3u (at %lld, %llds ago) ",
			   "network",
			   cur_timeout, worst_timeout, worst_timestamp,
			   now - worst_timestamp);
		lprocfs_at_hist_helper(m, &imp->imp_at.iat_net_latency);

		for (i = 0; i < IMP_AT_MAX_PORTALS; i++) {
			struct adaptive_timeout *service_est;

			if (imp->imp_at.iat_portal[i] == 0)
				break;

			service_est = &imp->imp_at.iat_service_estimate[i];
			cur_timeout = at_get(service_est);
			worst_timeout = service_est->at_worst_timeout_ever;
			worst_timestamp = service_est->at_worst_timestamp;
			seq_printf(m, "portal %-2d  : cur %3u  worst %3u (at %lld, %llds ago) ",
				   imp->imp_at.iat_portal[i], cur_timeout,
				   worst_timeout,
				   worst_timestamp, now - worst_timestamp);
			lprocfs_at_hist_helper(m, service_est);
		}

	}

	return rc;
}
EXPORT_SYMBOL(ldebugfs_timeouts_seq_read);

int ldebugfs_connect_flags_seq_read(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_import *imp;
	u64 flags, flags2;
	int rc;

	with_imp_locked(obd, imp, rc) {
		flags = imp->imp_connect_data.ocd_connect_flags;
		flags2 = imp->imp_connect_data.ocd_connect_flags2;
		seq_printf(m, "flags=%#llx\n", flags);
		seq_printf(m, "flags2=%#llx\n", flags2);
		obd_connect_seq_flags2str(m, flags, flags2, "\n");
		seq_puts(m, "\n");
	}

	return rc;
}
EXPORT_SYMBOL(ldebugfs_connect_flags_seq_read);

static const struct attribute *obd_def_uuid_attrs[] = {
	&lustre_attr_uuid.attr,
	NULL,
};

static const struct attribute *obd_def_attrs[] = {
	&lustre_attr_blocksize.attr,
	&lustre_attr_kbytestotal.attr,
	&lustre_attr_kbytesfree.attr,
	&lustre_attr_kbytesavail.attr,
	&lustre_attr_filestotal.attr,
	&lustre_attr_filesfree.attr,
	&lustre_attr_uuid.attr,
	NULL,
};

static void obd_sysfs_release(struct kobject *kobj)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	complete(&obd->obd_kobj_unregister);
}

int lprocfs_obd_setup(struct obd_device *obd, bool uuid_only)
{
	int rc;

	if (!obd || obd->obd_magic != OBD_DEVICE_MAGIC)
		return -ENODEV;

	rc = kobject_set_name(&obd->obd_kset.kobj, "%s", obd->obd_name);
	if (rc)
		return rc;

	obd->obd_ktype.sysfs_ops = &lustre_sysfs_ops;
	obd->obd_ktype.release = obd_sysfs_release;

	obd->obd_kset.kobj.parent = &obd->obd_type->typ_kobj;
	obd->obd_kset.kobj.ktype = &obd->obd_ktype;
	init_completion(&obd->obd_kobj_unregister);
	rc = kset_register(&obd->obd_kset);
	if (rc)
		return rc;

	if (uuid_only)
		obd->obd_attrs = obd_def_uuid_attrs;
	else
		obd->obd_attrs = obd_def_attrs;

	rc = sysfs_create_files(&obd->obd_kset.kobj, obd->obd_attrs);
	if (rc) {
		kset_unregister(&obd->obd_kset);
		return rc;
	}

	obd->obd_debugfs_entry = debugfs_create_dir(obd->obd_name,
					obd->obd_type->typ_debugfs_entry);
	ldebugfs_add_vars(obd->obd_debugfs_entry, obd->obd_debugfs_vars, obd);

	return rc;
}
EXPORT_SYMBOL_GPL(lprocfs_obd_setup);

int lprocfs_obd_cleanup(struct obd_device *obd)
{
	if (!obd)
		return -EINVAL;

	debugfs_remove_recursive(obd->obd_debugfs_entry);

	/* obd device never allocated a kset */
	if (!obd->obd_kset.kobj.state_initialized)
		return 0;

	if (obd->obd_attrs) {
		sysfs_remove_files(&obd->obd_kset.kobj, obd->obd_attrs);
		obd->obd_attrs = NULL;
	}

	kset_unregister(&obd->obd_kset);
	wait_for_completion(&obd->obd_kobj_unregister);

	return 0;
}
EXPORT_SYMBOL_GPL(lprocfs_obd_cleanup);

int lprocfs_stats_alloc_one(struct lprocfs_stats *stats, unsigned int cpuid)
{
	struct lprocfs_counter *cntr;
	unsigned int percpusize;
	int rc = -ENOMEM;
	unsigned long flags = 0;
	int i;

	LASSERT(!stats->ls_percpu[cpuid]);
	LASSERT((stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU) == 0);

	percpusize = lprocfs_stats_counter_size(stats);
	stats->ls_percpu[cpuid] = kzalloc(percpusize, GFP_ATOMIC);
	if (stats->ls_percpu[cpuid]) {
		rc = 0;
		if (unlikely(stats->ls_biggest_alloc_num <= cpuid)) {
			if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE)
				spin_lock_irqsave(&stats->ls_lock, flags);
			else
				spin_lock(&stats->ls_lock);
			if (stats->ls_biggest_alloc_num <= cpuid)
				stats->ls_biggest_alloc_num = cpuid + 1;
			if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE)
				spin_unlock_irqrestore(&stats->ls_lock, flags);
			else
				spin_unlock(&stats->ls_lock);
		}
		/* initialize the ls_percpu[cpuid] non-zero counter */
		for (i = 0; i < stats->ls_num; ++i) {
			cntr = lprocfs_stats_counter_get(stats, cpuid, i);
			cntr->lc_min = LC_MIN_INIT;
		}
	}
	return rc;
}

struct lprocfs_stats *lprocfs_alloc_stats(unsigned int num,
					  enum lprocfs_stats_flags flags)
{
	struct lprocfs_stats *stats;
	unsigned int num_entry;
	unsigned int percpusize = 0;
	int i;

	if (num == 0)
		return NULL;

	if (lprocfs_no_percpu_stats != 0)
		flags |= LPROCFS_STATS_FLAG_NOPERCPU;

	if (flags & LPROCFS_STATS_FLAG_NOPERCPU)
		num_entry = 1;
	else
		num_entry = num_possible_cpus();

	/* alloc percpu pointers for all possible cpu slots */
	stats = kvzalloc(offsetof(typeof(*stats), ls_percpu[num_entry]),
			 GFP_KERNEL);
	if (!stats)
		return NULL;

	stats->ls_num = num;
	stats->ls_flags = flags;
	spin_lock_init(&stats->ls_lock);

	/* alloc num of counter headers */
	stats->ls_cnt_header = kvmalloc_array(stats->ls_num,
					      sizeof(*stats->ls_cnt_header),
					      GFP_KERNEL | __GFP_ZERO);
	if (!stats->ls_cnt_header)
		goto fail;

	if ((flags & LPROCFS_STATS_FLAG_NOPERCPU) != 0) {
		/* contains only one set counters */
		percpusize = lprocfs_stats_counter_size(stats);
		stats->ls_percpu[0] = kzalloc(percpusize, GFP_ATOMIC);
		if (!stats->ls_percpu[0])
			goto fail;
		stats->ls_biggest_alloc_num = 1;
	} else if ((flags & LPROCFS_STATS_FLAG_IRQ_SAFE) != 0) {
		/* alloc all percpu data */
		for (i = 0; i < num_entry; ++i)
			if (lprocfs_stats_alloc_one(stats, i) < 0)
				goto fail;
	}

	return stats;

fail:
	lprocfs_free_stats(&stats);
	return NULL;
}
EXPORT_SYMBOL(lprocfs_alloc_stats);

void lprocfs_free_stats(struct lprocfs_stats **statsh)
{
	struct lprocfs_stats *stats = *statsh;
	unsigned int num_entry;
	unsigned int percpusize;
	unsigned int i;

	if (!stats || stats->ls_num == 0)
		return;
	*statsh = NULL;

	if (stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU)
		num_entry = 1;
	else
		num_entry = num_possible_cpus();

	percpusize = lprocfs_stats_counter_size(stats);
	for (i = 0; i < num_entry; i++)
		kfree(stats->ls_percpu[i]);
	kvfree(stats->ls_cnt_header);
	kvfree(stats);
}
EXPORT_SYMBOL(lprocfs_free_stats);

u64 lprocfs_stats_collector(struct lprocfs_stats *stats, int idx,
			      enum lprocfs_fields_flags field)
{
	unsigned int i;
	unsigned int num_cpu;
	unsigned long flags = 0;
	u64 ret = 0;

	LASSERT(stats);

	num_cpu = lprocfs_stats_lock(stats, LPROCFS_GET_NUM_CPU, &flags);
	for (i = 0; i < num_cpu; i++) {
		if (!stats->ls_percpu[i])
			continue;
		ret += lprocfs_read_helper(
				lprocfs_stats_counter_get(stats, i, idx),
				&stats->ls_cnt_header[idx], stats->ls_flags,
				field);
	}
	lprocfs_stats_unlock(stats, LPROCFS_GET_NUM_CPU, &flags);
	return ret;
}
EXPORT_SYMBOL(lprocfs_stats_collector);

void lprocfs_clear_stats(struct lprocfs_stats *stats)
{
	struct lprocfs_counter *percpu_cntr;
	int i;
	int j;
	unsigned int num_entry;
	unsigned long flags = 0;

	num_entry = lprocfs_stats_lock(stats, LPROCFS_GET_NUM_CPU, &flags);

	for (i = 0; i < num_entry; i++) {
		if (!stats->ls_percpu[i])
			continue;
		for (j = 0; j < stats->ls_num; j++) {
			percpu_cntr = lprocfs_stats_counter_get(stats, i, j);
			percpu_cntr->lc_count = 0;
			percpu_cntr->lc_min = LC_MIN_INIT;
			percpu_cntr->lc_max = 0;
			percpu_cntr->lc_sumsquare = 0;
			percpu_cntr->lc_sum = 0;
			if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE)
				percpu_cntr->lc_sum_irq	= 0;
		}
	}

	lprocfs_stats_unlock(stats, LPROCFS_GET_NUM_CPU, &flags);
}
EXPORT_SYMBOL(lprocfs_clear_stats);

static ssize_t lprocfs_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct lprocfs_stats *stats = seq->private;

	lprocfs_clear_stats(stats);

	return len;
}

static void *lprocfs_stats_seq_start(struct seq_file *p, loff_t *pos)
{
	struct lprocfs_stats *stats = p->private;

	return (*pos < stats->ls_num) ? pos : NULL;
}

static void lprocfs_stats_seq_stop(struct seq_file *p, void *v)
{
}

static void *lprocfs_stats_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	(*pos)++;
	return lprocfs_stats_seq_start(p, pos);
}

/* seq file export of one lprocfs counter */
static int lprocfs_stats_seq_show(struct seq_file *p, void *v)
{
	struct lprocfs_stats *stats = p->private;
	struct lprocfs_counter_header *hdr;
	struct lprocfs_counter ctr;
	int idx = *(loff_t *)v;

	if (idx == 0) {
		struct timespec64 now;

		ktime_get_real_ts64(&now);
		seq_printf(p, "%-25s %llu.%9lu secs.usecs\n",
			   "snapshot_time",
			   (s64)now.tv_sec, (unsigned long)now.tv_nsec);
	}

	hdr = &stats->ls_cnt_header[idx];
	lprocfs_stats_collect(stats, idx, &ctr);

	if (ctr.lc_count != 0) {
		seq_printf(p, "%-25s %lld samples [%s]",
			   hdr->lc_name, ctr.lc_count, hdr->lc_units);

		if ((hdr->lc_config & LPROCFS_CNTR_AVGMINMAX) &&
		    (ctr.lc_count > 0)) {
			seq_printf(p, " %lld %lld %lld",
				   ctr.lc_min, ctr.lc_max, ctr.lc_sum);
			if (hdr->lc_config & LPROCFS_CNTR_STDDEV)
				seq_printf(p, " %lld", ctr.lc_sumsquare);
		}
		seq_putc(p, '\n');
	}

	return 0;
}

static const struct seq_operations lprocfs_stats_seq_sops = {
	.start		= lprocfs_stats_seq_start,
	.stop		= lprocfs_stats_seq_stop,
	.next		= lprocfs_stats_seq_next,
	.show		= lprocfs_stats_seq_show,
};

static int lprocfs_stats_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &lprocfs_stats_seq_sops);
	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private;

	return 0;
}

const struct file_operations ldebugfs_stats_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= lprocfs_stats_seq_open,
	.read		= seq_read,
	.write		= lprocfs_stats_seq_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
EXPORT_SYMBOL(ldebugfs_stats_seq_fops);

void lprocfs_counter_init(struct lprocfs_stats *stats, int index,
			  unsigned int conf, const char *name,
			  const char *units)
{
	struct lprocfs_counter_header *header;
	struct lprocfs_counter *percpu_cntr;
	unsigned long flags = 0;
	unsigned int i;
	unsigned int num_cpu;

	header = &stats->ls_cnt_header[index];
	LASSERTF(header, "Failed to allocate stats header:[%d]%s/%s\n",
		 index, name, units);

	header->lc_config = conf;
	header->lc_name = name;
	header->lc_units = units;

	num_cpu = lprocfs_stats_lock(stats, LPROCFS_GET_NUM_CPU, &flags);
	for (i = 0; i < num_cpu; ++i) {
		if (!stats->ls_percpu[i])
			continue;
		percpu_cntr = lprocfs_stats_counter_get(stats, i, index);
		percpu_cntr->lc_count = 0;
		percpu_cntr->lc_min = LC_MIN_INIT;
		percpu_cntr->lc_max = 0;
		percpu_cntr->lc_sumsquare = 0;
		percpu_cntr->lc_sum = 0;
		if ((stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE) != 0)
			percpu_cntr->lc_sum_irq	= 0;
	}
	lprocfs_stats_unlock(stats, LPROCFS_GET_NUM_CPU, &flags);
}
EXPORT_SYMBOL(lprocfs_counter_init);

static const char * const mps_stats[] = {
	[LPROC_MD_CLOSE]		= "close",
	[LPROC_MD_CREATE]		= "create",
	[LPROC_MD_ENQUEUE]		= "enqueue",
	[LPROC_MD_GETATTR]		= "getattr",
	[LPROC_MD_INTENT_LOCK]		= "intent_lock",
	[LPROC_MD_LINK]			= "link",
	[LPROC_MD_RENAME]		= "rename",
	[LPROC_MD_SETATTR]		= "setattr",
	[LPROC_MD_FSYNC]		= "fsync",
	[LPROC_MD_READ_PAGE]		= "read_page",
	[LPROC_MD_UNLINK]		= "unlink",
	[LPROC_MD_SETXATTR]		= "setxattr",
	[LPROC_MD_GETXATTR]		= "getxattr",
	[LPROC_MD_INTENT_GETATTR_ASYNC]	= "intent_getattr_async",
	[LPROC_MD_REVALIDATE_LOCK]	= "revalidate_lock",
};

int ldebugfs_alloc_md_stats(struct obd_device *obd,
			    unsigned int num_private_stats)
{
	struct lprocfs_stats *stats;
	unsigned int num_stats;
	int i;

	/* No obd device debugfs tree to attach too */
	if (!obd->obd_debugfs_entry) {
		CWARN("%s: missing debugfs tree for registering md_stats.\n",
		      obd->obd_name);
		return 0;
	}

	if (obd->obd_md_stats)
		return -EINVAL;

	num_stats = ARRAY_SIZE(mps_stats) + num_private_stats;
	stats = lprocfs_alloc_stats(num_stats, 0);
	if (!stats)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(mps_stats); i++) {
		lprocfs_counter_init(stats, i, 0, mps_stats[i], "reqs");
		if (!stats->ls_cnt_header[i].lc_name) {
			CERROR("Missing md_stat initializer md_op operation at offset %d. Aborting.\n",
			       i);
			LBUG();
		}
	}
	obd->obd_md_stats = stats;

	debugfs_create_file("md_stats", 0644, obd->obd_debugfs_entry,
			    obd->obd_md_stats, &ldebugfs_stats_seq_fops);
	return 0;
}
EXPORT_SYMBOL(ldebugfs_alloc_md_stats);

void ldebugfs_free_md_stats(struct obd_device *obd)
{
	struct lprocfs_stats *stats = obd->obd_md_stats;

	if (!stats)
		return;

	obd->obd_md_stats = NULL;
	lprocfs_free_stats(&stats);
}
EXPORT_SYMBOL(ldebugfs_free_md_stats);

s64 lprocfs_read_helper(struct lprocfs_counter *lc,
			  struct lprocfs_counter_header *header,
			  enum lprocfs_stats_flags flags,
			  enum lprocfs_fields_flags field)
{
	s64 ret = 0;

	if (!lc || !header)
		return 0;

	switch (field) {
	case LPROCFS_FIELDS_FLAGS_CONFIG:
		ret = header->lc_config;
		break;
	case LPROCFS_FIELDS_FLAGS_SUM:
		ret = lc->lc_sum;
		if ((flags & LPROCFS_STATS_FLAG_IRQ_SAFE) != 0)
			ret += lc->lc_sum_irq;
		break;
	case LPROCFS_FIELDS_FLAGS_MIN:
		ret = lc->lc_min;
		break;
	case LPROCFS_FIELDS_FLAGS_MAX:
		ret = lc->lc_max;
		break;
	case LPROCFS_FIELDS_FLAGS_AVG:
		ret = (lc->lc_max - lc->lc_min) / 2;
		break;
	case LPROCFS_FIELDS_FLAGS_SUMSQUARE:
		ret = lc->lc_sumsquare;
		break;
	case LPROCFS_FIELDS_FLAGS_COUNT:
		ret = lc->lc_count;
		break;
	default:
		break;
	}

	return ret;
}
EXPORT_SYMBOL(lprocfs_read_helper);

int lprocfs_write_helper(const char __user *buffer, unsigned long count,
			 int *val)
{
	return lprocfs_write_frac_helper(buffer, count, val, 1);
}
EXPORT_SYMBOL(lprocfs_write_helper);

int lprocfs_write_u64_helper(const char __user *buffer, unsigned long count,
			     u64 *val)
{
	return lprocfs_write_frac_u64_helper(buffer, count, val, 1);
}
EXPORT_SYMBOL(lprocfs_write_u64_helper);

int lprocfs_write_frac_u64_helper(const char __user *buffer,
				  unsigned long count, u64 *val, int mult)
{
	char kernbuf[22], *end, *pbuf;
	u64 whole, frac = 0, units;
	unsigned int frac_d = 1;
	int sign = 1;

	if (count > (sizeof(kernbuf) - 1))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;

	kernbuf[count] = '\0';
	pbuf = kernbuf;
	if (*pbuf == '-') {
		sign = -1;
		pbuf++;
	}

	whole = simple_strtoull(pbuf, &end, 10);
	if (pbuf == end)
		return -EINVAL;

	if (*end == '.') {
		int i;

		pbuf = end + 1;

		/* need to limit frac_d to a u32 */
		if (strlen(pbuf) > 10)
			pbuf[10] = '\0';

		frac = simple_strtoull(pbuf, &end, 10);
		/* count decimal places */
		for (i = 0; i < (end - pbuf); i++)
			frac_d *= 10;
	}

	units = 1;
	if (end) {
		switch (tolower(*end)) {
		case 'p':
			units <<= 10;
			/* fall through */
		case 't':
			units <<= 10;
			/* fall through */
		case 'g':
			units <<= 10;
			/* fall through */
		case 'm':
			units <<= 10;
			/* fall through */
		case 'k':
			units <<= 10;
		}
	}
	/* Specified units override the multiplier */
	if (units > 1)
		mult = units;

	frac *= mult;
	do_div(frac, frac_d);
	*val = sign * (whole * mult + frac);
	return 0;
}
EXPORT_SYMBOL(lprocfs_write_frac_u64_helper);

/**
 * Find the string @name in the input @buffer, and return a pointer to the
 * value immediately following @name, reducing @count appropriately.
 * If @name is not found the original @buffer is returned.
 */
char *lprocfs_find_named_value(const char *buffer, const char *name,
			       size_t *count)
{
	char *val;
	size_t buflen = *count;

	val = strnstr(buffer, name, buflen);
	if (!val)
		return (char *)buffer;

	val += strlen(name);				/* skip prefix */
	while (val < buffer + buflen && isspace(*val))	/* skip separator */
		val++;

	*count = 0;
	while (val < buffer + buflen && isalnum(*val)) {
		++*count;
		++val;
	}

	return val - *count;
}
EXPORT_SYMBOL(lprocfs_find_named_value);

void lprocfs_oh_tally(struct obd_histogram *oh, unsigned int value)
{
	if (value >= OBD_HIST_MAX)
		value = OBD_HIST_MAX - 1;

	spin_lock(&oh->oh_lock);
	oh->oh_buckets[value]++;
	spin_unlock(&oh->oh_lock);
}
EXPORT_SYMBOL(lprocfs_oh_tally);

void lprocfs_oh_tally_log2(struct obd_histogram *oh, unsigned int value)
{
	unsigned int val = 0;

	if (likely(value != 0))
		val = min(fls(value - 1), OBD_HIST_MAX);

	lprocfs_oh_tally(oh, val);
}
EXPORT_SYMBOL(lprocfs_oh_tally_log2);

unsigned long lprocfs_oh_sum(struct obd_histogram *oh)
{
	unsigned long ret = 0;
	int i;

	for (i = 0; i < OBD_HIST_MAX; i++)
		ret +=  oh->oh_buckets[i];
	return ret;
}
EXPORT_SYMBOL(lprocfs_oh_sum);

void lprocfs_oh_clear(struct obd_histogram *oh)
{
	spin_lock(&oh->oh_lock);
	memset(oh->oh_buckets, 0, sizeof(oh->oh_buckets));
	spin_unlock(&oh->oh_lock);
}
EXPORT_SYMBOL(lprocfs_oh_clear);

int ldebugfs_root_squash_seq_write(const char __user *buffer,
				   unsigned long count,
				   struct root_squash_info *squash, char *name)
{
	char kernbuf[64], *tmp, *errmsg;
	unsigned long uid, gid;
	int rc;

	if (count >= sizeof(kernbuf)) {
		errmsg = "string too long";
		rc = -EINVAL;
		goto failed_noprint;
	}
	if (copy_from_user(kernbuf, buffer, count)) {
		errmsg = "bad address";
		rc = -EFAULT;
		goto failed_noprint;
	}
	kernbuf[count] = '\0';

	/* look for uid gid separator */
	tmp = strchr(kernbuf, ':');
	if (!tmp) {
		errmsg = "needs uid:gid format";
		rc = -EINVAL;
		goto failed;
	}
	*tmp = '\0';
	tmp++;

	/* parse uid */
	if (kstrtoul(kernbuf, 0, &uid) != 0) {
		errmsg = "bad uid";
		rc = -EINVAL;
		goto failed;
	}
	/* parse gid */
	if (kstrtoul(tmp, 0, &gid) != 0) {
		errmsg = "bad gid";
		rc = -EINVAL;
		goto failed;
	}

	squash->rsi_uid = uid;
	squash->rsi_gid = gid;

	LCONSOLE_INFO("%s: root_squash is set to %u:%u\n",
		      name, squash->rsi_uid, squash->rsi_gid);
	return count;

failed:
	if (tmp) {
		tmp--;
		*tmp = ':';
	}
	CWARN("%s: failed to set root_squash to \"%s\", %s, rc = %d\n",
	      name, kernbuf, errmsg, rc);
	return rc;
failed_noprint:
	CWARN("%s: failed to set root_squash due to %s, rc = %d\n",
	      name, errmsg, rc);
	return rc;
}
EXPORT_SYMBOL(ldebugfs_root_squash_seq_write);

int ldebugfs_nosquash_nids_seq_write(const char __user *buffer,
				     unsigned long count,
				     struct root_squash_info *squash,
				     char *name)
{
	char *kernbuf = NULL, *errmsg;
	LIST_HEAD(tmp);
	int len = count;
	int rc;

	if (count > 4096) {
		errmsg = "string too long";
		rc = -EINVAL;
		goto failed;
	}

	kernbuf = kzalloc(count + 1, GFP_NOFS);
	if (!kernbuf) {
		errmsg = "no memory";
		rc = -ENOMEM;
		goto failed;
	}

	if (copy_from_user(kernbuf, buffer, count)) {
		errmsg = "bad address";
		rc = -EFAULT;
		goto failed;
	}
	kernbuf[count] = '\0';

	if (count > 0 && kernbuf[count - 1] == '\n')
		len = count - 1;

	if ((len == 4 && !strncmp(kernbuf, "NONE", len)) ||
	    (len == 5 && !strncmp(kernbuf, "clear", len))) {
		/* empty string is special case */
		spin_lock(&squash->rsi_lock);
		if (!list_empty(&squash->rsi_nosquash_nids))
			cfs_free_nidlist(&squash->rsi_nosquash_nids);
		spin_unlock(&squash->rsi_lock);
		LCONSOLE_INFO("%s: nosquash_nids is cleared\n", name);
		kfree(kernbuf);
		return count;
	}

	if (cfs_parse_nidlist(kernbuf, count, &tmp) <= 0) {
		errmsg = "can't parse";
		rc = -EINVAL;
		goto failed;
	}
	LCONSOLE_INFO("%s: nosquash_nids set to %s\n",
		      name, kernbuf);
	kfree(kernbuf);
	kernbuf = NULL;

	spin_lock(&squash->rsi_lock);
	if (!list_empty(&squash->rsi_nosquash_nids))
		cfs_free_nidlist(&squash->rsi_nosquash_nids);
	list_splice(&tmp, &squash->rsi_nosquash_nids);
	spin_unlock(&squash->rsi_lock);

	return count;

failed:
	if (kernbuf) {
		CWARN("%s: failed to set nosquash_nids to \"%s\", %s rc = %d\n",
		      name, kernbuf, errmsg, rc);
		kfree(kernbuf);
		kernbuf = NULL;
	} else {
		CWARN("%s: failed to set nosquash_nids due to %s rc = %d\n",
		      name, errmsg, rc);
	}
	return rc;
}
EXPORT_SYMBOL(ldebugfs_nosquash_nids_seq_write);

ssize_t lustre_attr_show(struct kobject *kobj,
			 struct attribute *attr, char *buf)
{
	struct lustre_attr *a = container_of(attr, struct lustre_attr, attr);

	return a->show ? a->show(kobj, attr, buf) : 0;
}
EXPORT_SYMBOL_GPL(lustre_attr_show);

ssize_t lustre_attr_store(struct kobject *kobj, struct attribute *attr,
			  const char *buf, size_t len)
{
	struct lustre_attr *a = container_of(attr, struct lustre_attr, attr);

	return a->store ? a->store(kobj, attr, buf, len) : len;
}
EXPORT_SYMBOL_GPL(lustre_attr_store);

const struct sysfs_ops lustre_sysfs_ops = {
	.show		= lustre_attr_show,
	.store		= lustre_attr_store,
};
EXPORT_SYMBOL_GPL(lustre_sysfs_ops);

ssize_t max_pages_per_rpc_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return sprintf(buf, "%d\n", cli->cl_max_pages_per_rpc);
}
EXPORT_SYMBOL(max_pages_per_rpc_show);

ssize_t max_pages_per_rpc_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	struct obd_import *imp;
	struct obd_connect_data *ocd;
	int chunk_mask, rc;
	u64 val;

	rc = sysfs_memparse(buffer, count, &val, "B");
	if (rc)
		return rc;

	/* if the max_pages is specified in bytes, convert to pages */
	if (val >= ONE_MB_BRW_SIZE)
		val >>= PAGE_SHIFT;

	with_imp_locked(obd, imp, rc) {
		ocd = &imp->imp_connect_data;
		chunk_mask = ~((1 << (cli->cl_chunkbits - PAGE_SHIFT)) - 1);
		/* max_pages_per_rpc must be chunk aligned */
		val = (val + ~chunk_mask) & chunk_mask;
		if (!val || (ocd->ocd_brw_size &&
			     val > ocd->ocd_brw_size >> PAGE_SHIFT)) {
			up_read(&obd->u.cli.cl_sem);
			return -ERANGE;
		}

		spin_lock(&cli->cl_loi_list_lock);
		cli->cl_max_pages_per_rpc = val;
		client_adjust_max_dirty(cli);
		spin_unlock(&cli->cl_loi_list_lock);
	}

	return rc ?: count;
}
EXPORT_SYMBOL(max_pages_per_rpc_store);

ssize_t short_io_bytes_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	int rc;

	spin_lock(&cli->cl_loi_list_lock);
	rc = sprintf(buf, "%d\n", cli->cl_max_short_io_bytes);
	spin_unlock(&cli->cl_loi_list_lock);
	return rc;
}
EXPORT_SYMBOL(short_io_bytes_show);

/* Used to catch people who think they're specifying pages. */
#define MIN_SHORT_IO_BYTES 64

ssize_t short_io_bytes_store(struct kobject *kobj, struct attribute *attr,
			     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	u64 val;
	int rc;

	if (strcmp(buffer, "-1") == 0) {
		val = OBD_DEF_SHORT_IO_BYTES;
	} else {
		rc = sysfs_memparse(buffer, count, &val, "B");
		if (rc)
			goto out;
	}

	if (val && (val < MIN_SHORT_IO_BYTES || val > LNET_MTU)) {
		rc = -ERANGE;
		goto out;
	}

	rc = count;

	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_max_short_io_bytes = min_t(unsigned long long,
					   val, OST_MAX_SHORT_IO_BYTES);
	spin_unlock(&cli->cl_loi_list_lock);

out:
	return rc;
}
EXPORT_SYMBOL(short_io_bytes_store);
