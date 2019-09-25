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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/atomic.h>
#include <linux/miscdevice.h>
#include <linux/libcfs/libcfs.h>
#include <linux/uaccess.h>

#include <obd_support.h>
#include <obd_class.h>
#include <uapi/linux/lnet/lnetctl.h>
#include <lustre_kernelcomm.h>
#include <lprocfs_status.h>
#include <linux/list.h>
#include <cl_object.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <uapi/linux/lnet/libcfs_ioctl.h>
#include "llog_internal.h"

/* The following are visible and mutable through /sys/fs/lustre. */
unsigned int obd_debug_peer_on_timeout;
EXPORT_SYMBOL(obd_debug_peer_on_timeout);
unsigned int obd_dump_on_timeout;
EXPORT_SYMBOL(obd_dump_on_timeout);
unsigned int obd_dump_on_eviction;
EXPORT_SYMBOL(obd_dump_on_eviction);
unsigned long obd_max_dirty_pages;
EXPORT_SYMBOL(obd_max_dirty_pages);
atomic_long_t obd_dirty_pages;
EXPORT_SYMBOL(obd_dirty_pages);
unsigned int obd_timeout = OBD_TIMEOUT_DEFAULT;   /* seconds */
EXPORT_SYMBOL(obd_timeout);
unsigned int obd_timeout_set;
EXPORT_SYMBOL(obd_timeout_set);
/* Adaptive timeout defs here instead of ptlrpc module for /sys/fs/ access */
unsigned int at_min;
EXPORT_SYMBOL(at_min);
unsigned int at_max = 600;
EXPORT_SYMBOL(at_max);
unsigned int at_history = 600;
EXPORT_SYMBOL(at_history);
int at_early_margin = 5;
EXPORT_SYMBOL(at_early_margin);
int at_extra = 30;
EXPORT_SYMBOL(at_extra);

static int class_resolve_dev_name(u32 len, const char *name)
{
	int rc;
	int dev;

	if (!len || !name) {
		CERROR("No name passed,!\n");
		rc = -EINVAL;
		goto out;
	}
	if (name[len - 1] != 0) {
		CERROR("Name not nul terminated!\n");
		rc = -EINVAL;
		goto out;
	}

	CDEBUG(D_IOCTL, "device name %s\n", name);
	dev = class_name2dev(name);
	if (dev == -1) {
		CDEBUG(D_IOCTL, "No device for name %s!\n", name);
		rc = -EINVAL;
		goto out;
	}

	CDEBUG(D_IOCTL, "device name %s, dev %d\n", name, dev);
	rc = dev;

out:
	return rc;
}

#define OBD_MAX_IOCTL_BUFFER    8192

static int obd_ioctl_is_invalid(struct obd_ioctl_data *data)
{
	if (data->ioc_len > BIT(30)) {
		CERROR("OBD ioctl: ioc_len larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen1 > BIT(30)) {
		CERROR("OBD ioctl: ioc_inllen1 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen2 > BIT(30)) {
		CERROR("OBD ioctl: ioc_inllen2 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen3 > BIT(30)) {
		CERROR("OBD ioctl: ioc_inllen3 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen4 > BIT(30)) {
		CERROR("OBD ioctl: ioc_inllen4 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inlbuf1 && data->ioc_inllen1 == 0) {
		CERROR("OBD ioctl: inlbuf1 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf2 && data->ioc_inllen2 == 0) {
		CERROR("OBD ioctl: inlbuf2 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf3 && data->ioc_inllen3 == 0) {
		CERROR("OBD ioctl: inlbuf3 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf4 && data->ioc_inllen4 == 0) {
		CERROR("OBD ioctl: inlbuf4 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_pbuf1 && data->ioc_plen1 == 0) {
		CERROR("OBD ioctl: pbuf1 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_pbuf2 && data->ioc_plen2 == 0) {
		CERROR("OBD ioctl: pbuf2 pointer but 0 length\n");
		return 1;
	}

	if (!data->ioc_pbuf1 && data->ioc_plen1 != 0) {
		CERROR("OBD ioctl: plen1 set but NULL pointer\n");
		return 1;
	}

	if (!data->ioc_pbuf2 && data->ioc_plen2 != 0) {
		CERROR("OBD ioctl: plen2 set but NULL pointer\n");
		return 1;
	}

	if (obd_ioctl_packlen(data) > data->ioc_len) {
		CERROR("OBD ioctl: packlen exceeds ioc_len (%d > %d)\n",
		       obd_ioctl_packlen(data), data->ioc_len);
		return 1;
	}

	return 0;
}

/* buffer MUST be at least the size of obd_ioctl_hdr */
int obd_ioctl_getdata(struct obd_ioctl_data **datap, int *len, void __user *arg)
{
	struct obd_ioctl_data *data;
	struct obd_ioctl_hdr hdr;
	int offset = 0;
	int err;

	if (copy_from_user(&hdr, arg, sizeof(hdr)))
		return -EFAULT;

	if (hdr.ioc_version != OBD_IOCTL_VERSION) {
		CERROR("Version mismatch kernel (%x) vs application (%x)\n",
		       OBD_IOCTL_VERSION, hdr.ioc_version);
		return -EINVAL;
	}

	if (hdr.ioc_len > OBD_MAX_IOCTL_BUFFER) {
		CERROR("User buffer len %d exceeds %d max buffer\n",
		       hdr.ioc_len, OBD_MAX_IOCTL_BUFFER);
		return -EINVAL;
	}

	if (hdr.ioc_len < sizeof(struct obd_ioctl_data)) {
		CERROR("User buffer too small for ioctl (%d)\n", hdr.ioc_len);
		return -EINVAL;
	}

	/* When there are lots of processes calling vmalloc on multi-core
	 * system, the high lock contention will hurt performance badly,
	 * obdfilter-survey is an example, which relies on ioctl. So we'd
	 * better avoid vmalloc on ioctl path. LU-66
	 */
	data = kvzalloc(hdr.ioc_len, GFP_KERNEL);
	if (!data) {
		CERROR("Cannot allocate control buffer of len %d\n",
		       hdr.ioc_len);
		return -EINVAL;
	}
	*len = hdr.ioc_len;
	*datap = data;

	if (copy_from_user(data, arg, hdr.ioc_len)) {
		err = -EFAULT;
		goto free_buf;
	}

	if (hdr.ioc_len != data->ioc_len) {
		err = -EINVAL;
		goto free_buf;
	}

	if (obd_ioctl_is_invalid(data)) {
		CERROR("ioctl not correctly formatted\n");
		err = -EINVAL;
		goto free_buf;
	}

	if (data->ioc_inllen1) {
		data->ioc_inlbuf1 = &data->ioc_bulk[0];
		offset += cfs_size_round(data->ioc_inllen1);
	}

	if (data->ioc_inllen2) {
		data->ioc_inlbuf2 = &data->ioc_bulk[0] + offset;
		offset += cfs_size_round(data->ioc_inllen2);
	}

	if (data->ioc_inllen3) {
		data->ioc_inlbuf3 = &data->ioc_bulk[0] + offset;
		offset += cfs_size_round(data->ioc_inllen3);
	}

	if (data->ioc_inllen4)
		data->ioc_inlbuf4 = &data->ioc_bulk[0] + offset;

	return 0;

free_buf:
	kvfree(data);
	return err;
}
EXPORT_SYMBOL(obd_ioctl_getdata);

int class_handle_ioctl(unsigned int cmd, unsigned long arg)
{
	struct obd_ioctl_data *data;
	struct libcfs_debug_ioctl_data *debug_data;
	struct obd_device *obd = NULL;
	int err = 0, len = 0;

	/* only for debugging */
	if (cmd == LIBCFS_IOC_DEBUG_MASK) {
		debug_data = (struct libcfs_debug_ioctl_data *)arg;
		libcfs_subsystem_debug = debug_data->subs;
		libcfs_debug = debug_data->debug;
		return 0;
	}

	CDEBUG(D_IOCTL, "cmd = %x\n", cmd);
	if (obd_ioctl_getdata(&data, &len, (void __user *)arg)) {
		CERROR("OBD ioctl: data error\n");
		return -EINVAL;
	}

	switch (cmd) {
	case OBD_IOC_PROCESS_CFG: {
		struct lustre_cfg *lcfg;

		if (!data->ioc_plen1 || !data->ioc_pbuf1) {
			CERROR("No config buffer passed!\n");
			err = -EINVAL;
			goto out;
		}
		lcfg = kzalloc(data->ioc_plen1, GFP_NOFS);
		if (!lcfg) {
			err = -ENOMEM;
			goto out;
		}
		if (copy_from_user(lcfg, data->ioc_pbuf1, data->ioc_plen1))
			err = -EFAULT;
		if (!err)
			err = lustre_cfg_sanity_check(lcfg, data->ioc_plen1);
		if (!err)
			err = class_process_config(lcfg);

		kfree(lcfg);
		goto out;
	}

	case OBD_GET_VERSION: {

		/* This was the method to pass to user land the lustre version.
		 * Today that information is in the sysfs tree so we can in the
		 * future remove this.
		 */
		BUILD_BUG_ON(OBD_OCD_VERSION(3, 0, 53, 0) <=
			     LUSTRE_VERSION_CODE);

		if (!data->ioc_inlbuf1) {
			CERROR("No buffer passed in ioctl\n");
			err = -EINVAL;
			goto out;
		}

		if (strlen(LUSTRE_VERSION_STRING) + 1 > data->ioc_inllen1) {
			CERROR("ioctl buffer too small to hold version\n");
			err = -EINVAL;
			goto out;
		}

		WARN_ONCE(1,
			  "ioctl(OBD_GET_VERSION) is deprecated, use llapi_get_version_string() and/or relink\n");

		memcpy(data->ioc_bulk, LUSTRE_VERSION_STRING,
		       strlen(LUSTRE_VERSION_STRING) + 1);

		if (copy_to_user((void __user *)arg, data, len))
			err = -EFAULT;
		goto out;
	}
	case OBD_IOC_NAME2DEV: {
		/* Resolve a device name.  This does not change the
		 * currently selected device.
		 */
		int dev;

		dev = class_resolve_dev_name(data->ioc_inllen1,
					     data->ioc_inlbuf1);
		data->ioc_dev = dev;
		if (dev < 0) {
			err = -EINVAL;
			goto out;
		}

		if (copy_to_user((void __user *)arg, data, sizeof(*data)))
			err = -EFAULT;
		goto out;
	}

	case OBD_IOC_UUID2DEV: {
		/* Resolve a device uuid.  This does not change the
		 * currently selected device.
		 */
		int dev;
		struct obd_uuid uuid;

		if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
			CERROR("No UUID passed!\n");
			err = -EINVAL;
			goto out;
		}
		if (data->ioc_inlbuf1[data->ioc_inllen1 - 1] != 0) {
			CERROR("UUID not NUL terminated!\n");
			err = -EINVAL;
			goto out;
		}

		CDEBUG(D_IOCTL, "device name %s\n", data->ioc_inlbuf1);
		obd_str2uuid(&uuid, data->ioc_inlbuf1);
		dev = class_uuid2dev(&uuid);
		data->ioc_dev = dev;
		if (dev == -1) {
			CDEBUG(D_IOCTL, "No device for UUID %s!\n",
			       data->ioc_inlbuf1);
			err = -EINVAL;
			goto out;
		}

		CDEBUG(D_IOCTL, "device name %s, dev %d\n", data->ioc_inlbuf1,
		       dev);

		if (copy_to_user((void __user *)arg, data, sizeof(*data)))
			err = -EFAULT;
		goto out;
	}

	case OBD_IOC_GETDEVICE: {
		int     index = data->ioc_count;
		char    *status, *str;

		if (!data->ioc_inlbuf1) {
			CERROR("No buffer passed in ioctl\n");
			err = -EINVAL;
			goto out;
		}
		if (data->ioc_inllen1 < 128) {
			CERROR("ioctl buffer too small to hold version\n");
			err = -EINVAL;
			goto out;
		}

		obd = class_num2obd(index);
		if (!obd) {
			err = -ENOENT;
			goto out;
		}

		if (obd->obd_stopping)
			status = "ST";
		else if (obd->obd_set_up)
			status = "UP";
		else if (obd->obd_attached)
			status = "AT";
		else
			status = "--";
		str = (char *)data->ioc_bulk;
		snprintf(str, len - sizeof(*data), "%3d %s %s %s %s %d",
			 (int)index, status, obd->obd_type->typ_name,
			 obd->obd_name, obd->obd_uuid.uuid,
			 atomic_read(&obd->obd_refcount));

		if (copy_to_user((void __user *)arg, data, len))
			err = -EFAULT;
		goto out;
	}
	}

	if (data->ioc_dev == OBD_DEV_BY_DEVNAME) {
		if (data->ioc_inllen4 <= 0 || !data->ioc_inlbuf4) {
			err = -EINVAL;
			goto out;
		}
		if (strnlen(data->ioc_inlbuf4, MAX_OBD_NAME) >= MAX_OBD_NAME) {
			err = -EINVAL;
			goto out;
		}
		obd = class_name2obd(data->ioc_inlbuf4);
	} else if (data->ioc_dev < class_devno_max()) {
		obd = class_num2obd(data->ioc_dev);
	} else {
		CERROR("OBD ioctl: No device\n");
		err = -EINVAL;
		goto out;
	}

	if (!obd) {
		CERROR("OBD ioctl : No Device %d\n", data->ioc_dev);
		err = -EINVAL;
		goto out;
	}
	LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);

	if (!obd->obd_set_up || obd->obd_stopping) {
		CERROR("OBD ioctl: device not setup %d\n", data->ioc_dev);
		err = -EINVAL;
		goto out;
	}

	switch (cmd) {
	case OBD_IOC_NO_TRANSNO:
		if (!obd->obd_attached) {
			CERROR("Device %d not attached\n", obd->obd_minor);
			err = -ENODEV;
			goto out;
		}
		CDEBUG(D_HA, "%s: disabling committed-transno notification\n",
		       obd->obd_name);
		err = 0;
		break;

	default:
		err = obd_iocontrol(cmd, obd->obd_self_export, len, data, NULL);
		if (err)
			goto out;

		if (copy_to_user((void __user *)arg, data, len))
			err = -EFAULT;
		break;
	}

 out:
	kvfree(data);
	return err;
} /* class_handle_ioctl */

/* to control /dev/obd */
static long obd_class_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	/* Allow non-root access for OBD_IOC_PING_TARGET - used by lfs check */
	if (!capable(CAP_SYS_ADMIN) && (cmd != OBD_IOC_PING_TARGET))
		return -EACCES;

	if ((cmd & 0xffffff00) == ((int)'T') << 8) /* ignore all tty ioctls */
		return -ENOTTY;

	return class_handle_ioctl(cmd, (unsigned long)arg);
}

/* declare character device */
static const struct file_operations obd_psdev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= obd_class_ioctl,
};

/* modules setup */
static struct miscdevice obd_psdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= OBD_DEV_NAME,
	.fops		= &obd_psdev_fops,
};

static int obd_init_checks(void)
{
	u64 u64val, div64val;
	char buf[64];
	int len, ret = 0;

	CDEBUG(D_INFO, "LPU64=%s, LPD64=%s, LPX64=%s\n", "%llu", "%lld",
	       "%#llx");

	CDEBUG(D_INFO, "OBD_OBJECT_EOF = %#llx\n", (u64)OBD_OBJECT_EOF);

	u64val = OBD_OBJECT_EOF;
	CDEBUG(D_INFO, "u64val OBD_OBJECT_EOF = %#llx\n", u64val);
	if (u64val != OBD_OBJECT_EOF) {
		CERROR("u64 %#llx(%d) != 0xffffffffffffffff\n",
		       u64val, (int)sizeof(u64val));
		ret = -EINVAL;
	}
	len = snprintf(buf, sizeof(buf), "%#llx", u64val);
	if (len != 18) {
		CWARN("LPX64 wrong length! strlen(%s)=%d != 18\n", buf, len);
		ret = -EINVAL;
	}

	div64val = OBD_OBJECT_EOF;
	CDEBUG(D_INFO, "u64val OBD_OBJECT_EOF = %#llx\n", u64val);
	if (u64val != OBD_OBJECT_EOF) {
		CERROR("u64 %#llx(%d) != 0xffffffffffffffff\n",
		       u64val, (int)sizeof(u64val));
		ret = -EOVERFLOW;
	}
	if (u64val >> 8 != OBD_OBJECT_EOF >> 8) {
		CERROR("u64 %#llx(%d) != 0xffffffffffffffff\n",
		       u64val, (int)sizeof(u64val));
		return -EOVERFLOW;
	}
	if (do_div(div64val, 256) != (u64val & 255)) {
		CERROR("do_div(%#llx,256) != %llu\n", u64val, u64val & 255);
		return -EOVERFLOW;
	}
	if (u64val >> 8 != div64val) {
		CERROR("do_div(%#llx,256) %llu != %llu\n",
		       u64val, div64val, u64val >> 8);
		return -EOVERFLOW;
	}
	len = snprintf(buf, sizeof(buf), "%#llx", u64val);
	if (len != 18) {
		CWARN("LPX64 wrong length! strlen(%s)=%d != 18\n", buf, len);
		ret = -EINVAL;
	}
	len = snprintf(buf, sizeof(buf), "%llu", u64val);
	if (len != 20) {
		CWARN("LPU64 wrong length! strlen(%s)=%d != 20\n", buf, len);
		ret = -EINVAL;
	}
	len = snprintf(buf, sizeof(buf), "%lld", u64val);
	if (len != 2) {
		CWARN("LPD64 wrong length! strlen(%s)=%d != 2\n", buf, len);
		ret = -EINVAL;
	}
	if ((u64val & ~PAGE_MASK) >= PAGE_SIZE) {
		CWARN("mask failed: u64val %llu >= %llu\n", u64val,
		      (u64)PAGE_SIZE);
		ret = -EINVAL;
	}

	return ret;
}

static int __init obdclass_init(void)
{
	int err;

	LCONSOLE_INFO("Lustre: Build Version: " LUSTRE_VERSION_STRING "\n");

	err = libcfs_setup();
	if (err)
		return err;

	libcfs_kkuc_init();

	err = obd_zombie_impexp_init();
	if (err)
		return err;

	err = obd_init_checks();
	if (err)
		goto cleanup_zombie_impexp;

	err = class_handle_init();
	if (err)
		goto cleanup_zombie_impexp;

	err = misc_register(&obd_psdev);
	if (err) {
		CERROR("cannot register OBD miscdevices: err %d\n", err);
		goto cleanup_class_handle;
	}

	/* Default the dirty page cache cap to 1/2 of system memory.
	 * For clients with less memory, a larger fraction is needed
	 * for other purposes (mostly for BGL).
	 */
	if (totalram_pages() <= 512 << (20 - PAGE_SHIFT))
		obd_max_dirty_pages = totalram_pages() / 4;
	else
		obd_max_dirty_pages = totalram_pages() / 2;

	err = obd_init_caches();
	if (err)
		goto cleanup_deregister;

	err = class_procfs_init();
	if (err)
		goto cleanup_caches;

	err = lu_global_init();
	if (err)
		goto cleanup_class_procfs;

	err = cl_global_init();
	if (err != 0)
		goto cleanup_lu_global;

	err = llog_info_init();
	if (err)
		goto cleanup_cl_global;

	/* simulate a late OOM situation now to require all
	 * alloc'ed/initialized resources to be freed
	 */
	if (!OBD_FAIL_CHECK(OBD_FAIL_OBDCLASS_MODULE_LOAD))
		return 0;

	/* force error to ensure module will be unloaded/cleaned */
	err = -ENOMEM;

	llog_info_fini();

cleanup_cl_global:
	cl_global_fini();

cleanup_lu_global:
	lu_global_fini();

cleanup_class_procfs:
	class_procfs_clean();

cleanup_caches:
	obd_cleanup_caches();

cleanup_deregister:
	misc_deregister(&obd_psdev);

cleanup_class_handle:
	class_handle_cleanup();

cleanup_zombie_impexp:
	obd_zombie_impexp_stop();

	if (err)
		return err;

	return err;
}

static void obdclass_exit(void)
{
	misc_deregister(&obd_psdev);
	llog_info_fini();
	cl_global_fini();
	lu_global_fini();

	obd_cleanup_caches();

	class_procfs_clean();

	class_handle_cleanup();
	class_del_uuid(NULL); /* Delete all UUIDs. */
	obd_zombie_impexp_stop();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Class Driver");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(obdclass_init);
module_exit(obdclass_exit);
