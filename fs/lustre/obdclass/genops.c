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
 *
 * lustre/obdclass/genops.c
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS
#include <obd_class.h>
#include <lustre_log.h>
#include <lprocfs_status.h>
#include <lustre_kernelcomm.h>

DEFINE_RWLOCK(obd_dev_lock);
static struct obd_device *obd_devs[MAX_OBD_DEVICES];

static struct kmem_cache *obd_device_cachep;
struct kmem_cache *obdo_cachep;
EXPORT_SYMBOL(obdo_cachep);
static struct kmem_cache *import_cachep;

static struct kobj_type class_ktype;
static struct workqueue_struct *zombie_wq;
static void obd_zombie_export_add(struct obd_export *exp);
static void obd_zombie_import_add(struct obd_import *imp);

/*
 * support functions: we could use inter-module communication, but this
 * is more portable to other OS's
 */
static struct obd_device *obd_device_alloc(void)
{
	struct obd_device *obd;

	obd = kmem_cache_zalloc(obd_device_cachep, GFP_NOFS);
	if (obd)
		obd->obd_magic = OBD_DEVICE_MAGIC;
	return obd;
}

static void obd_device_free(struct obd_device *obd)
{
	LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC,
		 "obd %p obd_magic %08x != %08x\n",
		 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
	if (obd->obd_namespace) {
		CERROR("obd %p: namespace %p was not properly cleaned up (obd_force=%d)!\n",
		       obd, obd->obd_namespace, obd->obd_force);
		LBUG();
	}
	lu_ref_fini(&obd->obd_reference);
	kmem_cache_free(obd_device_cachep, obd);
}

static struct obd_type *class_search_type(const char *name)
{
	struct kobject *kobj = kset_find_obj(lustre_kset, name);

	if (kobj && kobj->ktype == &class_ktype)
		return container_of(kobj, struct obd_type, typ_kobj);
	kobject_put(kobj);

	return NULL;
}

static struct obd_type *class_get_type(const char *name)
{
	struct obd_type *type;

	rcu_read_lock();
	type = class_search_type(name);

	if (!type) {
		const char *modname = name;

		rcu_read_unlock();
		if (!request_module("%s", modname)) {
			CDEBUG(D_INFO, "Loaded module '%s'\n", modname);
		} else {
			LCONSOLE_ERROR_MSG(0x158, "Can't load module '%s'\n",
					   modname);
		}
		rcu_read_lock();
		type = class_search_type(name);
	}
	if (type) {
		/*
		 * Holding rcu_read_lock() matches the synchronize_rcu() call
		 * in free_module() and ensures that if type->typ_dt_ops is
		 * not yet NULL, then the module won't be freed until after
		 * we rcu_read_unlock().
		 */
		const struct obd_ops *dt_ops = READ_ONCE(type->typ_dt_ops);
		if (dt_ops && try_module_get(dt_ops->owner)) {
			atomic_inc(&type->typ_refcnt);
			/* class_search_type() returned a counted reference,
			 * but we don't need that count any more as
			 * we have one through typ_refcnt.
			 */
			kobject_put(&type->typ_kobj);
		} else {
			kobject_put(&type->typ_kobj);
			type = NULL;
		}
	}
	rcu_read_unlock();
	return type;
}

void class_put_type(struct obd_type *type)
{
	LASSERT(type);
	module_put(type->typ_dt_ops->owner);
	atomic_dec(&type->typ_refcnt);
}

static void class_sysfs_release(struct kobject *kobj)
{
	struct obd_type *type = container_of(kobj, struct obd_type, typ_kobj);

	debugfs_remove_recursive(type->typ_debugfs_entry);

	if (type->typ_lu)
		lu_device_type_fini(type->typ_lu);

	kfree(type);
}

static struct kobj_type class_ktype = {
	.sysfs_ops	= &lustre_sysfs_ops,
	.release	= class_sysfs_release,
};

#define CLASS_MAX_NAME 1024

int class_register_type(const struct obd_ops *dt_ops,
			const struct md_ops *md_ops,
			const char *name,
			struct lu_device_type *ldt)
{
	struct obd_type *type;
	int rc;

	/* sanity check */
	LASSERT(strnlen(name, CLASS_MAX_NAME) < CLASS_MAX_NAME);

	type = class_search_type(name);
	if (type) {
		CDEBUG(D_IOCTL, "Type %s already registered\n", name);
		kobject_put(&type->typ_kobj);
		return -EEXIST;
	}

	type = kzalloc(sizeof(*type), GFP_NOFS);
	if (!type)
		return -ENOMEM;

	type->typ_kobj.kset = lustre_kset;
	kobject_init(&type->typ_kobj, &class_ktype);

	type->typ_dt_ops = dt_ops;
	type->typ_md_ops = md_ops;

	rc = kobject_add(&type->typ_kobj, &lustre_kset->kobj, "%s", name);
	if (rc)
		goto failed;

	type->typ_debugfs_entry = debugfs_create_dir(type->typ_name,
						     debugfs_lustre_root);

	if (ldt) {
		type->typ_lu = ldt;
		rc = lu_device_type_init(ldt);
		if (rc != 0)
			goto failed;
	}

	return 0;

failed:
	kobject_put(&type->typ_kobj);

	return rc;
}
EXPORT_SYMBOL(class_register_type);

int class_unregister_type(const char *name)
{
	struct obd_type *type = class_search_type(name);

	if (!type) {
		CERROR("unknown obd type\n");
		return -EINVAL;
	}

	/*
	 * Ensure that class_get_type doesn't try to get the module
	 * as it could be freed before the obd_type is released.
	 * synchronize_rcu() will be called before the module
	 * is freed.
	 */
	type->typ_dt_ops = NULL;

	if (atomic_read(&type->typ_refcnt)) {
		CERROR("type %s has refcount (%d)\n", name, atomic_read(&type->typ_refcnt));
		/* This is a bad situation, let's make the best of it */
		/* Remove ops, but leave the name for debugging */
		type->typ_md_ops = NULL;
		kobject_put(&type->typ_kobj);
		return -EBUSY;
	}

	/* Put the ref returned by class_search_type() */
	kobject_put(&type->typ_kobj);
	/* Put the final ref */
	kobject_put(&type->typ_kobj);

	return 0;
} /* class_unregister_type */
EXPORT_SYMBOL(class_unregister_type);

/**
 * Create a new obd device.
 *
 * Allocate the new obd_device and initialize it.
 *
 * @type_name:		obd device type string.
 * @name:		obd device name.
 * @uuid:		obd device UUID.
 *
 * Returns:		newdev pointer to created obd_device
 *			ERR_PTR(errno) on error
 */
struct obd_device *class_newdev(const char *type_name, const char *name,
				const char *uuid)
{
	struct obd_device *newdev;
	struct obd_type *type = NULL;

	if (strlen(name) >= MAX_OBD_NAME) {
		CERROR("name/uuid must be < %u bytes long\n", MAX_OBD_NAME);
		return ERR_PTR(-EINVAL);
	}

	type = class_get_type(type_name);
	if (!type) {
		CERROR("OBD: unknown type: %s\n", type_name);
		return ERR_PTR(-ENODEV);
	}

	newdev = obd_device_alloc();
	if (!newdev) {
		class_put_type(type);
		return ERR_PTR(-ENOMEM);
	}

	LASSERT(newdev->obd_magic == OBD_DEVICE_MAGIC);
	strncpy(newdev->obd_name, name, sizeof(newdev->obd_name) - 1);
	newdev->obd_type = type;
	newdev->obd_minor = -1;

	rwlock_init(&newdev->obd_pool_lock);
	newdev->obd_pool_limit = 0;
	newdev->obd_pool_slv = 0;

	INIT_LIST_HEAD(&newdev->obd_exports);
	INIT_LIST_HEAD(&newdev->obd_unlinked_exports);
	INIT_LIST_HEAD(&newdev->obd_delayed_exports);
	spin_lock_init(&newdev->obd_nid_lock);
	spin_lock_init(&newdev->obd_dev_lock);
	mutex_init(&newdev->obd_dev_mutex);
	spin_lock_init(&newdev->obd_osfs_lock);
	/* newdev->obd_osfs_age must be set to a value in the distant
	 * past to guarantee a fresh statfs is fetched on mount.
	 */
	newdev->obd_osfs_age = ktime_get_seconds() - 1000;

	/* XXX belongs in setup not attach  */
	init_rwsem(&newdev->obd_observer_link_sem);
	/* recovery data */
	init_waitqueue_head(&newdev->obd_evict_inprogress_waitq);

	llog_group_init(&newdev->obd_olg);
	/* Detach drops this */
	atomic_set(&newdev->obd_refcount, 1);
	lu_ref_init(&newdev->obd_reference);
	lu_ref_add(&newdev->obd_reference, "newdev", newdev);

	newdev->obd_conn_inprogress = 0;

	strncpy(newdev->obd_uuid.uuid, uuid, UUID_MAX);

	CDEBUG(D_IOCTL, "Allocate new device %s (%p)\n",
	       newdev->obd_name, newdev);

	return newdev;
}

/**
 * Free obd device.
 *
 * @obd obd_device to be freed
 *
 * RETURN none
 */
void class_free_dev(struct obd_device *obd)
{
	struct obd_type *obd_type = obd->obd_type;

	LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC, "%p obd_magic %08x != %08x\n",
		 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
	LASSERTF(obd->obd_minor == -1 || obd == obd_devs[obd->obd_minor],
		 "obd %p != obd_devs[%d] %p\n",
		 obd, obd->obd_minor, obd_devs[obd->obd_minor]);
	LASSERTF(atomic_read(&obd->obd_refcount) == 0,
		 "obd_refcount should be 0, not %d\n",
		 atomic_read(&obd->obd_refcount));
	LASSERT(obd_type);

	CDEBUG(D_INFO, "Release obd device %s obd_type name =%s\n",
	       obd->obd_name, obd->obd_type->typ_name);

	CDEBUG(D_CONFIG, "finishing cleanup of obd %s (%s)\n",
	       obd->obd_name, obd->obd_uuid.uuid);
	if (obd->obd_stopping) {
		int err;

		/* If we're not stopping, we were never set up */
		err = obd_cleanup(obd);
		if (err)
			CERROR("Cleanup %s returned %d\n",
			       obd->obd_name, err);
	}

	obd_device_free(obd);

	class_put_type(obd_type);
}

/**
 * Unregister obd device.
 *
 * Free slot in obd_dev[] used by @obd.
 *
 * @new_obd	obd_device to be unregistered
 *
 * RETURN	none
 */
void class_unregister_device(struct obd_device *obd)
{
	write_lock(&obd_dev_lock);
	if (obd->obd_minor >= 0) {
		LASSERT(obd_devs[obd->obd_minor] == obd);
		obd_devs[obd->obd_minor] = NULL;
		obd->obd_minor = -1;
	}
	write_unlock(&obd_dev_lock);
}

/**
 * Register obd device.
 *
 * Find free slot in obd_devs[], fills it with @new_obd.
 *
 * @new_obd	obd_device to be registered
 *
 * RETURN	0		success
 *		-EEXIST		device with this name is registered
 *		-EOVERFLOW	obd_devs[] is full
 */
int class_register_device(struct obd_device *new_obd)
{
	int new_obd_minor = 0;
	bool minor_assign = false;
	int ret = 0;
	int i;

	write_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		struct obd_device *obd = class_num2obd(i);

		if (obd && (strcmp(new_obd->obd_name, obd->obd_name) == 0)) {
			CERROR("%s: already exists, won't add\n",
			       obd->obd_name);
			/* in case we found a free slot before duplicate */
			minor_assign = false;
			ret = -EEXIST;
			break;
		}
		if (!minor_assign && !obd) {
			new_obd_minor = i;
			minor_assign = true;
		}
	}

	if (minor_assign) {
		new_obd->obd_minor = new_obd_minor;
		LASSERTF(!obd_devs[new_obd_minor], "obd_devs[%d] %p\n",
			 new_obd_minor, obd_devs[new_obd_minor]);
		obd_devs[new_obd_minor] = new_obd;
	} else {
		if (ret == 0) {
			ret = -EOVERFLOW;
			CERROR("%s: all %u/%u devices used, increase MAX_OBD_DEVICES: rc = %d\n",
			       new_obd->obd_name, i, class_devno_max(), ret);
		}
	}
	write_unlock(&obd_dev_lock);

	return ret;
}


int class_name2dev(const char *name)
{
	int i;

	if (!name)
		return -1;

	read_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		struct obd_device *obd = class_num2obd(i);

		if (obd && strcmp(name, obd->obd_name) == 0) {
			/* Make sure we finished attaching before we give
			 * out any references
			 */
			LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
			if (obd->obd_attached) {
				read_unlock(&obd_dev_lock);
				return i;
			}
			break;
		}
	}
	read_unlock(&obd_dev_lock);

	return -1;
}

struct obd_device *class_name2obd(const char *name)
{
	int dev = class_name2dev(name);

	if (dev < 0 || dev > class_devno_max())
		return NULL;
	return class_num2obd(dev);
}
EXPORT_SYMBOL(class_name2obd);

int class_uuid2dev(struct obd_uuid *uuid)
{
	int i;

	read_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		struct obd_device *obd = class_num2obd(i);

		if (obd && obd_uuid_equals(uuid, &obd->obd_uuid)) {
			LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
			read_unlock(&obd_dev_lock);
			return i;
		}
	}
	read_unlock(&obd_dev_lock);

	return -1;
}

/**
 * Get obd device from ::obd_devs[]
 *
 * @num		array index
 *
 * Return:	NULL if ::obd_devs[@num] does not contains an obd device
 *		otherwise return the obd device there.
 */
struct obd_device *class_num2obd(int num)
{
	struct obd_device *obd = NULL;

	if (num < class_devno_max()) {
		obd = obd_devs[num];
		if (!obd)
			return NULL;

		LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC,
			 "%p obd_magic %08x != %08x\n",
			 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
		LASSERTF(obd->obd_minor == num,
			 "%p obd_minor %0d != %0d\n",
			 obd, obd->obd_minor, num);
	}

	return obd;
}

/* Search for a client OBD connected to tgt_uuid.  If grp_uuid is
 * specified, then only the client with that uuid is returned,
 * otherwise any client connected to the tgt is returned.
 */
struct obd_device *class_find_client_obd(struct obd_uuid *tgt_uuid,
					 const char *type_name,
					 struct obd_uuid *grp_uuid)
{
	int i;

	read_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		struct obd_device *obd = class_num2obd(i);

		if (!obd)
			continue;
		if ((strncmp(obd->obd_type->typ_name, type_name,
			     strlen(type_name)) == 0)) {
			if (obd_uuid_equals(tgt_uuid,
					    &obd->u.cli.cl_target_uuid) &&
			    ((grp_uuid) ? obd_uuid_equals(grp_uuid,
							 &obd->obd_uuid) : 1)) {
				read_unlock(&obd_dev_lock);
				return obd;
			}
		}
	}
	read_unlock(&obd_dev_lock);

	return NULL;
}
EXPORT_SYMBOL(class_find_client_obd);

/* Iterate the obd_device list looking devices have grp_uuid. Start
 * searching at *next, and if a device is found, the next index to look
 * at is saved in *next. If next is NULL, then the first matching device
 * will always be returned.
 */
struct obd_device *class_devices_in_group(struct obd_uuid *grp_uuid, int *next)
{
	int i;

	if (!next)
		i = 0;
	else if (*next >= 0 && *next < class_devno_max())
		i = *next;
	else
		return NULL;

	read_lock(&obd_dev_lock);
	for (; i < class_devno_max(); i++) {
		struct obd_device *obd = class_num2obd(i);

		if (!obd)
			continue;
		if (obd_uuid_equals(grp_uuid, &obd->obd_uuid)) {
			if (next)
				*next = i + 1;
			read_unlock(&obd_dev_lock);
			return obd;
		}
	}
	read_unlock(&obd_dev_lock);

	return NULL;
}
EXPORT_SYMBOL(class_devices_in_group);

/**
 * to notify sptlrpc log for @fsname has changed, let every relevant OBD
 * adjust sptlrpc settings accordingly.
 */
int class_notify_sptlrpc_conf(const char *fsname, int namelen)
{
	struct obd_device *obd;
	const char *type;
	int i, rc = 0, rc2;

	LASSERT(namelen > 0);

	read_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		obd = class_num2obd(i);

		if (!obd || obd->obd_set_up == 0 || obd->obd_stopping)
			continue;

		/* only notify mdc, osc, mdt, ost */
		type = obd->obd_type->typ_name;
		if (strcmp(type, LUSTRE_MDC_NAME) != 0 &&
		    strcmp(type, LUSTRE_OSC_NAME) != 0 &&
		    strcmp(type, LUSTRE_MDT_NAME) != 0 &&
		    strcmp(type, LUSTRE_OST_NAME) != 0)
			continue;

		if (strncmp(obd->obd_name, fsname, namelen))
			continue;

		class_incref(obd, __func__, obd);
		read_unlock(&obd_dev_lock);
		rc2 = obd_set_info_async(NULL, obd->obd_self_export,
					 sizeof(KEY_SPTLRPC_CONF),
					 KEY_SPTLRPC_CONF, 0, NULL, NULL);
		rc = rc ? rc : rc2;
		class_decref(obd, __func__, obd);
		read_lock(&obd_dev_lock);
	}
	read_unlock(&obd_dev_lock);
	return rc;
}
EXPORT_SYMBOL(class_notify_sptlrpc_conf);

void obd_cleanup_caches(void)
{
	kmem_cache_destroy(obd_device_cachep);
	obd_device_cachep = NULL;
	kmem_cache_destroy(obdo_cachep);
	obdo_cachep = NULL;
	kmem_cache_destroy(import_cachep);
	import_cachep = NULL;
}

int obd_init_caches(void)
{
	LASSERT(!obd_device_cachep);
	obd_device_cachep = kmem_cache_create("ll_obd_dev_cache",
					      sizeof(struct obd_device),
					      0, 0, NULL);
	if (!obd_device_cachep)
		goto out;

	LASSERT(!obdo_cachep);
	obdo_cachep = kmem_cache_create("ll_obdo_cache", sizeof(struct obdo),
					0, 0, NULL);
	if (!obdo_cachep)
		goto out;

	LASSERT(!import_cachep);
	import_cachep = kmem_cache_create("ll_import_cache",
					  sizeof(struct obd_import),
					  0, 0, NULL);
	if (!import_cachep)
		goto out;

	return 0;
out:
	obd_cleanup_caches();
	return -ENOMEM;
}

static const char export_handle_owner[] = "export";

/* map connection to client */
struct obd_export *class_conn2export(struct lustre_handle *conn)
{
	struct obd_export *export;

	if (!conn) {
		CDEBUG(D_CACHE, "looking for null handle\n");
		return NULL;
	}

	if (conn->cookie == -1) {  /* this means assign a new connection */
		CDEBUG(D_CACHE, "want a new connection\n");
		return NULL;
	}

	CDEBUG(D_INFO, "looking for export cookie %#llx\n", conn->cookie);
	export = class_handle2object(conn->cookie, export_handle_owner);
	return export;
}
EXPORT_SYMBOL(class_conn2export);

struct obd_device *class_exp2obd(struct obd_export *exp)
{
	if (exp)
		return exp->exp_obd;
	return NULL;
}
EXPORT_SYMBOL(class_exp2obd);

struct obd_import *class_exp2cliimp(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;

	if (!obd)
		return NULL;
	return obd->u.cli.cl_import;
}
EXPORT_SYMBOL(class_exp2cliimp);

/* Export management functions */
static void class_export_destroy(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;

	LASSERT(refcount_read(&exp->exp_handle.h_ref) == 0);
	LASSERT(obd);

	CDEBUG(D_IOCTL, "destroying export %p/%s for %s\n", exp,
	       exp->exp_client_uuid.uuid, obd->obd_name);

	ptlrpc_connection_put(exp->exp_connection);

	LASSERT(list_empty(&exp->exp_outstanding_replies));
	LASSERT(list_empty(&exp->exp_uncommitted_replies));
	LASSERT(list_empty(&exp->exp_req_replay_queue));
	LASSERT(list_empty(&exp->exp_hp_rpcs));
	obd_destroy_export(exp);
	/* self export doesn't hold a reference to an obd, although it
	 * exists until freeing of the obd
	 */
	if (exp != obd->obd_self_export)
		class_decref(obd, "export", exp);

	kfree_rcu(exp, exp_handle.h_rcu);
}

struct obd_export *class_export_get(struct obd_export *exp)
{
	refcount_inc(&exp->exp_handle.h_ref);
	CDEBUG(D_INFO, "GET export %p refcount=%d\n", exp,
	       refcount_read(&exp->exp_handle.h_ref));
	return exp;
}
EXPORT_SYMBOL(class_export_get);

void class_export_put(struct obd_export *exp)
{
	LASSERT(refcount_read(&exp->exp_handle.h_ref) >  0);
	LASSERT(refcount_read(&exp->exp_handle.h_ref) < LI_POISON);
	CDEBUG(D_INFO, "PUTting export %p : new refcount %d\n", exp,
	       refcount_read(&exp->exp_handle.h_ref) - 1);

	if (refcount_dec_and_test(&exp->exp_handle.h_ref)) {
		struct obd_device *obd = exp->exp_obd;

		CDEBUG(D_IOCTL, "final put %p/%s\n",
		       exp, exp->exp_client_uuid.uuid);

		if (exp == obd->obd_self_export) {
			/* self export should be destroyed without
			 * zombie thread as it doesn't hold a
			 * reference to obd and doesn't hold any
			 * resources
			 */
			class_export_destroy(exp);
			/* self export is destroyed, no class
			 * references exist and it is safe to free
			 * obd
			 */
			class_free_dev(obd);
		} else {
			LASSERT(!list_empty(&exp->exp_obd_chain));
			obd_zombie_export_add(exp);
		}
	}
}
EXPORT_SYMBOL(class_export_put);

static void obd_zombie_exp_cull(struct work_struct *ws)
{
	struct obd_export *export = container_of(ws, struct obd_export,
						 exp_zombie_work);

	class_export_destroy(export);
}

/* Creates a new export, adds it to the hash table, and returns a
 * pointer to it. The refcount is 2: one for the hash reference, and
 * one for the pointer returned by this function.
 */
static struct obd_export *__class_new_export(struct obd_device *obd,
					     struct obd_uuid *cluuid,
					     bool is_self)
{
	struct obd_export *export;
	int rc = 0;

	export = kzalloc(sizeof(*export), GFP_NOFS);
	if (!export)
		return ERR_PTR(-ENOMEM);

	export->exp_conn_cnt = 0;
	/* 2 = class_handle_hash + last */
	refcount_set(&export->exp_handle.h_ref, 2);
	atomic_set(&export->exp_rpc_count, 0);
	atomic_set(&export->exp_cb_count, 0);
	atomic_set(&export->exp_locks_count, 0);
#if LUSTRE_TRACKS_LOCK_EXP_REFS
	INIT_LIST_HEAD(&export->exp_locks_list);
	spin_lock_init(&export->exp_locks_list_guard);
#endif
	atomic_set(&export->exp_replay_count, 0);
	export->exp_obd = obd;
	INIT_LIST_HEAD(&export->exp_outstanding_replies);
	spin_lock_init(&export->exp_uncommitted_replies_lock);
	INIT_LIST_HEAD(&export->exp_uncommitted_replies);
	INIT_LIST_HEAD(&export->exp_req_replay_queue);
	INIT_HLIST_NODE(&export->exp_handle.h_link);
	INIT_LIST_HEAD(&export->exp_hp_rpcs);
	class_handle_hash(&export->exp_handle, export_handle_owner);
	spin_lock_init(&export->exp_lock);
	spin_lock_init(&export->exp_rpc_lock);
	spin_lock_init(&export->exp_bl_list_lock);
	INIT_LIST_HEAD(&export->exp_bl_list);
	INIT_WORK(&export->exp_zombie_work, obd_zombie_exp_cull);

	export->exp_sp_peer = LUSTRE_SP_ANY;
	export->exp_flvr.sf_rpc = SPTLRPC_FLVR_INVALID;
	export->exp_client_uuid = *cluuid;
	obd_init_export(export);

	spin_lock(&obd->obd_dev_lock);
	if (!obd_uuid_equals(cluuid, &obd->obd_uuid)) {
		/* shouldn't happen, but might race */
		if (obd->obd_stopping) {
			rc = -ENODEV;
			goto exit_unlock;
		}

		rc = obd_uuid_add(obd, export);
		if (rc) {
			LCONSOLE_WARN("%s: denying duplicate export for %s, %d\n",
				      obd->obd_name, cluuid->uuid, rc);
			goto exit_unlock;
		}
	}

	if (!is_self) {
		class_incref(obd, "export", export);
		list_add(&export->exp_obd_chain, &export->exp_obd->obd_exports);
		obd->obd_num_exports++;
	} else {
		INIT_LIST_HEAD(&export->exp_obd_chain);
	}
	spin_unlock(&obd->obd_dev_lock);
	return export;

exit_unlock:
	spin_unlock(&obd->obd_dev_lock);
	class_handle_unhash(&export->exp_handle);
	obd_destroy_export(export);
	kfree(export);
	return ERR_PTR(rc);
}

struct obd_export *class_new_export(struct obd_device *obd,
				    struct obd_uuid *uuid)
{
	return __class_new_export(obd, uuid, false);
}
EXPORT_SYMBOL(class_new_export);

struct obd_export *class_new_export_self(struct obd_device *obd,
					 struct obd_uuid *uuid)
{
	return __class_new_export(obd, uuid, true);
}

void class_unlink_export(struct obd_export *exp)
{
	class_handle_unhash(&exp->exp_handle);

	if (exp->exp_obd->obd_self_export == exp) {
		class_export_put(exp);
		return;
	}

	spin_lock(&exp->exp_obd->obd_dev_lock);
	/* delete an uuid-export hashitem from hashtables */
	if (exp != exp->exp_obd->obd_self_export)
		obd_uuid_del(exp->exp_obd, exp);

	list_move(&exp->exp_obd_chain, &exp->exp_obd->obd_unlinked_exports);
	exp->exp_obd->obd_num_exports--;
	spin_unlock(&exp->exp_obd->obd_dev_lock);
	class_export_put(exp);
}

/* Import management functions */
static void class_import_destroy(struct obd_import *imp)
{
	struct obd_import_conn *imp_conn;

	CDEBUG(D_IOCTL, "destroying import %p for %s\n", imp,
	       imp->imp_obd->obd_name);

	LASSERT(refcount_read(&imp->imp_handle.h_ref) == 0);

	ptlrpc_connection_put(imp->imp_connection);

	while ((imp_conn = list_first_entry_or_null(&imp->imp_conn_list,
						    struct obd_import_conn,
						    oic_item)) != NULL) {
		list_del_init(&imp_conn->oic_item);
		ptlrpc_connection_put(imp_conn->oic_conn);
		kfree(imp_conn);
	}

	LASSERT(!imp->imp_sec);
	class_decref(imp->imp_obd, "import", imp);
	kfree_rcu(imp, imp_handle.h_rcu);
}

static const char import_handle_owner[] = "import";

struct obd_import *class_import_get(struct obd_import *import)
{
	refcount_inc(&import->imp_handle.h_ref);
	CDEBUG(D_INFO, "GET import %p refcount=%d obd=%s\n", import,
	       refcount_read(&import->imp_handle.h_ref),
	       import->imp_obd->obd_name);
	return import;
}
EXPORT_SYMBOL(class_import_get);

void class_import_put(struct obd_import *imp)
{
	LASSERT(refcount_read(&imp->imp_handle.h_ref) > 0);

	CDEBUG(D_INFO, "import %p refcount=%d obd=%s\n", imp,
	       refcount_read(&imp->imp_handle.h_ref) - 1,
	       imp->imp_obd->obd_name);

	if (refcount_dec_and_test(&imp->imp_handle.h_ref)) {
		CDEBUG(D_INFO, "final put import %p\n", imp);
		obd_zombie_import_add(imp);
	}

	/* catch possible import put race */
	LASSERT(refcount_read(&imp->imp_handle.h_ref) >= 0);
}
EXPORT_SYMBOL(class_import_put);

static void init_imp_at(struct imp_at *at)
{
	int i;

	at_init(&at->iat_net_latency, 0, 0);
	for (i = 0; i < IMP_AT_MAX_PORTALS; i++) {
		/* max service estimates are tracked on the server side, so
		 * don't use the AT history here, just use the last reported
		 * val. (But keep hist for proc histogram, worst_ever)
		 */
		at_init(&at->iat_service_estimate[i], INITIAL_CONNECT_TIMEOUT,
			AT_FLG_NOHIST);
	}
}

static void obd_zombie_imp_cull(struct work_struct *ws)
{
	struct obd_import *import = container_of(ws, struct obd_import,
						 imp_zombie_work);

	class_import_destroy(import);
}

struct obd_import *class_new_import(struct obd_device *obd)
{
	struct obd_import *imp;

	imp = kzalloc(sizeof(*imp), GFP_NOFS);
	if (!imp)
		return NULL;

	INIT_LIST_HEAD(&imp->imp_pinger_chain);
	INIT_LIST_HEAD(&imp->imp_replay_list);
	INIT_LIST_HEAD(&imp->imp_sending_list);
	INIT_LIST_HEAD(&imp->imp_delayed_list);
	INIT_LIST_HEAD(&imp->imp_committed_list);
	INIT_LIST_HEAD(&imp->imp_unreplied_list);
	imp->imp_known_replied_xid = 0;
	imp->imp_replay_cursor = &imp->imp_committed_list;
	spin_lock_init(&imp->imp_lock);
	imp->imp_last_success_conn = 0;
	imp->imp_state = LUSTRE_IMP_NEW;
	imp->imp_obd = class_incref(obd, "import", imp);
	mutex_init(&imp->imp_sec_mutex);
	init_waitqueue_head(&imp->imp_recovery_waitq);
	INIT_WORK(&imp->imp_zombie_work, obd_zombie_imp_cull);

	refcount_set(&imp->imp_handle.h_ref, 2);
	atomic_set(&imp->imp_unregistering, 0);
	atomic_set(&imp->imp_inflight, 0);
	atomic_set(&imp->imp_replay_inflight, 0);
	atomic_set(&imp->imp_inval_count, 0);
	INIT_LIST_HEAD(&imp->imp_conn_list);
	INIT_HLIST_NODE(&imp->imp_handle.h_link);
	class_handle_hash(&imp->imp_handle, import_handle_owner);
	init_imp_at(&imp->imp_at);

	/* the default magic is V2, will be used in connect RPC, and
	 * then adjusted according to the flags in request/reply.
	 */
	imp->imp_msg_magic = LUSTRE_MSG_MAGIC_V2;

	return imp;
}
EXPORT_SYMBOL(class_new_import);

void class_destroy_import(struct obd_import *import)
{
	LASSERT(import);
	LASSERT(import != LP_POISON);

	class_handle_unhash(&import->imp_handle);

	spin_lock(&import->imp_lock);
	import->imp_generation++;
	spin_unlock(&import->imp_lock);
	class_import_put(import);
}
EXPORT_SYMBOL(class_destroy_import);

#if LUSTRE_TRACKS_LOCK_EXP_REFS

void __class_export_add_lock_ref(struct obd_export *exp, struct ldlm_lock *lock)
{
	spin_lock(&exp->exp_locks_list_guard);

	LASSERT(lock->l_exp_refs_nr >= 0);

	if (lock->l_exp_refs_target && lock->l_exp_refs_target != exp) {
		LCONSOLE_WARN("setting export %p for lock %p which already has export %p\n",
			      exp, lock, lock->l_exp_refs_target);
	}
	if ((lock->l_exp_refs_nr++) == 0) {
		list_add(&lock->l_exp_refs_link, &exp->exp_locks_list);
		lock->l_exp_refs_target = exp;
	}
	CDEBUG(D_INFO, "lock = %p, export = %p, refs = %u\n",
	       lock, exp, lock->l_exp_refs_nr);
	spin_unlock(&exp->exp_locks_list_guard);
}

void __class_export_del_lock_ref(struct obd_export *exp, struct ldlm_lock *lock)
{
	spin_lock(&exp->exp_locks_list_guard);
	LASSERT(lock->l_exp_refs_nr > 0);
	if (lock->l_exp_refs_target != exp) {
		LCONSOLE_WARN("lock %p, mismatching export pointers: %p, %p\n",
			      lock, lock->l_exp_refs_target, exp);
	}
	if (-- lock->l_exp_refs_nr == 0) {
		list_del_init(&lock->l_exp_refs_link);
		lock->l_exp_refs_target = NULL;
	}
	CDEBUG(D_INFO, "lock = %p, export = %p, refs = %u\n",
	       lock, exp, lock->l_exp_refs_nr);
	spin_unlock(&exp->exp_locks_list_guard);
}
#endif

/* A connection defines an export context in which preallocation can
 * be managed. This releases the export pointer reference, and returns
 * the export handle, so the export refcount is 1 when this function
 * returns.
 */
int class_connect(struct lustre_handle *conn, struct obd_device *obd,
		  struct obd_uuid *cluuid)
{
	struct obd_export *export;

	LASSERT(conn);
	LASSERT(obd);
	LASSERT(cluuid);

	export = class_new_export(obd, cluuid);
	if (IS_ERR(export))
		return PTR_ERR(export);

	conn->cookie = export->exp_handle.h_cookie;
	class_export_put(export);

	CDEBUG(D_IOCTL, "connect: client %s, cookie %#llx\n",
	       cluuid->uuid, conn->cookie);
	return 0;
}
EXPORT_SYMBOL(class_connect);

/* This function removes 1-3 references from the export:
 * 1 - for export pointer passed
 * and if disconnect really need
 * 2 - removing from hash
 * 3 - in client_unlink_export
 * The export pointer passed to this function can destroyed
 */
int class_disconnect(struct obd_export *export)
{
	int already_disconnected;

	if (!export) {
		CWARN("attempting to free NULL export %p\n", export);
		return -EINVAL;
	}

	spin_lock(&export->exp_lock);
	already_disconnected = export->exp_disconnected;
	export->exp_disconnected = 1;
	spin_unlock(&export->exp_lock);

	/* class_cleanup(), abort_recovery(), and class_fail_export()
	 * all end up in here, and if any of them race we shouldn't
	 * call extra class_export_puts().
	 */
	if (already_disconnected)
		goto no_disconn;

	CDEBUG(D_IOCTL, "disconnect: cookie %#llx\n",
	       export->exp_handle.h_cookie);

	class_unlink_export(export);
no_disconn:
	class_export_put(export);
	return 0;
}
EXPORT_SYMBOL(class_disconnect);

void class_fail_export(struct obd_export *exp)
{
	int rc, already_failed;

	spin_lock(&exp->exp_lock);
	already_failed = exp->exp_failed;
	exp->exp_failed = 1;
	spin_unlock(&exp->exp_lock);

	if (already_failed) {
		CDEBUG(D_HA, "disconnecting dead export %p/%s; skipping\n",
		       exp, exp->exp_client_uuid.uuid);
		return;
	}

	CDEBUG(D_HA, "disconnecting export %p/%s\n",
	       exp, exp->exp_client_uuid.uuid);

	if (obd_dump_on_timeout)
		libcfs_debug_dumplog();

	/* need for safe call CDEBUG after obd_disconnect */
	class_export_get(exp);

	/* Most callers into obd_disconnect are removing their own reference
	 * (request, for example) in addition to the one from the hash table.
	 * We don't have such a reference here, so make one.
	 */
	class_export_get(exp);
	rc = obd_disconnect(exp);
	if (rc)
		CERROR("disconnecting export %p failed: %d\n", exp, rc);
	else
		CDEBUG(D_HA, "disconnected export %p/%s\n",
		       exp, exp->exp_client_uuid.uuid);
	class_export_put(exp);
}
EXPORT_SYMBOL(class_fail_export);

#if LUSTRE_TRACKS_LOCK_EXP_REFS
void (*class_export_dump_hook)(struct obd_export *) = NULL;
#endif

/**
 * Add export to the obd_zombie thread and notify it.
 */
static void obd_zombie_export_add(struct obd_export *exp)
{
	spin_lock(&exp->exp_obd->obd_dev_lock);
	LASSERT(!list_empty(&exp->exp_obd_chain));
	list_del_init(&exp->exp_obd_chain);
	spin_unlock(&exp->exp_obd->obd_dev_lock);
	queue_work(zombie_wq, &exp->exp_zombie_work);
}

/**
 * Add import to the obd_zombie thread and notify it.
 */
static void obd_zombie_import_add(struct obd_import *imp)
{
	LASSERT(!imp->imp_sec);
	queue_work(zombie_wq, &imp->imp_zombie_work);
}

/**
 * wait when obd_zombie import/export queues become empty
 */
void obd_zombie_barrier(void)
{
	flush_workqueue(zombie_wq);
}
EXPORT_SYMBOL(obd_zombie_barrier);

/**
 * start destroy zombie import/export thread
 */
int obd_zombie_impexp_init(void)
{
	zombie_wq = alloc_workqueue("obd_zombid", 0, 0);
	if (!zombie_wq)
		return -ENOMEM;

	return 0;
}

/**
 * stop destroy zombie import/export thread
 */
void obd_zombie_impexp_stop(void)
{
	destroy_workqueue(zombie_wq);
}

struct obd_request_slot_waiter {
	struct list_head	orsw_entry;
	wait_queue_head_t	orsw_waitq;
	bool			orsw_signaled;
};

static bool obd_request_slot_avail(struct client_obd *cli,
				   struct obd_request_slot_waiter *orsw)
{
	bool avail;

	spin_lock(&cli->cl_loi_list_lock);
	avail = !!list_empty(&orsw->orsw_entry);
	spin_unlock(&cli->cl_loi_list_lock);

	return avail;
};

/*
 * For network flow control, the RPC sponsor needs to acquire a credit
 * before sending the RPC. The credits count for a connection is defined
 * by the "cl_max_rpcs_in_flight". If all the credits are occpuied, then
 * the subsequent RPC sponsors need to wait until others released their
 * credits, or the administrator increased the "cl_max_rpcs_in_flight".
 */
int obd_get_request_slot(struct client_obd *cli)
{
	struct obd_request_slot_waiter orsw;
	int rc;

	spin_lock(&cli->cl_loi_list_lock);
	if (cli->cl_rpcs_in_flight < cli->cl_max_rpcs_in_flight) {
		cli->cl_rpcs_in_flight++;
		spin_unlock(&cli->cl_loi_list_lock);
		return 0;
	}

	init_waitqueue_head(&orsw.orsw_waitq);
	list_add_tail(&orsw.orsw_entry, &cli->cl_flight_waiters);
	orsw.orsw_signaled = false;
	spin_unlock(&cli->cl_loi_list_lock);

	rc = l_wait_event_abortable(orsw.orsw_waitq,
				    obd_request_slot_avail(cli, &orsw) ||
				    orsw.orsw_signaled);

	/*
	 * Here, we must take the lock to avoid the on-stack 'orsw' to be
	 * freed but other (such as obd_put_request_slot) is using it.
	 */
	spin_lock(&cli->cl_loi_list_lock);
	if (rc) {
		if (!orsw.orsw_signaled) {
			if (list_empty(&orsw.orsw_entry))
				cli->cl_rpcs_in_flight--;
			else
				list_del(&orsw.orsw_entry);
		}
	}

	if (orsw.orsw_signaled) {
		LASSERT(list_empty(&orsw.orsw_entry));

		rc = -EINTR;
	}
	spin_unlock(&cli->cl_loi_list_lock);

	return rc;
}
EXPORT_SYMBOL(obd_get_request_slot);

void obd_put_request_slot(struct client_obd *cli)
{
	struct obd_request_slot_waiter *orsw;

	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_rpcs_in_flight--;

	/* If there is free slot, wakeup the first waiter. */
	if (!list_empty(&cli->cl_flight_waiters) &&
	    likely(cli->cl_rpcs_in_flight < cli->cl_max_rpcs_in_flight)) {
		orsw = list_first_entry(&cli->cl_flight_waiters,
					struct obd_request_slot_waiter,
					orsw_entry);
		list_del_init(&orsw->orsw_entry);
		cli->cl_rpcs_in_flight++;
		wake_up(&orsw->orsw_waitq);
	}
	spin_unlock(&cli->cl_loi_list_lock);
}
EXPORT_SYMBOL(obd_put_request_slot);

u32 obd_get_max_rpcs_in_flight(struct client_obd *cli)
{
	return cli->cl_max_rpcs_in_flight;
}
EXPORT_SYMBOL(obd_get_max_rpcs_in_flight);

int obd_set_max_rpcs_in_flight(struct client_obd *cli, u32 max)
{
	struct obd_request_slot_waiter *orsw;
	const char *type_name;
	u32 old;
	int diff;
	int rc;
	int i;

	if (max > OBD_MAX_RIF_MAX || max < 1)
		return -ERANGE;

	type_name = cli->cl_import->imp_obd->obd_type->typ_name;
	if (!strcmp(type_name, LUSTRE_MDC_NAME)) {
		/*
		 * adjust max_mod_rpcs_in_flight to ensure it is always
		 * strictly lower that max_rpcs_in_flight
		 */
		if (max < 2) {
			CERROR("%s: cannot set max_rpcs_in_flight to 1 because it must be higher than max_mod_rpcs_in_flight value\n",
			       cli->cl_import->imp_obd->obd_name);
			return -ERANGE;
		}
		if (max <= cli->cl_max_mod_rpcs_in_flight) {
			rc = obd_set_max_mod_rpcs_in_flight(cli, max - 1);
			if (rc)
				return rc;
		}
	}

	spin_lock(&cli->cl_loi_list_lock);
	old = cli->cl_max_rpcs_in_flight;
	cli->cl_max_rpcs_in_flight = max;
	client_adjust_max_dirty(cli);

	diff = max - old;

	/* We increase the max_rpcs_in_flight, then wakeup some waiters. */
	for (i = 0; i < diff; i++) {
		orsw = list_first_entry_or_null(&cli->cl_flight_waiters,
						struct obd_request_slot_waiter,
						orsw_entry);
		if (!orsw)
			break;

		list_del_init(&orsw->orsw_entry);
		cli->cl_rpcs_in_flight++;
		wake_up(&orsw->orsw_waitq);
	}
	spin_unlock(&cli->cl_loi_list_lock);

	return 0;
}
EXPORT_SYMBOL(obd_set_max_rpcs_in_flight);

int obd_set_max_mod_rpcs_in_flight(struct client_obd *cli, u16 max)
{
	struct obd_connect_data *ocd;
	u16 maxmodrpcs;
	u16 prev;

	if (max > OBD_MAX_RIF_MAX || max < 1)
		return -ERANGE;

	/* cannot exceed or equal max_rpcs_in_flight */
	if (max >= cli->cl_max_rpcs_in_flight) {
		CERROR("%s: can't set max_mod_rpcs_in_flight to a value (%hu) higher or equal to max_rpcs_in_flight value (%u)\n",
		       cli->cl_import->imp_obd->obd_name,
		       max, cli->cl_max_rpcs_in_flight);
		return -ERANGE;
	}

	/* cannot exceed max modify RPCs in flight supported by the server */
	ocd = &cli->cl_import->imp_connect_data;
	if (ocd->ocd_connect_flags & OBD_CONNECT_MULTIMODRPCS)
		maxmodrpcs = ocd->ocd_maxmodrpcs;
	else
		maxmodrpcs = 1;
	if (max > maxmodrpcs) {
		CERROR("%s: can't set max_mod_rpcs_in_flight to a value (%hu) higher than max_mod_rpcs_per_client value (%hu) returned by the server at connection\n",
		       cli->cl_import->imp_obd->obd_name,
		       max, maxmodrpcs);
		return -ERANGE;
	}

	spin_lock(&cli->cl_mod_rpcs_lock);

	prev = cli->cl_max_mod_rpcs_in_flight;
	cli->cl_max_mod_rpcs_in_flight = max;

	/* wakeup waiters if limit has been increased */
	if (cli->cl_max_mod_rpcs_in_flight > prev)
		wake_up(&cli->cl_mod_rpcs_waitq);

	spin_unlock(&cli->cl_mod_rpcs_lock);

	return 0;
}
EXPORT_SYMBOL(obd_set_max_mod_rpcs_in_flight);

#define pct(a, b) (b ? (a * 100) / b : 0)

int obd_mod_rpc_stats_seq_show(struct client_obd *cli, struct seq_file *seq)
{
	unsigned long mod_tot = 0, mod_cum;
	struct timespec64 now;
	int i;

	ktime_get_real_ts64(&now);

	spin_lock(&cli->cl_mod_rpcs_lock);

	seq_printf(seq, "snapshot_time:		%llu.%9lu (secs.nsecs)\n",
		   (s64)now.tv_sec, (unsigned long)now.tv_nsec);
	seq_printf(seq, "modify_RPCs_in_flight:  %hu\n",
		   cli->cl_mod_rpcs_in_flight);

	seq_puts(seq, "\n\t\t\tmodify\n");
	seq_puts(seq, "rpcs in flight        rpcs   %% cum %%\n");

	mod_tot = lprocfs_oh_sum(&cli->cl_mod_rpcs_hist);

	mod_cum = 0;
	for (i = 0; i < OBD_HIST_MAX; i++) {
		unsigned long mod = cli->cl_mod_rpcs_hist.oh_buckets[i];

		mod_cum += mod;
		seq_printf(seq, "%d:\t\t%10lu %3lu %3lu\n",
			   i, mod, pct(mod, mod_tot),
			   pct(mod_cum, mod_tot));
		if (mod_cum == mod_tot)
			break;
	}

	spin_unlock(&cli->cl_mod_rpcs_lock);

	return 0;
}
EXPORT_SYMBOL(obd_mod_rpc_stats_seq_show);
#undef pct

/*
 * The number of modify RPCs sent in parallel is limited
 * because the server has a finite number of slots per client to
 * store request result and ensure reply reconstruction when needed.
 * On the client, this limit is stored in cl_max_mod_rpcs_in_flight
 * that takes into account server limit and cl_max_rpcs_in_flight
 * value.
 * On the MDC client, to avoid a potential deadlock (see Bugzilla 3462),
 * one close request is allowed above the maximum.
 */
static inline bool obd_mod_rpc_slot_avail_locked(struct client_obd *cli,
						 bool close_req)
{
	bool avail;

	/* A slot is available if
	 * - number of modify RPCs in flight is less than the max
	 * - it's a close RPC and no other close request is in flight
	 */
	avail = cli->cl_mod_rpcs_in_flight < cli->cl_max_mod_rpcs_in_flight ||
		(close_req && !cli->cl_close_rpcs_in_flight);

	return avail;
}

static inline bool obd_mod_rpc_slot_avail(struct client_obd *cli,
					  bool close_req)
{
	bool avail;

	spin_lock(&cli->cl_mod_rpcs_lock);
	avail = obd_mod_rpc_slot_avail_locked(cli, close_req);
	spin_unlock(&cli->cl_mod_rpcs_lock);
	return avail;
}

static inline bool obd_skip_mod_rpc_slot(const struct lookup_intent *it)
{
	if (it &&
	    (it->it_op == IT_GETATTR || it->it_op == IT_LOOKUP ||
	     it->it_op == IT_READDIR ||
	     (it->it_op == IT_LAYOUT && !(it->it_flags & MDS_FMODE_WRITE))))
		return true;
	return false;
}

/* Get a modify RPC slot from the obd client @cli according
 * to the kind of operation @opc that is going to be sent
 * and the intent @it of the operation if it applies.
 * If the maximum number of modify RPCs in flight is reached
 * the thread is put to sleep.
 * Returns the tag to be set in the request message. Tag 0
 * is reserved for non-modifying requests.
 */
u16 obd_get_mod_rpc_slot(struct client_obd *cli, u32 opc,
			 struct lookup_intent *it)
{
	bool close_req = false;
	u16 i, max;

	/* read-only metadata RPCs don't consume a slot on MDT
	 * for reply reconstruction
	 */
	if (obd_skip_mod_rpc_slot(it))
		return 0;

	if (opc == MDS_CLOSE)
		close_req = true;

	do {
		spin_lock(&cli->cl_mod_rpcs_lock);
		max = cli->cl_max_mod_rpcs_in_flight;
		if (obd_mod_rpc_slot_avail_locked(cli, close_req)) {
			/* there is a slot available */
			cli->cl_mod_rpcs_in_flight++;
			if (close_req)
				cli->cl_close_rpcs_in_flight++;
			lprocfs_oh_tally(&cli->cl_mod_rpcs_hist,
					 cli->cl_mod_rpcs_in_flight);
			/* find a free tag */
			i = find_first_zero_bit(cli->cl_mod_tag_bitmap,
						max + 1);
			LASSERT(i < OBD_MAX_RIF_MAX);
			LASSERT(!test_and_set_bit(i, cli->cl_mod_tag_bitmap));
			spin_unlock(&cli->cl_mod_rpcs_lock);
			/* tag 0 is reserved for non-modify RPCs */
			return i + 1;
		}
		spin_unlock(&cli->cl_mod_rpcs_lock);

		CDEBUG(D_RPCTRACE, "%s: sleeping for a modify RPC slot opc %u, max %hu\n",
		       cli->cl_import->imp_obd->obd_name, opc, max);

		wait_event_idle(cli->cl_mod_rpcs_waitq,
				obd_mod_rpc_slot_avail(cli, close_req));
	} while (true);
}
EXPORT_SYMBOL(obd_get_mod_rpc_slot);

/*
 * Put a modify RPC slot from the obd client @cli according
 * to the kind of operation @opc that has been sent and the
 * intent @it of the operation if it applies.
 */
void obd_put_mod_rpc_slot(struct client_obd *cli, u32 opc,
			  struct lookup_intent *it, u16 tag)
{
	bool close_req = false;

	if (obd_skip_mod_rpc_slot(it))
		return;

	if (opc == MDS_CLOSE)
		close_req = true;

	spin_lock(&cli->cl_mod_rpcs_lock);
	cli->cl_mod_rpcs_in_flight--;
	if (close_req)
		cli->cl_close_rpcs_in_flight--;
	/* release the tag in the bitmap */
	LASSERT(tag - 1 < OBD_MAX_RIF_MAX);
	LASSERT(test_and_clear_bit(tag - 1, cli->cl_mod_tag_bitmap) != 0);
	spin_unlock(&cli->cl_mod_rpcs_lock);
	wake_up(&cli->cl_mod_rpcs_waitq);
}
EXPORT_SYMBOL(obd_put_mod_rpc_slot);
