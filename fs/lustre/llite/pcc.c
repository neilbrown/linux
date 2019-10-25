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
 * Copyright (c) 2017, DDN Storage Corporation.
 */
/*
 * Persistent Client Cache
 *
 * PCC is a new framework which provides a group of local cache on Lustre
 * client side. It works in two modes: RW-PCC enables a read-write cache on the
 * local SSDs of a single client; RO-PCC provides a read-only cache on the
 * local SSDs of multiple clients. Less overhead is visible to the applications
 * and network latencies and lock conflicts can be significantly reduced.
 *
 * For RW-PCC, no global namespace will be provided. Each client uses its own
 * local storage as a cache for itself. Local file system is used to manage
 * the data on local caches. Cached I/O is directed to local file system while
 * normal I/O is directed to OSTs. RW-PCC uses HSM for data synchronization.
 * It uses HSM copytool to restore file from local caches to Lustre OSTs. Each
 * PCC has a copytool instance running with unique archive number. Any remote
 * access from another Lustre client would trigger the data synchronization. If
 * a client with RW-PCC goes offline, the cached data becomes inaccessible for
 * other client temporarily. And after the RW-PCC client reboots and the
 * copytool restarts, the data will be accessible again.
 *
 * Following is what will happen in different conditions for RW-PCC:
 *
 * > When file is being created on RW-PCC
 *
 * A normal HSM released file is created on MDT;
 * An empty mirror file is created on local cache;
 * The HSM status of the Lustre file will be set to archived and released;
 * The archive number will be set to the proper value.
 *
 * > When file is being prefetched to RW-PCC
 *
 * An file is copied to the local cache;
 * The HSM status of the Lustre file will be set to archived and released;
 * The archive number will be set to the proper value.
 *
 * > When file is being accessed from PCC
 *
 * Data will be read directly from local cache;
 * Metadata will be read from MDT, except file size;
 * File size will be got from local cache.
 *
 * > When PCC cached file is being accessed on another client
 *
 * RW-PCC cached files are automatically restored when a process on another
 * client tries to read or modify them. The corresponding I/O will block
 * waiting for the released file to be restored. This is transparent to the
 * process.
 *
 * For RW-PCC, when a file is being created, a rule-based policy is used to
 * determine whether it will be cached. Rule-based caching of newly created
 * files can determine which file can use a cache on PCC directly without any
 * admission control.
 *
 * RW-PCC design can accelerate I/O intensive applications with one-to-one
 * mappings between files and accessing clients. However, in several use cases,
 * files will never be updated, but need to be read simultaneously from many
 * clients. RO-PCC implements a read-only caching on Lustre clients using
 * SSDs. RO-PCC is based on the same framework as RW-PCC, expect
 * that no HSM mechanism is used.
 *
 * The main advantages to use this SSD cache on the Lustre clients via PCC
 * is that:
 * - The I/O stack becomes much simpler for the cached data, as there is no
 *   interference with I/Os from other clients, which enables easier
 *   performance optimizations;
 * - The requirements on the HW inside the client nodes are small, any kind of
 *   SSDs or even HDDs can be used as cache devices;
 * - Caching reduces the pressure on the object storage targets (OSTs), as
 *   small or random I/Os can be regularized to big sequential I/Os and
 *   temporary files do not even need to be flushed to OSTs.
 *
 * PCC can accelerate applications with certain I/O patterns:
 * - small-sized random writes (< 1MB) from a single client
 * - repeated read of data that is larger than RAM
 * - clients with high network latency
 *
 * Author: Li Xi <lixi@ddn.com>
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include "pcc.h"
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/mount.h>
#include "llite_internal.h"

struct kmem_cache *pcc_inode_slab;

void pcc_super_init(struct pcc_super *super)
{
	spin_lock_init(&super->pccs_lock);
	INIT_LIST_HEAD(&super->pccs_datasets);
}

/**
 * pcc_dataset_add - Add a Cache policy to control which files need be
 * cached and where it will be cached.
 *
 * @super: superblock of pcc
 * @pathname: root path of pcc
 * @id: HSM archive ID
 * @projid: files with specified project ID will be cached.
 */
static int
pcc_dataset_add(struct pcc_super *super, const char *pathname,
		u32 archive_id, u32 projid)
{
	int rc;
	struct pcc_dataset *dataset;
	struct pcc_dataset *tmp;
	bool found = false;

	dataset = kzalloc(sizeof(*dataset), GFP_NOFS);
	if (!dataset)
		return -ENOMEM;

	rc = kern_path(pathname, LOOKUP_DIRECTORY, &dataset->pccd_path);
	if (unlikely(rc)) {
		kfree(dataset);
		return rc;
	}
	strncpy(dataset->pccd_pathname, pathname, PATH_MAX);
	dataset->pccd_id = archive_id;
	dataset->pccd_projid = projid;
	atomic_set(&dataset->pccd_refcount, 1);

	spin_lock(&super->pccs_lock);
	list_for_each_entry(tmp, &super->pccs_datasets, pccd_linkage) {
		if (tmp->pccd_id == archive_id) {
			found = true;
			break;
		}
	}
	if (!found)
		list_add(&dataset->pccd_linkage, &super->pccs_datasets);
	spin_unlock(&super->pccs_lock);

	if (found) {
		pcc_dataset_put(dataset);
		rc = -EEXIST;
	}

	return rc;
}

struct pcc_dataset *
pcc_dataset_get(struct pcc_super *super, u32 projid, u32 archive_id)
{
	struct pcc_dataset *dataset;
	struct pcc_dataset *selected = NULL;

	if (projid == 0 && archive_id == 0)
		return NULL;

	/*
	 * archive ID is unique in the list, projid might be duplicate,
	 * we just return last added one as first priority.
	 */
	spin_lock(&super->pccs_lock);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		if (projid && dataset->pccd_projid != projid)
			continue;
		if (archive_id && dataset->pccd_id != archive_id)
			continue;
		atomic_inc(&dataset->pccd_refcount);
		selected = dataset;
		break;
	}
	spin_unlock(&super->pccs_lock);
	if (selected)
		CDEBUG(D_CACHE, "matched projid %u, PCC create\n",
		       selected->pccd_projid);
	return selected;
}

void
pcc_dataset_put(struct pcc_dataset *dataset)
{
	if (atomic_dec_and_test(&dataset->pccd_refcount)) {
		path_put(&dataset->pccd_path);
		kfree(dataset);
	}
}

static int
pcc_dataset_del(struct pcc_super *super, char *pathname)
{
	struct list_head *l, *tmp;
	struct pcc_dataset *dataset;
	int rc = -ENOENT;

	spin_lock(&super->pccs_lock);
	list_for_each_safe(l, tmp, &super->pccs_datasets) {
		dataset = list_entry(l, struct pcc_dataset, pccd_linkage);
		if (strcmp(dataset->pccd_pathname, pathname) == 0) {
			list_del(&dataset->pccd_linkage);
			pcc_dataset_put(dataset);
			rc = 0;
			break;
		}
	}
	spin_unlock(&super->pccs_lock);
	return rc;
}

static void
pcc_dataset_dump(struct pcc_dataset *dataset, struct seq_file *m)
{
	seq_printf(m, "%s:\n", dataset->pccd_pathname);
	seq_printf(m, "  rwid: %u\n", dataset->pccd_id);
	seq_printf(m, "  autocache: projid=%u\n", dataset->pccd_projid);
}

int
pcc_super_dump(struct pcc_super *super, struct seq_file *m)
{
	struct pcc_dataset *dataset;

	spin_lock(&super->pccs_lock);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		pcc_dataset_dump(dataset, m);
	}
	spin_unlock(&super->pccs_lock);
	return 0;
}

void pcc_super_fini(struct pcc_super *super)
{
	struct pcc_dataset *dataset, *tmp;

	list_for_each_entry_safe(dataset, tmp,
				 &super->pccs_datasets, pccd_linkage) {
		list_del(&dataset->pccd_linkage);
		pcc_dataset_put(dataset);
	}
}


static bool pathname_is_valid(const char *pathname)
{
	/* Needs to be absolute path */
	if (!pathname || strlen(pathname) == 0 ||
	    strlen(pathname) >= PATH_MAX || pathname[0] != '/')
		return false;
	return true;
}

static struct pcc_cmd *
pcc_cmd_parse(char *buffer, unsigned long count)
{
	static struct pcc_cmd *cmd;
	char *token;
	char *val;
	unsigned long tmp;
	int rc = 0;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		rc = -ENOMEM;
		goto out;
	}

	/* clear all setting */
	if (strncmp(buffer, "clear", 5) == 0) {
		cmd->pccc_cmd = PCC_CLEAR_ALL;
		rc = 0;
		goto out;
	}

	val = buffer;
	token = strsep(&val, " ");
	if (!val || strlen(val) == 0) {
		rc = -EINVAL;
		goto out_free_cmd;
	}

	/* Type of the command */
	if (strcmp(token, "add") == 0) {
		cmd->pccc_cmd = PCC_ADD_DATASET;
	} else if (strcmp(token, "del") == 0) {
		cmd->pccc_cmd = PCC_DEL_DATASET;
	} else {
		rc = -EINVAL;
		goto out_free_cmd;
	}

	/* Pathname of the dataset */
	token = strsep(&val, " ");
	if ((!val && cmd->pccc_cmd != PCC_DEL_DATASET) ||
	    !pathname_is_valid(token)) {
		rc = -EINVAL;
		goto out_free_cmd;
	}
	cmd->pccc_pathname = token;

	if (cmd->pccc_cmd == PCC_ADD_DATASET) {
		/* archive ID */
		token = strsep(&val, " ");
		if (!val) {
			rc = -EINVAL;
			goto out_free_cmd;
		}

		rc = kstrtoul(token, 10, &tmp);
		if (rc != 0) {
			rc = -EINVAL;
			goto out_free_cmd;
		}
		if (tmp == 0) {
			rc = -EINVAL;
			goto out_free_cmd;
		}
		cmd->u.pccc_add.pccc_id = tmp;

		token = val;
		rc = kstrtoul(token, 10, &tmp);
		if (rc != 0) {
			rc = -EINVAL;
			goto out_free_cmd;
		}
		if (tmp == 0) {
			rc = -EINVAL;
			goto out_free_cmd;
		}
		cmd->u.pccc_add.pccc_projid = tmp;
	}

	goto out;
out_free_cmd:
	kfree(cmd);
out:
	if (rc)
		cmd = ERR_PTR(rc);
	return cmd;
}

int pcc_cmd_handle(char *buffer, unsigned long count,
		   struct pcc_super *super)
{
	int rc = 0;
	struct pcc_cmd *cmd;

	cmd = pcc_cmd_parse(buffer, count);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	switch (cmd->pccc_cmd) {
	case PCC_ADD_DATASET:
		rc = pcc_dataset_add(super, cmd->pccc_pathname,
				      cmd->u.pccc_add.pccc_id,
				      cmd->u.pccc_add.pccc_projid);
		break;
	case PCC_DEL_DATASET:
		rc = pcc_dataset_del(super, cmd->pccc_pathname);
		break;
	case PCC_CLEAR_ALL:
		pcc_super_fini(super);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	kfree(cmd);
	return rc;
}

static inline void pcc_inode_lock(struct inode *inode)
{
	mutex_lock(&ll_i2info(inode)->lli_pcc_lock);
}

static inline void pcc_inode_unlock(struct inode *inode)
{
	mutex_unlock(&ll_i2info(inode)->lli_pcc_lock);
}

static void pcc_inode_init(struct pcc_inode *pcci, struct ll_inode_info *lli)
{
	pcci->pcci_lli = lli;
	lli->lli_pcc_inode = pcci;
	atomic_set(&pcci->pcci_refcount, 0);
	pcci->pcci_type = LU_PCC_NONE;
	pcci->pcci_layout_gen = CL_LAYOUT_GEN_NONE;
	atomic_set(&pcci->pcci_active_ios, 0);
	init_waitqueue_head(&pcci->pcci_waitq);
}

static void pcc_inode_fini(struct pcc_inode *pcci)
{
	struct ll_inode_info *lli = pcci->pcci_lli;

	path_put(&pcci->pcci_path);
	pcci->pcci_type = LU_PCC_NONE;
	kmem_cache_free(pcc_inode_slab, pcci);
	lli->lli_pcc_inode = NULL;
}

static void pcc_inode_get(struct pcc_inode *pcci)
{
	atomic_inc(&pcci->pcci_refcount);
}

static void pcc_inode_put(struct pcc_inode *pcci)
{
	if (atomic_dec_and_test(&pcci->pcci_refcount))
		pcc_inode_fini(pcci);
}

void pcc_inode_free(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	if (pcci) {
		WARN_ON(atomic_read(&pcci->pcci_refcount) > 1);
		pcc_inode_put(pcci);
	}
}

/*
 * TODO:
 * As Andreas suggested, we'd better use new layout to
 * reduce overhead:
 * (fid->f_oid >> 16 & oxFFFF)/FID
 */
#define MAX_PCC_DATABASE_PATH (6 * 5 + FID_NOBRACE_LEN + 1)
static int pcc_fid2dataset_path(char *buf, int sz, struct lu_fid *fid)
{
	return snprintf(buf, sz, "%04x/%04x/%04x/%04x/%04x/%04x/"
			DFID_NOBRACE,
			(fid)->f_oid       & 0xFFFF,
			(fid)->f_oid >> 16 & 0xFFFF,
			(unsigned int)((fid)->f_seq       & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 16 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 32 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 48 & 0xFFFF),
			PFID(fid));
}

void pcc_file_init(struct pcc_file *pccf)
{
	pccf->pccf_file = NULL;
	pccf->pccf_type = LU_PCC_NONE;
}

static inline bool pcc_inode_has_layout(struct pcc_inode *pcci)
{
	return pcci->pcci_layout_gen != CL_LAYOUT_GEN_NONE;
}

int pcc_file_open(struct inode *inode, struct file *file)
{
	struct pcc_inode *pcci;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct file *pcc_file;
	struct path *path;
	struct qstr *dname;
	int rc = 0;

	if (!S_ISREG(inode->i_mode))
		return 0;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (!pcci)
		goto out_unlock;

	if (atomic_read(&pcci->pcci_refcount) == 0 ||
	    !pcc_inode_has_layout(pcci))
		goto out_unlock;

	pcc_inode_get(pcci);
	WARN_ON(pccf->pccf_file);

	path = &pcci->pcci_path;
	dname = &path->dentry->d_name;
	CDEBUG(D_CACHE, "opening pcc file '%.*s'\n", dname->len,
	       dname->name);
	pcc_file = dentry_open(path, file->f_flags, current_cred());
	if (IS_ERR_OR_NULL(pcc_file)) {
		rc = pcc_file ? PTR_ERR(pcc_file) : -EINVAL;
		pcc_inode_put(pcci);
	} else {
		pccf->pccf_file = pcc_file;
		pccf->pccf_type = pcci->pcci_type;
	}

out_unlock:
	pcc_inode_unlock(inode);
	return rc;
}

void pcc_file_release(struct inode *inode, struct file *file)
{
	struct pcc_inode *pcci;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf;
	struct path *path;
	struct qstr *dname;

	if (!S_ISREG(inode->i_mode) || !fd)
		return;

	pccf = &fd->fd_pcc_file;
	pcc_inode_lock(inode);
	if (!pccf->pccf_file)
		goto out;

	pcci = ll_i2pcci(inode);
	LASSERT(pcci);
	path = &pcci->pcci_path;
	dname = &path->dentry->d_name;
	CDEBUG(D_CACHE, "releasing pcc file \"%.*s\"\n", dname->len,
	       dname->name);
	pcc_inode_put(pcci);
	fput(pccf->pccf_file);
	pccf->pccf_file = NULL;
out:
	pcc_inode_unlock(inode);
}

static inline void pcc_layout_gen_set(struct pcc_inode *pcci,
				      u32 gen)
{
	pcci->pcci_layout_gen = gen;
}

static void pcc_io_init(struct inode *inode, bool *cached)
{
	struct pcc_inode *pcci;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);
		atomic_inc(&pcci->pcci_active_ios);
		*cached = true;
	} else {
		*cached = false;
	}
	pcc_inode_unlock(inode);
}

static void pcc_io_fini(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	LASSERT(pcci && atomic_read(&pcci->pcci_active_ios) > 0);
	if (atomic_dec_and_test(&pcci->pcci_active_ios))
		wake_up_all(&pcci->pcci_waitq);
}


static ssize_t
__pcc_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;

	return file->f_op->read_iter(iocb, iter);
}

ssize_t pcc_file_read_iter(struct kiocb *iocb,
			   struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct inode *inode = file_inode(file);
	ssize_t result;

	if (!pccf->pccf_file) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	iocb->ki_filp = pccf->pccf_file;
	/* generic_file_aio_read does not support ext4-dax,
	 * __pcc_file_read_iter uses ->aio_read hook directly
	 * to add support for ext4-dax.
	 */
	result = __pcc_file_read_iter(iocb, iter);
	iocb->ki_filp = file;

	pcc_io_fini(inode);
	return result;
}

static ssize_t
__pcc_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;

	return file->f_op->write_iter(iocb, iter);
}

ssize_t pcc_file_write_iter(struct kiocb *iocb,
			    struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct inode *inode = file_inode(file);
	ssize_t result;

	if (!pccf->pccf_file) {
		*cached = false;
		return 0;
	}

	if (pccf->pccf_type != LU_PCC_READWRITE) {
		*cached = false;
		return -EAGAIN;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	if (OBD_FAIL_CHECK(OBD_FAIL_LLITE_PCC_FAKE_ERROR)) {
		result = -ENOSPC;
		goto out;
	}

	iocb->ki_filp = pccf->pccf_file;

	/* Since __pcc_file_write_iter makes write calls via
	 * the normal vfs interface to the local PCC file system,
	 * the inode lock is not needed.
	 */
	result = __pcc_file_write_iter(iocb, iter);
	iocb->ki_filp = file;
out:
	pcc_io_fini(inode);
	return result;
}

int pcc_inode_setattr(struct inode *inode, struct iattr *attr,
		      bool *cached)
{
	int rc = 0;
	struct iattr attr2 = *attr;
	struct dentry *pcc_dentry;
	struct pcc_inode *pcci;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	attr2.ia_valid = attr->ia_valid & (ATTR_SIZE | ATTR_ATIME |
			 ATTR_ATIME_SET | ATTR_MTIME | ATTR_MTIME_SET |
			 ATTR_CTIME);
	pcci = ll_i2pcci(inode);
	pcc_dentry = pcci->pcci_path.dentry;
	inode_lock(pcc_dentry->d_inode);
	rc = pcc_dentry->d_inode->i_op->setattr(pcc_dentry, &attr2);
	inode_unlock(pcc_dentry->d_inode);

	pcc_io_fini(inode);
	return rc;
}

int pcc_inode_getattr(struct inode *inode, bool *cached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct kstat stat;
	s64 atime;
	s64 mtime;
	s64 ctime;
	int rc = 0;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	rc = vfs_getattr(&ll_i2pcci(inode)->pcci_path, &stat,
			 STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);

	if (rc)
		goto out;

	ll_inode_size_lock(inode);
	if (test_and_clear_bit(LLIF_UPDATE_ATIME, &lli->lli_flags) ||
	    inode->i_atime.tv_sec < lli->lli_atime)
		inode->i_atime.tv_sec = lli->lli_atime;

	inode->i_mtime.tv_sec = lli->lli_mtime;
	inode->i_ctime.tv_sec = lli->lli_ctime;

	atime = inode->i_atime.tv_sec;
	mtime = inode->i_mtime.tv_sec;
	ctime = inode->i_ctime.tv_sec;

	if (atime < stat.atime.tv_sec)
		atime = stat.atime.tv_sec;

	if (ctime < stat.ctime.tv_sec)
		ctime = stat.ctime.tv_sec;

	if (mtime < stat.mtime.tv_sec)
		mtime = stat.mtime.tv_sec;

	i_size_write(inode, stat.size);
	inode->i_blocks = stat.blocks;

	inode->i_atime.tv_sec = atime;
	inode->i_mtime.tv_sec = mtime;
	inode->i_ctime.tv_sec = ctime;

	ll_inode_size_unlock(inode);
out:
	pcc_io_fini(inode);
	return rc;
}

ssize_t pcc_file_splice_read(struct file *in_file, loff_t *ppos,
			     struct pipe_inode_info *pipe,
			     size_t count, unsigned int flags,
			     bool *cached)
{
	struct inode *inode = file_inode(in_file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(in_file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	ssize_t result;

	*cached = false;
	if (!pcc_file)
		return 0;

	if (!file_inode(pcc_file)->i_fop->splice_read)
		return -ENOTSUPP;

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	result = file_inode(pcc_file)->i_fop->splice_read(pcc_file,
							  ppos, pipe, count,
							  flags);

	pcc_io_fini(inode);
	return result;
}

int pcc_fsync(struct file *file, loff_t start, loff_t end,
	      int datasync, bool *cached)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	int rc;

	if (!pcc_file) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	rc = file_inode(pcc_file)->i_fop->fsync(pcc_file,
						start, end, datasync);

	pcc_io_fini(inode);
	return rc;
}

int pcc_file_mmap(struct file *file, struct vm_area_struct *vma,
		  bool *cached)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	struct pcc_inode *pcci;
	int rc = 0;

	if (!pcc_file || !file_inode(pcc_file)->i_fop->mmap) {
		*cached = false;
		return 0;
	}

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 1);
		*cached = true;
		vma->vm_file = pcc_file;
		rc = file_inode(pcc_file)->i_fop->mmap(pcc_file, vma);
		vma->vm_file = file;
		/* Save the vm ops of backend PCC */
		vma->vm_private_data = (void *)vma->vm_ops;
	} else {
		*cached = false;
	}
	pcc_inode_unlock(inode);

	return rc;
}

void pcc_vm_open(struct vm_area_struct *vma)
{
	struct pcc_inode *pcci;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	const struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->open)
		return;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		vma->vm_file = pcc_file;
		pcc_vm_ops->open(vma);
		vma->vm_file = file;
	}
	pcc_inode_unlock(inode);
}

void pcc_vm_close(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	const struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->close)
		return;

	pcc_inode_lock(inode);
	/* Layout lock maybe revoked here */
	vma->vm_file = pcc_file;
	pcc_vm_ops->close(vma);
	vma->vm_file = file;
	pcc_inode_unlock(inode);
}

int pcc_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
		     bool *cached)
{
	struct page *page = vmf->page;
	struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	const struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;
	int rc;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->page_mkwrite) {
		*cached = false;
		return 0;
	}

	/* Pause to allow for a race with concurrent detach */
	OBD_FAIL_TIMEOUT(OBD_FAIL_LLITE_PCC_MKWRITE_PAUSE, cfs_fail_val);

	pcc_io_init(inode, cached);
	if (!*cached) {
		/* This happens when the file is detached from PCC after got
		 * the fault page via ->fault() on the inode of the PCC copy.
		 * Here it can not simply fall back to normal Lustre I/O path.
		 * The reason is that the address space of fault page used by
		 * ->page_mkwrite() is still the one of PCC inode. In the
		 * normal Lustre ->page_mkwrite() I/O path, it will be wrongly
		 * handled as the address space of the fault page is not
		 * consistent with the one of the Lustre inode (though the
		 * fault page was truncated).
		 * As the file is detached from PCC, the fault page must
		 * be released frist, and retry the mmap write (->fault() and
		 * ->page_mkwrite).
		 * We use an ugly and tricky method by returning
		 * VM_FAULT_NOPAGE | VM_FAULT_RETRY to the caller
		 * __do_page_fault and retry the memory fault handling.
		 */
		if (page->mapping == file_inode(pcc_file)->i_mapping) {
			*cached = true;
			up_read(&mm->mmap_sem);
			return VM_FAULT_RETRY | VM_FAULT_NOPAGE;
		}

		return 0;
	}

	/*
	 * This fault injection can also be used to simulate -ENOSPC and
	 * -EDQUOT failure of underlying PCC backend fs.
	 */
	if (OBD_FAIL_CHECK(OBD_FAIL_LLITE_PCC_DETACH_MKWRITE)) {
		pcc_io_fini(inode);
		pcc_ioctl_detach(inode);
		up_read(&mm->mmap_sem);
		return VM_FAULT_RETRY | VM_FAULT_NOPAGE;
	}

	vma->vm_file = pcc_file;
	rc = pcc_vm_ops->page_mkwrite(vmf);
	vma->vm_file = file;

	pcc_io_fini(inode);
	return rc;
}

int pcc_fault(struct vm_area_struct *vma, struct vm_fault *vmf,
	      bool *cached)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	const struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;
	int rc;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->fault) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	vma->vm_file = pcc_file;
	rc = pcc_vm_ops->fault(vmf);
	vma->vm_file = file;

	pcc_io_fini(inode);
	return rc;
}

static void pcc_layout_wait(struct pcc_inode *pcci)
{
	if (atomic_read(&pcci->pcci_active_ios) > 0)
		CDEBUG(D_CACHE, "Waiting for IO completion: %d\n",
		       atomic_read(&pcci->pcci_active_ios));
	wait_event_idle(pcci->pcci_waitq,
			atomic_read(&pcci->pcci_active_ios) == 0);
}

static void __pcc_layout_invalidate(struct pcc_inode *pcci)
{
	pcci->pcci_type = LU_PCC_NONE;
	pcc_layout_gen_set(pcci, CL_LAYOUT_GEN_NONE);
	pcc_layout_wait(pcci);
}

void pcc_layout_invalidate(struct inode *inode)
{
	struct pcc_inode *pcci;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);
		__pcc_layout_invalidate(pcci);

		CDEBUG(D_CACHE, "Invalidate "DFID" layout gen %d\n",
		       PFID(&ll_i2info(inode)->lli_fid), pcci->pcci_layout_gen);

		pcc_inode_put(pcci);
	}
	pcc_inode_unlock(inode);
}

static int pcc_inode_remove(struct pcc_inode *pcci)
{
	struct dentry *dentry;
	int rc;

	dentry = pcci->pcci_path.dentry;
	rc = vfs_unlink(dentry->d_parent->d_inode, dentry, NULL);
	if (rc)
		CWARN("failed to unlink cached file, rc = %d\n", rc);

	return rc;
}

/* Create directory under base if directory does not exist */
static struct dentry *
pcc_mkdir(struct dentry *base, const char *name, umode_t mode)
{
	int rc;
	struct dentry *dentry;
	struct inode *dir = base->d_inode;

	inode_lock(dir);
	dentry = lookup_one_len(name, base, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_is_positive(dentry))
		goto out;

	rc = vfs_mkdir(dir, dentry, mode);
	if (rc) {
		dput(dentry);
		dentry = ERR_PTR(rc);
		goto out;
	}
out:
	inode_unlock(dir);
	return dentry;
}

static struct dentry *
pcc_mkdir_p(struct dentry *root, char *path, umode_t mode)
{
	char *ptr, *entry_name;
	struct dentry *parent;
	struct dentry *child = ERR_PTR(-EINVAL);

	ptr = path;
	while (*ptr == '/')
		ptr++;

	entry_name = ptr;
	parent = dget(root);
	while ((ptr = strchr(ptr, '/')) != NULL) {
		*ptr = '\0';
		child = pcc_mkdir(parent, entry_name, mode);
		*ptr = '/';
		dput(parent);
		if (IS_ERR(child))
			break;

		parent = child;
		ptr++;
		entry_name = ptr;
	}

	return child;
}

/* Create file under base. If file already exist, return failure */
static struct dentry *
pcc_create(struct dentry *base, const char *name, umode_t mode)
{
	int rc;
	struct dentry *dentry;
	struct inode *dir = base->d_inode;

	inode_lock(dir);
	dentry = lookup_one_len(name, base, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_is_positive(dentry))
		goto out;

	rc = vfs_create(dir, dentry, mode, false);
	if (rc) {
		dput(dentry);
		dentry = ERR_PTR(rc);
		goto out;
	}
out:
	inode_unlock(dir);
	return dentry;
}

/* Must be called with pcci->pcci_lock held */
static void pcc_inode_attach_init(struct pcc_dataset *dataset,
				  struct pcc_inode *pcci,
				  struct dentry *dentry,
				  enum lu_pcc_type type)
{
	pcci->pcci_path.mnt = mntget(dataset->pccd_path.mnt);
	pcci->pcci_path.dentry = dentry;
	LASSERT(atomic_read(&pcci->pcci_refcount) == 0);
	atomic_set(&pcci->pcci_refcount, 1);
	pcci->pcci_type = type;
	pcci->pcci_attr_valid = false;
}

static int __pcc_inode_create(struct pcc_dataset *dataset,
			      struct lu_fid *fid,
			      struct dentry **dentry)
{
	char *path;
	struct dentry *base;
	struct dentry *child;
	int rc = 0;

	path = kzalloc(MAX_PCC_DATABASE_PATH, GFP_NOFS);
	if (!path)
		return -ENOMEM;

	pcc_fid2dataset_path(path, MAX_PCC_DATABASE_PATH, fid);

	base = pcc_mkdir_p(dataset->pccd_path.dentry, path, 0700);
	if (IS_ERR(base)) {
		rc = PTR_ERR(base);
		goto out;
	}

	snprintf(path, MAX_PCC_DATABASE_PATH, DFID_NOBRACE, PFID(fid));
	child = pcc_create(base, path, 0600);
	if (IS_ERR(child)) {
		rc = PTR_ERR(child);
		goto out_base;
	}
	*dentry = child;

out_base:
	dput(base);
out:
	kfree(path);
	return rc;
}

int pcc_inode_create(struct pcc_dataset *dataset, struct lu_fid *fid,
		     struct dentry **pcc_dentry)
{
	return __pcc_inode_create(dataset, fid, pcc_dentry);
}

int pcc_inode_create_fini(struct pcc_dataset *dataset, struct inode *inode,
			  struct dentry *pcc_dentry)
{
	struct pcc_inode *pcci;
	int rc = 0;

	pcc_inode_lock(inode);
	LASSERT(!ll_i2pcci(inode));
	pcci = kmem_cache_zalloc(pcc_inode_slab, GFP_NOFS);
	if (!pcci) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	pcc_inode_init(pcci, ll_i2info(inode));
	pcc_inode_attach_init(dataset, pcci, pcc_dentry, LU_PCC_READWRITE);
	/* Set the layout generation of newly created file with 0 */
	pcc_layout_gen_set(pcci, 0);

out_unlock:
	if (rc) {
		int rc2;

		rc2 = vfs_unlink(pcc_dentry->d_parent->d_inode,
				 pcc_dentry, NULL);
		if (rc2)
			CWARN("failed to unlink PCC file, rc = %d\n", rc2);

		dput(pcc_dentry);
	}

	pcc_inode_unlock(inode);
	return rc;
}

static int pcc_filp_write(struct file *filp, const void *buf, ssize_t count,
			  loff_t *offset)
{
	while (count > 0) {
		ssize_t size;

		size = vfs_write(filp, (const void __user *)buf, count, offset);
		if (size < 0)
			return size;
		count -= size;
		buf += size;
	}
	return 0;
}

static int pcc_copy_data(struct file *src, struct file *dst)
{
	int rc = 0;
	ssize_t rc2;
	mm_segment_t oldfs;
	loff_t pos, offset = 0;
	size_t buf_len = 1048576;
	void *buf;

	buf = kvzalloc(buf_len, GFP_NOFS);
	if (!buf)
		return -ENOMEM;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	while (1) {
		pos = offset;
		rc2 = vfs_read(src, (void __user *)buf, buf_len, &pos);
		if (rc2 < 0) {
			rc = rc2;
			goto out_fs;
		} else if (rc2 == 0)
			break;

		pos = offset;
		rc = pcc_filp_write(dst, buf, rc2, &pos);
		if (rc < 0)
			goto out_fs;
		offset += rc2;
	}

out_fs:
	set_fs(oldfs);
	kvfree(buf);
	return rc;
}

static int pcc_attach_allowed_check(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	int rc = 0;

	pcc_inode_lock(inode);
	if (lli->lli_pcc_state & PCC_STATE_FL_ATTACHING) {
		rc = -EBUSY;
		goto out_unlock;
	}

	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		rc = -EEXIST;
		goto out_unlock;
	}

	lli->lli_pcc_state |= PCC_STATE_FL_ATTACHING;
out_unlock:
	pcc_inode_unlock(inode);
	return rc;
}

int pcc_readwrite_attach(struct file *file, struct inode *inode,
			 u32 archive_id)
{
	struct pcc_dataset *dataset;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	struct dentry *dentry;
	struct file *pcc_filp;
	struct path path;
	int rc;

	rc = pcc_attach_allowed_check(inode);
	if (rc)
		return rc;

	dataset = pcc_dataset_get(&ll_i2sbi(inode)->ll_pcc_super, 0,
				  archive_id);
	if (!dataset)
		return -ENOENT;

	rc = __pcc_inode_create(dataset, &lli->lli_fid, &dentry);
	if (rc)
		goto out_dataset_put;

	path.mnt = dataset->pccd_path.mnt;
	path.dentry = dentry;
	pcc_filp = dentry_open(&path, O_TRUNC | O_WRONLY | O_LARGEFILE,
			       current_cred());
	if (IS_ERR_OR_NULL(pcc_filp)) {
		rc = pcc_filp ? PTR_ERR(pcc_filp) : -EINVAL;
		goto out_dentry;
	}

	rc = pcc_copy_data(file, pcc_filp);
	if (rc)
		goto out_fput;

	/* Pause to allow for a race with concurrent HSM remove */
	OBD_FAIL_TIMEOUT(OBD_FAIL_LLITE_PCC_ATTACH_PAUSE, cfs_fail_val);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	LASSERT(!pcci);
	pcci = kmem_cache_zalloc(pcc_inode_slab, GFP_NOFS);
	if (!pcci) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	pcc_inode_init(pcci, lli);
	pcc_inode_attach_init(dataset, pcci, dentry, LU_PCC_READWRITE);
out_unlock:
	pcc_inode_unlock(inode);
out_fput:
	fput(pcc_filp);
out_dentry:
	if (rc) {
		int rc2;

		rc2 = vfs_unlink(dentry->d_parent->d_inode, dentry, NULL);
		if (rc2)
			CWARN("failed to unlink PCC file, rc = %d\n", rc2);

		dput(dentry);
	}
out_dataset_put:
	pcc_dataset_put(dataset);
	return rc;
}

int pcc_readwrite_attach_fini(struct file *file, struct inode *inode,
			      u32 gen, bool lease_broken, int rc,
			      bool attached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	u32 gen2;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	lli->lli_pcc_state &= ~PCC_STATE_FL_ATTACHING;
	if ((rc || lease_broken)) {
		if (attached && pcci)
			pcc_inode_put(pcci);

		goto out_unlock;
	}

	/* PCC inode may be released due to layout lock revocatioin */
	if (!pcci) {
		rc = -ESTALE;
		goto out_unlock;
	}

	LASSERT(attached);
	rc = ll_layout_refresh(inode, &gen2);
	if (!rc) {
		if (gen2 == gen) {
			pcc_layout_gen_set(pcci, gen);
		} else {
			CDEBUG(D_CACHE,
			       DFID" layout changed from %d to %d.\n",
			       PFID(ll_inode2fid(inode)), gen, gen2);
			rc = -ESTALE;
			goto out_put;
		}
	}

out_put:
	if (rc) {
		pcc_inode_remove(pcci);
		pcc_inode_put(pcci);
	}
out_unlock:
	pcc_inode_unlock(inode);
	return rc;
}

int pcc_ioctl_detach(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	int rc = 0;

	pcc_inode_lock(inode);
	pcci = lli->lli_pcc_inode;
	if (!pcci || lli->lli_pcc_state & PCC_STATE_FL_ATTACHING ||
	    !pcc_inode_has_layout(pcci))
		goto out_unlock;

	__pcc_layout_invalidate(pcci);
	pcc_inode_put(pcci);

out_unlock:
	pcc_inode_unlock(inode);
	return rc;
}

int pcc_ioctl_state(struct file *file, struct inode *inode,
		    struct lu_pcc_state *state)
{
	int rc = 0;
	int count;
	char *buf;
	char *path;
	int buf_len = sizeof(state->pccs_path);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct pcc_inode *pcci;

	if (buf_len <= 0)
		return -EINVAL;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (!pcci) {
		state->pccs_type = LU_PCC_NONE;
		goto out_unlock;
	}

	count = atomic_read(&pcci->pcci_refcount);
	if (count == 0) {
		state->pccs_type = LU_PCC_NONE;
		state->pccs_open_count = 0;
		goto out_unlock;
	}

	if (pcc_inode_has_layout(pcci))
		count--;
	if (pccf->pccf_file)
		count--;
	state->pccs_type = pcci->pcci_type;
	state->pccs_open_count = count;
	state->pccs_flags = ll_i2info(inode)->lli_pcc_state;
	path = dentry_path_raw(pcci->pcci_path.dentry, buf, buf_len);
	if (IS_ERR(path)) {
		rc = PTR_ERR(path);
		goto out_unlock;
	}

	if (strlcpy(state->pccs_path, path, buf_len) >= buf_len) {
		rc = -ENAMETOOLONG;
		goto out_unlock;
	}

out_unlock:
	pcc_inode_unlock(inode);
	kfree(buf);
	return rc;
}
