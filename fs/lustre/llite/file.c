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
 * lustre/llite/file.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE
#include <lustre_dlm.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <uapi/linux/lustre/lustre_fiemap.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <uapi/linux/fscrypt.h>
#include <lustre_swab.h>
#include <linux/falloc.h>

#include <cl_object.h>
#include "llite_internal.h"
#include "vvp_internal.h"

struct split_param {
	struct inode	*sp_inode;
	u16		sp_mirror_id;
};

struct pcc_param {
	u64	pa_data_version;
	u32	pa_archive_id;
	u32	pa_layout_gen;
};

static int
ll_put_grouplock(struct inode *inode, struct file *file, unsigned long arg);

static int ll_lease_close(struct obd_client_handle *och, struct inode *inode,
			  bool *lease_broken);

static struct ll_file_data *ll_file_data_get(void)
{
	struct ll_file_data *fd;

	fd = kmem_cache_zalloc(ll_file_data_slab, GFP_KERNEL);
	if (!fd)
		return NULL;
	fd->fd_write_failed = false;
	pcc_file_init(&fd->fd_pcc_file);

	return fd;
}

static void ll_file_data_put(struct ll_file_data *fd)
{
	if (fd)
		kmem_cache_free(ll_file_data_slab, fd);
}

/**
 * Packs all the attributes into @op_data for the CLOSE rpc.
 */
static void ll_prepare_close(struct inode *inode, struct md_op_data *op_data,
			     struct obd_client_handle *och)
{
	struct ll_inode_info *lli = ll_i2info(inode);

	ll_prep_md_op_data(op_data, inode, NULL, NULL,
			   0, 0, LUSTRE_OPC_ANY, NULL);

	op_data->op_attr.ia_mode = inode->i_mode;
	op_data->op_attr.ia_atime = inode->i_atime;
	op_data->op_attr.ia_mtime = inode->i_mtime;
	op_data->op_attr.ia_ctime = inode->i_ctime;
	op_data->op_attr.ia_size = i_size_read(inode);
	op_data->op_attr.ia_valid |= (ATTR_MODE | ATTR_ATIME | ATTR_ATIME_SET |
				      ATTR_MTIME | ATTR_MTIME_SET |
				      ATTR_CTIME);
	op_data->op_xvalid |= OP_XVALID_CTIME_SET;
	op_data->op_attr_blocks = inode->i_blocks;
	op_data->op_attr_flags = ll_inode_to_ext_flags(inode->i_flags);
	if (test_bit(LLIF_PROJECT_INHERIT, &lli->lli_flags))
		op_data->op_attr_flags |= LUSTRE_PROJINHERIT_FL;
	op_data->op_open_handle = och->och_open_handle;

	/*
	 * For HSM: if inode data has been modified, pack it so that
	 * MDT can set data dirty flag in the archive.
	 */
	if (och->och_flags & FMODE_WRITE &&
	    test_and_clear_bit(LLIF_DATA_MODIFIED, &lli->lli_flags))
		op_data->op_bias |= MDS_DATA_MODIFIED;
}

/**
 * Perform a close, possibly with a bias.
 * The meaning of "data" depends on the value of "bias".
 *
 * If @bias is MDS_HSM_RELEASE then @data is a pointer to the data version.
 * If @bias is MDS_CLOSE_LAYOUT_SWAP then @data is a pointer to the inode to
 * swap layouts with.
 */
static int ll_close_inode_openhandle(struct inode *inode,
				     struct obd_client_handle *och,
				     enum mds_op_bias bias,
				     void *data)
{
	const struct ll_inode_info *lli = ll_i2info(inode);
	struct obd_export *md_exp = ll_i2mdexp(inode);
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int rc;

	if (!class_exp2obd(md_exp)) {
		CERROR("%s: invalid MDC connection handle closing " DFID "\n",
		       ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid));
		rc = 0;
		goto out;
	}

	op_data = kzalloc(sizeof(*op_data), GFP_NOFS);
	/*
	 * We leak openhandle and request here on error, but not much to be
	 * done in OOM case since app won't retry close on error either.
	 */
	if (!op_data) {
		rc = -ENOMEM;
		goto out;
	}

	ll_prepare_close(inode, op_data, och);
	switch (bias) {
	case MDS_CLOSE_LAYOUT_MERGE:
		/* merge blocks from the victim inode */
		op_data->op_attr_blocks += ((struct inode *)data)->i_blocks;
		op_data->op_attr.ia_valid |= ATTR_SIZE;
		op_data->op_xvalid |= OP_XVALID_BLOCKS;
		/* fallthrough */
	case MDS_CLOSE_LAYOUT_SPLIT:
	case MDS_CLOSE_LAYOUT_SWAP: {
		struct split_param *sp = data;

		LASSERT(data);
		op_data->op_bias |= bias;
		op_data->op_data_version = 0;
		op_data->op_lease_handle = och->och_lease_handle;
		if (bias == MDS_CLOSE_LAYOUT_SPLIT) {
			op_data->op_fid2 = *ll_inode2fid(sp->sp_inode);
			op_data->op_mirror_id = sp->sp_mirror_id;
		} else {
			op_data->op_fid2 = *ll_inode2fid(data);
		}
		break;
	}

	case MDS_CLOSE_RESYNC_DONE: {
		struct ll_ioc_lease *ioc = data;

		LASSERT(data);
		op_data->op_attr_blocks +=
			ioc->lil_count * op_data->op_attr_blocks;
		op_data->op_attr.ia_valid |= ATTR_SIZE;
		op_data->op_xvalid |= OP_XVALID_BLOCKS;
		op_data->op_bias |= MDS_CLOSE_RESYNC_DONE;

		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_data = &ioc->lil_ids[0];
		op_data->op_data_size =
			ioc->lil_count * sizeof(ioc->lil_ids[0]);
		break;
	}

	case MDS_PCC_ATTACH: {
		struct pcc_param *param = data;

		LASSERT(data);
		op_data->op_bias |= MDS_HSM_RELEASE | MDS_PCC_ATTACH;
		op_data->op_archive_id = param->pa_archive_id;
		op_data->op_data_version = param->pa_data_version;
		op_data->op_lease_handle = och->och_lease_handle;
		break;
	}

	case MDS_HSM_RELEASE:
		LASSERT(data);
		op_data->op_bias |= MDS_HSM_RELEASE;
		op_data->op_data_version = *(u64 *)data;
		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_attr.ia_valid |= ATTR_SIZE;
		op_data->op_xvalid |= OP_XVALID_BLOCKS;
		break;

	default:
		LASSERT(!data);
		break;
	}

	if (!(op_data->op_attr.ia_valid & ATTR_SIZE))
		op_data->op_xvalid |= OP_XVALID_LAZYSIZE;
	if (!(op_data->op_xvalid & OP_XVALID_BLOCKS))
		op_data->op_xvalid |= OP_XVALID_LAZYBLOCKS;

	rc = md_close(md_exp, op_data, och->och_mod, &req);
	if (rc && rc != -EINTR) {
		CERROR("%s: inode " DFID " mdc close failed: rc = %d\n",
		       md_exp->exp_obd->obd_name, PFID(&lli->lli_fid), rc);
	}

	if (rc == 0 && (op_data->op_bias & bias)) {
		struct mdt_body *body;

		body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
		if (!(body->mbo_valid & OBD_MD_CLOSE_INTENT_EXECED))
			rc = -EBUSY;

		if (bias & MDS_PCC_ATTACH) {
			struct pcc_param *param = data;

			param->pa_layout_gen = body->mbo_layout_gen;
		}
	}

	ll_finish_md_op_data(op_data);

out:
	md_clear_open_replay_data(md_exp, och);
	och->och_open_handle.cookie = DEAD_HANDLE_MAGIC;
	kfree(och);

	ptlrpc_req_finished(req);
	return rc;
}

int ll_md_real_close(struct inode *inode, fmode_t fmode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct obd_client_handle **och_p;
	struct obd_client_handle *och;
	u64 *och_usecount;
	int rc = 0;

	if (fmode & FMODE_WRITE) {
		och_p = &lli->lli_mds_write_och;
		och_usecount = &lli->lli_open_fd_write_count;
	} else if (fmode & FMODE_EXEC) {
		och_p = &lli->lli_mds_exec_och;
		och_usecount = &lli->lli_open_fd_exec_count;
	} else {
		LASSERT(fmode & FMODE_READ);
		och_p = &lli->lli_mds_read_och;
		och_usecount = &lli->lli_open_fd_read_count;
	}

	mutex_lock(&lli->lli_och_mutex);
	if (*och_usecount > 0) {
		/* There are still users of this handle, so skip
		 * freeing it.
		 */
		mutex_unlock(&lli->lli_och_mutex);
		return 0;
	}

	och = *och_p;
	*och_p = NULL;
	mutex_unlock(&lli->lli_och_mutex);

	if (och) {
		/* There might be a race and this handle may already
		 * be closed.
		 */
		rc = ll_close_inode_openhandle(inode, och, 0, NULL);
	}

	return rc;
}

static int ll_md_close(struct inode *inode, struct file *file)
{
	struct ll_file_data *fd = file->private_data;
	struct ll_inode_info *lli = ll_i2info(inode);
	int lockmode;
	u64 flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_TEST_LOCK;
	struct lustre_handle lockh;
	union ldlm_policy_data policy = {
		.l_inodebits = { MDS_INODELOCK_OPEN }
	};
	int rc = 0;

	/* clear group lock, if present */
	if (unlikely(fd->fd_flags & LL_FILE_GROUP_LOCKED))
		ll_put_grouplock(inode, file, fd->fd_grouplock.lg_gid);

	if (fd->fd_lease_och) {
		bool lease_broken;

		/* Usually the lease is not released when the
		 * application crashed, we need to release here.
		 */
		rc = ll_lease_close(fd->fd_lease_och, inode, &lease_broken);
		CDEBUG(rc ? D_ERROR : D_INODE,
		       "Clean up lease " DFID " %d/%d\n",
		       PFID(&lli->lli_fid), rc, lease_broken);

		fd->fd_lease_och = NULL;
	}

	if (fd->fd_och) {
		rc = ll_close_inode_openhandle(inode, fd->fd_och, 0, NULL);
		fd->fd_och = NULL;
		goto out;
	}

	/* Let's see if we have good enough OPEN lock on the file and if
	 * we can skip talking to MDS
	 */

	mutex_lock(&lli->lli_och_mutex);
	if (fd->fd_omode & FMODE_WRITE) {
		lockmode = LCK_CW;
		LASSERT(lli->lli_open_fd_write_count);
		lli->lli_open_fd_write_count--;
	} else if (fd->fd_omode & FMODE_EXEC) {
		lockmode = LCK_PR;
		LASSERT(lli->lli_open_fd_exec_count);
		lli->lli_open_fd_exec_count--;
	} else {
		lockmode = LCK_CR;
		LASSERT(lli->lli_open_fd_read_count);
		lli->lli_open_fd_read_count--;
	}
	mutex_unlock(&lli->lli_och_mutex);

	/* LU-4398: do not cache write open lock if the file has exec bit */
	if ((lockmode == LCK_CW && inode->i_mode & 0111) ||
	    !md_lock_match(ll_i2mdexp(inode), flags, ll_inode2fid(inode),
			   LDLM_IBITS, &policy, lockmode, &lockh))
		rc = ll_md_real_close(inode, fd->fd_omode);

out:
	file->private_data = NULL;
	ll_file_data_put(fd);

	return rc;
}

/* While this returns an error code, fput() the caller does not, so we need
 * to make every effort to clean up all of our state here.  Also, applications
 * rarely check close errors and even if an error is returned they will not
 * re-try the close call.
 */
int ll_file_release(struct inode *inode, struct file *file)
{
	struct ll_file_data *fd;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ll_inode_info *lli = ll_i2info(inode);
	ktime_t kstart = ktime_get();
	int rc;

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);

	fd = file->private_data;
	LASSERT(fd);

	/* The last ref on @file, maybe not be the owner pid of statahead,
	 * because parent and child process can share the same file handle.
	 */
	if (S_ISDIR(inode->i_mode) && lli->lli_opendir_key == fd)
		ll_deauthorize_statahead(inode, fd);

	if (is_root_inode(inode)) {
		file->private_data = NULL;
		ll_file_data_put(fd);
		rc = 0;
		goto out;
	}

	pcc_file_release(inode, file);

	if (!S_ISDIR(inode->i_mode)) {
		if (lli->lli_clob)
			lov_read_and_clear_async_rc(lli->lli_clob);
		lli->lli_async_rc = 0;
	}

	rc = ll_md_close(inode, file);

	if (CFS_FAIL_TIMEOUT_MS(OBD_FAIL_PTLRPC_DUMP_LOG, cfs_fail_val))
		libcfs_debug_dumplog();

out:
	if (!rc && inode->i_sb->s_root != file_dentry(file))
		ll_stats_ops_tally(sbi, LPROC_LL_RELEASE,
				   ktime_us_delta(ktime_get(), kstart));
	return rc;
}

static inline int ll_dom_readpage(void *data, struct page *page)
{
	struct niobuf_local *lnb = data;
	void *kaddr;
	int rc = 0;

	struct inode *inode = page2inode(page);

	kaddr = kmap_atomic(page);
	memcpy(kaddr, lnb->lnb_data, lnb->lnb_len);
	if (lnb->lnb_len < PAGE_SIZE)
		memset(kaddr + lnb->lnb_len, 0,
		       PAGE_SIZE - lnb->lnb_len);
	flush_dcache_page(page);
	SetPageUptodate(page);
	kunmap_atomic(kaddr);

	if (inode && IS_ENCRYPTED(inode) && S_ISREG(inode->i_mode)) {
		if (!fscrypt_has_encryption_key(inode))
			CDEBUG(D_SEC, "no enc key for "DFID"\n",
			       PFID(ll_inode2fid(inode)));
		else {
			unsigned int offs = 0;

			while (offs < PAGE_SIZE) {
				/* decrypt only if page is not empty */
				if (memcmp(page_address(page) + offs,
					   page_address(ZERO_PAGE(0)),
					   LUSTRE_ENCRYPTION_UNIT_SIZE) == 0)
					break;

				rc = fscrypt_decrypt_pagecache_blocks(page,
						    LUSTRE_ENCRYPTION_UNIT_SIZE,
								      offs);
				if (rc)
					break;

				offs += LUSTRE_ENCRYPTION_UNIT_SIZE;
			}
		}
	}
	unlock_page(page);

	return rc;
}

void ll_dom_finish_open(struct inode *inode, struct ptlrpc_request *req)
{
	struct lu_env *env;
	struct cl_io *io;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct address_space *mapping = inode->i_mapping;
	struct page *vmpage;
	struct niobuf_remote *rnb;
	struct mdt_body *body;
	char *data;
	unsigned long index, start;
	struct niobuf_local lnb;
	u16 refcheck;
	int rc;

	if (!obj)
		return;

	if (!req_capsule_field_present(&req->rq_pill, &RMF_NIOBUF_INLINE,
				       RCL_SERVER))
		return;

	rnb = req_capsule_server_get(&req->rq_pill, &RMF_NIOBUF_INLINE);
	if (!rnb || rnb->rnb_len == 0)
		return;

	/* LU-11595: Server may return whole file and that is OK always or
	 * it may return just file tail and its offset must be aligned with
	 * client PAGE_SIZE to be used on that client, if server's PAGE_SIZE is
	 * smaller then offset may be not aligned and that data is just ignored.
	 */
	if (rnb->rnb_offset & ~PAGE_MASK)
		return;

	/* Server returns whole file or just file tail if it fills in reply
	 * buffer, in both cases total size should be equal to the file size.
	 */
	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	if (rnb->rnb_offset + rnb->rnb_len != body->mbo_dom_size &&
	    !(inode && IS_ENCRYPTED(inode))) {
		CERROR("%s: server returns off/len %llu/%u but size %llu\n",
		       ll_i2sbi(inode)->ll_fsname, rnb->rnb_offset,
		       rnb->rnb_len, body->mbo_dom_size);
		return;
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return;
	io = vvp_env_thread_io(env);
	io->ci_obj = obj;
	io->ci_ignore_layout = 1;
	rc = cl_io_init(env, io, CIT_MISC, obj);
	if (rc)
		goto out_io;

	CDEBUG(D_INFO, "Get data along with open at %llu len %i, size %llu\n",
	       rnb->rnb_offset, rnb->rnb_len, body->mbo_dom_size);

	data = (char *)rnb + sizeof(*rnb);

	lnb.lnb_file_offset = rnb->rnb_offset;
	start = lnb.lnb_file_offset >> PAGE_SHIFT;
	index = 0;
	LASSERT((lnb.lnb_file_offset & ~PAGE_MASK) == 0);
	lnb.lnb_page_offset = 0;
	do {
		struct cl_page *page;

		lnb.lnb_data = data + (index << PAGE_SHIFT);
		lnb.lnb_len = rnb->rnb_len - (index << PAGE_SHIFT);
		if (lnb.lnb_len > PAGE_SIZE)
			lnb.lnb_len = PAGE_SIZE;

		vmpage = read_cache_page(mapping, index + start,
					 ll_dom_readpage, &lnb);
		if (IS_ERR(vmpage)) {
			CWARN("%s: cannot fill page %lu for "DFID
			      " with data: rc = %li\n",
			      ll_i2sbi(inode)->ll_fsname, index + start,
			      PFID(lu_object_fid(&obj->co_lu)),
			      PTR_ERR(vmpage));
			break;
		}
		lock_page(vmpage);
		if (!vmpage->mapping) {
			unlock_page(vmpage);
			put_page(vmpage);
			/* page was truncated */
			break;
		}
		/* attach VM page to CL page cache */
		page = cl_page_find(env, obj, vmpage->index, vmpage,
				    CPT_CACHEABLE);
		if (IS_ERR(page)) {
			ClearPageUptodate(vmpage);
			unlock_page(vmpage);
			put_page(vmpage);
			break;
		}
		cl_page_export(env, page, 1);
		cl_page_put(env, page);
		unlock_page(vmpage);
		put_page(vmpage);
		index++;
	} while (rnb->rnb_len > (index << PAGE_SHIFT));

out_io:
	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);
}

static int ll_intent_file_open(struct dentry *de, void *lmm, int lmmsize,
			       struct lookup_intent *itp)
{
	struct inode *inode = d_inode(de);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct dentry *parent = de->d_parent;
	char *name = NULL;
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int len = 0, rc;

	LASSERT(parent);
	LASSERT(itp->it_flags & MDS_OPEN_BY_FID);

	/*
	 * if server supports open-by-fid, or file name is invalid, don't pack
	 * name in open request
	 */
	if (OBD_FAIL_CHECK(OBD_FAIL_LLITE_OPEN_BY_NAME) ||
	    !(exp_connect_flags(sbi->ll_md_exp) & OBD_CONNECT_OPEN_BY_FID)) {
retry:
		len = de->d_name.len;
		name = kmalloc(len + 1, GFP_NOFS);
		if (!name)
			return -ENOMEM;

		/* race here */
		spin_lock(&de->d_lock);
		if (len != de->d_name.len) {
			spin_unlock(&de->d_lock);
			kfree(name);
			goto retry;
		}
		memcpy(name, de->d_name.name, len);
		name[len] = '\0';
		spin_unlock(&de->d_lock);

		if (!lu_name_is_valid_2(name, len)) {
			kfree(name);
			return -ESTALE;
		}
	}

	op_data  = ll_prep_md_op_data(NULL, d_inode(parent), inode, name, len,
				      O_RDWR, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data)) {
		kfree(name);
		return PTR_ERR(op_data);
	}
	op_data->op_data = lmm;
	op_data->op_data_size = lmmsize;

	rc = md_intent_lock(sbi->ll_md_exp, op_data, itp, &req,
			    &ll_md_blocking_ast, 0);
	kfree(name);
	ll_finish_md_op_data(op_data);
	if (rc == -ESTALE) {
		/* reason for keep own exit path - don`t flood log
		 * with messages with -ESTALE errors.
		 */
		if (!it_disposition(itp, DISP_OPEN_OPEN) ||
		    it_open_error(DISP_OPEN_OPEN, itp))
			goto out;
		ll_release_openhandle(inode, itp);
		goto out;
	}

	if (it_disposition(itp, DISP_LOOKUP_NEG)) {
		rc = -ENOENT;
		goto out;
	}

	if (rc != 0 || it_open_error(DISP_OPEN_OPEN, itp)) {
		rc = rc ? rc : it_open_error(DISP_OPEN_OPEN, itp);
		CDEBUG(D_VFSTRACE, "lock enqueue: err: %d\n", rc);
		goto out;
	}

	rc = ll_prep_inode(&inode, req, NULL, itp);

	if (!rc && itp->it_lock_mode) {
		u64 bits = 0;

		/* If we got a lock back and it has a LOOKUP bit set,
		 * make sure the dentry is marked as valid so we can find it.
		 * We don't need to care about actual hashing since other bits
		 * of kernel will deal with that later.
		 */
		ll_set_lock_data(sbi->ll_md_exp, de->d_inode, itp, &bits);
		if (bits & MDS_INODELOCK_LOOKUP)
			ll_d2d(de)->lld_invalid = 0;
		/* if DoM bit returned along with LAYOUT bit then there
		 * can be read-on-open data returned.
		 */
		if (bits & MDS_INODELOCK_DOM && bits & MDS_INODELOCK_LAYOUT)
			ll_dom_finish_open(inode, req);
	}

out:
	ptlrpc_req_finished(req);
	ll_intent_drop_lock(itp);

	/*
	 * We did open by fid, but by the time we got to the server,
	 * the object disappeared. If this is a create, we cannot really
	 * tell the userspace that the file it was trying to create
	 * does not exist. Instead let's return -ESTALE, and the VFS will
	 * retry the create with LOOKUP_REVAL that we are going to catch
	 * in ll_revalidate_dentry() and use lookup then.
	 */
	if (rc == -ENOENT && itp->it_op & IT_CREAT)
		rc = -ESTALE;

	return rc;
}

static int ll_och_fill(struct obd_export *md_exp, struct lookup_intent *it,
		       struct obd_client_handle *och)
{
	struct mdt_body *body;

	body = req_capsule_server_get(&it->it_request->rq_pill, &RMF_MDT_BODY);
	och->och_open_handle = body->mbo_open_handle;
	och->och_fid = body->mbo_fid1;
	och->och_lease_handle.cookie = it->it_lock_handle;
	och->och_magic = OBD_CLIENT_HANDLE_MAGIC;
	och->och_flags = it->it_flags;

	return md_set_open_replay_data(md_exp, och, it);
}

static int ll_local_open(struct file *file, struct lookup_intent *it,
			 struct ll_file_data *fd, struct obd_client_handle *och)
{
	struct inode *inode = file_inode(file);

	LASSERT(!file->private_data);

	LASSERT(fd);

	if (och) {
		int rc;

		rc = ll_och_fill(ll_i2sbi(inode)->ll_md_exp, it, och);
		if (rc != 0)
			return rc;
	}

	file->private_data = fd;
	ll_readahead_init(inode, &fd->fd_ras);
	fd->fd_omode = it->it_flags & (FMODE_READ | FMODE_WRITE | FMODE_EXEC);

	/* ll_cl_context initialize */
	rwlock_init(&fd->fd_lock);
	INIT_LIST_HEAD(&fd->fd_lccs);

	return 0;
}

/* Open a file, and (for the very first open) create objects on the OSTs at
 * this time.  If opened with O_LOV_DELAY_CREATE, then we don't do the object
 * creation or open until ll_lov_setstripe() ioctl is called.
 *
 * If we already have the stripe MD locally then we don't request it in
 * md_open(), by passing a lmm_size = 0.
 *
 * It is up to the application to ensure no other processes open this file
 * in the O_LOV_DELAY_CREATE case, or the default striping pattern will be
 * used.  We might be able to avoid races of that sort by getting lli_open_sem
 * before returning in the O_LOV_DELAY_CREATE case and dropping it here
 * or in ll_file_release(), but I'm not sure that is desirable/necessary.
 */
int ll_file_open(struct inode *inode, struct file *file)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lookup_intent *it, oit = { .it_op = IT_OPEN,
					  .it_flags = file->f_flags };
	struct obd_client_handle **och_p = NULL;
	u64 *och_usecount = NULL;
	struct ll_file_data *fd;
	ktime_t kstart = ktime_get();
	int rc = 0;

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p), flags %o\n",
	       PFID(ll_inode2fid(inode)), inode, file->f_flags);

	it = file->private_data; /* XXX: compat macro */
	file->private_data = NULL; /* prevent ll_local_open assertion */

	if (S_ISREG(inode->i_mode)) {
		rc = fscrypt_file_open(inode, file);
		if (rc)
			goto out_nofiledata;
	}

	fd = ll_file_data_get();
	if (!fd) {
		rc = -ENOMEM;
		goto out_nofiledata;
	}

	fd->fd_file = file;
	if (S_ISDIR(inode->i_mode))
		ll_authorize_statahead(inode, fd);

	if (is_root_inode(inode)) {
		file->private_data = fd;
		return 0;
	}

	if (!it || !it->it_disposition) {
		/* Convert f_flags into access mode. We cannot use file->f_mode,
		 * because everything but O_ACCMODE mask was stripped from
		 * there
		 */
		if ((oit.it_flags + 1) & O_ACCMODE)
			oit.it_flags++;
		if (file->f_flags & O_TRUNC)
			oit.it_flags |= FMODE_WRITE;

		/* kernel only call f_op->open in dentry_open.  filp_open calls
		 * dentry_open after call to open_namei that checks permissions.
		 * Only nfsd_open call dentry_open directly without checking
		 * permissions and because of that this code below is safe.
		 */
		if (oit.it_flags & (FMODE_WRITE | FMODE_READ))
			oit.it_flags |= MDS_OPEN_OWNEROVERRIDE;

		/* We do not want O_EXCL here, presumably we opened the file
		 * already? XXX - NFS implications?
		 */
		oit.it_flags &= ~O_EXCL;

		/* bug20584, if "it_flags" contains O_CREAT, the file will be
		 * created if necessary, then "IT_CREAT" should be set to keep
		 * consistent with it
		 */
		if (oit.it_flags & O_CREAT)
			oit.it_op |= IT_CREAT;

		it = &oit;
	}

restart:
	/* Let's see if we have file open on MDS already. */
	if (it->it_flags & FMODE_WRITE) {
		och_p = &lli->lli_mds_write_och;
		och_usecount = &lli->lli_open_fd_write_count;
	} else if (it->it_flags & FMODE_EXEC) {
		och_p = &lli->lli_mds_exec_och;
		och_usecount = &lli->lli_open_fd_exec_count;
	} else {
		och_p = &lli->lli_mds_read_och;
		och_usecount = &lli->lli_open_fd_read_count;
	}

	mutex_lock(&lli->lli_och_mutex);
	if (*och_p) { /* Open handle is present */
		if (it_disposition(it, DISP_OPEN_OPEN)) {
			/* Well, there's extra open request that we do not need,
			 * let's close it somehow. This will decref request.
			 */
			rc = it_open_error(DISP_OPEN_OPEN, it);
			if (rc) {
				mutex_unlock(&lli->lli_och_mutex);
				goto out_openerr;
			}

			ll_release_openhandle(inode, it);
		}
		(*och_usecount)++;

		rc = ll_local_open(file, it, fd, NULL);
		if (rc) {
			(*och_usecount)--;
			mutex_unlock(&lli->lli_och_mutex);
			goto out_openerr;
		}
	} else {
		LASSERT(*och_usecount == 0);
		if (!it->it_disposition) {
			struct dentry *dentry = file_dentry(file);
			struct ll_dentry_data *ldd;

			/* We cannot just request lock handle now, new ELC code
			 * means that one of other OPEN locks for this file
			 * could be cancelled, and since blocking ast handler
			 * would attempt to grab och_mutex as well, that would
			 * result in a deadlock
			 */
			mutex_unlock(&lli->lli_och_mutex);
			/*
			 * Normally called under two situations:
			 * 1. NFS export.
			 * 2. A race/condition on MDS resulting in no open
			 *    handle to be returned from LOOKUP|OPEN request,
			 *    for example if the target entry was a symlink.
			 *
			 * Only fetch MDS_OPEN_LOCK if this is in NFS path,
			 * marked by a bit set in ll_iget_for_nfs. Clear the
			 * bit so that it's not confusing later callers.
			 *
			 * NB; when ldd is NULL, it must have come via normal
			 * lookup path only, since ll_iget_for_nfs always calls
			 * ll_d_init().
			 */
			ldd = ll_d2d(dentry);
			if (ldd && ldd->lld_nfs_dentry) {
				ldd->lld_nfs_dentry = 0;
				if (!filename_is_volatile(dentry->d_name.name,
							  dentry->d_name.len,
							  NULL))
					it->it_flags |= MDS_OPEN_LOCK;
			}

			/*
			 * Always specify MDS_OPEN_BY_FID because we don't want
			 * to get file with different fid.
			 */
			it->it_flags |= MDS_OPEN_BY_FID;
			rc = ll_intent_file_open(dentry, NULL, 0, it);
			if (rc)
				goto out_openerr;

			goto restart;
		}
		*och_p = kzalloc(sizeof(**och_p), GFP_NOFS);
		if (!*och_p) {
			rc = -ENOMEM;
			goto out_och_free;
		}

		(*och_usecount)++;

		/* md_intent_lock() didn't get a request ref if there was an
		 * open error, so don't do cleanup on the request here
		 * (bug 3430)
		 */
		/* XXX (green): Should not we bail out on any error here, not
		 * just open error?
		 */
		rc = it_open_error(DISP_OPEN_OPEN, it);
		if (rc)
			goto out_och_free;

		LASSERTF(it_disposition(it, DISP_ENQ_OPEN_REF),
			 "inode %p: disposition %x, status %d\n", inode,
			 it_disposition(it, ~0), it->it_status);

		rc = ll_local_open(file, it, fd, *och_p);
		if (rc)
			goto out_och_free;
	}

	rc = pcc_file_open(inode, file);
	if (rc)
		goto out_och_free;

	mutex_unlock(&lli->lli_och_mutex);

	/* lockless for direct IO so that it can do IO in parallel */
	if (file->f_flags & O_DIRECT)
		fd->fd_flags |= LL_FILE_LOCKLESS_IO;
	fd = NULL;

	/* Must do this outside lli_och_mutex lock to prevent deadlock where
	 * different kind of OPEN lock for this same inode gets cancelled
	 * by ldlm_cancel_lru
	 */
	if (!S_ISREG(inode->i_mode))
		goto out_och_free;
	cl_lov_delay_create_clear(&file->f_flags);
	goto out_och_free;

out_och_free:
	if (rc) {
		if (och_p && *och_p) {
			kfree(*och_p);
			*och_p = NULL;
			(*och_usecount)--;
		}
		mutex_unlock(&lli->lli_och_mutex);

out_openerr:
		if (lli->lli_opendir_key == fd)
			ll_deauthorize_statahead(inode, fd);

		if (fd)
			ll_file_data_put(fd);
	} else {
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_OPEN,
				   ktime_us_delta(ktime_get(), kstart));
	}

out_nofiledata:
	if (it && it_disposition(it, DISP_ENQ_OPEN_REF)) {
		ptlrpc_req_finished(it->it_request);
		it_clear_disposition(it, DISP_ENQ_OPEN_REF);
	}

	return rc;
}

static int ll_md_blocking_lease_ast(struct ldlm_lock *lock,
				    struct ldlm_lock_desc *desc,
				    void *data, int flag)
{
	int rc;
	struct lustre_handle lockh;

	switch (flag) {
	case LDLM_CB_BLOCKING:
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		if (rc < 0) {
			CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
			return rc;
		}
		break;
	case LDLM_CB_CANCELING:
		/* do nothing */
		break;
	}
	return 0;
}

/**
 * When setting a lease on a file, we take ownership of the lli_mds_*_och
 * and save it as fd->fd_och so as to force client to reopen the file even
 * if it has an open lock in cache already.
 */
static int ll_lease_och_acquire(struct inode *inode, struct file *file,
				struct lustre_handle *old_open_handle)
{
	struct ll_file_data *fd = file->private_data;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct obd_client_handle **och_p;
	u64 *och_usecount;
	int rc = 0;

	/* Get the openhandle of the file */
	mutex_lock(&lli->lli_och_mutex);
	if (fd->fd_lease_och) {
		rc = -EBUSY;
		goto out_unlock;
	}

	if (!fd->fd_och) {
		if (file->f_mode & FMODE_WRITE) {
			LASSERT(lli->lli_mds_write_och);
			och_p = &lli->lli_mds_write_och;
			och_usecount = &lli->lli_open_fd_write_count;
		} else {
			LASSERT(lli->lli_mds_read_och);
			och_p = &lli->lli_mds_read_och;
			och_usecount = &lli->lli_open_fd_read_count;
		}

		if (*och_usecount > 1) {
			rc = -EBUSY;
			goto out_unlock;
		}

		fd->fd_och = *och_p;
		*och_usecount = 0;
		*och_p = NULL;
	}

	*old_open_handle = fd->fd_och->och_open_handle;

out_unlock:
	mutex_unlock(&lli->lli_och_mutex);
	return rc;
}

/**
 * Release ownership on lli_mds_*_och when putting back a file lease.
 */
static int ll_lease_och_release(struct inode *inode, struct file *file)
{
	struct ll_file_data *fd = file->private_data;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct obd_client_handle *old_och = NULL;
	struct obd_client_handle **och_p;
	u64 *och_usecount;
	int rc = 0;

	mutex_lock(&lli->lli_och_mutex);
	if (file->f_mode & FMODE_WRITE) {
		och_p = &lli->lli_mds_write_och;
		och_usecount = &lli->lli_open_fd_write_count;
	} else {
		och_p = &lli->lli_mds_read_och;
		och_usecount = &lli->lli_open_fd_read_count;
	}

	/*
	 * The file may have been open by another process (broken lease) so
	 * *och_p is not NULL. In this case we should simply increase usecount
	 * and close fd_och.
	 */
	if (*och_p) {
		old_och = fd->fd_och;
		(*och_usecount)++;
	} else {
		*och_p = fd->fd_och;
		*och_usecount = 1;
	}
	fd->fd_och = NULL;
	mutex_unlock(&lli->lli_och_mutex);

	if (old_och)
		rc = ll_close_inode_openhandle(inode, old_och, 0, NULL);

	return rc;
}

/**
 * Acquire a lease and open the file.
 */
static struct obd_client_handle *
ll_lease_open(struct inode *inode, struct file *file, fmode_t fmode,
	      u64 open_flags)
{
	struct lookup_intent it = { .it_op = IT_OPEN };
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	struct lustre_handle old_open_handle = { 0 };
	struct obd_client_handle *och = NULL;
	int rc;
	int rc2;

	if (fmode != FMODE_WRITE && fmode != FMODE_READ)
		return ERR_PTR(-EINVAL);

	if (file) {
		if (!(fmode & file->f_mode) || (file->f_mode & FMODE_EXEC))
			return ERR_PTR(-EPERM);

		rc = ll_lease_och_acquire(inode, file, &old_open_handle);
		if (rc)
			return ERR_PTR(rc);
	}

	och = kzalloc(sizeof(*och), GFP_KERNEL);
	if (!och)
		return ERR_PTR(-ENOMEM);

	op_data = ll_prep_md_op_data(NULL, inode, inode, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data)) {
		rc = PTR_ERR(op_data);
		goto out;
	}

	/* To tell the MDT this openhandle is from the same owner */
	op_data->op_open_handle = old_open_handle;

	it.it_flags = fmode | open_flags;
	it.it_flags |= MDS_OPEN_LOCK | MDS_OPEN_BY_FID | MDS_OPEN_LEASE;
	rc = md_intent_lock(sbi->ll_md_exp, op_data, &it, &req,
			    &ll_md_blocking_lease_ast,
	/* LDLM_FL_NO_LRU: To not put the lease lock into LRU list, otherwise
	 * it can be cancelled which may mislead applications that the lease is
	 * broken;
	 * LDLM_FL_EXCL: Set this flag so that it won't be matched by normal
	 * open in ll_md_blocking_ast(). Otherwise as ll_md_blocking_lease_ast
	 * doesn't deal with openhandle, so normal openhandle will be leaked.
	 */
			    LDLM_FL_NO_LRU | LDLM_FL_EXCL);
	ll_finish_md_op_data(op_data);
	ptlrpc_req_finished(req);
	if (rc < 0)
		goto out_release_it;

	if (it_disposition(&it, DISP_LOOKUP_NEG)) {
		rc = -ENOENT;
		goto out_release_it;
	}

	rc = it_open_error(DISP_OPEN_OPEN, &it);
	if (rc)
		goto out_release_it;

	LASSERT(it_disposition(&it, DISP_ENQ_OPEN_REF));
	rc = ll_och_fill(sbi->ll_md_exp, &it, och);
	if (rc)
		goto out_release_it;

	if (!it_disposition(&it, DISP_OPEN_LEASE)) /* old server? */ {
		rc = -EOPNOTSUPP;
		goto out_close;
	}

	/* already get lease, handle lease lock */
	ll_set_lock_data(sbi->ll_md_exp, inode, &it, NULL);
	if (!it.it_lock_mode ||
	    !(it.it_lock_bits & MDS_INODELOCK_OPEN)) {
		/* open lock must return for lease */
		CERROR(DFID "lease granted but no open lock, %d/%llu.\n",
		       PFID(ll_inode2fid(inode)), it.it_lock_mode,
		       it.it_lock_bits);
		rc = -EPROTO;
		goto out_close;
	}

	ll_intent_release(&it);
	return och;

out_close:
	/* Cancel open lock */
	if (it.it_lock_mode != 0) {
		ldlm_lock_decref_and_cancel(&och->och_lease_handle,
					    it.it_lock_mode);
		it.it_lock_mode = 0;
		och->och_lease_handle.cookie = 0ULL;
	}
	rc2 = ll_close_inode_openhandle(inode, och, 0, NULL);
	if (rc2 < 0)
		CERROR("%s: error closing file " DFID ": %d\n",
		       sbi->ll_fsname, PFID(&ll_i2info(inode)->lli_fid), rc2);
	och = NULL; /* och has been freed in ll_close_inode_openhandle() */
out_release_it:
	ll_intent_release(&it);
out:
	kfree(och);
	return ERR_PTR(rc);
}

/**
 * Check whether a layout swap can be done between two inodes.
 *
 * @inode1:	First inode to check
 * @inode2:	Second inode to check
 *
 * Return:	0 on success, layout swap can be performed between
 *		both inodes
 *		negative error code if requirements are not met
 */
static int ll_check_swap_layouts_validity(struct inode *inode1,
					  struct inode *inode2)
{
	if (!S_ISREG(inode1->i_mode) || !S_ISREG(inode2->i_mode))
		return -EINVAL;

	if (inode_permission(inode1, MAY_WRITE) ||
	    inode_permission(inode2, MAY_WRITE))
		return -EPERM;

	if (inode1->i_sb != inode2->i_sb)
		return -EXDEV;

	return 0;
}

static int ll_swap_layouts_close(struct obd_client_handle *och,
				 struct inode *inode, struct inode *inode2)
{
	const struct lu_fid *fid1 = ll_inode2fid(inode);
	const struct lu_fid *fid2;
	int rc;

	CDEBUG(D_INODE, "%s: biased close of file " DFID "\n",
	       ll_i2sbi(inode)->ll_fsname, PFID(fid1));

	rc = ll_check_swap_layouts_validity(inode, inode2);
	if (rc < 0)
		goto out_free_och;

	/* We now know that inode2 is a lustre inode */
	fid2 = ll_inode2fid(inode2);

	rc = lu_fid_cmp(fid1, fid2);
	if (!rc) {
		rc = -EINVAL;
		goto out_free_och;
	}

	/*
	 * Close the file and {swap,merge} layouts between inode & inode2.
	 * NB: lease lock handle is released in mdc_close_layout_swap_pack()
	 * because we still need it to pack l_remote_handle to MDT.
	 */
	rc = ll_close_inode_openhandle(inode, och, MDS_CLOSE_LAYOUT_SWAP,
				       inode2);

	och = NULL; /* freed in ll_close_inode_openhandle() */

out_free_och:
	kfree(och);
	return rc;
}

/**
 * Release lease and close the file.
 * It will check if the lease has ever broken.
 */
static int ll_lease_close_intent(struct obd_client_handle *och,
				 struct inode *inode,
				 bool *lease_broken, enum mds_op_bias bias,
				 void *data)
{
	struct ldlm_lock *lock;
	bool cancelled = true;

	lock = ldlm_handle2lock(&och->och_lease_handle);
	if (lock) {
		lock_res_and_lock(lock);
		cancelled = ldlm_is_cancel(lock);
		unlock_res_and_lock(lock);
		LDLM_LOCK_PUT(lock);
	}

	CDEBUG(D_INODE, "lease for " DFID " broken? %d, bias: %x\n",
	       PFID(&ll_i2info(inode)->lli_fid), cancelled, bias);

	if (lease_broken)
		*lease_broken = cancelled;

	if (!cancelled && !bias)
		ldlm_cli_cancel(&och->och_lease_handle, 0);
	if (cancelled) { /* no need to excute intent */
		bias = 0;
		data = NULL;
	}

	return ll_close_inode_openhandle(inode, och, bias, data);
}

static int ll_lease_close(struct obd_client_handle *och, struct inode *inode,
			  bool *lease_broken)
{
	return ll_lease_close_intent(och, inode, lease_broken, 0, NULL);
}

/**
 * After lease is taken, send the RPC MDS_REINT_RESYNC to the MDT
 */
static int ll_lease_file_resync(struct obd_client_handle *och,
				struct inode *inode, unsigned long arg)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	struct ll_ioc_lease_id ioc;
	u64 data_version_unused;
	int rc;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	if (copy_from_user(&ioc, (struct ll_ioc_lease_id __user *)arg,
			   sizeof(ioc)))
		return -EFAULT;

	/* before starting file resync, it's necessary to clean up page cache
	 * in client memory, otherwise once the layout version is increased,
	 * writing back cached data will be denied the OSTs.
	 */
	rc = ll_data_version(inode, &data_version_unused, LL_DV_WR_FLUSH);
	if (rc)
		goto out;

	op_data->op_lease_handle = och->och_lease_handle;
	op_data->op_mirror_id = ioc.lil_mirror_id;
	rc = md_file_resync(sbi->ll_md_exp, op_data);
	if (rc)
		goto out;

out:
	ll_finish_md_op_data(op_data);
	return rc;
}

int ll_merge_attr(const struct lu_env *env, struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct cl_attr *attr = vvp_env_thread_attr(env);
	s64 atime;
	s64 mtime;
	s64 ctime;
	int rc = 0;

	ll_inode_size_lock(inode);

	/*
	 * merge timestamps the most recently obtained from MDS with
	 * timestamps obtained from OSTSs.
	 *
	 * Do not overwrite atime of inode because it may be refreshed
	 * by file_accessed() function. If the read was served by cache
	 * data, there is no RPC to be sent so that atime may not be
	 * transferred to OSTs at all. MDT only updates atime at close time
	 * if it's at least 'mdd.*.atime_diff' older.
	 * All in all, the atime in Lustre does not strictly comply with
	 * POSIX. Solving this problem needs to send an RPC to MDT for each
	 * read, this will hurt performance.
	 */
	if (inode->i_atime.tv_sec < lli->lli_atime ||
	    test_and_clear_bit(LLIF_UPDATE_ATIME, &lli->lli_flags))
		inode->i_atime.tv_sec = lli->lli_atime;

	inode->i_mtime.tv_sec = lli->lli_mtime;
	inode->i_ctime.tv_sec = lli->lli_ctime;

	mtime = inode->i_mtime.tv_sec;
	atime = inode->i_atime.tv_sec;
	ctime = inode->i_ctime.tv_sec;

	cl_object_attr_lock(obj);
	if (OBD_FAIL_CHECK(OBD_FAIL_MDC_MERGE))
		rc = -EINVAL;
	else
		rc = cl_object_attr_get(env, obj, attr);
	cl_object_attr_unlock(obj);

	if (rc != 0) {
		if (rc == -ENODATA)
			rc = 0;
		goto out_size_unlock;
	}

	if (atime < attr->cat_atime)
		atime = attr->cat_atime;

	if (ctime < attr->cat_ctime)
		ctime = attr->cat_ctime;

	if (mtime < attr->cat_mtime)
		mtime = attr->cat_mtime;

	CDEBUG(D_VFSTRACE, DFID " updating i_size %llu\n",
	       PFID(&lli->lli_fid), attr->cat_size);

	i_size_write(inode, attr->cat_size);

	inode->i_blocks = attr->cat_blocks;

	inode->i_mtime.tv_sec = mtime;
	inode->i_atime.tv_sec = atime;
	inode->i_ctime.tv_sec = ctime;

out_size_unlock:
	ll_inode_size_unlock(inode);

	return rc;
}

/**
 * Set designated mirror for I/O.
 *
 * So far only read, write, and truncated can support to issue I/O to
 * designated mirror.
 */
void ll_io_set_mirror(struct cl_io *io, const struct file *file)
{
	struct ll_file_data *fd = file->private_data;

	/* clear layout version for generic(non-resync) I/O in case it carries
	 * stale layout version due to I/O restart
	 */
	io->ci_layout_version = 0;

	/* FLR: disable non-delay for designated mirror I/O because obviously
	 * only one mirror is available
	 */
	if (fd->fd_designated_mirror > 0) {
		io->ci_ndelay = 0;
		io->ci_designated_mirror = fd->fd_designated_mirror;
		io->ci_layout_version = fd->fd_layout_version;
	}

	CDEBUG(D_VFSTRACE, "%s: desiginated mirror: %d\n",
	       file->f_path.dentry->d_name.name, io->ci_designated_mirror);
}

static bool file_is_noatime(const struct file *file)
{
	const struct vfsmount *mnt = file->f_path.mnt;
	const struct inode *inode = file_inode(file);

	/* Adapted from file_accessed() and touch_atime().*/
	if (file->f_flags & O_NOATIME)
		return true;

	if (inode->i_flags & S_NOATIME)
		return true;

	if (IS_NOATIME(inode))
		return true;

	if (mnt->mnt_flags & (MNT_NOATIME | MNT_READONLY))
		return true;

	if ((mnt->mnt_flags & MNT_NODIRATIME) && S_ISDIR(inode->i_mode))
		return true;

	if ((inode->i_sb->s_flags & SB_NODIRATIME) && S_ISDIR(inode->i_mode))
		return true;

	return false;
}

void ll_io_init(struct cl_io *io, const struct file *file, int write,
		struct vvp_io_args *args)
{
	struct ll_file_data *fd  = file->private_data;
	struct inode *inode = file_inode(file);

	io->u.ci_rw.crw_nonblock = file->f_flags & O_NONBLOCK;
	io->ci_lock_no_expand = fd->ll_lock_no_expand;

	if (write) {
		io->u.ci_wr.wr_append = !!(file->f_flags & O_APPEND);
		io->u.ci_wr.wr_sync = file->f_flags & O_SYNC ||
				      file->f_flags & O_DIRECT ||
				      IS_SYNC(inode);
		io->u.ci_wr.wr_sync |= !!(args &&
					  (args->u.normal.via_iocb->ki_flags &
					   IOCB_DSYNC));
	}

	io->ci_obj = ll_i2info(inode)->lli_clob;
	io->ci_lockreq = CILR_MAYBE;
	if (ll_file_nolock(file)) {
		io->ci_lockreq = CILR_NEVER;
		io->ci_no_srvlock = 1;
	} else if (file->f_flags & O_APPEND) {
		io->ci_lockreq = CILR_MANDATORY;
	}

	io->ci_noatime = file_is_noatime(file);
	io->ci_async_readahead = false;

	/* FLR: only use non-delay I/O for read as there is only one
	 * available mirror for write.
	 */
	io->ci_ndelay = !write;

	ll_io_set_mirror(io, file);
}

static void ll_heat_add(struct inode *inode, enum cl_io_type iot,
			u64 count)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	enum obd_heat_type sample_type;
	enum obd_heat_type iobyte_type;
	u64 now = ktime_get_real_seconds();

	if (!ll_sbi_has_file_heat(sbi) ||
	    lli->lli_heat_flags & LU_HEAT_FLAG_OFF)
		return;

	if (iot == CIT_READ) {
		sample_type = OBD_HEAT_READSAMPLE;
		iobyte_type = OBD_HEAT_READBYTE;
	} else if (iot == CIT_WRITE) {
		sample_type = OBD_HEAT_WRITESAMPLE;
		iobyte_type = OBD_HEAT_WRITEBYTE;
	} else {
		return;
	}

	spin_lock(&lli->lli_heat_lock);
	obd_heat_add(&lli->lli_heat_instances[sample_type], now, 1,
		     sbi->ll_heat_decay_weight, sbi->ll_heat_period_second);
	obd_heat_add(&lli->lli_heat_instances[iobyte_type], now, count,
		     sbi->ll_heat_decay_weight, sbi->ll_heat_period_second);
	spin_unlock(&lli->lli_heat_lock);
}

static ssize_t
ll_file_io_generic(const struct lu_env *env, struct vvp_io_args *args,
		   struct file *file, enum cl_io_type iot,
		   loff_t *ppos, size_t count)
{
	struct ll_inode_info *lli = ll_i2info(file_inode(file));
	struct ll_file_data *fd  = file->private_data;
	struct vvp_io *vio = vvp_env_io(env);
	struct range_lock range;
	struct cl_io *io;
	ssize_t result = 0;
	int rc = 0;
	unsigned int retried = 0;
	unsigned int ignore_lockless = 0;
	bool is_aio = false;
	struct cl_dio_aio *ci_aio = NULL;

	CDEBUG(D_VFSTRACE, "file: %pD, type: %d ppos: %llu, count: %zu\n",
	       file, iot, *ppos, count);

	io = vvp_env_thread_io(env);
	if (file->f_flags & O_DIRECT) {
		if (!is_sync_kiocb(args->u.normal.via_iocb))
			is_aio = true;
		ci_aio = cl_aio_alloc(args->u.normal.via_iocb);
		if (!ci_aio) {
			rc = -ENOMEM;
			goto out;
		}
	}

restart:
	io = vvp_env_thread_io(env);
	ll_io_init(io, file, iot == CIT_WRITE, args);
	io->ci_aio = ci_aio;
	io->ci_ignore_lockless = ignore_lockless;
	io->ci_ndelay_tried = retried;

	if (cl_io_rw_init(env, io, iot, *ppos, count) == 0) {
		bool range_locked = false;

		if (file->f_flags & O_APPEND)
			range_lock_init(&range, 0, LUSTRE_EOF);
		else
			range_lock_init(&range, *ppos, *ppos + count - 1);

		vio->vui_fd  = file->private_data;
		vio->vui_iter = args->u.normal.via_iter;
		vio->vui_iocb = args->u.normal.via_iocb;
		/*
		 * Direct IO reads must also take range lock,
		 * or multiple reads will try to work on the same pages
		 * See LU-6227 for details.
		 */
		if (((iot == CIT_WRITE) ||
		     (iot == CIT_READ && (file->f_flags & O_DIRECT))) &&
		    !(vio->vui_fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
			CDEBUG(D_VFSTRACE, "Range lock [%llu, %llu]\n",
			       range.rl_start,
			       range.rl_last);
			rc = range_lock(&lli->lli_write_tree, &range);
			if (rc < 0)
				goto out;

			range_locked = true;
		}
		ll_cl_add(file, env, io, LCC_RW);
		rc = cl_io_loop(env, io);
		ll_cl_remove(file, env);
		if (range_locked) {
			CDEBUG(D_VFSTRACE, "Range unlock [%llu, %llu]\n",
			       range.rl_start,
			       range.rl_last);
			range_unlock(&lli->lli_write_tree, &range);
		}
	} else {
		/* cl_io_rw_init() handled IO */
		rc = io->ci_result;
	}

	/*
	 * In order to move forward AIO, ci_nob was increased,
	 * but that doesn't mean io have been finished, it just
	 * means io have been submited, we will always return
	 * EIOCBQUEUED to the caller, So we could only return
	 * number of bytes in non-AIO case.
	 */
	if (io->ci_nob > 0) {
		if (!is_aio) {
			result += io->ci_nob;
			*ppos = io->u.ci_wr.wr.crw_pos;
		}
		count -= io->ci_nob;

		/* prepare IO restart */
		if (count > 0)
			args->u.normal.via_iter = vio->vui_iter;
	}
out:
	cl_io_fini(env, io);

	CDEBUG(D_VFSTRACE,
	       "%s: %d io complete with rc: %d, result: %zd, restart: %d\n",
	       file->f_path.dentry->d_name.name,
	       iot, rc, result, io->ci_need_restart);

	if ((!rc || rc == -ENODATA || rc == -ENOLCK) &&
	    count > 0 && io->ci_need_restart) {
		CDEBUG(D_VFSTRACE,
		       "%s: restart %s from %lld, count:%zu, result: %zd\n",
		       file_dentry(file)->d_name.name,
		       iot == CIT_READ ? "read" : "write",
		       *ppos, count, result);
		/* preserve the tried count for FLR */
		retried = io->ci_ndelay_tried;
		ignore_lockless = io->ci_ignore_lockless;
		goto restart;
	}

	if (io->ci_aio) {
		/*
		 * VFS will call aio_complete() if no -EIOCBQUEUED
		 * is returned for AIO, so we can not call aio_complete()
		 * in our end_io().
		 */
		if (rc != -EIOCBQUEUED)
			io->ci_aio->cda_no_aio_complete = 1;
		/**
		 * Drop one extra reference so that end_io() could be
		 * called for this IO context, we could call it after
		 * we make sure all AIO requests have been proceed.
		 */
		cl_sync_io_note(env, &io->ci_aio->cda_sync,
				rc == -EIOCBQUEUED ? 0 : rc);
		if (!is_aio) {
			cl_aio_free(io->ci_aio);
			io->ci_aio = NULL;
		}
	}

	if (iot == CIT_READ) {
		if (result > 0)
			ll_stats_ops_tally(ll_i2sbi(file_inode(file)),
					   LPROC_LL_READ_BYTES, result);
	} else if (iot == CIT_WRITE) {
		if (result > 0) {
			ll_stats_ops_tally(ll_i2sbi(file_inode(file)),
					   LPROC_LL_WRITE_BYTES, result);
			fd->fd_write_failed = false;
		} else if (!result && !rc) {
			rc = io->ci_result;
			if (rc < 0)
				fd->fd_write_failed = true;
			else
				fd->fd_write_failed = false;
		} else if (rc != -ERESTARTSYS) {
			fd->fd_write_failed = true;
		}
	}

	CDEBUG(D_VFSTRACE, "iot: %d, result: %zd\n", iot, result);
	if (result > 0)
		ll_heat_add(file_inode(file), iot, result);

	return result > 0 ? result : rc;
}

/**
 * The purpose of fast read is to overcome per I/O overhead and improve IOPS
 * especially for small I/O.
 *
 * To serve a read request, CLIO has to create and initialize a cl_io and
 * then request DLM lock. This has turned out to have siginificant overhead
 * and affects the performance of small I/O dramatically.
 *
 * It's not necessary to create a cl_io for each I/O. Under the help of read
 * ahead, most of the pages being read are already in memory cache and we can
 * read those pages directly because if the pages exist, the corresponding DLM
 * lock must exist so that page content must be valid.
 *
 * In fast read implementation, the llite speculatively finds and reads pages
 * in memory cache. There are three scenarios for fast read:
 *   - If the page exists and is uptodate, kernel VM will provide the data and
 *     CLIO won't be intervened;
 *   - If the page was brought into memory by read ahead, it will be exported
 *     and read ahead parameters will be updated;
 *   - Otherwise the page is not in memory, we can't do fast read. Therefore,
 *     it will go back and invoke normal read, i.e., a cl_io will be created
 *     and DLM lock will be requested.
 *
 * POSIX compliance: posix standard states that read is intended to be atomic.
 * Lustre read implementation is in line with Linux kernel read implementation
 * and neither of them complies with POSIX standard in this matter. Fast read
 * doesn't make the situation worse on single node but it may interleave write
 * results from multiple nodes due to short read handling in ll_file_aio_read().
 *
 * @iocb:	kiocb from kernel
 * @iter:	user space buffers where the data will be copied
 *
 * Returns:	number of bytes have been read, or error code if error occurred.
 */
static ssize_t
ll_do_fast_read(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t result;

	if (!ll_sbi_has_fast_read(ll_i2sbi(file_inode(iocb->ki_filp))))
		return 0;

	/*
	 * NB: we can't do direct IO for fast read because it will need a lock
	 * to make IO engine happy.
	 */
	if (iocb->ki_filp->f_flags & O_DIRECT)
		return 0;

	result = generic_file_read_iter(iocb, iter);

	/*
	 * If the first page is not in cache, generic_file_aio_read() will be
	 * returned with -ENODATA.
	 * See corresponding code in ll_readpage().
	 */
	if (result == -ENODATA)
		result = 0;

	if (result > 0) {
		ll_heat_add(file_inode(iocb->ki_filp), CIT_READ, result);
		ll_stats_ops_tally(ll_i2sbi(file_inode(iocb->ki_filp)),
				   LPROC_LL_READ_BYTES, result);
	}

	return result;
}

static ssize_t ll_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct lu_env *env;
	struct vvp_io_args *args;
	struct file *file = iocb->ki_filp;
	ssize_t result;
	u16 refcheck;
	ssize_t rc2;
	ktime_t kstart = ktime_get();
	bool cached;

	if (!iov_iter_count(to))
		return 0;

	/**
	 * Currently when PCC read failed, we do not fall back to the
	 * normal read path, just return the error.
	 * The resaon is that: for RW-PCC, the file data may be modified
	 * in the PCC and inconsistent with the data on OSTs (or file
	 * data has been removed from the Lustre file system), at this
	 * time, fallback to the normal read path may read the wrong
	 * data.
	 * TODO: for RO-PCC (readonly PCC), fall back to normal read
	 * path: read data from data copy on OSTs.
	 */
	result = pcc_file_read_iter(iocb, to, &cached);
	if (cached)
		goto out;

	ll_ras_enter(file, iocb->ki_pos, iov_iter_count(to));

	result = ll_do_fast_read(iocb, to);
	if (result < 0 || iov_iter_count(to) == 0)
		goto out;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	args = ll_env_args(env);
	args->u.normal.via_iter = to;
	args->u.normal.via_iocb = iocb;

	rc2 = ll_file_io_generic(env, args, file, CIT_READ,
				 &iocb->ki_pos, iov_iter_count(to));
	if (rc2 > 0)
		result += rc2;
	else if (result == 0)
		result = rc2;

	cl_env_put(env, &refcheck);
out:
	if (result > 0) {
		ll_rw_stats_tally(ll_i2sbi(file_inode(file)), current->pid,
				  file->private_data, iocb->ki_pos, result,
				  READ);
		ll_stats_ops_tally(ll_i2sbi(file_inode(file)), LPROC_LL_READ,
				   ktime_us_delta(ktime_get(), kstart));
	}

	return result;
}

/**
 * Similar trick to ll_do_fast_read, this improves write speed for tiny writes.
 * If a page is already in the page cache and dirty (and some other things -
 * See ll_tiny_write_begin for the instantiation of these rules), then we can
 * write to it without doing a full I/O, because Lustre already knows about it
 * and will write it out.  This saves a lot of processing time.
 *
 * All writes here are within one page, so exclusion is handled by the page
 * lock on the vm page.  We do not do tiny writes for writes which touch
 * multiple pages because it's very unlikely multiple sequential pages are
 * are already dirty.
 *
 * We limit these to < PAGE_SIZE because PAGE_SIZE writes are relatively common
 * and are unlikely to be to already dirty pages.
 *
 * Attribute updates are important here, we do them in ll_tiny_write_end.
 */
static ssize_t ll_do_tiny_write(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t count = iov_iter_count(iter);
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	bool lock_inode = !IS_NOSEC(inode);
	ssize_t result = 0;

	/* Restrict writes to single page and < PAGE_SIZE.  See comment at top
	 * of function for why.
	 */
	if (count >= PAGE_SIZE ||
	    (iocb->ki_pos & (PAGE_SIZE-1)) + count > PAGE_SIZE)
		return 0;

	if (unlikely(lock_inode))
		inode_lock(inode);
	result = __generic_file_write_iter(iocb, iter);

	if (unlikely(lock_inode))
		inode_unlock(inode);

	/* If the page is not already dirty, ll_tiny_write_begin returns
	 * -ENODATA.  We continue on to normal write.
	 */
	if (result == -ENODATA)
		result = 0;

	if (result > 0) {
		ll_heat_add(inode, CIT_WRITE, result);
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_WRITE_BYTES,
				   result);
		set_bit(LLIF_DATA_MODIFIED, &ll_i2info(inode)->lli_flags);
	}

	CDEBUG(D_VFSTRACE, "result: %zu, original count %zu\n", result, count);

	return result;
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t ll_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct lu_env *env;
	struct vvp_io_args *args;
	ssize_t rc_tiny = 0, rc_normal;
	struct file *file = iocb->ki_filp;
	u16 refcheck;
	bool cached;
	ktime_t kstart = ktime_get();
	int result;

	if (!iov_iter_count(from)) {
		rc_normal = 0;
		goto out;
	}

	/**
	 * When PCC write failed, we usually do not fall back to the normal
	 * write path, just return the error. But there is a special case when
	 * returned error code is -ENOSPC due to running out of space on PCC HSM
	 * bakcend. At this time, it will fall back to normal I/O path and
	 * retry the I/O. As the file is in HSM released state, it will restore
	 * the file data to OSTs first and redo the write again. And the
	 * restore process will revoke the layout lock and detach the file
	 * from PCC cache automatically.
	 */
	result = pcc_file_write_iter(iocb, from, &cached);
	if (cached && result != -ENOSPC && result != -EDQUOT) {
		rc_normal = result;
		goto out;
	}

	/* NB: we can't do direct IO for tiny writes because they use the page
	 * cache, we can't do sync writes because tiny writes can't flush
	 * pages, and we can't do append writes because we can't guarantee the
	 * required DLM locks are held to protect file size.
	 */
	if (ll_sbi_has_tiny_write(ll_i2sbi(file_inode(file))) &&
	    !(file->f_flags & (O_DIRECT | O_SYNC | O_APPEND)))
		rc_tiny = ll_do_tiny_write(iocb, from);

	/* In case of error, go on and try normal write - Only stop if tiny
	 * write completed I/O.
	 */
	if (iov_iter_count(from) == 0) {
		rc_normal = rc_tiny;
		goto out;
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	args = ll_env_args(env);
	args->u.normal.via_iter = from;
	args->u.normal.via_iocb = iocb;

	rc_normal = ll_file_io_generic(env, args, file, CIT_WRITE,
				       &iocb->ki_pos, iov_iter_count(from));

	/* On success, combine bytes written. */
	if (rc_tiny >= 0 && rc_normal > 0)
		rc_normal += rc_tiny;
	/* On error, only return error from normal write if tiny write did not
	 * write any bytes.  Otherwise return bytes written by tiny write.
	 */
	else if (rc_tiny > 0)
		rc_normal = rc_tiny;

	cl_env_put(env, &refcheck);
out:
	if (rc_normal > 0) {
		ll_rw_stats_tally(ll_i2sbi(file_inode(file)), current->pid,
				  file->private_data, iocb->ki_pos,
				  rc_normal, WRITE);
		ll_stats_ops_tally(ll_i2sbi(file_inode(file)), LPROC_LL_WRITE,
				   ktime_us_delta(ktime_get(), kstart));
	}

	return rc_normal;
}

int ll_lov_setstripe_ea_info(struct inode *inode, struct dentry *dentry,
			     u64 flags, struct lov_user_md *lum,
			     int lum_size)
{
	struct lookup_intent oit = {
		.it_op = IT_OPEN,
		.it_flags = flags | MDS_OPEN_BY_FID,
	};
	int rc = 0;

	if ((__swab32(lum->lmm_magic) & le32_to_cpu(LOV_MAGIC_MASK)) ==
	    le32_to_cpu(LOV_MAGIC_MAGIC)) {
		/* this code will only exist for big-endian systems */
		lustre_swab_lov_user_md(lum, 0);
	}

	ll_inode_size_lock(inode);
	rc = ll_intent_file_open(dentry, lum, lum_size, &oit);
	if (rc < 0)
		goto out_unlock;

	ll_release_openhandle(inode, &oit);

out_unlock:
	ll_inode_size_unlock(inode);
	ll_intent_release(&oit);
	return rc;
}

int ll_lov_getstripe_ea_info(struct inode *inode, const char *filename,
			     struct lov_mds_md **lmmp, int *lmm_size,
			     struct ptlrpc_request **request)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct mdt_body *body;
	struct lov_mds_md *lmm = NULL;
	struct ptlrpc_request *req = NULL;
	struct md_op_data *op_data;
	int rc, lmmsize;

	rc = ll_get_default_mdsize(sbi, &lmmsize);
	if (rc)
		return rc;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, filename,
				     strlen(filename), lmmsize,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	op_data->op_valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA;
	rc = md_getattr_name(sbi->ll_md_exp, op_data, &req);
	ll_finish_md_op_data(op_data);
	if (rc < 0) {
		CDEBUG(D_INFO, "md_getattr_name failed on %s: rc %d\n",
		       filename, rc);
		goto out;
	}

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);

	lmmsize = body->mbo_eadatasize;

	if (!(body->mbo_valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
	    lmmsize == 0) {
		rc = -ENODATA;
		goto out;
	}

	lmm = req_capsule_server_sized_get(&req->rq_pill, &RMF_MDT_MD, lmmsize);

	if (lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V1) &&
	    lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V3) &&
	    lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_COMP_V1) &&
	    lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_FOREIGN)) {
		rc = -EPROTO;
		goto out;
	}

	/*
	 * This is coming from the MDS, so is probably in
	 * little endian. We convert it to host endian before
	 * passing it to userspace.
	 */
	if ((lmm->lmm_magic & __swab32(LOV_MAGIC_MAGIC)) ==
	    __swab32(LOV_MAGIC_MAGIC)) {
		int stripe_count = 0;

		if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V1) ||
		    lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V3)) {
			stripe_count = le16_to_cpu(lmm->lmm_stripe_count);
			if (le32_to_cpu(lmm->lmm_pattern) &
			    LOV_PATTERN_F_RELEASED)
				stripe_count = 0;
		}

		lustre_swab_lov_user_md((struct lov_user_md *)lmm, 0);

		/* if function called for directory - we should
		 * avoid swab not existent lsm objects
		 */
		if (lmm->lmm_magic == LOV_MAGIC_V1 && S_ISREG(body->mbo_mode))
			lustre_swab_lov_user_md_objects(
				((struct lov_user_md_v1 *)lmm)->lmm_objects,
				stripe_count);
		else if (lmm->lmm_magic == LOV_MAGIC_V3 &&
			 S_ISREG(body->mbo_mode))
			lustre_swab_lov_user_md_objects(
				((struct lov_user_md_v3 *)lmm)->lmm_objects,
				stripe_count);
	}

out:
	*lmmp = lmm;
	*lmm_size = lmmsize;
	*request = req;
	return rc;
}

static int ll_lov_setea(struct inode *inode, struct file *file,
			void __user *arg)
{
	u64 flags = MDS_OPEN_HAS_OBJS | FMODE_WRITE;
	struct lov_user_md *lump;
	int lum_size = sizeof(struct lov_user_md) +
		       sizeof(struct lov_user_ost_data);
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	lump = kzalloc(lum_size, GFP_KERNEL);
	if (!lump)
		return -ENOMEM;

	if (copy_from_user(lump, arg, lum_size)) {
		kvfree(lump);
		return -EFAULT;
	}

	rc = ll_lov_setstripe_ea_info(inode, file->f_path.dentry, flags, lump,
				      lum_size);
	cl_lov_delay_create_clear(&file->f_flags);

	kvfree(lump);
	return rc;
}

static int ll_file_getstripe(struct inode *inode, void __user *lum, size_t size)
{
	struct lu_env *env;
	u16 refcheck;
	int rc;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	rc = cl_object_getstripe(env, ll_i2info(inode)->lli_clob, lum, size);
	cl_env_put(env, &refcheck);
	return rc;
}

static int ll_lov_setstripe(struct inode *inode, struct file *file,
			    void __user *arg)
{
	struct lov_user_md __user *lum = (struct lov_user_md __user *)arg;
	struct lov_user_md *klum;
	int lum_size, rc;
	u64 flags = FMODE_WRITE;

	rc = ll_copy_user_md(lum, &klum);
	if (rc < 0)
		return rc;

	lum_size = rc;
	rc = ll_lov_setstripe_ea_info(inode, file->f_path.dentry, flags, klum,
				      lum_size);
	if (!rc) {
		u32 gen;

		rc = put_user(0, &lum->lmm_stripe_count);
		if (rc)
			goto out;

		rc = ll_layout_refresh(inode, &gen);
		if (rc)
			goto out;

		rc = ll_file_getstripe(inode, arg, lum_size);
		if (S_ISREG(inode->i_mode) && IS_ENCRYPTED(inode) &&
		    ll_i2info(inode)->lli_clob) {
			struct iattr attr = { 0 };

			rc = cl_setattr_ost(ll_i2info(inode)->lli_clob, &attr,
					    OP_XVALID_FLAGS, LUSTRE_ENCRYPT_FL);
		}
	}

	cl_lov_delay_create_clear(&file->f_flags);
out:
	kvfree(klum);
	return rc;
}

static int
ll_get_grouplock(struct inode *inode, struct file *file, unsigned long arg)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = file->private_data;
	struct cl_object *obj = lli->lli_clob;
	struct ll_grouplock grouplock;
	int rc;

	if (arg == 0) {
		CWARN("group id for group lock must not be 0\n");
		return -EINVAL;
	}

	if (ll_file_nolock(file))
		return -EOPNOTSUPP;

retry:
	if (file->f_flags & O_NONBLOCK) {
		if (!mutex_trylock(&lli->lli_group_mutex))
			return -EAGAIN;
	} else
		mutex_lock(&lli->lli_group_mutex);

	if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
		CWARN("group lock already existed with gid %lu\n",
		      fd->fd_grouplock.lg_gid);
		rc = -EINVAL;
		goto out;
	}
	if (arg != lli->lli_group_gid && lli->lli_group_users != 0) {
		if (file->f_flags & O_NONBLOCK) {
			rc = -EAGAIN;
			goto out;
		}
		mutex_unlock(&lli->lli_group_mutex);
		wait_var_event(&lli->lli_group_users, !lli->lli_group_users);
		rc = 0;
		goto retry;
	}
	LASSERT(!fd->fd_grouplock.lg_lock);

	/**
	 * XXX: group lock needs to protect all OST objects while PFL
	 * can add new OST objects during the IO, so we'd instantiate
	 * all OST objects before getting its group lock.
	 */
	if (obj) {
		struct cl_layout cl = {
			.cl_is_composite = false,
		};
		struct lu_extent ext = {
			.e_start = 0,
			.e_end = OBD_OBJECT_EOF,
		};
		struct lu_env *env;
		u16 refcheck;

		env = cl_env_get(&refcheck);
		if (IS_ERR(env)) {
			rc = PTR_ERR(env);
			goto out;
		}

		rc = cl_object_layout_get(env, obj, &cl);
		if (!rc && cl.cl_is_composite)
			rc = ll_layout_write_intent(inode, LAYOUT_INTENT_WRITE,
						    &ext);

		cl_env_put(env, &refcheck);
		if (rc)
			goto out;
	}

	rc = cl_get_grouplock(ll_i2info(inode)->lli_clob,
			      arg, (file->f_flags & O_NONBLOCK), &grouplock);

	if (rc)
		goto out;

	fd->fd_flags |= LL_FILE_GROUP_LOCKED;
	fd->fd_grouplock = grouplock;
	if (lli->lli_group_users == 0)
		lli->lli_group_gid = grouplock.lg_gid;
	lli->lli_group_users++;

	CDEBUG(D_INFO, "group lock %lu obtained\n", arg);
out:
	mutex_unlock(&lli->lli_group_mutex);

	return rc;
}

static int ll_put_grouplock(struct inode *inode, struct file *file,
			    unsigned long arg)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = file->private_data;
	struct ll_grouplock grouplock;
	int rc;

	mutex_lock(&lli->lli_group_mutex);
	if (!(fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
		CWARN("no group lock held\n");
		rc = -EINVAL;
		goto out;
	}
	LASSERT(fd->fd_grouplock.lg_lock);

	if (fd->fd_grouplock.lg_gid != arg) {
		CWARN("group lock %lu doesn't match current id %lu\n",
		      arg, fd->fd_grouplock.lg_gid);
		rc = -EINVAL;
		goto out;
	}

	grouplock = fd->fd_grouplock;
	memset(&fd->fd_grouplock, 0, sizeof(fd->fd_grouplock));
	fd->fd_flags &= ~LL_FILE_GROUP_LOCKED;

	cl_put_grouplock(&grouplock);

	lli->lli_group_users--;
	if (lli->lli_group_users == 0) {
		lli->lli_group_gid = 0;
		wake_up_var(&lli->lli_group_users);
	}
	CDEBUG(D_INFO, "group lock %lu released\n", arg);
	rc = 0;
out:
	mutex_unlock(&lli->lli_group_mutex);

	return rc;
}

/**
 * Close inode open handle
 *
 * @inode:	inode in question
 * @it:		intent which contains open info and result
 *
 * Returns:	0     success
 *		<0    failure
 */
int ll_release_openhandle(struct inode *inode, struct lookup_intent *it)
{
	struct obd_client_handle *och;
	int rc;

	LASSERT(inode);

	/* Root ? Do nothing. */
	if (is_root_inode(inode))
		return 0;

	/* No open handle to close? Move away */
	if (!it_disposition(it, DISP_OPEN_OPEN))
		return 0;

	LASSERT(it_open_error(DISP_OPEN_OPEN, it) == 0);

	och = kzalloc(sizeof(*och), GFP_NOFS);
	if (!och) {
		rc = -ENOMEM;
		goto out;
	}

	rc = ll_och_fill(ll_i2sbi(inode)->ll_md_exp, it, och);
	if (rc)
		goto out;

	rc = ll_close_inode_openhandle(inode, och, 0, NULL);
out:
	/* this one is in place of ll_file_open */
	if (it_disposition(it, DISP_ENQ_OPEN_REF)) {
		ptlrpc_req_finished(it->it_request);
		it_clear_disposition(it, DISP_ENQ_OPEN_REF);
	}
	return rc;
}

/**
 * Get size for inode for which FIEMAP mapping is requested.
 * Make the FIEMAP get_info call and returns the result.
 *
 * @fiemap:	kernel buffer to hold extens
 * @num_bytes:	kernel buffer size
 */
static int ll_do_fiemap(struct inode *inode, struct fiemap *fiemap,
			size_t num_bytes)
{
	struct ll_fiemap_info_key fmkey = { .lfik_name = KEY_FIEMAP, };
	struct lu_env *env;
	u16 refcheck;
	int rc = 0;

	/* Checks for fiemap flags */
	if (fiemap->fm_flags & ~LUSTRE_FIEMAP_FLAGS_COMPAT) {
		fiemap->fm_flags &= ~LUSTRE_FIEMAP_FLAGS_COMPAT;
		return -EBADR;
	}

	/* Check for FIEMAP_FLAG_SYNC */
	if (fiemap->fm_flags & FIEMAP_FLAG_SYNC) {
		rc = filemap_fdatawrite(inode->i_mapping);
		if (rc)
			return rc;
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	if (i_size_read(inode) == 0) {
		rc = ll_glimpse_size(inode);
		if (rc)
			goto out;
	}

	fmkey.lfik_oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
	obdo_from_inode(&fmkey.lfik_oa, inode, OBD_MD_FLSIZE);
	obdo_set_parent_fid(&fmkey.lfik_oa, &ll_i2info(inode)->lli_fid);

	/* If filesize is 0, then there would be no objects for mapping */
	if (fmkey.lfik_oa.o_size == 0) {
		fiemap->fm_mapped_extents = 0;
		rc = 0;
		goto out;
	}

	memcpy(&fmkey.lfik_fiemap, fiemap, sizeof(*fiemap));

	rc = cl_object_fiemap(env, ll_i2info(inode)->lli_clob,
			      &fmkey, fiemap, &num_bytes);
out:
	cl_env_put(env, &refcheck);
	return rc;
}

int ll_fid2path(struct inode *inode, void __user *arg)
{
	struct obd_export *exp = ll_i2mdexp(inode);
	const struct getinfo_fid2path __user *gfin = arg;
	struct getinfo_fid2path *gfout;
	u32 pathlen;
	size_t outsize;
	int rc;

	if (!capable(CAP_DAC_READ_SEARCH) &&
	    !(ll_i2sbi(inode)->ll_flags & LL_SBI_USER_FID2PATH))
		return -EPERM;

	/* Only need to get the buflen */
	if (get_user(pathlen, &gfin->gf_pathlen))
		return -EFAULT;

	if (pathlen > PATH_MAX)
		return -EINVAL;

	outsize = sizeof(*gfout) + pathlen;

	gfout = kzalloc(outsize, GFP_KERNEL);
	if (!gfout)
		return -ENOMEM;

	if (copy_from_user(gfout, arg, sizeof(*gfout))) {
		rc = -EFAULT;
		goto gf_free;
	}

	/*
	 * append root FID after gfout to let MDT know the root FID so that it
	 * can lookup the correct path, this is mainly for fileset.
	 * old server without fileset mount support will ignore this.
	 */
	*gfout->gf_root_fid = *ll_inode2fid(inode);

	/* Call mdc_iocontrol */
	rc = obd_iocontrol(OBD_IOC_FID2PATH, exp, outsize, gfout, NULL);
	if (rc != 0)
		goto gf_free;

	if (copy_to_user(arg, gfout, outsize))
		rc = -EFAULT;

gf_free:
	kfree(gfout);
	return rc;
}

static int
ll_ioc_data_version(struct inode *inode, struct ioc_data_version *ioc)
{
	struct cl_object *obj = ll_i2info(inode)->lli_clob;
	struct lu_env *env;
	struct cl_io *io;
	u16 refcheck;
	int result;

	ioc->idv_version = 0;
	ioc->idv_layout_version = UINT_MAX;

	/* If no file object initialized, we consider its version is 0. */
	if (!obj)
		return 0;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	io = vvp_env_thread_io(env);
	io->ci_obj = obj;
	io->u.ci_data_version.dv_data_version = 0;
	io->u.ci_data_version.dv_layout_version = UINT_MAX;
	io->u.ci_data_version.dv_flags = ioc->idv_flags;

restart:
	if (!cl_io_init(env, io, CIT_DATA_VERSION, io->ci_obj))
		result = cl_io_loop(env, io);
	else
		result = io->ci_result;

	ioc->idv_version = io->u.ci_data_version.dv_data_version;
	ioc->idv_layout_version = io->u.ci_data_version.dv_layout_version;

	cl_io_fini(env, io);

	if (unlikely(io->ci_need_restart))
		goto restart;

	cl_env_put(env, &refcheck);

	return result;
}

/*
 * Read the data_version for inode.
 *
 * This value is computed using stripe object version on OST.
 * Version is computed using server side locking.
 *
 * @param flags if do sync on the OST side;
 *		0: no sync
 *		LL_DV_RD_FLUSH: flush dirty pages, LCK_PR on OSTs
 *		LL_DV_WR_FLUSH: drop all caching pages, LCK_PW on OSTs
 */
int ll_data_version(struct inode *inode, u64 *data_version, int flags)
{
	struct ioc_data_version ioc = { .idv_flags = flags };
	int rc;

	rc = ll_ioc_data_version(inode, &ioc);
	if (!rc)
		*data_version = ioc.idv_version;

	return rc;
}

/*
 * Trigger a HSM release request for the provided inode.
 */
int ll_hsm_release(struct inode *inode)
{
	struct lu_env *env;
	struct obd_client_handle *och = NULL;
	u64 data_version = 0;
	int rc;
	u16 refcheck;

	CDEBUG(D_INODE, "%s: Releasing file " DFID ".\n",
	       ll_i2sbi(inode)->ll_fsname,
	       PFID(&ll_i2info(inode)->lli_fid));

	och = ll_lease_open(inode, NULL, FMODE_WRITE, MDS_OPEN_RELEASE);
	if (IS_ERR(och)) {
		rc = PTR_ERR(och);
		goto out;
	}

	/* Grab latest data_version and [am]time values */
	rc = ll_data_version(inode, &data_version, LL_DV_WR_FLUSH);
	if (rc != 0)
		goto out;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env)) {
		rc = PTR_ERR(env);
		goto out;
	}

	rc = ll_merge_attr(env, inode);
	cl_env_put(env, &refcheck);

	/* If error happen, we have the wrong size for a file.
	 * Don't release it.
	 */
	if (rc != 0)
		goto out;

	/* Release the file.
	 * NB: lease lock handle is released in mdc_hsm_release_pack() because
	 * we still need it to pack l_remote_handle to MDT.
	 */
	rc = ll_close_inode_openhandle(inode, och, MDS_HSM_RELEASE,
				       &data_version);
	och = NULL;

out:
	if (och && !IS_ERR(och)) /* close the file */
		ll_lease_close(och, inode, NULL);

	return rc;
}

struct ll_swap_stack {
	u64		dv1;
	u64		dv2;
	struct inode   *inode1;
	struct inode   *inode2;
	bool		check_dv1;
	bool		check_dv2;
};

static int ll_swap_layouts(struct file *file1, struct file *file2,
			   struct lustre_swap_layouts *lsl)
{
	struct mdc_swap_layouts msl;
	struct md_op_data *op_data;
	u32 gid;
	u64 dv;
	struct ll_swap_stack *llss = NULL;
	int rc;

	llss = kzalloc(sizeof(*llss), GFP_KERNEL);
	if (!llss)
		return -ENOMEM;

	llss->inode1 = file_inode(file1);
	llss->inode2 = file_inode(file2);

	rc = ll_check_swap_layouts_validity(llss->inode1, llss->inode2);
	if (rc < 0)
		goto free;

	/* we use 2 bool because it is easier to swap than 2 bits */
	if (lsl->sl_flags & SWAP_LAYOUTS_CHECK_DV1)
		llss->check_dv1 = true;

	if (lsl->sl_flags & SWAP_LAYOUTS_CHECK_DV2)
		llss->check_dv2 = true;

	/* we cannot use lsl->sl_dvX directly because we may swap them */
	llss->dv1 = lsl->sl_dv1;
	llss->dv2 = lsl->sl_dv2;

	rc = lu_fid_cmp(ll_inode2fid(llss->inode1), ll_inode2fid(llss->inode2));
	if (!rc) /* same file, done! */
		goto free;

	if (rc < 0) { /* sequentialize it */
		swap(llss->inode1, llss->inode2);
		swap(file1, file2);
		swap(llss->dv1, llss->dv2);
		swap(llss->check_dv1, llss->check_dv2);
	}

	gid = lsl->sl_gid;
	if (gid != 0) { /* application asks to flush dirty cache */
		rc = ll_get_grouplock(llss->inode1, file1, gid);
		if (rc < 0)
			goto free;

		rc = ll_get_grouplock(llss->inode2, file2, gid);
		if (rc < 0) {
			ll_put_grouplock(llss->inode1, file1, gid);
			goto free;
		}
	}

	/* ultimate check, before swapping the layouts we check if
	 * dataversion has changed (if requested)
	 */
	if (llss->check_dv1) {
		rc = ll_data_version(llss->inode1, &dv, 0);
		if (rc)
			goto putgl;
		if (dv != llss->dv1) {
			rc = -EAGAIN;
			goto putgl;
		}
	}

	if (llss->check_dv2) {
		rc = ll_data_version(llss->inode2, &dv, 0);
		if (rc)
			goto putgl;
		if (dv != llss->dv2) {
			rc = -EAGAIN;
			goto putgl;
		}
	}

	/* struct md_op_data is used to send the swap args to the mdt
	 * only flags is missing, so we use struct mdc_swap_layouts
	 * through the md_op_data->op_data
	 */
	/* flags from user space have to be converted before they are send to
	 * server, no flag is sent today, they are only used on the client
	 */
	msl.msl_flags = 0;
	rc = -ENOMEM;
	op_data = ll_prep_md_op_data(NULL, llss->inode1, llss->inode2, NULL, 0,
				     0, LUSTRE_OPC_ANY, &msl);
	if (IS_ERR(op_data)) {
		rc = PTR_ERR(op_data);
		goto free;
	}

	rc = obd_iocontrol(LL_IOC_LOV_SWAP_LAYOUTS, ll_i2mdexp(llss->inode1),
			   sizeof(*op_data), op_data, NULL);
	ll_finish_md_op_data(op_data);

putgl:
	if (gid != 0) {
		ll_put_grouplock(llss->inode2, file2, gid);
		ll_put_grouplock(llss->inode1, file1, gid);
	}

free:
	kfree(llss);

	return rc;
}

int ll_hsm_state_set(struct inode *inode, struct hsm_state_set *hss)
{
	struct obd_export *exp = ll_i2mdexp(inode);
	struct md_op_data *op_data;
	int rc;

	/* Detect out-of range masks */
	if ((hss->hss_setmask | hss->hss_clearmask) & ~HSM_FLAGS_MASK)
		return -EINVAL;

	/* Non-root users are forbidden to set or clear flags which are
	 * NOT defined in HSM_USER_MASK.
	 */
	if (((hss->hss_setmask | hss->hss_clearmask) & ~HSM_USER_MASK) &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!exp_connect_archive_id_array(exp)) {
		/* Detect out-of range archive id */
		if ((hss->hss_valid & HSS_ARCHIVE_ID) &&
		    (hss->hss_archive_id > LL_HSM_ORIGIN_MAX_ARCHIVE))
			return -EINVAL;
	}

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, hss);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	rc = obd_iocontrol(LL_IOC_HSM_STATE_SET, exp, sizeof(*op_data),
			   op_data, NULL);

	ll_finish_md_op_data(op_data);

	return rc;
}

static int ll_hsm_import(struct inode *inode, struct file *file,
			 struct hsm_user_import *hui)
{
	struct hsm_state_set *hss = NULL;
	struct iattr *attr = NULL;
	int rc;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	/* set HSM flags */
	hss = kzalloc(sizeof(*hss), GFP_KERNEL);
	if (!hss)
		return -ENOMEM;

	hss->hss_valid = HSS_SETMASK | HSS_ARCHIVE_ID;
	hss->hss_archive_id = hui->hui_archive_id;
	hss->hss_setmask = HS_ARCHIVED | HS_EXISTS | HS_RELEASED;
	rc = ll_hsm_state_set(inode, hss);
	if (rc != 0)
		goto free_hss;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		rc = -ENOMEM;
		goto free_hss;
	}

	attr->ia_mode = hui->hui_mode & 0777;
	attr->ia_mode |= S_IFREG;
	attr->ia_uid = make_kuid(&init_user_ns, hui->hui_uid);
	attr->ia_gid = make_kgid(&init_user_ns, hui->hui_gid);
	attr->ia_size = hui->hui_size;
	attr->ia_mtime.tv_sec = hui->hui_mtime;
	attr->ia_mtime.tv_nsec = hui->hui_mtime_ns;
	attr->ia_atime.tv_sec = hui->hui_atime;
	attr->ia_atime.tv_nsec = hui->hui_atime_ns;

	attr->ia_valid = ATTR_SIZE | ATTR_MODE | ATTR_FORCE |
			 ATTR_UID | ATTR_GID |
			 ATTR_MTIME | ATTR_MTIME_SET |
			 ATTR_ATIME | ATTR_ATIME_SET;

	inode_lock(inode);

	rc = ll_setattr_raw(file->f_path.dentry, attr, 0, true);
	if (rc == -ENODATA)
		rc = 0;

	inode_unlock(inode);

	kfree(attr);
free_hss:
	kfree(hss);
	return rc;
}

static inline long ll_lease_type_from_fmode(fmode_t fmode)
{
	return ((fmode & FMODE_READ) ? LL_LEASE_RDLCK : 0) |
	       ((fmode & FMODE_WRITE) ? LL_LEASE_WRLCK : 0);
}

static int ll_file_futimes_3(struct file *file, const struct ll_futimes_3 *lfu)
{
	struct inode *inode = file_inode(file);
	struct iattr ia = {
		.ia_valid = ATTR_ATIME | ATTR_ATIME_SET |
			    ATTR_MTIME | ATTR_MTIME_SET |
			    ATTR_CTIME,
		.ia_atime = {
			.tv_sec = lfu->lfu_atime_sec,
			.tv_nsec = lfu->lfu_atime_nsec,
		},
		.ia_mtime = {
			.tv_sec = lfu->lfu_mtime_sec,
			.tv_nsec = lfu->lfu_mtime_nsec,
		},
		.ia_ctime = {
			.tv_sec = lfu->lfu_ctime_sec,
			.tv_nsec = lfu->lfu_ctime_nsec,
		},
	};
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	inode_lock(inode);
	rc = ll_setattr_raw(file_dentry(file), &ia, OP_XVALID_CTIME_SET,
			    false);
	inode_unlock(inode);

	return rc;
}

static enum cl_lock_mode cl_mode_user_to_kernel(enum lock_mode_user mode)
{
	enum cl_lock_mode cl_mode;

	switch (mode) {
	case MODE_READ_USER:
		cl_mode = CLM_READ;
		break;
	case MODE_WRITE_USER:
		cl_mode = CLM_WRITE;
		break;
	default:
		cl_mode = -EINVAL;
		break;
	}
	return cl_mode;
}

static const char *const user_lockname[] = LOCK_MODE_NAMES;

/* Used to allow the upper layers of the client to request an LDLM lock
 * without doing an actual read or write.
 *
 * Used for ladvise lockahead to manually request specific locks.
 *
 * @file	file this ladvise lock request is on
 * @ladvise	ladvise struct describing this lock request
 *
 * Return	0 on success, no detailed result available (sync requests
 *		and requests sent to the server [not handled locally]
 *              cannot return detailed results)
 *
 *		LLA_RESULT_{SAME,DIFFERENT} - detailed result of the lock
 *		request, see definitions for details.
 *
 *		negative errno on error
 */
int ll_file_lock_ahead(struct file *file, struct llapi_lu_ladvise *ladvise)
{
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct cl_lock_descr *descr = NULL;
	struct cl_lock *lock = NULL;
	struct cl_io *io  = NULL;
	struct lu_env *env = NULL;
	enum cl_lock_mode cl_mode;
	u64 start = ladvise->lla_start;
	u64 end = ladvise->lla_end;
	u16 refcheck;
	int result;

	CDEBUG(D_VFSTRACE,
	       "Lock request: file=%pd, inode=%p, mode=%s start=%llu, end=%llu\n",
	       dentry, dentry->d_inode,
	       user_lockname[ladvise->lla_lockahead_mode], start, end);

	cl_mode = cl_mode_user_to_kernel(ladvise->lla_lockahead_mode);
	if (cl_mode < 0) {
		result = cl_mode;
		goto out;
	}

	/* Get IO environment */
	result = cl_io_get(inode, &env, &io, &refcheck);
	if (result <= 0)
		goto out;

	result = cl_io_init(env, io, CIT_MISC, io->ci_obj);
	if (result > 0) {
		/*
		 * nothing to do for this io. This currently happens when
		 * stripe sub-object's are not yet created.
		 */
		result = io->ci_result;
	} else if (result == 0) {
		lock = vvp_env_lock(env);
		descr = &lock->cll_descr;

		descr->cld_obj = io->ci_obj;
		/* Convert byte offsets to pages */
		descr->cld_start = cl_index(io->ci_obj, start);
		descr->cld_end = cl_index(io->ci_obj, end);
		descr->cld_mode = cl_mode;
		/* CEF_MUST is used because we do not want to convert a
		 * lockahead request to a lockless lock
		 */
		descr->cld_enq_flags = CEF_MUST | CEF_LOCK_NO_EXPAND |
				       CEF_NONBLOCK;

		if (ladvise->lla_peradvice_flags & LF_ASYNC)
			descr->cld_enq_flags |= CEF_SPECULATIVE;

		result = cl_lock_request(env, io, lock);

		/* On success, we need to release the lock */
		if (result >= 0)
			cl_lock_release(env, lock);
	}
	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);

	/* -ECANCELED indicates a matching lock with a different extent
	 * was already present, and -EEXIST indicates a matching lock
	 * on exactly the same extent was already present.
	 * We convert them to positive values for userspace to make
	 * recognizing true errors easier.
	 * Note we can only return these detailed results on async requests,
	 * as sync requests look the same as i/o requests for locking.
	 */
	if (result == -ECANCELED)
		result = LLA_RESULT_DIFFERENT;
	else if (result == -EEXIST)
		result = LLA_RESULT_SAME;

out:
	return result;
}

static const char *const ladvise_names[] = LU_LADVISE_NAMES;

static int ll_ladvise_sanity(struct inode *inode,
			     struct llapi_lu_ladvise *ladvise)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	enum lu_ladvise_type advice = ladvise->lla_advice;
	/* Note the peradvice flags is a 32 bit field, so per advice flags must
	 * be in the first 32 bits of enum ladvise_flags
	 */
	u32 flags = ladvise->lla_peradvice_flags;
	/* 3 lines at 80 characters per line, should be plenty */
	int rc = 0;

	if (advice > LU_LADVISE_MAX || advice == LU_LADVISE_INVALID) {
		rc = -EINVAL;
		CDEBUG(D_VFSTRACE,
		       "%s: advice with value '%d' not recognized, last supported advice is %s (value '%d'): rc = %d\n",
		       sbi->ll_fsname, advice,
		       ladvise_names[LU_LADVISE_MAX - 1], LU_LADVISE_MAX - 1,
		       rc);
		goto out;
	}

	/* Per-advice checks */
	switch (advice) {
	case LU_LADVISE_LOCKNOEXPAND:
		if (flags & ~LF_LOCKNOEXPAND_MASK) {
			rc = -EINVAL;
			CDEBUG(D_VFSTRACE,
			       "%s: Invalid flags (%x) for %s: rc = %d\n",
			       sbi->ll_fsname, flags,
			       ladvise_names[advice], rc);
			goto out;
		}
		break;
	case LU_LADVISE_LOCKAHEAD:
		/* Currently only READ and WRITE modes can be requested */
		if (ladvise->lla_lockahead_mode >= MODE_MAX_USER ||
		    ladvise->lla_lockahead_mode == 0) {
			rc = -EINVAL;
			CDEBUG(D_VFSTRACE,
			       "%s: Invalid mode (%d) for %s: rc = %d\n",
			       sbi->ll_fsname,
			       ladvise->lla_lockahead_mode,
			       ladvise_names[advice], rc);
			goto out;
		}
		/* fallthrough */
	case LU_LADVISE_WILLREAD:
	case LU_LADVISE_DONTNEED:
	default:
		/* Note fall through above - These checks apply to all advices
		 * except LOCKNOEXPAND
		 */
		if (flags & ~LF_DEFAULT_MASK) {
			rc = -EINVAL;
			CDEBUG(D_VFSTRACE,
			       "%s: Invalid flags (%x) for %s: rc = %d\n",
			       sbi->ll_fsname, flags,
			       ladvise_names[advice], rc);
			goto out;
		}
		if (ladvise->lla_start >= ladvise->lla_end) {
			rc = -EINVAL;
			CDEBUG(D_VFSTRACE,
			       "%s: Invalid range (%llu to %llu) for %s: rc = %d\n",
			       sbi->ll_fsname,
			       ladvise->lla_start, ladvise->lla_end,
			       ladvise_names[advice], rc);
			goto out;
		}
		break;
	}

out:
	return rc;
}
#undef ERRSIZE

/*
 * Give file access advices
 *
 * The ladvise interface is similar to Linux fadvise() system call, except it
 * forwards the advices directly from Lustre client to server. The server side
 * codes will apply appropriate read-ahead and caching techniques for the
 * corresponding files.
 *
 * A typical workload for ladvise is e.g. a bunch of different clients are
 * doing small random reads of a file, so prefetching pages into OSS cache
 * with big linear reads before the random IO is a net benefit. Fetching
 * all that data into each client cache with fadvise() may not be, due to
 * much more data being sent to the client.
 */
static int ll_ladvise(struct inode *inode, struct file *file, u64 flags,
		      struct llapi_lu_ladvise *ladvise)
{
	struct cl_ladvise_io *lio;
	struct lu_env *env;
	struct cl_io *io;
	u16 refcheck;
	int rc;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	io = vvp_env_thread_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;

	/* initialize parameters for ladvise */
	lio = &io->u.ci_ladvise;
	lio->li_start = ladvise->lla_start;
	lio->li_end = ladvise->lla_end;
	lio->li_fid = ll_inode2fid(inode);
	lio->li_advice = ladvise->lla_advice;
	lio->li_flags = flags;

	if (!cl_io_init(env, io, CIT_LADVISE, io->ci_obj))
		rc = cl_io_loop(env, io);
	else
		rc = io->ci_result;

	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);
	return rc;
}

static int ll_lock_noexpand(struct file *file, int flags)
{
	struct ll_file_data *fd = file->private_data;

	fd->ll_lock_no_expand = !(flags & LF_UNSET);

	return 0;
}

int ll_ioctl_fsgetxattr(struct inode *inode, unsigned int cmd,
			unsigned long arg)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct fsxattr fsxattr;

	if (copy_from_user(&fsxattr,
			   (const struct fsxattr __user *)arg,
			   sizeof(fsxattr)))
		return -EFAULT;

	fsxattr.fsx_xflags = ll_inode_flags_to_xflags(inode->i_flags);
	if (test_bit(LLIF_PROJECT_INHERIT, &lli->lli_flags))
		fsxattr.fsx_xflags |= FS_XFLAG_PROJINHERIT;
	fsxattr.fsx_projid = ll_i2info(inode)->lli_projid;
	if (copy_to_user((struct fsxattr __user *)arg,
			 &fsxattr, sizeof(fsxattr)))
		return -EFAULT;

	return 0;
}

int ll_ioctl_check_project(struct inode *inode, struct fsxattr *fa)
{
	/*
	 * Project Quota ID state is only allowed to change from within the init
	 * namespace. Enforce that restriction only if we are trying to change
	 * the quota ID state. Everything else is allowed in user namespaces.
	 */
	if (current_user_ns() == &init_user_ns)
		return 0;

	if (ll_i2info(inode)->lli_projid != fa->fsx_projid)
		return -EINVAL;

	if (test_bit(LLIF_PROJECT_INHERIT, &ll_i2info(inode)->lli_flags)) {
		if (!(fa->fsx_xflags & FS_XFLAG_PROJINHERIT))
			return -EINVAL;
	} else {
		if (fa->fsx_xflags & FS_XFLAG_PROJINHERIT)
			return -EINVAL;
	}

	return 0;
}

int ll_ioctl_fssetxattr(struct inode *inode, unsigned int cmd,
			unsigned long arg)
{
	struct ptlrpc_request *req = NULL;
	struct md_op_data *op_data;
	struct fsxattr fsxattr;
	struct cl_object *obj;
	struct iattr *attr;
	int rc = 0;
	int flags;

	if (copy_from_user(&fsxattr,
			   (const struct fsxattr __user *)arg,
			   sizeof(fsxattr)))
		return -EFAULT;

	rc = ll_ioctl_check_project(inode, &fsxattr);
	if (rc)
		return rc;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	flags = ll_xflags_to_inode_flags(fsxattr.fsx_xflags);
	op_data->op_attr_flags = ll_inode_to_ext_flags(flags);
	if (fsxattr.fsx_xflags & FS_XFLAG_PROJINHERIT)
		op_data->op_attr_flags |= LUSTRE_PROJINHERIT_FL;
	op_data->op_projid = fsxattr.fsx_projid;
	op_data->op_xvalid |= OP_XVALID_PROJID;
	rc = md_setattr(ll_i2sbi(inode)->ll_md_exp, op_data, NULL,
			0, &req);
	ptlrpc_req_finished(req);
	if (rc)
		goto out_fsxattr;

	ll_update_inode_flags(inode, op_data->op_attr_flags);
	obj = ll_i2info(inode)->lli_clob;
	if (!obj)
		goto out_fsxattr;

	/* Avoiding OST RPC if this is only project ioctl */
	if (fsxattr.fsx_xflags == 0 ||
	    fsxattr.fsx_xflags == FS_XFLAG_PROJINHERIT)
		goto out_fsxattr;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr) {
		rc = -ENOMEM;
		goto out_fsxattr;
	}

	rc = cl_setattr_ost(obj, attr, OP_XVALID_FLAGS,
			    fsxattr.fsx_xflags);
	kfree(attr);
out_fsxattr:
	ll_finish_md_op_data(op_data);

	return rc;
}

static long ll_file_unlock_lease(struct file *file, struct ll_ioc_lease *ioc,
				 unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = file->private_data;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct obd_client_handle *och = NULL;
	struct split_param sp;
	struct pcc_param param;
	bool lease_broken = false;
	fmode_t fmode = 0;
	enum mds_op_bias bias = 0;
	struct file *layout_file = NULL;
	void *data = NULL;
	size_t data_size = 0;
	bool attached = false;
	long rc, rc2 = 0;

	mutex_lock(&lli->lli_och_mutex);
	if (fd->fd_lease_och) {
		och = fd->fd_lease_och;
		fd->fd_lease_och = NULL;
	}
	mutex_unlock(&lli->lli_och_mutex);

	if (!och)
		return -ENOLCK;

	fmode = och->och_flags;

	switch (ioc->lil_flags) {
	case LL_LEASE_RESYNC_DONE:
		if (ioc->lil_count > IOC_IDS_MAX) {
			rc = -EINVAL;
			goto out_lease_close;
		}

		data_size = offsetof(typeof(*ioc), lil_ids[ioc->lil_count]);
		data = kzalloc(data_size, GFP_KERNEL);
		if (!data) {
			rc = -ENOMEM;
			goto out_lease_close;
		}

		if (copy_from_user(data, (void __user *)arg, data_size)) {
			rc = -EFAULT;
			goto out_lease_close;
		}

		bias = MDS_CLOSE_RESYNC_DONE;
		break;
	case LL_LEASE_LAYOUT_MERGE: {
		int fd;

		if (ioc->lil_count != 1) {
			rc = -EINVAL;
			goto out_lease_close;
		}

		arg += sizeof(*ioc);
		if (copy_from_user(&fd, (void __user *)arg, sizeof(u32))) {
			rc = -EFAULT;
			goto out_lease_close;
		}

		layout_file = fget(fd);
		if (!layout_file) {
			rc = -EBADF;
			goto out_lease_close;
		}

		if ((file->f_flags & O_ACCMODE) == O_RDONLY ||
		    (layout_file->f_flags & O_ACCMODE) == O_RDONLY) {
			rc = -EPERM;
			goto out_lease_close;
		}

		data = file_inode(layout_file);
		bias = MDS_CLOSE_LAYOUT_MERGE;
		break;
	}
	case LL_LEASE_LAYOUT_SPLIT: {
		int fdv;
		int mirror_id;

		if (ioc->lil_count != 2) {
			rc = -EINVAL;
			goto out_lease_close;
		}

		arg += sizeof(*ioc);
		if (copy_from_user(&fdv, (void __user *)arg, sizeof(u32))) {
			rc = -EFAULT;
			goto out_lease_close;
		}

		arg += sizeof(u32);
		if (copy_from_user(&mirror_id, (void __user *)arg,
				   sizeof(u32))) {
			rc = -EFAULT;
			goto out_lease_close;
		}

		layout_file = fget(fdv);
		if (!layout_file) {
			rc = -EBADF;
			goto out_lease_close;
		}

		sp.sp_inode = file_inode(layout_file);
		sp.sp_mirror_id = (u16)mirror_id;
		data = &sp;
		bias = MDS_CLOSE_LAYOUT_SPLIT;
		break;
	}
	case LL_LEASE_PCC_ATTACH:
		if (ioc->lil_count != 1)
			return -EINVAL;

		arg += sizeof(*ioc);
		if (copy_from_user(&param.pa_archive_id, (void __user *)arg,
				   sizeof(u32))) {
			rc2 = -EFAULT;
			goto out_lease_close;
		}

		rc2 = pcc_readwrite_attach(file, inode, param.pa_archive_id);
		if (rc2)
			goto out_lease_close;

		attached = true;
		/* Grab latest data version */
		rc2 = ll_data_version(inode, &param.pa_data_version,
				     LL_DV_WR_FLUSH);
		if (rc2)
			goto out_lease_close;

		data = &param;
		bias = MDS_PCC_ATTACH;
		break;
	default:
		/* without close intent */
		break;
	}

out_lease_close:
	rc = ll_lease_close_intent(och, inode, &lease_broken, bias, data);
	if (rc < 0)
		goto out;

	rc = ll_lease_och_release(inode, file);
	if (rc < 0)
		goto out;

	if (lease_broken)
		fmode = 0;

out:
	switch (ioc->lil_flags) {
	case LL_LEASE_RESYNC_DONE:
		kfree(data);
		break;
	case LL_LEASE_LAYOUT_MERGE:
	case LL_LEASE_LAYOUT_SPLIT:
		if (layout_file)
			fput(layout_file);
		break;
	case LL_LEASE_PCC_ATTACH:
		if (!rc)
			rc = rc2;
		rc = pcc_readwrite_attach_fini(file, inode,
					       param.pa_layout_gen,
					       lease_broken, rc,
					       attached);
		break;
	}

	if (!rc)
		rc = ll_lease_type_from_fmode(fmode);
	return rc;
}

static long ll_file_set_lease(struct file *file, struct ll_ioc_lease *ioc,
			      unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = file->private_data;
	struct obd_client_handle *och = NULL;
	u64 open_flags = 0;
	bool lease_broken;
	fmode_t fmode;
	long rc;

	switch (ioc->lil_mode) {
	case LL_LEASE_WRLCK:
		if (!(file->f_mode & FMODE_WRITE))
			return -EPERM;
		fmode = FMODE_WRITE;
		break;
	case LL_LEASE_RDLCK:
		if (!(file->f_mode & FMODE_READ))
			return -EPERM;
		fmode = FMODE_READ;
		break;
	case LL_LEASE_UNLCK:
		return ll_file_unlock_lease(file, ioc, arg);
	default:
		return -EINVAL;
	}

	CDEBUG(D_INODE, "Set lease with mode %u\n", fmode);

	/* apply for lease */
	if (ioc->lil_flags & LL_LEASE_RESYNC)
		open_flags = MDS_OPEN_RESYNC;
	och = ll_lease_open(inode, file, fmode, open_flags);
	if (IS_ERR(och))
		return PTR_ERR(och);

	if (ioc->lil_flags & LL_LEASE_RESYNC) {
		rc = ll_lease_file_resync(och, inode, arg);
		if (rc) {
			ll_lease_close(och, inode, NULL);
			return rc;
		}
		rc = ll_layout_refresh(inode, &fd->fd_layout_version);
		if (rc) {
			ll_lease_close(och, inode, NULL);
			return rc;
		}
	}

	rc = 0;
	mutex_lock(&lli->lli_och_mutex);
	if (!fd->fd_lease_och) {
		fd->fd_lease_och = och;
		och = NULL;
	}
	mutex_unlock(&lli->lli_och_mutex);
	if (och) {
		/* impossible now that only excl is supported for now */
		ll_lease_close(och, inode, &lease_broken);
		rc = -EBUSY;
	}
	return rc;
}

static void ll_heat_get(struct inode *inode, struct lu_heat *heat)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	u64 now = ktime_get_real_seconds();
	int i;

	spin_lock(&lli->lli_heat_lock);
	heat->lh_flags = lli->lli_heat_flags;
	for (i = 0; i < heat->lh_count; i++)
		heat->lh_heat[i] = obd_heat_get(&lli->lli_heat_instances[i],
						now, sbi->ll_heat_decay_weight,
						sbi->ll_heat_period_second);
	spin_unlock(&lli->lli_heat_lock);
}

static int ll_heat_set(struct inode *inode, enum lu_heat_flag flags)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	int rc = 0;

	spin_lock(&lli->lli_heat_lock);
	if (flags & LU_HEAT_FLAG_CLEAR)
		obd_heat_clear(lli->lli_heat_instances, OBD_HEAT_COUNT);

	if (flags & LU_HEAT_FLAG_OFF)
		lli->lli_heat_flags |= LU_HEAT_FLAG_OFF;
	else
		lli->lli_heat_flags &= ~LU_HEAT_FLAG_OFF;

	spin_unlock(&lli->lli_heat_lock);

	return rc;
}

static long
ll_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = file->private_data;
	int flags, rc;

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p),cmd=%x\n",
	       PFID(ll_inode2fid(inode)), inode, cmd);
	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_IOCTL, 1);

	/* asm-ppc{,64} declares TCGETS, et. al. as type 't' not 'T' */
	if (_IOC_TYPE(cmd) == 'T' || _IOC_TYPE(cmd) == 't') /* tty ioctls */
		return -ENOTTY;

	switch (cmd) {
	case LL_IOC_GETFLAGS:
		/* Get the current value of the file flags */
		return put_user(fd->fd_flags, (int __user *)arg);
	case LL_IOC_SETFLAGS:
	case LL_IOC_CLRFLAGS:
		/* Set or clear specific file flags */
		/* XXX This probably needs checks to ensure the flags are
		 *     not abused, and to handle any flag side effects.
		 */
		if (get_user(flags, (int __user *)arg))
			return -EFAULT;

		if (cmd == LL_IOC_SETFLAGS) {
			if ((flags & LL_FILE_IGNORE_LOCK) &&
			    !(file->f_flags & O_DIRECT)) {
				CERROR("%s: unable to disable locking on non-O_DIRECT file\n",
				       current->comm);
				return -EINVAL;
			}

			fd->fd_flags |= flags;
		} else {
			fd->fd_flags &= ~flags;
		}
		return 0;
	case LL_IOC_LOV_SETSTRIPE:
	case LL_IOC_LOV_SETSTRIPE_NEW:
		return ll_lov_setstripe(inode, file, (void __user *)arg);
	case LL_IOC_LOV_SETEA:
		return ll_lov_setea(inode, file, (void __user *)arg);
	case LL_IOC_LOV_SWAP_LAYOUTS: {
		struct file *file2;
		struct lustre_swap_layouts lsl;

		if (copy_from_user(&lsl, (char __user *)arg,
				   sizeof(struct lustre_swap_layouts)))
			return -EFAULT;

		if ((file->f_flags & O_ACCMODE) == O_RDONLY)
			return -EPERM;

		file2 = fget(lsl.sl_fd);
		if (!file2)
			return -EBADF;

		/* O_WRONLY or O_RDWR */
		if ((file2->f_flags & O_ACCMODE) == O_RDONLY) {
			rc = -EPERM;
			goto out;
		}

		if (lsl.sl_flags & SWAP_LAYOUTS_CLOSE) {
			struct obd_client_handle *och = NULL;
			struct ll_inode_info *lli;
			struct inode *inode2;

			lli = ll_i2info(inode);
			mutex_lock(&lli->lli_och_mutex);
			if (fd->fd_lease_och) {
				och = fd->fd_lease_och;
				fd->fd_lease_och = NULL;
			}
			mutex_unlock(&lli->lli_och_mutex);
			if (!och) {
				rc = -ENOLCK;
				goto out;
			}
			inode2 = file_inode(file2);
			rc = ll_swap_layouts_close(och, inode, inode2);
		} else {
			rc = ll_swap_layouts(file, file2, &lsl);
		}
out:
		fput(file2);
		return rc;
	}
	case LL_IOC_LOV_GETSTRIPE:
	case LL_IOC_LOV_GETSTRIPE_NEW:
		return ll_file_getstripe(inode, (void __user *)arg, 0);
	case FS_IOC_GETFLAGS:
	case FS_IOC_SETFLAGS:
		return ll_iocontrol(inode, file, cmd, arg);
	case FSFILT_IOC_GETVERSION:
	case FS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);
	/* We need to special case any other ioctls we want to handle,
	 * to send them to the MDS/OST as appropriate and to properly
	 * network encode the arg field.
	 */
	case FS_IOC_SETVERSION:
		return -ENOTSUPP;

	case LL_IOC_GROUP_LOCK:
		return ll_get_grouplock(inode, file, arg);
	case LL_IOC_GROUP_UNLOCK:
		return ll_put_grouplock(inode, file, arg);
	case IOC_OBD_STATFS:
		return ll_obd_statfs(inode, (void __user *)arg);

	case LL_IOC_FLUSHCTX:
		return ll_flush_ctx(inode);
	case LL_IOC_PATH2FID: {
		if (copy_to_user((void __user *)arg, ll_inode2fid(inode),
				 sizeof(struct lu_fid)))
			return -EFAULT;

		return 0;
	}
	case LL_IOC_GETPARENT:
		return ll_getparent(file, (struct getparent __user *)arg);
	case OBD_IOC_FID2PATH:
		return ll_fid2path(inode, (void __user *)arg);
	case LL_IOC_DATA_VERSION: {
		struct ioc_data_version	idv;
		int rc;

		if (copy_from_user(&idv, (char __user *)arg, sizeof(idv)))
			return -EFAULT;

		idv.idv_flags &= LL_DV_RD_FLUSH | LL_DV_WR_FLUSH;
		rc = ll_ioc_data_version(inode, &idv);
		if (rc == 0 && copy_to_user((char __user *)arg, &idv,
					    sizeof(idv)))
			return -EFAULT;

		return rc;
	}

	case LL_IOC_GET_MDTIDX: {
		int mdtidx;

		mdtidx = ll_get_mdt_idx(inode);
		if (mdtidx < 0)
			return mdtidx;

		if (put_user(mdtidx, (int __user *)arg))
			return -EFAULT;

		return 0;
	}
	case OBD_IOC_GETDTNAME:
	case OBD_IOC_GETMDNAME:
		return ll_get_obd_name(inode, cmd, arg);
	case LL_IOC_HSM_STATE_GET: {
		struct md_op_data *op_data;
		struct hsm_user_state *hus;
		int rc;

		hus = kzalloc(sizeof(*hus), GFP_KERNEL);
		if (!hus)
			return -ENOMEM;

		op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
					     LUSTRE_OPC_ANY, hus);
		if (IS_ERR(op_data)) {
			kfree(hus);
			return PTR_ERR(op_data);
		}

		rc = obd_iocontrol(cmd, ll_i2mdexp(inode), sizeof(*op_data),
				   op_data, NULL);

		if (copy_to_user((void __user *)arg, hus, sizeof(*hus)))
			rc = -EFAULT;

		ll_finish_md_op_data(op_data);
		kfree(hus);
		return rc;
	}
	case LL_IOC_HSM_STATE_SET: {
		struct hsm_state_set *hss;
		int rc;

		hss = memdup_user((char __user *)arg, sizeof(*hss));
		if (IS_ERR(hss))
			return PTR_ERR(hss);

		rc = ll_hsm_state_set(inode, hss);

		kfree(hss);
		return rc;
	}
	case LL_IOC_HSM_ACTION: {
		struct md_op_data *op_data;
		struct hsm_current_action *hca;
		int rc;

		hca = kzalloc(sizeof(*hca), GFP_KERNEL);
		if (!hca)
			return -ENOMEM;

		op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
					     LUSTRE_OPC_ANY, hca);
		if (IS_ERR(op_data)) {
			kfree(hca);
			return PTR_ERR(op_data);
		}

		rc = obd_iocontrol(cmd, ll_i2mdexp(inode), sizeof(*op_data),
				   op_data, NULL);

		if (copy_to_user((char __user *)arg, hca, sizeof(*hca)))
			rc = -EFAULT;

		ll_finish_md_op_data(op_data);
		kfree(hca);
		return rc;
	}
	case LL_IOC_SET_LEASE_OLD: {
		struct ll_ioc_lease ioc = { .lil_mode = (u32)arg };

		return ll_file_set_lease(file, &ioc, 0);
	}
	case LL_IOC_SET_LEASE: {
		struct ll_ioc_lease ioc;

		if (copy_from_user(&ioc, (void __user *)arg, sizeof(ioc)))
			return -EFAULT;

		return ll_file_set_lease(file, &ioc, arg);
	}
	case LL_IOC_GET_LEASE: {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct ldlm_lock *lock = NULL;
		fmode_t fmode = 0;

		mutex_lock(&lli->lli_och_mutex);
		if (fd->fd_lease_och) {
			struct obd_client_handle *och = fd->fd_lease_och;

			lock = ldlm_handle2lock(&och->och_lease_handle);
			if (lock) {
				lock_res_and_lock(lock);
				if (!ldlm_is_cancel(lock))
					fmode = och->och_flags;
				unlock_res_and_lock(lock);
				LDLM_LOCK_PUT(lock);
			}
		}
		mutex_unlock(&lli->lli_och_mutex);
		return ll_lease_type_from_fmode(fmode);
	}
	case LL_IOC_HSM_IMPORT: {
		struct hsm_user_import *hui;

		hui = memdup_user((void __user *)arg, sizeof(*hui));
		if (IS_ERR(hui))
			return PTR_ERR(hui);

		rc = ll_hsm_import(inode, file, hui);

		kfree(hui);
		return rc;
	}
	case LL_IOC_FUTIMES_3: {
		const struct ll_futimes_3 __user *lfu_user;
		struct ll_futimes_3 lfu;

		lfu_user = (const struct ll_futimes_3 __user *)arg;
		if (copy_from_user(&lfu, lfu_user, sizeof(lfu)))
			return -EFAULT;

		return ll_file_futimes_3(file, &lfu);
	}
	case LL_IOC_LADVISE: {
		struct llapi_ladvise_hdr __user *u_ladvise_hdr;
		struct llapi_ladvise_hdr *k_ladvise_hdr;
		int alloc_size = sizeof(*k_ladvise_hdr);
		int num_advise;
		int i;

		rc = 0;
		u_ladvise_hdr = (void __user *)arg;
		k_ladvise_hdr = kzalloc(alloc_size, GFP_KERNEL);
		if (!k_ladvise_hdr)
			return -ENOMEM;

		if (copy_from_user(k_ladvise_hdr, u_ladvise_hdr, alloc_size)) {
			rc = -EFAULT;
			goto out_ladvise;
		}

		if (k_ladvise_hdr->lah_magic != LADVISE_MAGIC ||
		    k_ladvise_hdr->lah_count < 1) {
			rc = -EINVAL;
			goto out_ladvise;
		}

		num_advise = k_ladvise_hdr->lah_count;
		if (num_advise >= LAH_COUNT_MAX) {
			rc = -EFBIG;
			goto out_ladvise;
		}

		kfree(k_ladvise_hdr);
		alloc_size = offsetof(typeof(*k_ladvise_hdr),
				      lah_advise[num_advise]);
		k_ladvise_hdr = kzalloc(alloc_size, GFP_KERNEL);
		if (!k_ladvise_hdr)
			return -ENOMEM;

		/*
		 * TODO: submit multiple advices to one server in a single RPC
		 */
		if (copy_from_user(k_ladvise_hdr, u_ladvise_hdr, alloc_size)) {
			rc = -EFAULT;
			goto out_ladvise;
		}

		for (i = 0; i < num_advise; i++) {
			struct llapi_lu_ladvise __user *u_ladvise;
			struct llapi_lu_ladvise *k_ladvise;

			k_ladvise = &k_ladvise_hdr->lah_advise[i];
			u_ladvise = &u_ladvise_hdr->lah_advise[i];

			rc = ll_ladvise_sanity(inode, k_ladvise);
			if (rc)
				goto out_ladvise;

			switch (k_ladvise->lla_advice) {
			case LU_LADVISE_LOCKNOEXPAND:
				rc = ll_lock_noexpand(file,
						      k_ladvise->lla_peradvice_flags);
				goto out_ladvise;
			case LU_LADVISE_LOCKAHEAD:
				rc = ll_file_lock_ahead(file, k_ladvise);
				if (rc < 0)
					goto out_ladvise;

				if (put_user(rc,
					     &u_ladvise->lla_lockahead_result)) {
					rc = -EFAULT;
					goto out_ladvise;
				}
				break;
			default:
				rc = ll_ladvise(inode, file,
						k_ladvise_hdr->lah_flags,
						k_ladvise);
				if (rc)
					goto out_ladvise;
				break;
			}
		}

out_ladvise:
		kfree(k_ladvise_hdr);
		return rc;
	}
	case LL_IOC_FLR_SET_MIRROR: {
		/* mirror I/O must be direct to avoid polluting page cache
		 * by stale data.
		 */
		if (!(file->f_flags & O_DIRECT))
			return -EINVAL;

		fd->fd_designated_mirror = (u32)arg;
		return 0;
	}
	case FS_IOC_FSGETXATTR:
		return ll_ioctl_fsgetxattr(inode, cmd, arg);
	case FS_IOC_FSSETXATTR:
		return ll_ioctl_fssetxattr(inode, cmd, arg);
	case BLKSSZGET:
		return put_user(PAGE_SIZE, (int __user *)arg);
	case LL_IOC_HEAT_GET: {
		struct lu_heat uheat;
		struct lu_heat *heat;
		int size;

		if (copy_from_user(&uheat, (void __user *)arg, sizeof(uheat)))
			return -EFAULT;

		if (uheat.lh_count > OBD_HEAT_COUNT)
			uheat.lh_count = OBD_HEAT_COUNT;

		size = offsetof(typeof(uheat), lh_heat[uheat.lh_count]);
		heat = kzalloc(size, GFP_KERNEL);
		if (!heat)
			return -ENOMEM;

		heat->lh_count = uheat.lh_count;
		ll_heat_get(inode, heat);
		rc = copy_to_user((char __user *)arg, heat, size);
		kfree(heat);
		return rc ? -EFAULT : 0;
	}
	case LL_IOC_HEAT_SET: {
		u64 flags;

		if (copy_from_user(&flags, (void __user *)arg, sizeof(flags)))
			return -EFAULT;

		rc = ll_heat_set(inode, flags);
		return rc;
	}
	case LL_IOC_PCC_DETACH: {
		struct lu_pcc_detach *detach;

		detach = kzalloc(sizeof(*detach), GFP_KERNEL);
		if (!detach)
			return -ENOMEM;

		if (copy_from_user(detach,
				   (const struct lu_pcc_detach __user *)arg,
				   sizeof(*detach))) {
			rc = -EFAULT;
			goto out_detach_free;
		}

		if (!S_ISREG(inode->i_mode)) {
			rc = -EINVAL;
			goto out_detach_free;
		}

		if (!inode_owner_or_capable(inode)) {
			rc = -EPERM;
			goto out_detach_free;
		}

		rc = pcc_ioctl_detach(inode, detach->pccd_opt);
out_detach_free:
		kfree(detach);
		return rc;
	}
	case LL_IOC_PCC_STATE: {
		struct lu_pcc_state __user *ustate =
			(struct lu_pcc_state __user *)arg;
		struct lu_pcc_state *state;

		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return -ENOMEM;

		if (copy_from_user(state, ustate, sizeof(*state))) {
			rc = -EFAULT;
			goto out_state;
		}

		rc = pcc_ioctl_state(file, inode, state);
		if (rc)
			goto out_state;

		if (copy_to_user(ustate, state, sizeof(*state))) {
			rc = -EFAULT;
			goto out_state;
		}

out_state:
		kfree(state);
		return rc;
	}

	case FS_IOC_SET_ENCRYPTION_POLICY:
		if (!ll_sbi_has_encrypt(ll_i2sbi(inode)))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_set_policy(file, (const void __user *)arg);
	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
		if (!ll_sbi_has_encrypt(ll_i2sbi(inode)))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_policy_ex(file, (void __user *)arg);
	case FS_IOC_ADD_ENCRYPTION_KEY:
		if (!ll_sbi_has_encrypt(ll_i2sbi(inode)))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_add_key(file, (void __user *)arg);
	case FS_IOC_REMOVE_ENCRYPTION_KEY:
		if (!ll_sbi_has_encrypt(ll_i2sbi(inode)))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_remove_key(file, (void __user *)arg);
	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
		if (!ll_sbi_has_encrypt(ll_i2sbi(inode)))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_remove_key_all_users(file,
							  (void __user *)arg);
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
		if (!ll_sbi_has_encrypt(ll_i2sbi(inode)))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_key_status(file, (void __user *)arg);
	default:
		return obd_iocontrol(cmd, ll_i2dtexp(inode), 0, NULL,
				     (void __user *)arg);
	}
}

loff_t ll_lseek(struct inode *inode, loff_t offset, int whence)
{
	struct lu_env *env;
	struct cl_io *io;
	struct cl_lseek_io *lsio;
	u16 refcheck;
	int rc;
	loff_t retval;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	io = vvp_env_thread_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;

	lsio = &io->u.ci_lseek;
	lsio->ls_start = offset;
	lsio->ls_whence = whence;
	lsio->ls_result = -ENXIO;

	do {
		rc = cl_io_init(env, io, CIT_LSEEK, io->ci_obj);
		if (!rc)
			rc = cl_io_loop(env, io);
		else
			rc = io->ci_result;
		retval = rc ? : lsio->ls_result;
		cl_io_fini(env, io);
	} while (unlikely(io->ci_need_restart));

	cl_env_put(env, &refcheck);

	return retval;
}

static loff_t ll_file_seek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file_inode(file);
	loff_t retval = offset, eof = 0;
	ktime_t kstart = ktime_get();

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p), to=%llu=%#llx(%d)\n",
	       PFID(ll_inode2fid(inode)), inode, retval, retval, origin);

	if (origin == SEEK_END) {
		retval = ll_glimpse_size(inode);
		if (retval != 0)
			return retval;
		eof = i_size_read(inode);
	}

	if (origin == SEEK_HOLE || origin == SEEK_DATA) {
		if (offset < 0)
			return -ENXIO;

		/* flush local cache first if any */
		cl_sync_file_range(inode, offset, OBD_OBJECT_EOF,
				   CL_FSYNC_LOCAL, 0);

		retval = ll_lseek(inode, offset, origin);
		if (retval < 0)
			return retval;
		retval = vfs_setpos(file, retval, ll_file_maxbytes(inode));
	} else {
		retval = generic_file_llseek_size(file, offset, origin,
						  ll_file_maxbytes(inode), eof);
	}
	if (retval >= 0)
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LLSEEK,
				   ktime_us_delta(ktime_get(), kstart));
	return retval;
}

static int ll_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = file->private_data;
	int rc, err;

	LASSERT(!S_ISDIR(inode->i_mode));

	/* catch async errors that were recorded back when async writeback
	 * failed for pages in this mapping.
	 */
	rc = lli->lli_async_rc;
	lli->lli_async_rc = 0;
	if (lli->lli_clob) {
		err = lov_read_and_clear_async_rc(lli->lli_clob);
		if (!rc)
			rc = err;
	}

	/* The application has been told about write failure already.
	 * Do not report failure again.
	 */
	if (fd->fd_write_failed)
		return 0;
	return rc ? -EIO : 0;
}

/**
 * Called to make sure a portion of file has been written out.
 * if @mode is not CL_FSYNC_LOCAL, it will send OST_SYNC RPCs to OST.
 *
 * Return how many pages have been written.
 */
int cl_sync_file_range(struct inode *inode, loff_t start, loff_t end,
		       enum cl_fsync_mode mode, int ignore_layout)
{
	struct lu_env *env;
	struct cl_io *io;
	struct cl_fsync_io *fio;
	int result;
	u16 refcheck;

	if (mode != CL_FSYNC_NONE && mode != CL_FSYNC_LOCAL &&
	    mode != CL_FSYNC_DISCARD && mode != CL_FSYNC_ALL)
		return -EINVAL;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	io = vvp_env_thread_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;
	io->ci_ignore_layout = ignore_layout;

	/* initialize parameters for sync */
	fio = &io->u.ci_fsync;
	fio->fi_start = start;
	fio->fi_end = end;
	fio->fi_fid = ll_inode2fid(inode);
	fio->fi_mode = mode;
	fio->fi_nr_written = 0;

	if (cl_io_init(env, io, CIT_FSYNC, io->ci_obj) == 0)
		result = cl_io_loop(env, io);
	else
		result = io->ci_result;
	if (result == 0)
		result = fio->fi_nr_written;
	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);

	return result;
}

int ll_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file_inode(file);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ptlrpc_request *req;
	ktime_t kstart = ktime_get();
	int rc, err;

	CDEBUG(D_VFSTRACE,
	       "VFS Op:inode=" DFID "(%p), start %lld, end %lld, datasync %d\n",
	       PFID(ll_inode2fid(inode)), inode, start, end, datasync);


	rc = file_write_and_wait_range(file, start, end);
	inode_lock(inode);

	/* catch async errors that were recorded back when async writeback
	 * failed for pages in this mapping.
	 */
	if (!S_ISDIR(inode->i_mode)) {
		err = lli->lli_async_rc;

		lli->lli_async_rc = 0;
		if (rc == 0)
			rc = err;
		if (lli->lli_clob) {
			err = lov_read_and_clear_async_rc(lli->lli_clob);
			if (rc == 0)
				rc = err;
		}
	}

	err = md_fsync(ll_i2sbi(inode)->ll_md_exp, ll_inode2fid(inode), &req);
	if (!rc)
		rc = err;
	if (!err)
		ptlrpc_req_finished(req);

	if (S_ISREG(inode->i_mode)) {
		struct ll_file_data *fd = file->private_data;
		bool cached;

		/* Sync metadata on MDT first, and then sync the cached data
		 * on PCC.
		 */
		err = pcc_fsync(file, start, end, datasync, &cached);
		if (!cached)
			err = cl_sync_file_range(inode, start, end,
						 CL_FSYNC_ALL, 0);
		if (rc == 0 && err < 0)
			rc = err;
		if (rc < 0)
			fd->fd_write_failed = true;
		else
			fd->fd_write_failed = false;
	}

	inode_unlock(inode);

	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FSYNC,
				   ktime_us_delta(ktime_get(), kstart));
	return rc;
}

static int
ll_file_flock(struct file *file, int cmd, struct file_lock *file_lock)
{
	struct inode *inode = file_inode(file);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ldlm_enqueue_info einfo = {
		.ei_type	= LDLM_FLOCK,
		.ei_cb_cp	= ldlm_flock_completion_ast,
		.ei_cbdata	= file_lock,
	};
	struct md_op_data *op_data;
	struct lustre_handle lockh = {0};
	union ldlm_policy_data flock = { { 0 } };
	int fl_type = file_lock->fl_type;
	ktime_t kstart = ktime_get();
	u64 flags = 0;
	int rc;
	int rc2 = 0;

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID " file_lock=%p\n",
	       PFID(ll_inode2fid(inode)), file_lock);


	if (file_lock->fl_flags & FL_FLOCK)
		LASSERT((cmd == F_SETLKW) || (cmd == F_SETLK));
	else if (!(file_lock->fl_flags & FL_POSIX))
		return -EINVAL;

	flock.l_flock.owner = (unsigned long)file_lock->fl_owner;
	flock.l_flock.pid = file_lock->fl_pid;
	flock.l_flock.start = file_lock->fl_start;
	flock.l_flock.end = file_lock->fl_end;

	switch (fl_type) {
	case F_RDLCK:
		einfo.ei_mode = LCK_PR;
		break;
	case F_UNLCK:
		/* An unlock request may or may not have any relation to
		 * existing locks so we may not be able to pass a lock handle
		 * via a normal ldlm_lock_cancel() request. The request may even
		 * unlock a byte range in the middle of an existing lock. In
		 * order to process an unlock request we need all of the same
		 * information that is given with a normal read or write record
		 * lock request. To avoid creating another ldlm unlock (cancel)
		 * message we'll treat a LCK_NL flock request as an unlock.
		 */
		einfo.ei_mode = LCK_NL;
		break;
	case F_WRLCK:
		einfo.ei_mode = LCK_PW;
		break;
	default:
		CDEBUG(D_INFO, "Unknown fcntl lock type: %d\n", fl_type);
		return -ENOTSUPP;
	}

	switch (cmd) {
	case F_SETLKW:
#ifdef F_SETLKW64
	case F_SETLKW64:
#endif
		flags = 0;
		break;
	case F_SETLK:
#ifdef F_SETLK64
	case F_SETLK64:
#endif
		flags = LDLM_FL_BLOCK_NOWAIT;
		break;
	case F_GETLK:
#ifdef F_GETLK64
	case F_GETLK64:
#endif
		flags = LDLM_FL_TEST_LOCK;
		break;
	default:
		CERROR("unknown fcntl lock command: %d\n", cmd);
		return -EINVAL;
	}

	/*
	 * Save the old mode so that if the mode in the lock changes we
	 * can decrement the appropriate reader or writer refcount.
	 */
	file_lock->fl_type = einfo.ei_mode;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	CDEBUG(D_DLMTRACE,
	       "inode=" DFID ", pid=%u, flags=%#llx, mode=%u, start=%llu, end=%llu\n",
	       PFID(ll_inode2fid(inode)), flock.l_flock.pid, flags,
	       einfo.ei_mode, flock.l_flock.start, flock.l_flock.end);

	rc = md_enqueue(sbi->ll_md_exp, &einfo, &flock, op_data, &lockh,
			flags);

	/* Restore the file lock type if not TEST lock. */
	if (!(flags & LDLM_FL_TEST_LOCK))
		file_lock->fl_type = fl_type;

	if ((rc == 0 || file_lock->fl_type == F_UNLCK) &&
	    !(flags & LDLM_FL_TEST_LOCK))
		rc2  = locks_lock_file_wait(file, file_lock);

	if (rc2 && file_lock->fl_type != F_UNLCK) {
		einfo.ei_mode = LCK_NL;
		md_enqueue(sbi->ll_md_exp, &einfo, &flock, op_data,
			   &lockh, flags);
		rc = rc2;
	}

	ll_finish_md_op_data(op_data);

	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FLOCK,
				   ktime_us_delta(ktime_get(), kstart));
	return rc;
}

int ll_get_fid_by_name(struct inode *parent, const char *name,
		       int namelen, struct lu_fid *fid,
		       struct inode **inode)
{
	struct md_op_data *op_data = NULL;
	struct ptlrpc_request *req;
	struct mdt_body *body;
	int rc;

	op_data = ll_prep_md_op_data(NULL, parent, NULL, name, namelen, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	op_data->op_valid = OBD_MD_FLID | OBD_MD_FLTYPE;
	rc = md_getattr_name(ll_i2sbi(parent)->ll_md_exp, op_data, &req);
	ll_finish_md_op_data(op_data);
	if (rc < 0)
		return rc;

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	if (!body) {
		rc = -EFAULT;
		goto out_req;
	}
	if (fid)
		*fid = body->mbo_fid1;

	if (inode)
		rc = ll_prep_inode(inode, req, parent->i_sb, NULL);
out_req:
	ptlrpc_req_finished(req);
	return rc;
}

int ll_migrate(struct inode *parent, struct file *file, struct lmv_user_md *lum,
	       const char *name)
{
	struct ptlrpc_request *request = NULL;
	struct obd_client_handle *och = NULL;
	struct inode *child_inode = NULL;
	struct dentry *dchild = NULL;
	struct md_op_data *op_data;
	struct mdt_body *body;
	u64 data_version = 0;
	size_t namelen = strlen(name);
	int lumlen = lmv_user_md_size(lum->lum_stripe_count, lum->lum_magic);
	struct qstr qstr;
	int rc;

	CDEBUG(D_VFSTRACE, "migrate " DFID "/%s to MDT%d stripe count %d\n",
	       PFID(ll_inode2fid(parent)), name,
	       lum->lum_stripe_offset, lum->lum_stripe_count);

	if (lum->lum_magic != cpu_to_le32(LMV_USER_MAGIC) &&
	    lum->lum_magic != cpu_to_le32(LMV_USER_MAGIC_SPECIFIC))
		lustre_swab_lmv_user_md(lum);

	/* Get child FID first */
	qstr.hash = full_name_hash(file_dentry(file), name, namelen);
	qstr.name = name;
	qstr.len = namelen;
	dchild = d_lookup(file_dentry(file), &qstr);
	if (dchild) {
		if (dchild->d_inode)
			child_inode = igrab(dchild->d_inode);
		dput(dchild);
	}

	if (!child_inode) {
		rc = ll_get_fid_by_name(parent, name, namelen, NULL,
					&child_inode);
		if (rc)
			return rc;
	}

	if (!child_inode)
		return -ENOENT;

	if (!(exp_connect_flags2(ll_i2sbi(parent)->ll_md_exp) &
	      OBD_CONNECT2_DIR_MIGRATE)) {
		if (le32_to_cpu(lum->lum_stripe_count) > 1 ||
		    ll_dir_striped(child_inode)) {
			CERROR("%s: MDT doesn't support stripe directory migration!\n",
			       ll_i2sbi(parent)->ll_fsname);
			rc = -EOPNOTSUPP;
			goto out_iput;
		}
	}

	/*
	 * lfs migrate command needs to be blocked on the client
	 * by checking the migrate FID against the FID of the
	 * filesystem root.
	 */
	if (child_inode == parent->i_sb->s_root->d_inode) {
		rc = -EINVAL;
		goto out_iput;
	}

	op_data = ll_prep_md_op_data(NULL, parent, NULL, name, namelen,
				     child_inode->i_mode, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data)) {
		rc = PTR_ERR(op_data);
		goto out_iput;
	}

	inode_lock(child_inode);
	op_data->op_fid3 = *ll_inode2fid(child_inode);
	if (!fid_is_sane(&op_data->op_fid3)) {
		CERROR("%s: migrate %s, but fid " DFID " is insane\n",
		       ll_i2sbi(parent)->ll_fsname, name,
		       PFID(&op_data->op_fid3));
		rc = -EINVAL;
		goto out_unlock;
	}

	op_data->op_cli_flags |= CLI_MIGRATE | CLI_SET_MEA;
	op_data->op_data = lum;
	op_data->op_data_size = lumlen;

again:
	if (S_ISREG(child_inode->i_mode)) {
		och = ll_lease_open(child_inode, NULL, FMODE_WRITE, 0);
		if (IS_ERR(och)) {
			rc = PTR_ERR(och);
			och = NULL;
			goto out_unlock;
		}

		rc = ll_data_version(child_inode, &data_version,
				     LL_DV_WR_FLUSH);
		if (rc)
			goto out_close;

		op_data->op_open_handle = och->och_open_handle;
		op_data->op_data_version = data_version;
		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_bias |= MDS_CLOSE_MIGRATE;

		spin_lock(&och->och_mod->mod_open_req->rq_lock);
		och->och_mod->mod_open_req->rq_replay = 0;
		spin_unlock(&och->och_mod->mod_open_req->rq_lock);
	}

	rc = md_rename(ll_i2sbi(parent)->ll_md_exp, op_data, name, namelen,
		       name, namelen, &request);
	if (!rc) {
		LASSERT(request);
		ll_update_times(request, parent);
	}

	if (rc == 0 || rc == -EAGAIN) {
		body = req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY);
		LASSERT(body);

		/*
		 * If the server does release layout lock, then we cleanup
		 * the client och here, otherwise release it in out_close:
		 */
		if (och && body->mbo_valid & OBD_MD_CLOSE_INTENT_EXECED) {
			obd_mod_put(och->och_mod);
			md_clear_open_replay_data(ll_i2sbi(parent)->ll_md_exp,
						  och);
			och->och_open_handle.cookie = DEAD_HANDLE_MAGIC;
			kfree(och);
			och = NULL;
		}
	}

	if (request) {
		ptlrpc_req_finished(request);
		request = NULL;
	}

	/* Try again if the lease has cancelled. */
	if (rc == -EAGAIN && S_ISREG(child_inode->i_mode))
		goto again;

out_close:
	if (och)
		ll_lease_close(och, child_inode, NULL);
	if (!rc)
		clear_nlink(child_inode);
out_unlock:
	inode_unlock(child_inode);
	ll_finish_md_op_data(op_data);
out_iput:
	iput(child_inode);
	return rc;
}

static int
ll_file_noflock(struct file *file, int cmd, struct file_lock *file_lock)
{
	struct ll_file_data *fd = file->private_data;

	/*
	 * In order to avoid flood of warning messages, only print one message
	 * for one file. And the entire message rate on the client is limited
	 * by CDEBUG_LIMIT too.
	 */
	if (!(fd->fd_flags & LL_FILE_FLOCK_WARNING)) {
		fd->fd_flags |= LL_FILE_FLOCK_WARNING;
		CDEBUG_LIMIT(D_TTY | D_CONSOLE,
			     "flock disabled, mount with '-o [local]flock' to enable\r\n");
	}
	return -EINVAL;
}

/**
 * test if some locks matching bits and l_req_mode are acquired
 * - bits can be in different locks
 * - if found clear the common lock bits in *bits
 * - the bits not found, are kept in *bits
 *
 * @inode:		inode
 * @bits:		searched lock bits [IN]
 * @l_req_mode:		searched lock mode
 *
 * Returns:		boolean, true iff all bits are found
 */
int ll_have_md_lock(struct inode *inode, u64 *bits,
		    enum ldlm_mode l_req_mode)
{
	struct lustre_handle lockh;
	union ldlm_policy_data policy;
	enum ldlm_mode mode = (l_req_mode == LCK_MINMODE) ?
			      (LCK_CR | LCK_CW | LCK_PR | LCK_PW) : l_req_mode;
	struct lu_fid *fid;
	u64 flags;
	int i;

	if (!inode)
		return 0;

	fid = &ll_i2info(inode)->lli_fid;
	CDEBUG(D_INFO, "trying to match res " DFID " mode %s\n", PFID(fid),
	       ldlm_lockname[mode]);

	flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
	for (i = 0; i < MDS_INODELOCK_NUMBITS && *bits != 0; i++) {
		policy.l_inodebits.bits = *bits & BIT(i);
		if (policy.l_inodebits.bits == 0)
			continue;

		if (md_lock_match(ll_i2mdexp(inode), flags, fid, LDLM_IBITS,
				  &policy, mode, &lockh)) {
			struct ldlm_lock *lock;

			lock = ldlm_handle2lock(&lockh);
			if (lock) {
				*bits &=
				      ~(lock->l_policy_data.l_inodebits.bits);
				LDLM_LOCK_PUT(lock);
			} else {
				*bits &= ~policy.l_inodebits.bits;
			}
		}
	}
	return *bits == 0;
}

enum ldlm_mode ll_take_md_lock(struct inode *inode, u64 bits,
			       struct lustre_handle *lockh, u64 flags,
			       enum ldlm_mode mode)
{
	union ldlm_policy_data policy = { .l_inodebits = { bits } };
	struct lu_fid *fid;

	fid = &ll_i2info(inode)->lli_fid;
	CDEBUG(D_INFO, "trying to match res " DFID "\n", PFID(fid));

	return md_lock_match(ll_i2mdexp(inode), flags | LDLM_FL_BLOCK_GRANTED,
			     fid, LDLM_IBITS, &policy, mode, lockh);
}

static int ll_inode_revalidate_fini(struct inode *inode, int rc)
{
	/* Already unlinked. Just update nlink and return success */
	if (rc == -ENOENT) {
		clear_nlink(inode);
		/* If it is striped directory, and there is bad stripe
		 * Let's revalidate the dentry again, instead of returning
		 * error
		 */
		if (ll_dir_striped(inode))
			return 0;

		/* This path cannot be hit for regular files unless in
		 * case of obscure races, so no need to validate size.
		 */
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return 0;
	} else if (rc != 0) {
		CDEBUG_LIMIT((rc == -EACCES || rc == -EIDRM) ? D_INFO : D_ERROR,
			     "%s: revalidate FID " DFID " error: rc = %d\n",
			     ll_i2sbi(inode)->ll_fsname,
			     PFID(ll_inode2fid(inode)), rc);
	}

	return rc;
}

static int ll_inode_revalidate(struct dentry *dentry, enum ldlm_intent_flags op)
{
	struct inode *parent;
	struct inode *inode = d_inode(dentry);
	struct obd_export *exp = ll_i2mdexp(inode);
	struct lookup_intent oit = {
		.it_op = op,
	};
	struct ptlrpc_request *req = NULL;
	struct md_op_data *op_data;
	const char *name = NULL;
	size_t namelen = 0;
	int rc = 0;

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p),name=%pd\n",
	       PFID(ll_inode2fid(inode)), inode, dentry);

	if (exp_connect_flags2(exp) & OBD_CONNECT2_GETATTR_PFID) {
		parent = dentry->d_parent->d_inode;
		name = dentry->d_name.name;
		namelen = dentry->d_name.len;
	} else {
		parent = inode;
	}

	op_data = ll_prep_md_op_data(NULL, parent, inode, name, namelen, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	/* Call getattr by fid */
	if (exp_connect_flags2(exp) & OBD_CONNECT2_GETATTR_PFID)
		op_data->op_flags = MF_GETATTR_BY_FID;
	rc = md_intent_lock(exp, op_data, &oit, &req, &ll_md_blocking_ast, 0);
	ll_finish_md_op_data(op_data);
	if (rc < 0) {
		rc = ll_inode_revalidate_fini(inode, rc);
		goto out;
	}

	rc = ll_revalidate_it_finish(req, &oit, inode);
	if (rc != 0) {
		ll_intent_release(&oit);
		goto out;
	}

	/* Unlinked? Unhash dentry, so it is not picked up later by
	 * do_lookup() -> ll_revalidate_it(). We cannot use d_drop
	 * here to preserve get_cwd functionality on 2.6.
	 * Bug 10503
	 */
	if (!d_inode(dentry)->i_nlink)
		d_lustre_invalidate(dentry);

	ll_lookup_finish_locks(&oit, inode);
out:
	ptlrpc_req_finished(req);

	return rc;
}

static int ll_merge_md_attr(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_attr attr = { 0 };
	int rc;

	LASSERT(lli->lli_lsm_md);

	if (!lmv_dir_striped(lli->lli_lsm_md))
		return 0;

	down_read(&lli->lli_lsm_sem);
	rc = md_merge_attr(ll_i2mdexp(inode), &lli->lli_fid, lli->lli_lsm_md,
			   &attr, ll_md_blocking_ast);
	up_read(&lli->lli_lsm_sem);
	if (rc)
		return rc;

	set_nlink(inode, attr.cat_nlink);
	inode->i_blocks = attr.cat_blocks;
	i_size_write(inode, attr.cat_size);

	ll_i2info(inode)->lli_atime = attr.cat_atime;
	ll_i2info(inode)->lli_mtime = attr.cat_mtime;
	ll_i2info(inode)->lli_ctime = attr.cat_ctime;

	return 0;
}

int ll_getattr(const struct path *path, struct kstat *stat,
	       u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct inode *dir = d_inode(path->dentry->d_parent);
	bool need_glimpse = true;
	ktime_t kstart = ktime_get();
	int rc = 0;

	/* The OST object(s) determine the file size, blocks and mtime. */
	if (!(request_mask & STATX_SIZE || request_mask & STATX_BLOCKS ||
	      request_mask & STATX_MTIME))
		need_glimpse = false;

	if (dentry_may_statahead(dir, path->dentry))
		ll_start_statahead(dir, path->dentry, need_glimpse &&
				   !(flags & AT_STATX_DONT_SYNC));

	if (flags & AT_STATX_DONT_SYNC)
		goto fill_attr;

	rc = ll_inode_revalidate(path->dentry, IT_GETATTR);
	if (rc < 0)
		return rc;

	if (S_ISREG(inode->i_mode)) {
		bool cached;

		if (!need_glimpse)
			goto fill_attr;

		rc = pcc_inode_getattr(inode, request_mask, flags, &cached);
		if (cached && rc < 0)
			return rc;

		if (cached)
			goto fill_attr;

		/*
		 * If the returned attr is masked with OBD_MD_FLSIZE &
		 * OBD_MD_FLBLOCKS & OBD_MD_FLMTIME, it means that the file size
		 * or blocks obtained from MDT is strictly correct, and the file
		 * is usually not being modified by clients, and the [a|m|c]time
		 * got from MDT is also strictly correct.
		 * Under this circumstance, it does not need to send glimpse
		 * RPCs to OSTs for file attributes such as the size and blocks.
		 */
		if (lli->lli_attr_valid & OBD_MD_FLSIZE &&
		    lli->lli_attr_valid & OBD_MD_FLBLOCKS &&
		    lli->lli_attr_valid & OBD_MD_FLMTIME) {
			inode->i_mtime.tv_sec = lli->lli_mtime;
			if (lli->lli_attr_valid & OBD_MD_FLATIME)
				inode->i_atime.tv_sec = lli->lli_atime;
			if (lli->lli_attr_valid & OBD_MD_FLCTIME)
				inode->i_ctime.tv_sec = lli->lli_ctime;
			goto fill_attr;
		}

		/* In case of restore, the MDT has the right size and has
		 * already send it back without granting the layout lock,
		 * inode is up-to-date so glimpse is useless.
		 * Also to glimpse we need the layout, in case of a running
		 * restore the MDT holds the layout lock so the glimpse will
		 * block up to the end of restore (getattr will block)
		 */
		if (!test_bit(LLIF_FILE_RESTORING,
					 &lli->lli_flags)) {
			rc = ll_glimpse_size(inode);
			if (rc < 0)
				return rc;
		}
	} else {
		/* If object isn't regular a file then don't validate size. */
		if (ll_dir_striped(inode)) {
			rc = ll_merge_md_attr(inode);
			if (rc < 0)
				return rc;
		}

		if (lli->lli_attr_valid & OBD_MD_FLATIME)
			inode->i_atime.tv_sec = lli->lli_atime;
		if (lli->lli_attr_valid & OBD_MD_FLMTIME)
			inode->i_mtime.tv_sec = lli->lli_mtime;
		if (lli->lli_attr_valid & OBD_MD_FLCTIME)
			inode->i_ctime.tv_sec = lli->lli_ctime;
	}

fill_attr:
	OBD_FAIL_TIMEOUT(OBD_FAIL_GETATTR_DELAY, 30);

	stat->dev = inode->i_sb->s_dev;
	if (ll_need_32bit_api(sbi)) {
		stat->ino = cl_fid_build_ino(&lli->lli_fid, 1);
		stat->dev = MKDEV(MAJOR(inode->i_sb->s_dev) & 0xff,
				  MINOR(inode->i_sb->s_dev) & 0xff);
		stat->rdev = MKDEV(MAJOR(inode->i_rdev) & 0xff,
				   MINOR(inode->i_rdev) & 0xff);
	} else {
		stat->dev = inode->i_sb->s_dev;
		stat->rdev = inode->i_rdev;
		stat->ino = inode->i_ino;
	}
	stat->mode = inode->i_mode;
	stat->uid = inode->i_uid;
	stat->gid = inode->i_gid;
	stat->atime = inode->i_atime;
	stat->mtime = inode->i_mtime;
	stat->ctime = inode->i_ctime;
	/* stat->blksize is used to tell about preferred IO size */
	if (sbi->ll_stat_blksize)
		stat->blksize = sbi->ll_stat_blksize;
	else if (S_ISREG(inode->i_mode))
		stat->blksize = 1 << min(PTLRPC_MAX_BRW_BITS + 1,
					 LL_MAX_BLKSIZE_BITS);
	else
		stat->blksize = (1 << inode->i_sb->s_blocksize_bits);

	stat->nlink = inode->i_nlink;
	stat->size = i_size_read(inode);
	stat->blocks = inode->i_blocks;

	if (flags & AT_STATX_DONT_SYNC) {
		if (stat->size == 0 &&
		    lli->lli_attr_valid & OBD_MD_FLLAZYSIZE)
			stat->size = lli->lli_lazysize;
		if (stat->blocks == 0 &&
		    lli->lli_attr_valid & OBD_MD_FLLAZYBLOCKS)
			stat->blocks = lli->lli_lazyblocks;
	}

	if (lli->lli_attr_valid & OBD_MD_FLBTIME) {
		stat->result_mask |= STATX_BTIME;
		stat->btime.tv_sec = lli->lli_btime;
	}

	stat->attributes_mask = STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND;
	stat->attributes |= ll_inode_to_ext_flags(inode->i_flags);
	stat->result_mask &= request_mask;

	ll_stats_ops_tally(sbi, LPROC_LL_GETATTR,
			   ktime_us_delta(ktime_get(), kstart));

	return 0;
}

int cl_falloc(struct inode *inode, int mode, loff_t offset, loff_t len)
{
	struct lu_env *env;
	struct cl_io *io;
	u16 refcheck;
	int rc; loff_t sa_falloc_end;
	loff_t size = i_size_read(inode);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	io = vvp_env_thread_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;
	io->ci_verify_layout = 1;
	io->u.ci_setattr.sa_parent_fid = lu_object_fid(&io->ci_obj->co_lu);
	io->u.ci_setattr.sa_falloc_mode = mode;
	io->u.ci_setattr.sa_falloc_offset = offset;
	io->u.ci_setattr.sa_falloc_len = len;
	io->u.ci_setattr.sa_falloc_end = io->u.ci_setattr.sa_falloc_offset +
		io->u.ci_setattr.sa_falloc_len;
	io->u.ci_setattr.sa_subtype = CL_SETATTR_FALLOCATE;
	sa_falloc_end = io->u.ci_setattr.sa_falloc_end;
	if (sa_falloc_end > size) {
		/* Check new size against VFS/VM file size limit and rlimit */
		rc = inode_newsize_ok(inode, sa_falloc_end);
		if (rc)
			goto out;
		if (sa_falloc_end > ll_file_maxbytes(inode)) {
			CDEBUG(D_INODE, "file size too large %llu > %llu\n",
			       (unsigned long long)(sa_falloc_end),
			       ll_file_maxbytes(inode));
			rc = -EFBIG;
			goto out;
		}
		io->u.ci_setattr.sa_attr.lvb_size = sa_falloc_end;
		if (!(mode & FALLOC_FL_KEEP_SIZE))
			io->u.ci_setattr.sa_avalid |= ATTR_SIZE;
	} else {
		io->u.ci_setattr.sa_attr.lvb_size = size;
	}

again:
	if (cl_io_init(env, io, CIT_SETATTR, io->ci_obj) == 0)
		rc = cl_io_loop(env, io);
	else
		rc = io->ci_result;

	cl_io_fini(env, io);
	if (unlikely(io->ci_need_restart))
		goto again;

out:
	cl_env_put(env, &refcheck);
	return rc;
}

long ll_fallocate(struct file *filp, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	int rc;

	/*
	 * Encrypted inodes can't handle collapse range or zero range or insert
	 * range since we would need to re-encrypt blocks with a different IV or
	 * XTS tweak (which are based on the logical block number).
	 * Similar to what ext4 does.
	 */
	if (IS_ENCRYPTED(inode) &&
	    (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE |
		     FALLOC_FL_ZERO_RANGE)))
		return -EOPNOTSUPP;

	/*
	 * Only mode == 0 (which is standard prealloc) is supported now.
	 * Punch is not supported yet.
	 */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FALLOCATE, 1);

	rc = cl_falloc(inode, mode, offset, len);

	return rc;
}

static int ll_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		     u64 start, u64 len)
{
	int rc;
	size_t num_bytes;
	struct fiemap *fiemap;
	unsigned int extent_count = fieinfo->fi_extents_max;

	num_bytes = sizeof(*fiemap) + (extent_count *
				       sizeof(struct fiemap_extent));
	fiemap = kvzalloc(num_bytes, GFP_KERNEL);
	if (!fiemap)
		return -ENOMEM;

	fiemap->fm_flags = fieinfo->fi_flags;
	fiemap->fm_extent_count = fieinfo->fi_extents_max;
	fiemap->fm_start = start;
	fiemap->fm_length = len;

	if (extent_count > 0 &&
	    copy_from_user(&fiemap->fm_extents[0], fieinfo->fi_extents_start,
			   sizeof(struct fiemap_extent))) {
		rc = -EFAULT;
		goto out;
	}

	rc = ll_do_fiemap(inode, fiemap, num_bytes);

	fieinfo->fi_flags = fiemap->fm_flags;
	fieinfo->fi_extents_mapped = fiemap->fm_mapped_extents;
	if (extent_count > 0 &&
	    copy_to_user(fieinfo->fi_extents_start, &fiemap->fm_extents[0],
			 fiemap->fm_mapped_extents *
			 sizeof(struct fiemap_extent))) {
		rc = -EFAULT;
		goto out;
	}
out:
	kvfree(fiemap);
	return rc;
}

int ll_inode_permission(struct inode *inode, int mask)
{
	struct ll_sb_info *sbi;
	struct root_squash_info *squash;
	const struct cred *old_cred = NULL;
	struct cred *cred = NULL;
	bool squash_id = false;
	ktime_t kstart = ktime_get();
	int rc = 0;

	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	/* As root inode are NOT getting validated in lookup operation,
	* need to do it before permission check.
	*/

	if (is_root_inode(inode)) {
		rc = ll_inode_revalidate(inode->i_sb->s_root, IT_LOOKUP);
		if (rc)
			return rc;
	}

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p), inode mode %x mask %o\n",
	       PFID(ll_inode2fid(inode)), inode, inode->i_mode, mask);

	/* squash fsuid/fsgid if needed */
	sbi = ll_i2sbi(inode);
	squash = &sbi->ll_squash;
	if (unlikely(squash->rsi_uid &&
		     uid_eq(current_fsuid(), GLOBAL_ROOT_UID) &&
		     !(sbi->ll_flags & LL_SBI_NOROOTSQUASH))) {
		squash_id = true;
	}

	if (squash_id) {
		CDEBUG(D_OTHER, "squash creds (%d:%d)=>(%d:%d)\n",
		       __kuid_val(current_fsuid()), __kgid_val(current_fsgid()),
		       squash->rsi_uid, squash->rsi_gid);

		/*
		 * update current process's credentials
		 * and FS capability
		 */
		cred = prepare_creds();
		if (!cred)
			return -ENOMEM;

		cred->fsuid = make_kuid(&init_user_ns, squash->rsi_uid);
		cred->fsgid = make_kgid(&init_user_ns, squash->rsi_gid);
		cred->cap_effective = cap_drop_nfsd_set(cred->cap_effective);
		cred->cap_effective = cap_drop_fs_set(cred->cap_effective);

		old_cred = override_creds(cred);
	}

	rc = generic_permission(inode, mask);

	/* restore current process's credentials and FS capability */
	if (squash_id) {
		revert_creds(old_cred);
		put_cred(cred);
	}

	if (!rc)
		ll_stats_ops_tally(sbi, LPROC_LL_INODE_PERM,
				   ktime_us_delta(ktime_get(), kstart));

	return rc;
}

/* -o localflock - only provides locally consistent flock locks */
const struct file_operations ll_file_operations = {
	.read_iter		= ll_file_read_iter,
	.write_iter		= ll_file_write_iter,
	.unlocked_ioctl		= ll_file_ioctl,
	.open			= ll_file_open,
	.release		= ll_file_release,
	.mmap			= ll_file_mmap,
	.llseek			= ll_file_seek,
	.splice_read		= generic_file_splice_read,
	.fsync			= ll_fsync,
	.flush			= ll_flush,
	.fallocate	= ll_fallocate,
};

const struct file_operations ll_file_operations_flock = {
	.read_iter		= ll_file_read_iter,
	.write_iter		= ll_file_write_iter,
	.unlocked_ioctl		= ll_file_ioctl,
	.open			= ll_file_open,
	.release		= ll_file_release,
	.mmap			= ll_file_mmap,
	.llseek			= ll_file_seek,
	.splice_read		= generic_file_splice_read,
	.fsync			= ll_fsync,
	.flush			= ll_flush,
	.flock			= ll_file_flock,
	.lock			= ll_file_flock,
	.fallocate	= ll_fallocate,
};

/* These are for -o noflock - to return ENOSYS on flock calls */
const struct file_operations ll_file_operations_noflock = {
	.read_iter		= ll_file_read_iter,
	.write_iter		= ll_file_write_iter,
	.unlocked_ioctl		= ll_file_ioctl,
	.open			= ll_file_open,
	.release		= ll_file_release,
	.mmap			= ll_file_mmap,
	.llseek			= ll_file_seek,
	.splice_read		= generic_file_splice_read,
	.fsync			= ll_fsync,
	.flush			= ll_flush,
	.flock			= ll_file_noflock,
	.lock			= ll_file_noflock,
	.fallocate	= ll_fallocate,
};

const struct inode_operations ll_file_inode_operations = {
	.setattr		= ll_setattr,
	.getattr		= ll_getattr,
	.permission		= ll_inode_permission,
	.listxattr		= ll_listxattr,
	.fiemap			= ll_fiemap,
	.get_acl		= ll_get_acl,
};

int ll_layout_conf(struct inode *inode, const struct cl_object_conf *conf)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct lu_env *env;
	int rc;
	u16 refcheck;

	if (!obj)
		return 0;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	rc = cl_conf_set(env, obj, conf);
	if (rc < 0)
		goto out;

	if (conf->coc_opc == OBJECT_CONF_SET) {
		struct ldlm_lock *lock = conf->coc_lock;
		struct cl_layout cl = {
			.cl_layout_gen = 0,
		};

		LASSERT(lock);
		LASSERT(ldlm_has_layout(lock));

		/* it can only be allowed to match after layout is
		 * applied to inode otherwise false layout would be
		 * seen. Applying layout should happen before dropping
		 * the intent lock.
		 */
		ldlm_lock_allow_match(lock);

		rc = cl_object_layout_get(env, obj, &cl);
		if (rc < 0)
			goto out;

		CDEBUG(D_VFSTRACE, DFID ": layout version change: %u -> %u\n",
		       PFID(&lli->lli_fid), ll_layout_version_get(lli),
		       cl.cl_layout_gen);
		ll_layout_version_set(lli, cl.cl_layout_gen);
	}
out:
	cl_env_put(env, &refcheck);
	return rc;
}

/* Fetch layout from MDT with getxattr request, if it's not ready yet */
static int ll_layout_fetch(struct inode *inode, struct ldlm_lock *lock)

{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req;
	void *lvbdata;
	void *lmm;
	int lmmsize;
	int rc;

	CDEBUG(D_INODE, DFID " LVB_READY=%d l_lvb_data=%p l_lvb_len=%d\n",
	       PFID(ll_inode2fid(inode)), ldlm_is_lvb_ready(lock),
	       lock->l_lvb_data, lock->l_lvb_len);

	if (lock->l_lvb_data)
		return 0;

	/* if layout lock was granted right away, the layout is returned
	 * within DLM_LVB of dlm reply; otherwise if the lock was ever
	 * blocked and then granted via completion ast, we have to fetch
	 * layout here. Please note that we can't use the LVB buffer in
	 * completion AST because it doesn't have a large enough buffer
	 */
	rc = ll_get_default_mdsize(sbi, &lmmsize);
	if (rc < 0)
		return rc;

	rc = md_getxattr(sbi->ll_md_exp, ll_inode2fid(inode), OBD_MD_FLXATTR,
			 XATTR_NAME_LOV, lmmsize, &req);
	if (rc < 0) {
		if (rc == -ENODATA) {
			rc = 0;
			goto out; /* empty layout */
		}
		return rc;
	}

	lmmsize = rc;
	rc = 0;
	if (lmmsize == 0) /* empty layout */ {
		rc = 0;
		goto out;
	}

	lmm = req_capsule_server_sized_get(&req->rq_pill, &RMF_EADATA, lmmsize);
	if (!lmm) {
		rc = -EFAULT;
		goto out;
	}

	lvbdata = kvzalloc(lmmsize, GFP_KERNEL);
	if (!lvbdata) {
		rc = -ENOMEM;
		goto out;
	}

	memcpy(lvbdata, lmm, lmmsize);
	lock_res_and_lock(lock);
	if (!lock->l_lvb_data) {
		lock->l_lvb_type = LVB_T_LAYOUT;
		lock->l_lvb_data = lvbdata;
		lock->l_lvb_len = lmmsize;
		lvbdata = NULL;
	}
	unlock_res_and_lock(lock);

	if (lvbdata)
		kvfree(lvbdata);
out:
	ptlrpc_req_finished(req);
	return rc;
}

/**
 * Apply the layout to the inode. Layout lock is held and will be released
 * in this function.
 */
static int ll_layout_lock_set(struct lustre_handle *lockh, enum ldlm_mode mode,
			      struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ldlm_lock *lock;
	struct cl_object_conf conf;
	int rc = 0;
	bool lvb_ready;
	bool wait_layout = false;

	LASSERT(lustre_handle_is_used(lockh));

	lock = ldlm_handle2lock(lockh);
	LASSERT(lock);
	LASSERT(ldlm_has_layout(lock));

	LDLM_DEBUG(lock, "File " DFID "(%p) being reconfigured",
		   PFID(&lli->lli_fid), inode);

	/* in case this is a caching lock and reinstate with new inode */
	md_set_lock_data(sbi->ll_md_exp, lockh, inode, NULL);

	lock_res_and_lock(lock);
	lvb_ready = ldlm_is_lvb_ready(lock);
	unlock_res_and_lock(lock);

	/* checking lvb_ready is racy but this is okay. The worst case is
	 * that multi processes may configure the file on the same time.
	 */
	if (lvb_ready) {
		rc = 0;
		goto out;
	}

	rc = ll_layout_fetch(inode, lock);
	if (rc < 0)
		goto out;

	/* for layout lock, lmm is returned in lock's lvb.
	 * lvb_data is immutable if the lock is held so it's safe to access it
	 * without res lock.
	 *
	 * set layout to file. Unlikely this will fail as old layout was
	 * surely eliminated
	 */
	memset(&conf, 0, sizeof(conf));
	conf.coc_opc = OBJECT_CONF_SET;
	conf.coc_inode = inode;
	conf.coc_lock = lock;
	conf.u.coc_layout.lb_buf = lock->l_lvb_data;
	conf.u.coc_layout.lb_len = lock->l_lvb_len;
	rc = ll_layout_conf(inode, &conf);

	/* refresh layout failed, need to wait */
	wait_layout = rc == -EBUSY;
out:
	LDLM_LOCK_PUT(lock);
	ldlm_lock_decref(lockh, mode);

	/* wait for IO to complete if it's still being used. */
	if (wait_layout) {
		CDEBUG(D_INODE, "%s: " DFID "(%p) wait for layout reconf\n",
		       sbi->ll_fsname, PFID(&lli->lli_fid), inode);

		memset(&conf, 0, sizeof(conf));
		conf.coc_opc = OBJECT_CONF_WAIT;
		conf.coc_inode = inode;
		rc = ll_layout_conf(inode, &conf);
		if (rc == 0)
			rc = -EAGAIN;

		CDEBUG(D_INODE,
		       "%s: file=" DFID " waiting layout return: %d.\n",
		       sbi->ll_fsname, PFID(&lli->lli_fid), rc);
	}
	return rc;
}

/**
 * Issue layout intent RPC to MDS.
 * @inode	file inode
 * @intent	layout intent
 *
 * Returns:	0 on success
 *		< 0 error code
 */
static int ll_layout_intent(struct inode *inode, struct layout_intent *intent)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	struct lookup_intent it;
	struct ptlrpc_request *req;
	int rc;

	op_data = ll_prep_md_op_data(NULL, inode, inode, NULL,
				     0, 0, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	op_data->op_data = intent;
	op_data->op_data_size = sizeof(*intent);

	memset(&it, 0, sizeof(it));
	it.it_op = IT_LAYOUT;
	if (intent->li_opc == LAYOUT_INTENT_WRITE ||
	    intent->li_opc == LAYOUT_INTENT_TRUNC)
		it.it_flags = FMODE_WRITE;

	LDLM_DEBUG_NOLOCK("%s: requeue layout lock for file " DFID "(%p)",
			  sbi->ll_fsname, PFID(&lli->lli_fid), inode);

	rc = md_intent_lock(sbi->ll_md_exp, op_data, &it, &req,
			    &ll_md_blocking_ast, 0);
	ptlrpc_req_finished(it.it_request);
	it.it_request = NULL;

	ll_finish_md_op_data(op_data);

	/* set lock data in case this is a new lock */
	if (!rc)
		ll_set_lock_data(sbi->ll_md_exp, inode, &it, NULL);

	ll_intent_drop_lock(&it);

	return rc;
}

/**
 * This function checks if there exists a LAYOUT lock on the client side,
 * or enqueues it if it doesn't have one in cache.
 *
 * This function will not hold layout lock so it may be revoked any time after
 * this function returns. Any operations depend on layout should be redone
 * in that case.
 *
 * This function should be called before lov_io_init() to get an uptodate
 * layout version, the caller should save the version number and after IO
 * is finished, this function should be called again to verify that layout
 * is not changed during IO time.
 */
int ll_layout_refresh(struct inode *inode, u32 *gen)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct layout_intent intent = {
		.li_opc = LAYOUT_INTENT_ACCESS,
	};
	struct lustre_handle lockh;
	enum ldlm_mode mode;
	int rc;

	*gen = ll_layout_version_get(lli);
	if (!(sbi->ll_flags & LL_SBI_LAYOUT_LOCK) || *gen != CL_LAYOUT_GEN_NONE)
		return 0;

	/* sanity checks */
	LASSERT(fid_is_sane(ll_inode2fid(inode)));
	LASSERT(S_ISREG(inode->i_mode));

	/* take layout lock mutex to enqueue layout lock exclusively. */
	mutex_lock(&lli->lli_layout_mutex);

	while (1) {
		/* mostly layout lock is caching on the local side, so try to
		 * match it before grabbing layout lock mutex.
		 */
		mode = ll_take_md_lock(inode, MDS_INODELOCK_LAYOUT, &lockh, 0,
				       LCK_CR | LCK_CW | LCK_PR |
				       LCK_PW | LCK_EX);
		if (mode != 0) { /* hit cached lock */
			rc = ll_layout_lock_set(&lockh, mode, inode);
			if (rc == -EAGAIN)
				continue;
			break;
		}

		rc = ll_layout_intent(inode, &intent);
		if (rc != 0)
			break;
	}

	if (rc == 0)
		*gen = ll_layout_version_get(lli);
	mutex_unlock(&lli->lli_layout_mutex);

	return rc;
}

/**
 * Issue layout intent RPC indicating where in a file an IO is about to write.
 *
 * @inode:	file inode.
 * @ext:	write range with start offset of fille in bytes where
 *		an IO is about to write, and exclusive end offset in
 *		bytes.
 *
 * Returns:	0 on success
 *		< 0 error code
 */
int ll_layout_write_intent(struct inode *inode, enum layout_intent_opc opc,
			   struct lu_extent *ext)
{
	struct layout_intent intent = {
		.li_opc = opc,
		.li_extent.e_start = ext->e_start,
		.li_extent.e_end = ext->e_end,
	};

	return ll_layout_intent(inode, &intent);
}

/**
 *  This function send a restore request to the MDT
 */
int ll_layout_restore(struct inode *inode, loff_t offset, u64 length)
{
	struct hsm_user_request	*hur;
	int len, rc;

	len = sizeof(struct hsm_user_request) +
	      sizeof(struct hsm_user_item);
	hur = kzalloc(len, GFP_NOFS);
	if (!hur)
		return -ENOMEM;

	hur->hur_request.hr_action = HUA_RESTORE;
	hur->hur_request.hr_archive_id = 0;
	hur->hur_request.hr_flags = 0;
	memcpy(&hur->hur_user_item[0].hui_fid, &ll_i2info(inode)->lli_fid,
	       sizeof(hur->hur_user_item[0].hui_fid));
	hur->hur_user_item[0].hui_extent.offset = offset;
	hur->hur_user_item[0].hui_extent.length = length;
	hur->hur_request.hr_itemcount = 1;
	rc = obd_iocontrol(LL_IOC_HSM_REQUEST, ll_i2sbi(inode)->ll_md_exp,
			   len, hur, NULL);
	kfree(hur);
	return rc;
}
