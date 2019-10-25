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
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/lu_tgt_descs.c
 *
 * Lustre target descriptions
 * These are the only exported functions, they provide some generic
 * infrastructure for target description management used by LOD/LMV
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/list.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lu_object.h>

/**
 * Allocate and initialize target table.
 *
 * A helper function to initialize the target table and allocate
 * a bitmap of the available targets.
 *
 * \param[in] ltd		target's table to initialize
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
int lu_tgt_descs_init(struct lu_tgt_descs *ltd)
{
	mutex_init(&ltd->ltd_mutex);
	init_rwsem(&ltd->ltd_rw_sem);

	/*
	 * the tgt array and bitmap are allocated/grown dynamically as tgts are
	 * added to the LOD/LMV, see lu_tgt_descs_add()
	 */
	ltd->ltd_tgt_bitmap = bitmap_zalloc(BITS_PER_LONG, GFP_NOFS);
	if (!ltd->ltd_tgt_bitmap)
		return -ENOMEM;

	ltd->ltd_tgts_size  = BITS_PER_LONG;
	ltd->ltd_tgtnr      = 0;

	ltd->ltd_death_row = 0;
	ltd->ltd_refcount  = 0;

	return 0;
}
EXPORT_SYMBOL(lu_tgt_descs_init);

/**
 * Free bitmap and target table pages.
 *
 * \param[in] ltd	target table
 */
void lu_tgt_descs_fini(struct lu_tgt_descs *ltd)
{
	int i;

	bitmap_free(ltd->ltd_tgt_bitmap);
	for (i = 0; i < TGT_PTRS; i++)
		kfree(ltd->ltd_tgt_idx[i]);
	ltd->ltd_tgts_size = 0;
}
EXPORT_SYMBOL(lu_tgt_descs_fini);

/**
 * Expand size of target table.
 *
 * When the target table is full, we have to extend the table. To do so,
 * we allocate new memory with some reserve, move data from the old table
 * to the new one and release memory consumed by the old table.
 *
 * \param[in] ltd		target table
 * \param[in] newsize		new size of the table
 *
 * \retval			0 on success
 * \retval			-ENOMEM if reallocation failed
 */
static int lu_tgt_descs_resize(struct lu_tgt_descs *ltd, u32 newsize)
{
	unsigned long *new_bitmap, *old_bitmap = NULL;

	/* someone else has already resize the array */
	if (newsize <= ltd->ltd_tgts_size)
		return 0;

	new_bitmap = bitmap_zalloc(newsize, GFP_NOFS);
	if (!new_bitmap)
		return -ENOMEM;

	if (ltd->ltd_tgts_size > 0) {
		/* the bitmap already exists, copy data from old one */
		bitmap_copy(new_bitmap, ltd->ltd_tgt_bitmap,
			    ltd->ltd_tgts_size);
		old_bitmap = ltd->ltd_tgt_bitmap;
	}

	ltd->ltd_tgts_size  = newsize;
	ltd->ltd_tgt_bitmap = new_bitmap;

	bitmap_free(old_bitmap);

	CDEBUG(D_CONFIG, "tgt size: %d\n", ltd->ltd_tgts_size);

	return 0;
}

/**
 * Add new target to target table.
 *
 * Extend target table if it's full, update target table and bitmap.
 * Notice we need to take ltd_rw_sem exclusively before entry to ensure
 * atomic switch.
 *
 * \param[in] ltd		target table
 * \param[in] tgt		new target desc
 *
 * \retval			0 on success
 * \retval			-ENOMEM if reallocation failed
 *				-EEXIST if target existed
 */
int lu_tgt_descs_add(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt)
{
	u32 index = tgt->ltd_index;
	int rc;

	if (index >= ltd->ltd_tgts_size) {
		u32 newsize = 1;

		while (newsize < index + 1)
			newsize = newsize << 1;

		rc = lu_tgt_descs_resize(ltd, newsize);
		if (rc)
			return rc;
	} else if (test_bit(index, ltd->ltd_tgt_bitmap)) {
		return -EEXIST;
	}

	if (ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] == NULL) {
		ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] =
			kzalloc(sizeof(*ltd->ltd_tgt_idx[0]), GFP_NOFS);
		if (ltd->ltd_tgt_idx[index / TGT_PTRS_PER_BLOCK] == NULL)
			return -ENOMEM;
	}

	LTD_TGT(ltd, tgt->ltd_index) = tgt;
	set_bit(tgt->ltd_index, ltd->ltd_tgt_bitmap);
	ltd->ltd_tgtnr++;

	return 0;
}
EXPORT_SYMBOL(lu_tgt_descs_add);

/**
 * Delete target from target table
 */
void lu_tgt_descs_del(struct lu_tgt_descs *ltd, struct lu_tgt_desc *tgt)
{
	LTD_TGT(ltd, tgt->ltd_index) = NULL;
	clear_bit(tgt->ltd_index, ltd->ltd_tgt_bitmap);
	ltd->ltd_tgtnr--;
}
EXPORT_SYMBOL(lu_tgt_descs_del);
