/* SPDX-License-Identifier: GPL-2.0
 *
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
 * Copyright (c) 2019, 2020, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_CRYPTO_H_
#define _LUSTRE_CRYPTO_H_

struct ll_sb_info;
int ll_set_encflags(struct inode *inode, void *encctx, u32 encctxlen,
		    bool preload);
void llcrypt_free_ctx(void *encctx);
bool ll_sbi_has_test_dummy_encryption(struct ll_sb_info *sbi);
bool ll_sbi_has_encrypt(struct ll_sb_info *sbi);
void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set);

#define __FS_HAS_ENCRYPTION 1
#include <linux/fscrypt.h>

#endif /* _LUSTRE_CRYPTO_H_ */
