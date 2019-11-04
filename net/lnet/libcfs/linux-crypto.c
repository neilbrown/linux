// SPDX-License-Identifier: GPL-2.0
/* GPL HEADER START
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
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * Please  visit http://www.xyratex.com/contact if you need additional
 * information or have any questions.
 *
 * GPL HEADER END
 */

/*
 * Copyright 2012 Xyratex Technology Limited
 *
 * Copyright (c) 2012, Intel Corporation.
 */

#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/libcfs/libcfs_crypto.h>
#include <linux/libcfs/libcfs.h>
#include "linux-crypto.h"

/**
 *  Array of hash algorithm speed in MByte per second
 */
static int cfs_crypto_hash_speeds[CFS_HASH_ALG_MAX];

/**
 * Initialize the state descriptor for the specified hash algorithm.
 *
 * An internal routine to allocate the hash-specific state in @req for
 * use with cfs_crypto_hash_digest() to compute the hash of a single message,
 * though possibly in multiple chunks.  The descriptor internal state should
 * be freed with cfs_crypto_hash_final().
 *
 * @hash_alg	hash algorithm id (CFS_HASH_ALG_*)
 * @type	pointer to the hash description in hash_types[]
 *		array
 * @req		hash state descriptor to be initialized
 * @key		initial hash value/state, NULL to use default
 *		value
 * @key_len	length of @key
 *
 * Return	0 on success
 *		negative errno on failure
 */
static int cfs_crypto_hash_alloc(enum cfs_crypto_hash_alg hash_alg,
				 const struct cfs_crypto_hash_type **type,
				 struct ahash_request **req,
				 unsigned char *key,
				 unsigned int key_len)
{
	struct crypto_ahash *tfm;
	int err = 0;

	*type = cfs_crypto_hash_type(hash_alg);
	if (!*type) {
		CWARN("Unsupported hash algorithm id = %d, max id is %d\n",
		      hash_alg, CFS_HASH_ALG_MAX);
		return -EINVAL;
	}

	/* Keys are only supported for the hmac version */
	if (key && key_len > 0) {
		char *algo_name;

		algo_name = kasprintf(GFP_KERNEL, "hmac(%s)",
				      (*type)->cht_name);
		if (!algo_name)
			return -ENOMEM;

		tfm = crypto_alloc_ahash(algo_name, 0, CRYPTO_ALG_ASYNC);
		kfree(algo_name);
	} else {
		tfm = crypto_alloc_ahash((*type)->cht_name, 0,
					 CRYPTO_ALG_ASYNC);
	}
	if (IS_ERR(tfm)) {
		CDEBUG(D_INFO, "Failed to alloc crypto hash %s\n",
		       (*type)->cht_name);
		return PTR_ERR(tfm);
	}

	*req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!*req) {
		CDEBUG(D_INFO, "Failed to alloc ahash_request for %s\n",
		       (*type)->cht_name);
		err = -ENOMEM;
		goto out_free_tfm;
	}

	ahash_request_set_callback(*req, 0, NULL, NULL);

	if (key)
		err = crypto_ahash_setkey(tfm, key, key_len);
	else if ((*type)->cht_key)
		err = crypto_ahash_setkey(tfm,
					  (unsigned char *)&((*type)->cht_key),
					  (*type)->cht_size);
	if (err)
		goto out_free_req;

	CDEBUG(D_INFO, "Using crypto hash: %s (%s) speed %d MB/s\n",
	       crypto_ahash_alg_name(tfm), crypto_ahash_driver_name(tfm),
	       cfs_crypto_hash_speeds[hash_alg]);

	err = crypto_ahash_init(*req);
	if (err) {
out_free_req:
		ahash_request_free(*req);
out_free_tfm:
		crypto_free_ahash(tfm);
	}
	return err;
}

/**
 * Calculate hash digest for the passed buffer.
 *
 * This should be used when computing the hash on a single contiguous buffer.
 * It combines the hash initialization, computation, and cleanup.
 *
 * @hash_alg	id of hash algorithm (CFS_HASH_ALG_*)
 * @buf		data buffer on which to compute hash
 * @buf_len	length of @buf in bytes
 * @key		initial value/state for algorithm,
 *		if @key = NULL use default initial value
 * @key_len	length of @key in bytes
 * @hash	pointer to computed hash value,
 *		if @hash = NULL then @hash_len is to digest
 *		size in bytes, returns -ENOSPC
 * @hash_len	size of @hash buffer
 *
 * Return:
 *	-EINVAL		@buf, @buf_len, @hash_len,
 *			@hash_alg invalid
 *	-ENOENT		@hash_alg is unsupported
 *	-ENOSPC		@hash is NULL, or @hash_len less than
 *			digest size
 *	0 for success
 *	negative errno for other errors from lower layers.
 */
int cfs_crypto_hash_digest(enum cfs_crypto_hash_alg hash_alg,
			   const void *buf, unsigned int buf_len,
			   unsigned char *key, unsigned int key_len,
			   unsigned char *hash, unsigned int *hash_len)
{
	struct scatterlist sl;
	struct ahash_request *req;
	int err;
	const struct cfs_crypto_hash_type *type;

	if (!buf || !buf_len || !hash_len)
		return -EINVAL;

	err = cfs_crypto_hash_alloc(hash_alg, &type, &req, key, key_len);
	if (err)
		return err;

	if (!hash || *hash_len < type->cht_size) {
		*hash_len = type->cht_size;
		crypto_free_ahash(crypto_ahash_reqtfm(req));
		ahash_request_free(req);
		return -ENOSPC;
	}
	sg_init_one(&sl, buf, buf_len);

	ahash_request_set_crypt(req, &sl, hash, sl.length);
	err = crypto_ahash_digest(req);
	crypto_free_ahash(crypto_ahash_reqtfm(req));
	ahash_request_free(req);

	return err;
}
EXPORT_SYMBOL(cfs_crypto_hash_digest);

/**
 * Allocate and initialize descriptor for hash algorithm.
 *
 * This should be used to initialize a hash descriptor for multiple calls
 * to a single hash function when computing the hash across multiple
 * separate buffers or pages using cfs_crypto_hash_update{,_page}().
 *
 * The hash descriptor should be freed with cfs_crypto_hash_final().
 *
 * @hash_alg	algorithm id (CFS_HASH_ALG_*)
 * @key		initial value/state for algorithm, if @key = NULL
 *		use default initial value
 * @key_len	length of @key in bytes
 *
 * Return:	pointer to descriptor of hash instance
 *		ERR_PTR(errno) in case of error
 */
struct ahash_request *
cfs_crypto_hash_init(enum cfs_crypto_hash_alg hash_alg,
		     unsigned char *key, unsigned int key_len)
{
	struct ahash_request *req;
	int err;
	const struct cfs_crypto_hash_type *type;

	err = cfs_crypto_hash_alloc(hash_alg, &type, &req, key, key_len);
	if (err)
		return ERR_PTR(err);
	return req;
}
EXPORT_SYMBOL(cfs_crypto_hash_init);

/**
 * Update hash digest computed on data within the given @page
 *
 * @hreq	hash state descriptor
 * @page	data page on which to compute the hash
 * @offset	offset within @page at which to start hash
 * @len		length of data on which to compute hash
 *
 * Return:	0 for success
 *		negative errno on failure
 */
int cfs_crypto_hash_update_page(struct ahash_request *req,
				struct page *page, unsigned int offset,
				unsigned int len)
{
	struct scatterlist sl;

	sg_init_table(&sl, 1);
	sg_set_page(&sl, page, len, offset & ~PAGE_MASK);

	ahash_request_set_crypt(req, &sl, NULL, sl.length);
	return crypto_ahash_update(req);
}
EXPORT_SYMBOL(cfs_crypto_hash_update_page);

/**
 * Update hash digest computed on the specified data
 *
 * @req		hash state descriptor
 * @buf		data buffer on which to compute the hash
 * @buf_len	length of @buf on which to compute hash
 *
 * Return:	0 for success
 *		negative errno on failure
 */
int cfs_crypto_hash_update(struct ahash_request *req,
			   const void *buf, unsigned int buf_len)
{
	struct scatterlist sl;

	sg_init_one(&sl, buf, buf_len);

	ahash_request_set_crypt(req, &sl, NULL, sl.length);
	return crypto_ahash_update(req);
}
EXPORT_SYMBOL(cfs_crypto_hash_update);

/**
 * Finish hash calculation, copy hash digest to buffer, clean up hash descriptor
 *
 * @req		hash descriptor
 * @hash	pointer to hash buffer to store hash digest
 * @hash_len	pointer to hash buffer size, if @req = NULL
 *		only free @req instead of computing the hash
 *
 * Return:
 *		0 for success
 *		-EOVERFLOW if hash_len is too small for the hash digest
 *		negative errno for other errors from lower layers
 */
int cfs_crypto_hash_final(struct ahash_request *req,
			  unsigned char *hash, unsigned int *hash_len)
{
	int err;
	int size = crypto_ahash_digestsize(crypto_ahash_reqtfm(req));

	if (!hash || !hash_len) {
		err = 0;
		goto free_ahash;
	}
	if (*hash_len < size) {
		err = -EOVERFLOW;
		goto free_ahash;
	}

	ahash_request_set_crypt(req, NULL, hash, 0);
	err = crypto_ahash_final(req);
	if (!err)
		*hash_len = size;
free_ahash:
	crypto_free_ahash(crypto_ahash_reqtfm(req));
	ahash_request_free(req);
	return err;
}
EXPORT_SYMBOL(cfs_crypto_hash_final);

/**
 * Compute the speed of specified hash function
 *
 * Run a speed test on the given hash algorithm on buffer using a 1MB buffer
 * size.  This is a reasonable buffer size for Lustre RPCs, even if the actual
 * RPC size is larger or smaller.
 *
 * The speed is stored internally in the cfs_crypto_hash_speeds[] array, and
 * is available through the cfs_crypto_hash_speed() function.
 *
 * This function needs to stay the same as obd_t10_performance_test() so that
 * the speeds are comparable.
 *
 * @hash_alg	hash algorithm id (CFS_HASH_ALG_*)
 * @buf		data buffer on which to compute the hash
 * @buf_len	length of @buf on which to compute hash
 */
static void cfs_crypto_performance_test(enum cfs_crypto_hash_alg hash_alg)
{
	int buf_len = max(PAGE_SIZE, 1048576UL);
	void *buf;
	unsigned long start, end;
	unsigned long bcount;
	int err = 0;
	struct page *page;
	unsigned char hash[CFS_CRYPTO_HASH_DIGESTSIZE_MAX];
	unsigned int hash_len = sizeof(hash);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		err = -ENOMEM;
		goto out_err;
	}

	buf = kmap(page);
	memset(buf, 0xAD, PAGE_SIZE);
	kunmap(page);

	for (start = jiffies, end = start + HZ / 4,
	     bcount = 0; time_before(jiffies, end) && err == 0; bcount++) {
		struct ahash_request *hdesc;
		int i;

		hdesc = cfs_crypto_hash_init(hash_alg, NULL, 0);
		if (IS_ERR(hdesc)) {
			err = PTR_ERR(hdesc);
			break;
		}

		for (i = 0; i < buf_len / PAGE_SIZE; i++) {
			err = cfs_crypto_hash_update_page(hdesc, page, 0,
							  PAGE_SIZE);
			if (err)
				break;
		}

		err = cfs_crypto_hash_final(hdesc, hash, &hash_len);
		if (err)
			break;
	}
	end = jiffies;
	__free_page(page);
out_err:
	if (err) {
		cfs_crypto_hash_speeds[hash_alg] = err;
		CDEBUG(D_INFO, "Crypto hash algorithm %s test error: rc = %d\n",
		       cfs_crypto_hash_name(hash_alg), err);
	} else {
		unsigned long tmp;

		tmp = ((bcount * buf_len / jiffies_to_msecs(end - start)) *
		       1000) / (1024 * 1024);
		cfs_crypto_hash_speeds[hash_alg] = (int)tmp;
		CDEBUG(D_CONFIG, "Crypto hash algorithm %s speed = %d MB/s\n",
		       cfs_crypto_hash_name(hash_alg),
		       cfs_crypto_hash_speeds[hash_alg]);
	}
}

/**
 * hash speed in Mbytes per second for valid hash algorithm
 *
 * Return the performance of the specified @hash_alg that was
 * computed using cfs_crypto_performance_test().  If the performance
 * has not yet been computed, do that when it is first requested.
 * That avoids computing the speed when it is not actually needed.
 * To avoid competing threads computing the checksum speed at the
 * same time, only compute a single checksum speed at one time.
 *
 * @hash_alg	hash algorithm id (CFS_HASH_ALG_*)
 *
 * Return:	positive speed of the hash function in MB/s
 *		-ENOENT if @hash_alg is unsupported
 *		negative errno if @hash_alg speed is unavailable
 */
int cfs_crypto_hash_speed(enum cfs_crypto_hash_alg hash_alg)
{
	if (hash_alg < CFS_HASH_ALG_MAX) {
		if (unlikely(cfs_crypto_hash_speeds[hash_alg] == 0)) {
			static DEFINE_MUTEX(crypto_hash_speed_mutex);

			mutex_lock(&crypto_hash_speed_mutex);
			if (cfs_crypto_hash_speeds[hash_alg] == 0)
				cfs_crypto_performance_test(hash_alg);
			mutex_unlock(&crypto_hash_speed_mutex);
		}
		return cfs_crypto_hash_speeds[hash_alg];
	}
	return -ENOENT;
}
EXPORT_SYMBOL(cfs_crypto_hash_speed);

/**
 * Run the performance test for all hash algorithms.
 *
 * Run the cfs_crypto_performance_test() benchmark for all of the available
 * hash functions using a 1MB buffer size.  This is a reasonable buffer size
 * for Lustre RPCs, even if the actual RPC size is larger or smaller.
 *
 * Since the setup cost and computation speed of various hash algorithms is
 * a function of the buffer size (and possibly internal contention of offload
 * engines), this speed only represents an estimate of the actual speed under
 * actual usage, but is reasonable for comparing available algorithms.
 *
 * The actual speeds are available via cfs_crypto_hash_speed() for later
 * comparison.
 *
 * Return:	0 on success
 *		-ENOMEM if no memory is available for test buffer
 */
static int cfs_crypto_test_hashes(void)
{
	enum cfs_crypto_hash_alg hash_alg;

	for (hash_alg = 0; hash_alg < CFS_HASH_ALG_SPEED_MAX; hash_alg++)
		cfs_crypto_performance_test(hash_alg);

	return 0;
}

static int adler32;

/**
 * Register available hash functions
 *
 * Return:	0
 */
int cfs_crypto_register(void)
{
	request_module("crc32c");

	if (cfs_crypto_adler32_register() == 0)
		adler32 = 1;

	/* check all algorithms and do performance test */
	cfs_crypto_test_hashes();
	return 0;
}

/**
 * Unregister previously registered hash functions
 */
void cfs_crypto_unregister(void)
{
	if (adler32)
		cfs_crypto_adler32_unregister();
	adler32 = 0;
}
