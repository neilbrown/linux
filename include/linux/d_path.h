/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_D_PATH_H
#define __LINUX_D_PATH_H

struct prepend_buffer {
	char *buf;
	int len;
	bool matched;
	int retries; /* remaining retries.  On zero, take locks */
	int lastlen; /* The previous length that we hope to match */
};
#define DECLARE_PREPEND_BUFFER(__name, __buf, __len)			\
	struct prepend_buffer __name = {.buf = __buf + __len,		\
					.len = __len, .retries = 8 }

static inline void d_prepend_restart(struct prepend_buffer *b,
				     char *buf, int len)
{
	/* Ensure we get the newest data */
	smp_rmb();

	b->lastlen = b->len;
	b->buf = buf;
	b->len = len;
	b->matched = true; /* Assume a match until proven otherwise */
	b->retries--;
	if (b->retries == 0)
		read_seqlock_excl(&rename_lock);
	else
		rcu_read_lock();
}

static inline bool d_prepend_done(struct prepend_buffer *b)
{
	if (b->retries == 0)
		read_sequnlock_excl(&rename_lock);
	else
		rcu_read_unlock();
	if (b->len != b->lastlen)
		b->matched = false;
	return b->matched || b->retries == 0;
}

static inline char *d_extract_string(struct prepend_buffer *p)
{
	if (likely(p->len >= 0))
		return p->buf;
	return ERR_PTR(-ENAMETOOLONG);
}

bool d_prepend(struct prepend_buffer *p, const char *str, int namelen);
bool d_prepend_name(struct prepend_buffer *p, const struct dentry *d);

#endif /* __LINUX_D_PATH_H */
