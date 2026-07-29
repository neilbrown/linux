/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/prefetch.h>
#include <linux/d_path.h>
#include "mount.h"
#include "internal.h"

static bool prepend_char(struct prepend_buffer *p, unsigned char c)
{
	if (likely(p->len > 0)) {
		if (p->matched && p->buf[-1] != c)
			p->matched = false;
		p->len--;
		*--p->buf = c;
		return true;
	}
	p->len = -1;
	return false;
}

/*
 * The source of the prepend data can be an optimistic load
 * of a dentry name and length. And because we don't hold any
 * locks, the length and the pointer to the name may not be
 * in sync if a concurrent rename happens, and the kernel
 * copy might fault as a result.
 *
 * The end result will correct itself when we check the
 * rename sequence count, but we need to be able to handle
 * the fault gracefully.
 */
static bool prepend_copy(void *dst, const void *src, int len)
{
	if (unlikely(copy_from_kernel_nofault(dst, src, len))) {
		memset(dst, 'x', len);
		return false;
	}
	return true;
}

static bool prepend_str(struct prepend_buffer *p, const char *str, int len)
{
	/*
	 * We know this string fits.  We might need to check if it matches
	 * the existing content.  If so we use prepend_copy() to a temp
	 * buffer and compare that to the prepend_buffer.
	 */
	char b[32];
	int start = 0;

	while (p->matched && start < len) {
		int clen = len - start;

		if (clen > sizeof(b))
			clen = sizeof(b);
		if (!prepend_copy(b, str+start, clen)) {
			p->matched = false;
			memset(p->buf, len, 'x');
			return false;
		}
		if (memcmp(p->buf + start, b, clen) != 0) {
			p->matched = false;
			memcpy(p->buf + start, b, clen);
		}
		start += clen;
	}
	if (start == len)
		return true;
	/* No check needed for the rest */
	return prepend_copy(p->buf + start, str + start, len - start);
}

bool d_prepend(struct prepend_buffer *p, const char *str, int namelen)
{
	// Already overflowed?
	if (p->len < 0)
		return false;

	// Will overflow?
	if (p->len < namelen) {
		// Fill as much as possible from the end of the name
		str += namelen - p->len;
		p->buf -= p->len;
		prepend_str(p, str, p->len);
		p->len = -1;
		return false;
	}

	// Fits fully
	p->len -= namelen;
	p->buf -= namelen;
	return prepend_str(p, str, namelen);
}
EXPORT_SYMBOL(d_prepend);

/**
 * d_prepend_name - prepend a pathname in front of current buffer pointer
 * @p: prepend buffer which contains buffer pointer and allocated length
 * @dentry: dentry which has the name.
 *
 * With RCU path tracing, it may race with d_move(). Use READ_ONCE() to
 * make sure that either the old or the new name pointer and length are
 * fetched. However, there may be mismatch between length and pointer.
 * But since the length cannot be trusted, we need to copy the name very
 * carefully when doing the prepend_copy(). It also prepends "/" at
 * the beginning of the name. Caller will retry until two consecutive runs
 * produce the same result. So any garbage in the buffer due to
 * mismatched pointer and length will be discarded.
 *
 * On the final attempt we use take_dentry_name_snapshot() to ensure
 * we don't get garbage.
 *
 * Load acquire is needed to make sure that we see the new name data even
 * if we might get the length wrong.
 */
bool d_prepend_name(struct prepend_buffer *p, const struct dentry *d)
{
	if (p->retries > 0) {
		const char *dname = smp_load_acquire(&d->d_name.name); /* ^^^ */
		u32 dlen = READ_ONCE(d->d_name.len);

		return d_prepend(p, dname, dlen) && prepend_char(p, '/');
	} else {
		struct name_snapshot ss;
		bool ret;

		take_dentry_name_snapshot(&ss, d);
		ret = d_prepend(p, ss.name.name, ss.name.len) &&
			prepend_char(p, '/');
		release_dentry_name_snapshot(&ss);
		return ret;
	}
}
EXPORT_SYMBOL(d_prepend_name);

static int __prepend_path(const struct dentry *dentry, const struct mount *mnt,
			  const struct path *root, struct prepend_buffer *p)
{
	while (dentry != root->dentry || &mnt->mnt != root->mnt) {
		const struct dentry *parent = READ_ONCE(dentry->d_parent);

		if (dentry == mnt->mnt.mnt_root) {
			struct mount *m = READ_ONCE(mnt->mnt_parent);
			struct mnt_namespace *mnt_ns;

			if (likely(mnt != m)) {
				dentry = READ_ONCE(mnt->mnt_mountpoint);
				mnt = m;
				continue;
			}
			/* Global root */
			mnt_ns = READ_ONCE(mnt->mnt_ns);
			/* open-coded is_mounted() to use local mnt_ns */
			if (!IS_ERR_OR_NULL(mnt_ns) && !is_anon_ns(mnt_ns))
				return 1;	// absolute root
			else
				return 2;	// detached or not attached yet
		}

		if (unlikely(dentry == parent))
			/* Escaped? */
			return 3;

		prefetch(parent);
		if (!d_prepend_name(p, dentry))
			break;
		dentry = parent;
	}
	return 0;
}

/**
 * prepend_path - Prepend path string to a buffer
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry
 * @p: prepend buffer which contains buffer pointer and allocated length
 *
 * The function will first try to write out the pathname without taking
 * any lock other than the RCU read lock to make sure that dentries
 * won't go away.  The path is generated twice and checked to be sure it
 * hasn't changed.  This will ensure we don't race with a rename of an
 * ancestor.  At most 8 attempts are made: if we cannot get a match in
 * that time anything we return won't be reliable anyway.  On the last
 * attempt we get exclusive read locks on mount_lock and rename_lock,
 * and use take_dentry_name_snapshot() to make the final path as sane as
 * possible.
 */
static int prepend_path(const struct path *path,
			const struct path *root,
			struct prepend_buffer *p)
{
	struct prepend_buffer b = *p;
	int error;

	do {
		/*
		 * restart/done helpers don't use mount_lock,
		 * and we must take it first - while retries is still 1.
		 */
		if (b.retries == 1)
			read_seqlock_excl(&mount_lock);
		d_prepend_restart(&b, p->buf, p->len);
		error = __prepend_path(path->dentry, real_mount(path->mnt),
				       root, &b);
		if (b.retries == 0)
			read_sequnlock_excl(&mount_lock);
	} while (!d_prepend_done(&b));

	if (unlikely(error == 3))
		b = *p;

	if (b.len == p->len)
		prepend_char(&b, '/');

	*p = b;
	return error;
}

/**
 * __d_path - return the path of a dentry
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name.
 *
 * Returns a pointer into the buffer or an error code if the
 * path was too long.
 *
 * "buflen" should be positive.
 *
 * If the path is not reachable from the supplied root, return %NULL.
 */
char *__d_path(const struct path *path,
	       const struct path *root,
	       char *buf, int buflen)
{
	DECLARE_PREPEND_BUFFER(b, buf, buflen);

	prepend_char(&b, 0);
	if (unlikely(prepend_path(path, root, &b) > 0))
		return NULL;
	return d_extract_string(&b);
}

char *d_absolute_path(const struct path *path,
	       char *buf, int buflen)
{
	struct path root = {};
	DECLARE_PREPEND_BUFFER(b, buf, buflen);

	prepend_char(&b, 0);
	if (unlikely(prepend_path(path, &root, &b) > 1))
		return ERR_PTR(-EINVAL);
	return d_extract_string(&b);
}

static void get_fs_root_rcu(struct fs_struct *fs, struct path *root)
{
	unsigned seq;

	do {
		seq = read_seqbegin(&fs->seq);
		*root = fs->root;
	} while (read_seqretry(&fs->seq, seq));
}

/**
 * d_path - return the path of a dentry
 * @path: path to report
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns a pointer into the buffer or an error code if the path was
 * too long. Note: Callers should use the returned pointer, not the passed
 * in buffer, to use the name! The implementation often starts at an offset
 * into the buffer, and may leave 0 bytes at the start.
 *
 * "buflen" should be positive.
 */
char *d_path(const struct path *path, char *buf, int buflen)
{
	DECLARE_PREPEND_BUFFER(b, buf, buflen);
	struct path root;

	/*
	 * We have various synthetic filesystems that never get mounted.  On
	 * these filesystems dentries are never used for lookup purposes, and
	 * thus don't need to be hashed.  They also don't need a name until a
	 * user wants to identify the object in /proc/pid/fd/.  The little hack
	 * below allows us to generate a name for these objects on demand:
	 *
	 * Some pseudo inodes are mountable.  When they are mounted
	 * path->dentry == path->mnt->mnt_root.  In that case don't call d_dname
	 * and instead have d_path return the mounted path.
	 */
	if (path->dentry->d_op && path->dentry->d_op->d_dname &&
	    (!IS_ROOT(path->dentry) || path->dentry != path->mnt->mnt_root ||
	     failfs_mnt(path->mnt)))
		return path->dentry->d_op->d_dname(path->dentry, buf, buflen);

	rcu_read_lock();
	get_fs_root_rcu(current->fs, &root);
	if (unlikely(d_unlinked(path->dentry)))
		d_prepend(&b, " (deleted)", 11);
	else
		prepend_char(&b, 0);
	prepend_path(path, &root, &b);
	rcu_read_unlock();

	return d_extract_string(&b);
}
EXPORT_SYMBOL(d_path);

/*
 * Helper function for dentry_operations.d_dname() members
 */
char *dynamic_dname(char *buffer, int buflen, const char *fmt, ...)
{
	va_list args;
	char *start;
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(buffer, buflen, fmt, args) + 1;
	va_end(args);

	if (sz > NAME_MAX || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	/* Move the formatted d_name to the end of the buffer. */
	start = buffer + (buflen - sz);
	return memmove(start, buffer, sz);
}

char *simple_dname(struct dentry *dentry, char *buffer, int buflen)
{
	DECLARE_PREPEND_BUFFER(b, buffer, buflen);
	/* these dentries are never renamed, so d_lock is not needed */
	d_prepend(&b, " (deleted)", 11);
	d_prepend(&b, dentry->d_name.name, dentry->d_name.len);
	prepend_char(&b, '/');
	return d_extract_string(&b);
}

/*
 * Write full pathname from the root of the filesystem into the buffer.
 */
static char *__dentry_path(const struct dentry *d, struct prepend_buffer *p)
{
	const struct dentry *dentry;
	struct prepend_buffer b = *p;

	do {
		dentry = d;
		d_prepend_restart(&b, p->buf, p->len);
		while (!IS_ROOT(dentry)) {
			const struct dentry *parent = dentry->d_parent;

			prefetch(parent);
			if (!d_prepend_name(&b, dentry))
				break;
			dentry = parent;
		}
		if (b.len == p->len)
			/* empty path... */
			prepend_char(&b, '/');
	} while (!d_prepend_done(&b));

	return d_extract_string(&b);
}

char *dentry_path_raw(const struct dentry *dentry, char *buf, int buflen)
{
	DECLARE_PREPEND_BUFFER(b, buf, buflen);

	prepend_char(&b, 0);
	return __dentry_path(dentry, &b);
}
EXPORT_SYMBOL(dentry_path_raw);

char *dentry_path(const struct dentry *dentry, char *buf, int buflen)
{
	DECLARE_PREPEND_BUFFER(b, buf, buflen);

	if (unlikely(d_unlinked(dentry)))
		d_prepend(&b, "//deleted", 10);
	else
		prepend_char(&b, 0);
	return __dentry_path(dentry, &b);
}

static void get_fs_root_and_pwd_rcu(struct fs_struct *fs, struct path *root,
				    struct path *pwd)
{
	unsigned seq;

	do {
		seq = read_seqbegin(&fs->seq);
		*root = fs->root;
		*pwd = fs->pwd;
	} while (read_seqretry(&fs->seq, seq));
}

/*
 * NOTE! The user-level library version returns a
 * character pointer. The kernel system call just
 * returns the length of the buffer filled (which
 * includes the ending '\0' character), or a negative
 * error value. So libc would do something like
 *
 *	char *getcwd(char * buf, size_t size)
 *	{
 *		int retval;
 *
 *		retval = sys_getcwd(buf, size);
 *		if (retval >= 0)
 *			return buf;
 *		errno = -retval;
 *		return NULL;
 *	}
 */
SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
	int error;
	struct path pwd, root;
	char *page = __getname();

	if (!page)
		return -ENOMEM;

	rcu_read_lock();
	get_fs_root_and_pwd_rcu(current->fs, &root, &pwd);

	if (unlikely(d_unlinked(pwd.dentry))) {
		rcu_read_unlock();
		error = -ENOENT;
	} else {
		unsigned len;
		DECLARE_PREPEND_BUFFER(b, page, PATH_MAX);

		prepend_char(&b, 0);
		if (unlikely(prepend_path(&pwd, &root, &b) > 0))
			d_prepend(&b, "(unreachable)", 13);
		rcu_read_unlock();

		len = PATH_MAX - b.len;
		if (unlikely(len > PATH_MAX))
			error = -ENAMETOOLONG;
		else if (unlikely(len > size))
			error = -ERANGE;
		else if (copy_to_user(buf, b.buf, len))
			error = -EFAULT;
		else
			error = len;
	}
	__putname(page);
	return error;
}
