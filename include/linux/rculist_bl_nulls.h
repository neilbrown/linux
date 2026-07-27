/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RCULIST_BL_NULLS_H
#define _LINUX_RCULIST_BL_NULLS_H

#include <linux/list_bl.h>
#include <linux/rculist_bl.h>
#include <linux/list_nulls.h>
#include <linux/rcupdate.h>

struct hlist_bl_nulls_head {
	struct hlist_nulls_node *first;
};

static inline struct hlist_nulls_node *hlist_bl_nulls_first(
	struct hlist_bl_nulls_head *h, struct hlist_nulls_node *nulls)
{
	struct hlist_nulls_node *ret =
		(struct hlist_nulls_node *)
		((unsigned long)h->first & ~LIST_BL_LOCKMASK);

	if (ret)
		return ret;
	else
		return nulls;
}

static inline void hlist_bl_nulls_lock(struct hlist_bl_nulls_head *b)
	__acquires(__bitlock(0, b))
{
	bit_spin_lock(0, (unsigned long *)b);
}

static inline void hlist_bl_nulls_unlock(struct hlist_bl_nulls_head *b)
	__releases(__bitlock(0, b))
{
	__bit_spin_unlock(0, (unsigned long *)b);
}

static inline void hlist_bl_nulls_lock_add_head(
	struct hlist_nulls_node *n,
	struct hlist_bl_nulls_head *h,
	struct hlist_nulls_node *nulls)
{
	struct hlist_nulls_node *first;

	hlist_bl_nulls_lock(h);
	/* don't need hlist_bl_first_rcu* because we're under lock */
	first = hlist_bl_nulls_first(h, nulls);
	n->next = first;
	if (!is_a_nulls(first))
		first->pprev = &n->next;
	n->pprev = &h->first;

	/*
	 * need _rcu because we can have concurrent lock free readers.
	 * This assignment unlocks the chain.
	 */
	rcu_assign_pointer(hlist_bl_first_rcu(h), n);
	preempt_enable();
	__release(__bitlock(0, &h->first));
}

static inline void hlist_bl_nulls_lock_del(struct hlist_nulls_node *n,
					   struct hlist_bl_nulls_head *h)
{
	hlist_bl_nulls_lock(h);
	if (hlist_bl_nulls_first(h, NULL) != n) {
		__hlist_nulls_del(n);
		hlist_bl_nulls_unlock(h);
	} else {
		/*
		 * n in first thing on list, update head
		 * and unlock in one operation.
		 */
		if (is_a_nulls(n->next))
			smp_store_release(&h->first, NULL);
		else
			smp_store_release(&h->first, n->next);
		preempt_enable();
		__release(__bitlock(0, &h->first));
	}
}

#define hlist_nulls_for_each_entry_from_rcu(tpos, pos, member)	\
	for (; !is_a_nulls(pos) &&				\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = rcu_dereference_raw(pos->next))

#endif /* _LINUX_RCULIST_BL_NULLS_H */
