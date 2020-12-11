/*
 * GPL HEADER START
 *
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

#ifndef _LUSTRE_WAIT_H
#define _LUSTRE_WAIT_H

/*
 * prepare_to_wait_event() does not support an exclusive
 * lifo wait.
 * However it will not relink the wait_queue_entry if
 * it is already linked.  So we link to the head of the
 * queue here, and it will stay there.
 */
static inline void prepare_to_wait_exclusive_head(
	wait_queue_head_t *waitq, wait_queue_entry_t *link)
{
	unsigned long flags;

	spin_lock_irqsave(&(waitq->lock), flags);
	if (list_empty(&link->entry))
		__add_wait_queue_exclusive(waitq, link);
	spin_unlock_irqrestore(&((waitq)->lock), flags);
}

#ifndef TASK_NOLOAD
#define __wait_event_idle_exclusive_timeout_cmd(wq_head, condition,	\
						timeout, cmd1, cmd2)	\
	___wait_event_idle(wq_head, ___wait_cond_timeout(condition),	\
			   1, timeout,					\
			   cmd1; __ret = schedule_timeout(__ret); cmd2)

#define wait_event_idle_exclusive_timeout_cmd(wq_head, condition, timeout,\
					      cmd1, cmd2)		\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_idle_exclusive_timeout_cmd(	\
			wq_head, condition, timeout, cmd1, cmd2);	\
	__ret;								\
})
#else /* ! TASK_NOLOAD */
#ifndef wait_event_idle_exclusive_timeout_cmd
#define __wait_event_idle_exclusive_timeout_cmd(wq_head, condition,	\
						timeout, cmd1, cmd2)	\
	___wait_event(wq_head, ___wait_cond_timeout(condition),	\
		      TASK_IDLE, 1, timeout,				\
		      cmd1; __ret = schedule_timeout(__ret); cmd2)

#define wait_event_idle_exclusive_timeout_cmd(wq_head, condition, timeout,\
					      cmd1, cmd2)		\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_idle_exclusive_timeout_cmd(	\
			wq_head, condition, timeout, cmd1, cmd2);	\
	__ret;								\
})
#endif
#endif

/* ___wait_event_lifo is used for lifo exclusive 'idle' waits */
#ifdef TASK_NOLOAD

#define ___wait_event_lifo(wq_head, condition, ret, cmd)		\
({									\
	wait_queue_entry_t	 __wq_entry;				\
	long __ret = ret;	/* explicit shadow */			\
									\
	init_wait(&__wq_entry);						\
	__wq_entry.flags =  WQ_FLAG_EXCLUSIVE;				\
	for (;;) {							\
		prepare_to_wait_exclusive_head(&wq_head, &__wq_entry);	\
		prepare_to_wait_event(&wq_head, &__wq_entry, TASK_IDLE);\
									\
		if (condition)						\
			break;						\
									\
		cmd;							\
	}								\
	finish_wait(&wq_head, &__wq_entry);				\
	__ret;								\
})
#else
#define ___wait_event_lifo(wq_head, condition, ret, cmd)		\
({									\
	wait_queue_entry_t __wq_entry;					\
	unsigned long flags;						\
	long __ret = ret;	/* explicit shadow */			\
	sigset_t __old_blocked, __new_blocked;				\
									\
	siginitset(&__new_blocked, LUSTRE_FATAL_SIGS);			\
	sigprocmask(0, &__new_blocked, &__old_blocked);			\
	init_wait(&__wq_entry);						\
	__wq_entry.flags = WQ_FLAG_EXCLUSIVE;				\
	for (;;) {							\
		prepare_to_wait_exclusive_head(&wq_head, &__wq_entry);	\
		prepare_to_wait_event(&wq_head, &__wq_entry,		\
				      TASK_INTERRUPTIBLE);		\
									\
		if (condition)						\
			break;						\
		/* See justification in ___wait_event_idle */		\
		if (signal_pending(current)) {				\
			spin_lock_irqsave(&current->sighand->siglock,	\
					  flags);			\
			clear_tsk_thread_flag(current, TIF_SIGPENDING);	\
			spin_unlock_irqrestore(&current->sighand->siglock,\
					       flags);			\
		}							\
		cmd;							\
	}								\
	sigprocmask(SIG_SETMASK, &__old_blocked, NULL);			\
	finish_wait(&wq_head, &__wq_entry);				\
	__ret;								\
})
#endif

#define wait_event_idle_exclusive_lifo(wq_head, condition)		\
do {									\
	might_sleep();							\
	if (!(condition))						\
		___wait_event_lifo(wq_head, condition, 0, schedule());	\
} while (0)

#define __wait_event_idle_lifo_timeout(wq_head, condition, timeout)	\
	___wait_event_lifo(wq_head, ___wait_cond_timeout(condition),	\
			   timeout,					\
			   __ret = schedule_timeout(__ret))

#define wait_event_idle_exclusive_lifo_timeout(wq_head, condition, timeout)\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_idle_lifo_timeout(wq_head,		\
						       condition,	\
						       timeout);	\
	__ret;								\
})

/* l_wait_event_abortable() is a bit like wait_event_killable()
 * except there is a fixed set of signals which will abort:
 * LUSTRE_FATAL_SIGS
 */
#define LUSTRE_FATAL_SIGS					 \
	(sigmask(SIGKILL) | sigmask(SIGINT) | sigmask(SIGTERM) | \
	 sigmask(SIGQUIT) | sigmask(SIGALRM))

#define l_wait_event_abortable(wq, condition)				\
({									\
	sigset_t __new_blocked, __old_blocked;				\
	int __ret = 0;							\
	siginitsetinv(&__new_blocked, LUSTRE_FATAL_SIGS);		\
	sigprocmask(SIG_BLOCK, &__new_blocked, &__old_blocked);		\
	__ret = wait_event_interruptible(wq, condition);		\
	sigprocmask(SIG_SETMASK, &__old_blocked, NULL);			\
	__ret;								\
})

#define l_wait_event_abortable_timeout(wq, condition, timeout)		\
({									\
	sigset_t __new_blocked, __old_blocked;				\
	int __ret = 0;							\
	siginitsetinv(&__new_blocked, LUSTRE_FATAL_SIGS);		\
	sigprocmask(SIG_BLOCK, &__new_blocked, &__old_blocked);		\
	__ret = wait_event_interruptible_timeout(wq, condition, timeout);\
	sigprocmask(SIG_SETMASK, &__old_blocked, NULL);			\
	__ret;								\
})

#define l_wait_event_abortable_exclusive(wq, condition)			\
({									\
	sigset_t __new_blocked, __old_blocked;				\
	int __ret = 0;							\
	siginitsetinv(&__new_blocked, LUSTRE_FATAL_SIGS);		\
	sigprocmask(SIG_BLOCK, &__new_blocked, &__old_blocked);		\
	__ret = wait_event_interruptible_exclusive(wq, condition);	\
	sigprocmask(SIG_SETMASK, &__old_blocked, NULL);			\
	__ret;								\
})
#endif /* _LUSTRE_WAIT_H */
