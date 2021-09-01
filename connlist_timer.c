#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include "connlist.h"
#include "connlist_timer.h"

struct timer_list aids_connlist_timer;

/// Evsio0n <cs@nexet.hk>
/// init_timer() is deprecated for linux version >= 4.15 
/// ref:https://lwn.net/Articles/735887/
/// Using timer_setup() returned timerlist.
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
static void aids_connlist_timer_func(unsigned long arg)
{
#else
static void aids_connlist_timer_func(struct timer_list *arg)
{
#endif
	aids_connlist_entry* entry;
	unsigned long flags;
	spin_lock_irqsave(&g_connlist_spinlock, flags);
	rcu_read_lock();
	list_for_each_entry_rcu(entry, &g_aids_connlist_head, link) {
		if(!time_after64(jiffies_64, entry->conn_info.timeout))
			break;
		aids_connlist_delete_sync(entry, 1);
	}
	rcu_read_unlock();
	spin_unlock_irqrestore(&g_connlist_spinlock, flags);
	
	aids_connlist_timer.expires = AIDS_CONNLIST_TIMEOUT_CHECK;
	add_timer(&aids_connlist_timer);
}

/// Using timer_setup() instead
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
int aids_connlist_timer_init(void)
{
	init_timer(&aids_connlist_timer);
	aids_connlist_timer.function = &aids_connlist_timer_func;
	aids_connlist_timer.data = 0;
	aids_connlist_timer.expires = AIDS_CONNLIST_TIMEOUT_CHECK;
	add_timer(&aids_connlist_timer);
	return 0;
}
#else
int aids_connlist_timer_init(void)
{
	timer_setup(&aids_connlist_timer,aids_connlist_timer_func,0);
	aids_connlist_timer.expires = AIDS_CONNLIST_TIMEOUT_CHECK;
	add_timer(&aids_connlist_timer);
	return 0;
}
#endif

void aids_connlist_timer_deinit(void)
{
	del_timer(&aids_connlist_timer);
}
