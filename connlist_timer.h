#ifndef AIDS_CONNLIST_TIMER_H
#define AIDS_CONNLIST_TIMER_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

#define AIDS_CONNLIST_TIMEOUT_CHECK_MS (1000 * 10)
#define AIDS_CONNLIST_TIMEOUT_CHECK (jiffies + msecs_to_jiffies(AIDS_CONNLIST_TIMEOUT_CHECK_MS))

extern struct timer_list aids_connlist_timer;

int aids_connlist_timer_init(void);

void aids_connlist_timer_deinit(void);

#endif
