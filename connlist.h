#ifndef AIDS_CONNLIST_H
#define AIDS_CONNLIST_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/jiffies.h>
#include "aids.h"

struct __aids_connlist_entry {
    struct list_head link;
    struct rcu_head rcu;
    struct aids_connection_info conn_info;
};
#define aids_connlist_entry struct __aids_connlist_entry

extern spinlock_t g_connlist_spinlock;
extern struct kmem_cache *aids_cache_connlist __read_mostly;

extern struct list_head g_aids_connlist_head;

void aids_connlist_move_head(aids_connlist_entry *entry, aids_connlist_entry *new_entry);

void aids_connlist_move_tail(aids_connlist_entry *entry, aids_connlist_entry *new_entry);

aids_connlist_entry* aids_connlist_next(struct list_head *connlist);

unsigned int aids_connlist_get_count(void);

aids_connlist_entry* aids_connlist_new(
	u32 saddr,
	u32 daddr,
	u16 sport,
	u16 dport,
	enum ip_conntrack_info ctinfo,
	u8 protocol,
	u32 appid,
	enum aids_connection_direct direct,
	u8 pkt_count
);

void aids_connlist_delete_sync(aids_connlist_entry* entry, u8 sync);

int aids_connlist_init(void);

void aids_connlist_deinit(void);

#endif
