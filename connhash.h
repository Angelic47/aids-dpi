#ifndef AIDS_CONNHASH_H
#define AIDS_CONNHASH_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include "connlist.h"
#include "packageinfo.h"

#define AIDS_CONNHASH_SIZE 4096

struct __aids_connhash_entry {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u8 protocol;
    aids_connlist_entry* connlist_entry;
	struct hlist_node node;
};
#define aids_connhash_entry struct __aids_connhash_entry

extern struct hlist_head g_aids_connhtable[AIDS_CONNHASH_SIZE] __read_mostly;
extern spinlock_t g_aids_connhtable_spinlock[AIDS_CONNHASH_SIZE] __read_mostly;

aids_connlist_entry* aids_connhash_query_or_new(
	u32 saddr,
	u32 daddr,
	u16 sport,
	u16 dport,
	enum ip_conntrack_info ctinfo,
	u8 protocol,
	enum aids_connection_direct direct,
	enum DIR *out_dir,
	unsigned char *user_data,
	u64 user_data_length,
	struct tcphdr *tcp_header
);

void aids_connhash_delete(
	u32 saddr,
	u32 daddr,
	u16 sport,
	u16 dport,
	u8 protocol,
	u8 sync
);

int aids_connhash_init(void);

void aids_connhash_deinit(void);

void aids_free_connlist(struct rcu_head *head);

#endif
