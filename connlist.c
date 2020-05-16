#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <linux/list.h>
#include "aids.h"
#include "connlist.h"
#include "connhash.h"

struct kmem_cache *aids_cache_connlist __read_mostly;

DEFINE_SPINLOCK(g_connlist_spinlock);

struct list_head g_aids_connlist_head = LIST_HEAD_INIT(g_aids_connlist_head);

void aids_connlist_move_head(aids_connlist_entry *entry, aids_connlist_entry *new_entry)
{
	list_del_rcu(&entry->link);
	call_rcu(&entry->rcu, aids_free_connlist);
	list_add_rcu(&new_entry->link, &g_aids_connlist_head);
}

void aids_connlist_move_tail(aids_connlist_entry *entry, aids_connlist_entry *new_entry)
{
	list_del_rcu(&entry->link);
	call_rcu(&entry->rcu, aids_free_connlist);
	list_add_tail_rcu(&new_entry->link, &g_aids_connlist_head);
}

static void inline adis_connlist_addtail(aids_connlist_entry *entry)
{
	list_add_tail_rcu(&entry->link, &g_aids_connlist_head);
}

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
)
{
	aids_connlist_entry *entry;
	entry = kmem_cache_zalloc(aids_cache_connlist, GFP_ATOMIC);
	if(!entry)
		return NULL;
	
	entry->conn_info.begintime = ktime_get_real();
	entry->conn_info.timeout = AIDS_CONNECTION_TIMEOUT;
	entry->conn_info.saddr = saddr;
	entry->conn_info.daddr = daddr;
	entry->conn_info.sport = sport;
	entry->conn_info.dport = dport;
	entry->conn_info.ctinfo = ctinfo;
	entry->conn_info.protocol = protocol;
	entry->conn_info.appid = appid;
	entry->conn_info.direct = direct;
	entry->conn_info.pkt_count = pkt_count;
	entry->conn_info.timeout = AIDS_CONNECTION_TIMEOUT;
	entry->conn_info.conn_status = AIDS_CONNECTION_UNTRACK;
	entry->conn_info.tcp_seq = 0;
	entry->conn_info.tcp_ack_seq = 0;
	entry->conn_info.is_http = 0;
	
	adis_connlist_addtail(entry);
	
	return entry;
}

void aids_free_connlist(struct rcu_head *head)
{
	aids_connlist_entry *entry = container_of(head, aids_connlist_entry, rcu);
	kmem_cache_free(aids_cache_connlist, entry);
}

unsigned int aids_connlist_get_count(void)
{
	unsigned int count = 0;
	aids_connlist_entry* entry;
	
	rcu_read_lock();
	list_for_each_entry_rcu(entry, &g_aids_connlist_head, link) {
		count += 1;
	}
	rcu_read_unlock();
	
	return count;
}

aids_connlist_entry* aids_connlist_next(struct list_head *connlist)
{
	aids_connlist_entry* entry;
	entry = list_entry_rcu((connlist)->next, typeof(*entry), link);
	if(&entry->link == &g_aids_connlist_head)
	{
		return NULL;
	}
	return entry;
}

void aids_connlist_emptyall(void)
{
	aids_connlist_entry* entry;
	
	rcu_read_lock();
	spin_lock(&g_connlist_spinlock);
	list_for_each_entry_rcu(entry, &g_aids_connlist_head, link) {
		aids_connlist_delete_sync(entry, 1);
	}
	spin_unlock(&g_connlist_spinlock);
	rcu_read_unlock();
}

int aids_connlist_init(void)
{
	aids_cache_connlist = kmem_cache_create("aids_connlist", sizeof(aids_connlist_entry), 0, 0, NULL);
	if(!aids_cache_connlist)
	{
		pr_err("[AngelIDS][DPI] Failed to kmem_cache_create aids_cache_connlist\n");
		return -ENOMEM;
	}
	return 0;
}

void aids_connlist_delete_sync(aids_connlist_entry* entry, u8 sync)
{
	if(sync)
		aids_connhash_delete(entry->conn_info.saddr, entry->conn_info.daddr, entry->conn_info.sport, entry->conn_info.dport, entry->conn_info.protocol, 0);
	
	list_del_rcu(&entry->link);
	call_rcu(&entry->rcu, aids_free_connlist);
}

void aids_connlist_deinit(void)
{
	if(aids_cache_connlist) {
		aids_connlist_emptyall();
		kmem_cache_destroy(aids_cache_connlist);
	}
}
