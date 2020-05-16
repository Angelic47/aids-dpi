#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/tcp.h>
#include "packageinfo.h"
#include "connhash.h"
#include "appidmatch.h"
#include "connlist.h"

static struct kmem_cache *aids_cache_connhash __read_mostly;

struct hlist_head g_aids_connhtable[AIDS_CONNHASH_SIZE] __read_mostly;

spinlock_t g_aids_connhtable_spinlock[AIDS_CONNHASH_SIZE] __read_mostly;

void inline aids_process_connection(struct tcphdr *tcp_header, aids_connlist_entry *new_entry)
{
	if(new_entry->conn_info.protocol != IPPROTO_TCP)
	{
		new_entry->conn_info.conn_status = AIDS_CONNECTION_UNTRACK;
		return;
	}
	switch(new_entry->conn_info.conn_status)
	{
		case AIDS_CONNECTION_UNTRACK:
			if(tcp_header->syn)
			{
				new_entry->conn_info.tcp_seq = ntohl(tcp_header->seq);
				new_entry->conn_info.conn_status = AIDS_CONNECTION_SYN_SENT;
			}
			break;
		case AIDS_CONNECTION_SYN_SENT:
			if(tcp_header->syn && tcp_header->ack && ntohl(tcp_header->ack_seq) == new_entry->conn_info.tcp_seq + 1)
			{
				new_entry->conn_info.tcp_ack_seq = ntohl(tcp_header->seq);
				new_entry->conn_info.conn_status = AIDS_CONNECTION_SYN_RECV;
			}
			break;
		case AIDS_CONNECTION_SYN_RECV:
			if(tcp_header->ack && ntohl(tcp_header->seq) == new_entry->conn_info.tcp_seq + 1 && ntohl(tcp_header->ack_seq) == new_entry->conn_info.tcp_ack_seq + 1)
			{
				new_entry->conn_info.conn_status = AIDS_CONNECTION_ESTABLISHED;
			}
			break;
		case AIDS_CONNECTION_ESTABLISHED:
			if(tcp_header->fin)
			{
				new_entry->conn_info.tcp_seq = ntohl(tcp_header->seq);
				new_entry->conn_info.conn_status = AIDS_CONNECTION_FIN_1;
			}
			break;
		case AIDS_CONNECTION_FIN_1:
			if(tcp_header->ack && ntohl(tcp_header->ack_seq) == new_entry->conn_info.tcp_seq + 1)
			{
				new_entry->conn_info.conn_status = AIDS_CONNECTION_FIN_2;
				if(!(tcp_header->fin))
					break;
			}
			else
				break;
		case AIDS_CONNECTION_FIN_2:
			if(tcp_header->fin)
			{
				new_entry->conn_info.tcp_seq = ntohl(tcp_header->seq);
				new_entry->conn_info.conn_status = AIDS_CONNECTION_FIN_3;
			}
			break;
		case AIDS_CONNECTION_FIN_3:
			if(tcp_header->ack && ntohl(tcp_header->ack_seq) == new_entry->conn_info.tcp_seq + 1)
			{
				new_entry->conn_info.conn_status = AIDS_CONNECTION_CLOSED;
			}
			break;
	}
}

u16 inline adis_connhash_gethash(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	unsigned long long hash_temp = (max(saddr, daddr) - min(saddr, daddr))*(65535 - max(sport, dport) + min(sport, dport));
	unsigned char* temp = (unsigned char*)&hash_temp;
	temp[0] = temp[0] ^ temp[1] ^ temp[2];
	temp[1] = temp[3] ^ temp[4] ^ temp[5];
	temp[1] = ((temp[1] & 240) >> 4) ^ (temp[1] & 15);
	return *(u16*)temp;
}

static void inline aids_connhash_add(aids_connhash_entry* entry, u16 hash)
{
	hlist_add_head(&entry->node, &g_aids_connhtable[hash]);
}

void aids_connhash_delete(
	u32 saddr,
	u32 daddr,
	u16 sport,
	u16 dport,
	u8 protocol,
	u8 sync
)
{
	u16 hash = adis_connhash_gethash(saddr, daddr, sport, dport);
	aids_connhash_entry* entry;
	aids_connlist_entry* listentry = NULL;
	unsigned long flags;
	
	spin_lock_irqsave(&g_aids_connhtable_spinlock[hash], flags);
	
	hlist_for_each_entry(entry, &g_aids_connhtable[hash], node)
	{
		if(entry->saddr == saddr && entry->daddr == daddr && entry->sport == sport && entry->dport == dport && entry->protocol == protocol)
		{
			listentry = entry->connlist_entry;
			hash_del(&entry->node);
			kmem_cache_free(aids_cache_connhash, entry);
			break;
		}
	}
	
	if(sync && listentry)
	{
		spin_lock(&g_connlist_spinlock);
		aids_connlist_delete_sync(listentry, 0);
		spin_unlock(&g_connlist_spinlock);
	}
	
	spin_unlock_irqrestore(&g_aids_connhtable_spinlock[hash], flags);
}

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
)
{
	unsigned char found = 0;
	u16 hash = adis_connhash_gethash(saddr, daddr, sport, dport);
	aids_connhash_entry* entry;
	unsigned long flags;
	
	local_irq_save(flags);
	spin_lock(&g_connlist_spinlock);
	spin_lock(&g_aids_connhtable_spinlock[hash]);

	aids_connlist_entry* connlist_entry;
	aids_connlist_entry* new_entry;
	hlist_for_each_entry(entry, &g_aids_connhtable[hash], node)
	{
		if(entry->saddr == saddr && entry->daddr == daddr && entry->sport == sport && entry->dport == dport && entry->protocol == protocol)
		{
			*out_dir = ORIGINAL;
			found = 1;
			break;
		}
		if(entry->daddr == saddr && entry->saddr == daddr && entry->dport == sport && entry->sport == dport && entry->protocol == protocol)
		{
			*out_dir = REPLY;
			found = 1;
			break;
		}
	}
	if (found)
	{
		connlist_entry = rcu_dereference(entry->connlist_entry);
		if (connlist_entry != NULL)
		{
			new_entry = kmem_cache_zalloc(aids_cache_connlist, GFP_ATOMIC);
			if (new_entry == NULL)
			{
				spin_unlock(&g_connlist_spinlock);
				spin_unlock(&g_aids_connhtable_spinlock[hash]);
				pr_warning("[AngelIDS][DPI] Memory full at aids_connhash_query_or_new() : 1\n");
				local_irq_restore(flags);
				return NULL;
			}
			*new_entry = *connlist_entry;
			new_entry->conn_info.timeout = AIDS_CONNECTION_TIMEOUT;
			new_entry->conn_info.ctinfo = ctinfo;
			aids_connlist_move_tail(connlist_entry, new_entry);
			entry->connlist_entry = new_entry;
			rcu_read_lock();
			connlist_entry = rcu_dereference(new_entry);
		}
		spin_unlock(&g_connlist_spinlock);
	}
	else
	{
		*out_dir = ORIGINAL;
		entry = kmem_cache_zalloc(aids_cache_connhash, GFP_ATOMIC);
		if(!entry)
		{
			spin_unlock(&g_connlist_spinlock);
			spin_unlock(&g_aids_connhtable_spinlock[hash]);
			local_irq_restore(flags);
			return NULL;
		}
		entry->saddr = saddr;
		entry->daddr = daddr;
		entry->sport = sport;
		entry->dport = dport;
		entry->protocol = protocol;
		entry->connlist_entry = aids_connlist_new(saddr, daddr, sport, dport, ctinfo, protocol, 0, direct, 0);
		spin_unlock(&g_connlist_spinlock);
		if(!entry->connlist_entry)
		{
			kmem_cache_free(aids_cache_connhash, entry);
			spin_unlock(&g_aids_connhtable_spinlock[hash]);
			local_irq_restore(flags);
			return NULL;
		}
		
		aids_connhash_add(entry, hash);
		rcu_read_lock();
		connlist_entry = rcu_dereference(entry->connlist_entry);
	}

	spin_unlock(&g_aids_connhtable_spinlock[hash]);
	local_irq_restore(flags);

	if (connlist_entry != NULL)
	{
		new_entry = kmem_cache_zalloc(aids_cache_connlist, GFP_ATOMIC);
		if (new_entry == NULL)
		{
			pr_warning("[AngelIDS][DPI] Memory full at aids_connhash_query_or_new() : 2\n");
			rcu_read_unlock();
			return NULL;
		}
		*new_entry = *connlist_entry;
		rcu_read_unlock();

		aids_process_connection(tcp_header, new_entry);
		
		if((new_entry->conn_info.protocol == IPPROTO_TCP && new_entry->conn_info.conn_status == AIDS_CONNECTION_ESTABLISHED) || (new_entry->conn_info.protocol != IPPROTO_TCP))
		{
			if (user_data_length && new_entry->conn_info.pkt_count < 255)
				new_entry->conn_info.pkt_count += 1;
			
			if (new_entry->conn_info.appid == 0 && new_entry->conn_info.pkt_count <= 7)
			{
				struct aids_package_info *package_info;
				u32 appid_ans;
				package_info = kmem_cache_zalloc(aids_cache_packageinfo, GFP_ATOMIC);
				if (package_info == NULL)
				{
					pr_warning("[AngelIDS][DPI] Memory full when restoring packageinfo\n");
					appid_ans = 0;
				}
				else
				{
					package_info->port = dport;
					package_info->data = user_data_length ? user_data : NULL;
					package_info->length = user_data_length;
					package_info->dir = *out_dir;
					package_info->proto = new_entry->conn_info.protocol; // todo: udp
					package_info->dst_addr = ntohl(daddr);
					package_info->pkt_seq = new_entry->conn_info.pkt_count;

					appid_ans = aids_get_app_id(package_info);
					new_entry->conn_info.appid = appid_ans;
					if(package_info->is_http)
						new_entry->conn_info.is_http = package_info->is_http;
				}
				aids_package_info_cleanup(package_info);
			}
		}

		spin_lock_irqsave(&g_connlist_spinlock, flags);
		
		if(new_entry->conn_info.conn_status == AIDS_CONNECTION_CLOSED)
		{
			new_entry->conn_info.timeout = AIDS_CONNECTION_TIMEOUT_IMM;
			aids_connlist_move_head(entry->connlist_entry, new_entry);
			entry->connlist_entry = new_entry;
		}
		else
		{
			list_replace_rcu(&entry->connlist_entry->link, &new_entry->link);
			call_rcu(&entry->connlist_entry->rcu, aids_free_connlist);
			entry->connlist_entry = new_entry;
		}
		spin_unlock_irqrestore(&g_connlist_spinlock, flags);
	}
	else
		rcu_read_unlock();
	return entry->connlist_entry;
}

static void aids_connhash_delete_all(void)
{
	u16 hash = 0;
	aids_connhash_entry* entry;
	aids_connlist_entry* listentry = NULL;
	
	for(hash = 0; hash < AIDS_CONNHASH_SIZE; hash ++) {
		spin_lock(&g_aids_connhtable_spinlock[hash]);
		hlist_for_each_entry(entry, &g_aids_connhtable[hash], node)
		{
			listentry = entry->connlist_entry;
			hash_del(&entry->node);
			kmem_cache_free(aids_cache_connhash, entry);
			spin_lock(&g_connlist_spinlock);
			aids_connlist_delete_sync(listentry, 0);
			spin_unlock(&g_connlist_spinlock);
		}
		spin_unlock(&g_aids_connhtable_spinlock[hash]);
	}
}

int aids_connhash_init(void)
{
	aids_cache_connhash = kmem_cache_create("aids_connhash", sizeof(aids_connhash_entry), 0, 0, NULL);
	if(!aids_cache_connhash)
	{
		pr_err("[AngelIDS][DPI] Failed to kmem_cache_create aids_cache_connhash\n");
		return -ENOMEM;
	}
	unsigned int i;
	for (i = 0; i < AIDS_CONNHASH_SIZE; i++) {
		INIT_HLIST_HEAD(&g_aids_connhtable[i]);
		spin_lock_init(&g_aids_connhtable_spinlock[i]);
	}
	return 0;
}

void aids_connhash_deinit(void)
{
	if(aids_cache_connhash) {
		aids_connhash_delete_all();
		kmem_cache_destroy(aids_cache_connhash);
	}
}
