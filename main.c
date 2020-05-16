#include "kernel_ver.h"
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include "connhash.h"
#include "connlist.h"
#include "proc.h"
#include "aids.h"
#include "packageinfo.h"
#include "appidmatch.h"
#include "connlist_timer.h"

static unsigned int aids_hookfunc_preroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st);
static unsigned int aids_hookfunc_postroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st);

static struct nf_hook_ops g_hook_preroute = {
	.hook = aids_hookfunc_preroute,
	.hooknum = NF_INET_PRE_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_LAST,
};

static struct nf_hook_ops g_hook_postroute = {
	.hook = aids_hookfunc_postroute,
	.hooknum = NF_INET_POST_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_LAST,
};

static int app_data_offset(const struct sk_buff *skb)
{
	int ip_hl = 4*ip_hdr(skb)->ihl;

	if( ip_hdr(skb)->protocol == IPPROTO_TCP ) {
		int tcp_hl = 4*(skb->data[ip_hl + 12] >> 4);

		return ip_hl + tcp_hl;
	} else if( ip_hdr(skb)->protocol == IPPROTO_UDP  ) {
		return ip_hl + 8;
	} else if( ip_hdr(skb)->protocol == IPPROTO_ICMP ) {
		return ip_hl + 8;
	} else {
		pr_warning("[AngelIDS][DPI] app_data_offset: unknown protocol()\n");
		return ip_hl + 8;
	}
}

unsigned int aids_hookfunc_execute(struct sk_buff* skb, enum aids_skb_direct direct)
{
	struct iphdr *ip_header = ip_hdr(skb);
	
	unsigned char *user_data = NULL;
	u64 user_data_length = 0;
	
	struct tcphdr *tcp_header = NULL;
	
	struct udphdr *udp_header = NULL;
	
	u16 sourcePort = 0;
	u16 destPort = 0;

	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	
	enum DIR packet_dir;
	
	skb_linearize(skb);
	
	if(skb->cb[20] == 1)
		return NF_ACCEPT;
	
	skb->cb[20] = 1;
	
	if (ip_header->protocol == IPPROTO_TCP)
	{
		tcp_header = (struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4));
		user_data = skb->data + app_data_offset(skb);
		user_data_length = skb_tail_pointer(skb) - user_data;
		sourcePort = ntohs(tcp_header->source);
		destPort = ntohs(tcp_header->dest);
	}
	else if(ip_header->protocol == IPPROTO_UDP)
	{
		udp_header = (struct udphdr*)((char*)ip_header + (ip_header->ihl * 4));
		user_data = skb->data + app_data_offset(skb);
		user_data_length = skb_tail_pointer(skb) - user_data;
		sourcePort = ntohs(udp_header->source);
		destPort = ntohs(udp_header->dest);
	}
	else
	{
		return NF_ACCEPT;
	}
	
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;
	
	aids_connlist_entry* connlist_entry = aids_connhash_query_or_new(
		ip_header->saddr,
		ip_header->daddr,
		sourcePort,
		destPort,
		ctinfo,
		ip_header->protocol,
		direct,
		&packet_dir,
		user_data,
		user_data_length,
		ip_header->protocol == IPPROTO_TCP ? tcp_header : NULL
	);
	rcu_read_lock();
	connlist_entry = rcu_dereference(connlist_entry);
	if (connlist_entry == NULL)
	{
		pr_warning("[AngelIDS][DPI] Memory full at aids_connhash_query_or_new()\n");
		rcu_read_unlock();
		return NF_ACCEPT;
	}
	rcu_read_unlock();
	
	return NF_ACCEPT;
}

static unsigned int aids_hookfunc_preroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st)
{
	return aids_hookfunc_execute(skb, AIDS_SKB_PREROUTE);
}

static unsigned int aids_hookfunc_postroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st)
{
	return aids_hookfunc_execute(skb, AIDS_SKB_POSTROUTE);
}

int aids_init_netfilter_hook(void)
{
	int status;
	pr_info("[AngelIDS][DPI] Registering g_hook_preroute\n");
	#ifdef AIDS_OLDER_KERNEL
	if(status = nf_register_hook(&g_hook_preroute))
	#else
	if(status = nf_register_net_hook(&init_net, &g_hook_preroute))
	#endif
	{
		pr_warning("[AngelIDS][DPI] Registering g_hook_preroute failed with code %d\n", status);
		return status;
	}
	pr_info("[AngelIDS][DPI] g_hook_preroute hook success\n");
	pr_info("[AngelIDS][DPI] Registering g_hook_postroute\n");
	#ifdef AIDS_OLDER_KERNEL
	if(status = nf_register_hook(&g_hook_postroute))
	#else
	if(status = nf_register_net_hook(&init_net, &g_hook_postroute))
	#endif
	{
		#ifdef AIDS_OLDER_KERNEL
		nf_unregister_hook(&g_hook_preroute);
		#else
		nf_unregister_net_hook(&init_net, &g_hook_preroute);
		#endif
		pr_warning("[AngelIDS][DPI] Registering g_hook_postroute failed with code %d\n", status);
		return status;
	}
	pr_info("[AngelIDS][DPI] g_hook_postroute hook success\n");
	return 0;
}

void aids_init_netfilter_unhook(void)
{
	pr_info("[AngelIDS][DPI] Unregisting hook\n");
	#ifdef AIDS_OLDER_KERNEL
	nf_unregister_hook(&g_hook_preroute);
	#else
	nf_unregister_net_hook(&init_net, &g_hook_preroute);
	#endif
	pr_info("[AngelIDS][DPI] g_hook_preroute unhook success\n");
	#ifdef AIDS_OLDER_KERNEL
	nf_unregister_hook(&g_hook_postroute);
	#else
	nf_unregister_net_hook(&init_net, &g_hook_postroute);
	#endif
	pr_info("[AngelIDS][DPI] g_hook_postroute unhook success\n");
}

static int __init aids_module_init(void)
{
	pr_info("AngelIDS - Deep Packet Inspection\n");
	if(aids_connlist_init())
	{
		pr_err("[AngelIDS][DPI] aids_connlist_init failed\n");
		return -ENOMEM;
	}
	if(aids_connhash_init())
	{
		pr_err("[AngelIDS][DPI] aids_connhash_init failed\n");
		aids_connlist_deinit();
		return -ENOMEM;
	}
	if(proc_init())
	{
		pr_err("[AngelIDS][DPI] proc_init failed\n");
		aids_connhash_deinit();
		aids_connlist_deinit();
		return -EINVAL;
	}
	if(aids_init_app_match())
	{
		proc_deinit();
		aids_connhash_deinit();
		aids_connlist_deinit();
		pr_err("[AngelIDS][DPI] aids_init_app_match failed\n");
		return -EINVAL;
	}
	if(aids_connlist_timer_init())
	{
		aids_app_match_deinit();
		proc_deinit();
		aids_connhash_deinit();
		aids_connlist_deinit();
		pr_err("[AngelIDS][DPI] aids_connlist_timer_init failed\n");
		return -EINVAL;
	}
	if(aids_init_netfilter_hook())
	{
		aids_connlist_timer_deinit();
		aids_app_match_deinit();
		proc_deinit();
		aids_connhash_deinit();
		aids_connlist_deinit();
		pr_err("[AngelIDS][DPI] aids_init_netfilter_hook failed\n");
		return -EINVAL;
	}
	return 0;
}

static void __exit aids_module_exit(void)
{
	pr_info("AngelIDS - Deep Packet Inspection unload\n");
	aids_init_netfilter_unhook();
	aids_connlist_timer_deinit();
	aids_app_match_deinit();
	proc_deinit();
	aids_connlist_deinit();
	aids_connhash_deinit();
}

module_init(aids_module_init);
module_exit(aids_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Angelic47 <admin@angelic47.com>");
MODULE_AUTHOR("Hwsasi <hw.shymsh@gmail.com>");
MODULE_DESCRIPTION("AngelIDS DPI module");
MODULE_ALIAS("aids-dpi");
