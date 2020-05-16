#ifndef AIDS_H
#define AIDS_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/jiffies.h>

#define NIPQUAD(addr) \
 ((unsigned char *)&(addr))[0], \
 ((unsigned char *)&(addr))[1], \
 ((unsigned char *)&(addr))[2], \
 ((unsigned char *)&(addr))[3]
 
#define AIDS_CONNECTION_TIMEOUT_MS (1000 * 180)
#define AIDS_CONNECTION_TIMEOUT (jiffies_64 + msecs_to_jiffies(AIDS_CONNECTION_TIMEOUT_MS))
#define AIDS_CONNECTION_TIMEOUT_IMM (jiffies_64 - 1)

enum aids_connection_direct
{
	AIDS_IN = 0,
	AIDS_OUT = 1
};

enum aids_skb_direct
{
	AIDS_SKB_PREROUTE = 0,
	AIDS_SKB_POSTROUTE = 1
};

enum aids_connection_status
{
	AIDS_CONNECTION_UNTRACK = 0,
	AIDS_CONNECTION_SYN_SENT = 1,
	AIDS_CONNECTION_SYN_RECV = 2,
	AIDS_CONNECTION_ESTABLISHED = 3,
	AIDS_CONNECTION_FIN_1 = 4,
	AIDS_CONNECTION_FIN_2 = 5,
	AIDS_CONNECTION_FIN_3 = 6,
	AIDS_CONNECTION_CLOSED = 7,
};

struct aids_connection_info
{
	ktime_t begintime;
	u64 timeout;
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	enum ip_conntrack_info ctinfo;
	u8 protocol;
	u32 appid;
	enum aids_connection_direct direct;
	u8 pkt_count;
	enum aids_connection_status conn_status;
	u32 tcp_seq;
	u32 tcp_ack_seq;
	u8 is_http;
};

char* aids_get_connection_status_message(enum aids_connection_status conn_status);

char* aids_get_proto_message(u8 proto);

#endif
