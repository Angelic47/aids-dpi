#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/netfilter/nf_conntrack.h>
#include "aids.h"

char* aids_get_connection_status_message(enum aids_connection_status conn_status)
{
	switch(conn_status)
	{
		case AIDS_CONNECTION_UNTRACK:
			return "UNTRACK";
		case AIDS_CONNECTION_SYN_SENT:
			return "SYN_SENT";
		case AIDS_CONNECTION_SYN_RECV:
			return "SYN_RECV";
		case AIDS_CONNECTION_ESTABLISHED:
			return "ESTABLISHED";
		case AIDS_CONNECTION_FIN_1:
			return "FIN_WAIT_1";
		case AIDS_CONNECTION_FIN_2:
			return "FIN_WAIT_2";
		case AIDS_CONNECTION_FIN_3:
			return "FIN_WAIT_3";
		case AIDS_CONNECTION_CLOSED:
			return "CLOSED";
		default:
			return "UNKNOWN";
	}
}

char* aids_get_proto_message(u8 proto)
{
	switch(proto)
	{
		case IPPROTO_IP:
			return "IP";
		case IPPROTO_ICMP:
			return "ICMP";
		case IPPROTO_IGMP:
			return "IGMP";
		case IPPROTO_IPIP:
			return "IPIP";
		case IPPROTO_TCP:
			return "TCP";
		case IPPROTO_EGP:
			return "EGP";
		case IPPROTO_PUP:
			return "PUP";
		case IPPROTO_UDP:
			return "UDP";
		case IPPROTO_IDP:
			return "IDP";
		case IPPROTO_TP:
			return "TP";
		case IPPROTO_DCCP:
			return "DCCP";
		case IPPROTO_IPV6:
			return "IPV6";
		case IPPROTO_RSVP:
			return "RSVP";
		case IPPROTO_GRE:
			return "GRE";
		case IPPROTO_ESP:
			return "ESP";
		case IPPROTO_AH:
			return "AH";
		case IPPROTO_MTP:
			return "MTP";
		case IPPROTO_BEETPH:
			return "BEETPH";
		case IPPROTO_ENCAP:
			return "ENCAP";
		case IPPROTO_PIM:
			return "PIM";
		case IPPROTO_COMP:
			return "COMP";
		case IPPROTO_SCTP:
			return "SCTP";
		case IPPROTO_UDPLITE:
			return "UDPLITE";
		case IPPROTO_MPLS:
			return "UDPLITE";
		case IPPROTO_RAW:
			return "RAW";
		default:
			return "UNKNOWN";
	}
}
