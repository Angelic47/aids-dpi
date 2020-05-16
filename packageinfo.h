#ifndef AIDS_PACKAGEINFO_H
#define AIDS_PACKAGEINFO_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include "http_header_id.h"

#define AIDS_HTTP_REQ_MODE 0
#define AIDS_HTTP_REQ_PATH 1
#define AIDS_HTTP_REQ_VERSION 2

#define AIDS_HTTP_RESP_VERSION 0
#define AIDS_HTTP_RESP_CODE 1
#define AIDS_HTTP_RESP_DESCRIPTION 2

#define AIDS_HTTP_PACKAGEINFO_MAX 3

enum Proto
{
	_ANY = 0,
	_TCP = 6,
	_UDP = 17
};

enum DIR
{
	BOTH = 0,
	ORIGINAL = 1,
	REPLY = 2
};

enum HTTP_PACKAGE_TYPE
{
	HTTP_REQUEST = 0,
	HTTP_RESPONSE = 1
};

struct aids_http_package_info
{
	char *buffer;
	u64 length;
};

struct aids_package_info
{
	char *data;
	u16 length;
	u16 port;
	
	enum Proto proto;
	enum DIR dir;
	u8 pkt_seq;
	u32 dst_addr;
	
	u8 is_http;
	enum HTTP_PACKAGE_TYPE http_type;
	struct aids_http_package_info http_package_info[AIDS_HTTP_PACKAGEINFO_MAX];
	struct aids_http_package_info http_header_info[HTTP_HEADER_ID_MAX];
};

#endif