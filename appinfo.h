#ifndef AIDS_APPINFO_H
#define AIDS_APPINFO_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include "packageinfo.h"
#include "aids.h"
#include "aids_bm.h"
#include "kpcre2.h"

#define AIDS_REGEXP_HTTPREQ "(GET|HEAD|POST|PUT|OPTION|DELETE|TRACE|CONNECT) (.+) HTTP/([0-9.]+)\\r\\n(.+?\\r\\n)\\r\\n(.*)"
#define AIDS_REGEXP_HTTPRESP "HTTP/([0-9.]+) ([0-9]+) (.+?)\\r\\n(.+?\\r\\n)\\r\\n(.*)"
#define AIDS_REGEXP_HTTPHEADER "[ ]*(.+?)[ ]*:[ ]*(.+?)\\r\\n"
#define AIDS_REGEXP_HTTP_PMATCHCOUNT 6
#define AIDS_REGEXP_HTTPHEADER_PMATCHCOUNT 3

enum MatchMethod {
	EXACT_MATCH = 0,
	REGULAR_MATCH = 1,
	NO_FIXED_DATA_MATCH = 2,
	MATCH_MULTI_DATA = 3,
	PART_EXACT_MATCH = 4,
	BM_MATCH_STR = 5
};

struct MultiSubnet
{
	u32 net;
	u32 mask;
};

struct aids_http_match_info
{
	u8 index;
	enum MatchMethod match_method;
	char *data;
	u32 data_len;
	
	regex_t re;
	
	struct aids_bm* bm;
};

struct aids_app_info
{
	u8 is_http;
	u32 appid;
	u16 *len_range;
	u16 len_range_count;
	u16* port_range;
	u16 port_range_count;
	enum Proto proto;
	enum DIR dir;
	u8 *pkt_seq;//bool[] 
	u32 *multi_dst_addr;
	u16 multi_dst_addr_count;
	struct MultiSubnet *multi_subnet;
	u16 multi_subnet_count;
	u32 rule_id;
    enum MatchMethod match_method;
	
	struct aids_http_match_info *http_match_info;
	u16 http_match_info_count;
	
	
	regex_t re;
	
	struct aids_bm* bm;
	
	char *data;
	u32 data_len;
};

struct aids_app_info_list
{
	struct aids_app_info app_info;
	struct aids_app_info_list* next;
};

struct aids_info_list_port
{
	struct aids_app_info_list* appinfo;
	struct aids_info_list_port* next;
};

struct aids_seg_tree_list
{
	struct aids_app_info_list* appinfo;
	struct aids_seg_tree_list* next;
};

struct aids_seg_tree_node
{
	u16 min_num, max_num, mid_num;
	struct aids_seg_tree_list *list;
	struct aids_seg_tree_node *left, *right;
};

void aids_package_info_http_cleanup(struct aids_package_info* package_info);

int aids_init_reg_http(void);
void aids_deinit_reg_http(void);

void aids_http_reg_match(struct aids_package_info* package_info);

void aids_init_appinfo(u16 max_seq_t);
void aids_deinit_appinfo(void);

void aids_del_app_info(struct aids_app_info* app_info);

struct aids_app_info_list* aids_create_info_list_node(struct aids_app_info appinfo);
void aids_set_info_list_node(struct aids_app_info_list** position, struct aids_app_info appinfo);
void aids_del_info_list(struct aids_app_info_list* position);

struct aids_info_list_port* aids_create_port_list_node(struct aids_app_info_list* appinfo);
void aids_set_port_list_node(struct aids_info_list_port** position, struct aids_app_info_list* appinfo);
void aids_del_port_list(struct aids_info_list_port* position);

struct aids_seg_tree_list* aids_create_seg_list_node(struct aids_app_info_list* appinfo);
void aids_set_seg_list_node(struct aids_seg_tree_list** position, struct aids_app_info_list* appinfo);
void aids_del_seg_list(struct aids_seg_tree_list* position);

struct aids_seg_tree_node* aids_create_seg_tree(u16 min, u16 max);
void aids_add_seg_tree_rule(u16 min, u16 max, struct aids_seg_tree_node* head, struct aids_app_info_list* appinfo);
void aids_init_seg_tree(struct aids_seg_tree_node* head, struct aids_app_info_list* info_list);
struct aids_seg_tree_list* aids_seg_tree_get_query_list(struct aids_seg_tree_node* head, u16 length);
u32 aids_seg_tree_get_appid(struct aids_seg_tree_node* head, struct aids_package_info* conn_info);
void aids_delete_seg_tree(struct aids_seg_tree_node* head);

u32 aids_check_if_app(struct aids_seg_tree_list* pointer, struct aids_package_info * conn_info);

#endif