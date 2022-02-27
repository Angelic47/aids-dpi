#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "appinfo.h"
#include "packageinfo.h"
#include "aids_bm.h"
#include "kpcre2.h"

static struct aids_info_list_port* port_index[65537];
static u16 max_seq = 0;

static regex_t g_aids_re_http_request;
static regex_t g_aids_re_http_response;
static regex_t g_aids_re_http_header;

void aids_package_info_http_cleanup(struct aids_package_info* package_info)
{
	if(package_info->http_header_info[AIDS_SEQ_INTERNAL_ONLY].buffer)
		kfree(package_info->http_header_info[AIDS_SEQ_INTERNAL_ONLY].buffer);
}

int aids_init_reg_http(void)
{
	int re_result;
	
	memset(&g_aids_re_http_request, 0, sizeof(regex_t));
	memset(&g_aids_re_http_response, 0, sizeof(regex_t));
	memset(&g_aids_re_http_header, 0, sizeof(regex_t));
	
	re_result = regcomp_s(&g_aids_re_http_request, AIDS_REGEXP_HTTPREQ, sizeof(AIDS_REGEXP_HTTPREQ) - 1, REG_DOTALL);
	if(re_result)
	{
		pr_warning("[AngelIDS][DPI] Failed to init HTTP request regexp: %d\n", re_result);
		return -EINVAL;
	}
	re_result = regcomp_s(&g_aids_re_http_response, AIDS_REGEXP_HTTPRESP, sizeof(AIDS_REGEXP_HTTPRESP) - 1, REG_DOTALL);
	if(re_result)
	{
		pr_warning("[AngelIDS][DPI] Failed to init HTTP response regexp: %d\n", re_result);
		return -EINVAL;
	}
	re_result = regcomp_s(&g_aids_re_http_header, AIDS_REGEXP_HTTPHEADER, sizeof(AIDS_REGEXP_HTTPHEADER) - 1, REG_DOTALL);
	if(re_result)
	{
		pr_warning("[AngelIDS][DPI] Failed to init HTTP header regexp: %d\n", re_result);
		return -EINVAL;
	}
	return 0;
}

void aids_deinit_reg_http(void)
{
	regfree(&g_aids_re_http_request);
	regfree(&g_aids_re_http_response);
	regfree(&g_aids_re_http_header);
}

static void inline aids_http_moveheader(struct aids_http_package_info* http_info, char *buffer, unsigned int start, unsigned int end)
{
	http_info->buffer = &buffer[start];
	http_info->length = end - start;
}

void aids_http_url_get_extension(struct aids_package_info* package_info, char *url, unsigned int length)
{
	char* pos_dot = 0;
	char* pos_end = url;
	while(pos_end < (url + length) && *pos_end != 0)
	{
		if(*pos_end == '?')
			break;
		if(*pos_end == '.')
			pos_dot = pos_end;
		else if(*pos_end == '/')
			pos_dot = 0;
		pos_end ++;
	}
	if(pos_dot)
	{
		while(*pos_dot == '.')
			pos_dot ++;
		if(pos_dot < pos_end)
		{
			package_info->http_header_info[AIDS_Ext_INTERNAL_ONLY].length = pos_end - pos_dot;
			package_info->http_header_info[AIDS_Ext_INTERNAL_ONLY].buffer = pos_dot;
			return;
		}
	}
	package_info->http_header_info[AIDS_Ext_INTERNAL_ONLY].length = 0;
	package_info->http_header_info[AIDS_Ext_INTERNAL_ONLY].buffer = NULL;
}

int aids_http_header_match(struct aids_package_info* package_info, char *header, u32 length)
{
	regex_t _re_http_header;
	_re_http_header = g_aids_re_http_header;
	
	_re_http_header.re_match_data = NULL;
	
	regmatch_t pmatch_header[AIDS_REGEXP_HTTPHEADER_PMATCHCOUNT];
	u32 position = 0;
	int http_id;
	char* seq_buffer = NULL;
	
	seq_buffer = (char *)kmalloc(AIDS_HTTPHEADER_SEQ_MAXLEN, GFP_ATOMIC);
	
	if(!seq_buffer)
	{
		pr_warning("[AngelIDS][DPI] aids_http_header_match: failed to alloc seq_buffer!\n");
		goto header_match_end;
	}
	
	seq_buffer[0] = '\x00';
	package_info->http_header_info[AIDS_SEQ_INTERNAL_ONLY].length = 1;
	
	while(position < length)
	{
		if(regexec_s(&_re_http_header, &(header[position]), length - position, AIDS_REGEXP_HTTPHEADER_PMATCHCOUNT, pmatch_header, 0))
			break;
		
		http_id = aids_httpheader_lookup(&(header[position + pmatch_header[1].rm_so]), pmatch_header[1].rm_eo - pmatch_header[1].rm_so);
		if(http_id != AIDS_TIRE_NO_MATCH)
			aids_http_moveheader(&(package_info->http_header_info[http_id]), &(header[position]), pmatch_header[2].rm_so, pmatch_header[2].rm_eo);
		
		if(package_info->http_header_info[AIDS_SEQ_INTERNAL_ONLY].length < AIDS_HTTPHEADER_SEQ_MAXLEN)
		{
			seq_buffer[package_info->http_header_info[AIDS_SEQ_INTERNAL_ONLY].length] = aids_httpheader_lookup_seq(&(header[position + pmatch_header[1].rm_so]), pmatch_header[1].rm_eo - pmatch_header[1].rm_so);
			package_info->http_header_info[AIDS_SEQ_INTERNAL_ONLY].length ++;
		}
		
		position = position + pmatch_header[0].rm_eo;
	}
	
	header_match_end:
	_re_http_header.re_pcre2_code = NULL;
	
	regfree(&_re_http_header);
	
	if(position == 0) {
		if(seq_buffer) vfree(seq_buffer);
		package_info->http_header_info[AIDS_SEQ_INTERNAL_ONLY].length = 0;
		return -EINVAL;
	} else {
		package_info->http_header_info[AIDS_SEQ_INTERNAL_ONLY].buffer = seq_buffer;
	}
	return 0;
}

void aids_http_reg_match(struct aids_package_info* package_info)
{
	regex_t _re_http_request;
	regex_t _re_http_response;
	
	_re_http_request = g_aids_re_http_request;
	_re_http_response = g_aids_re_http_response;
	
	_re_http_request.re_match_data = NULL;
	_re_http_response.re_match_data = NULL;
	
	regmatch_t pmatch[AIDS_REGEXP_HTTP_PMATCHCOUNT];
	
	if(!regexec_s(&_re_http_request, package_info->data, package_info->length, AIDS_REGEXP_HTTP_PMATCHCOUNT, pmatch, 0))
	{
		package_info->http_type = HTTP_REQUEST;
		aids_http_moveheader(&(package_info->http_package_info[AIDS_HTTP_REQ_MODE]), package_info->data, pmatch[1].rm_so, pmatch[1].rm_eo);
		aids_http_moveheader(&(package_info->http_package_info[AIDS_HTTP_REQ_PATH]), package_info->data, pmatch[2].rm_so, pmatch[2].rm_eo);
		aids_http_moveheader(&(package_info->http_header_info[AIDS_URL_INTERNAL_ONLY]), package_info->data, pmatch[2].rm_so, pmatch[2].rm_eo);
		aids_http_moveheader(&(package_info->http_package_info[AIDS_HTTP_REQ_VERSION]), package_info->data, pmatch[3].rm_so, pmatch[3].rm_eo);
		aids_http_moveheader(&(package_info->http_header_info[AIDS_Body_INTERNAL_ONLY]), package_info->data, pmatch[5].rm_so, pmatch[5].rm_eo);
		aids_http_url_get_extension(package_info, &(package_info->data[pmatch[2].rm_so]), pmatch[2].rm_eo - pmatch[2].rm_so);
		
		if(aids_http_header_match(package_info, &(package_info->data[pmatch[4].rm_so]), pmatch[4].rm_eo - pmatch[4].rm_so))
			goto http_match_end;
		
		package_info->is_http = 1;
		
		goto http_match_end;
	}
	if(!regexec_s(&_re_http_response, package_info->data, package_info->length, AIDS_REGEXP_HTTP_PMATCHCOUNT, pmatch, 0))
	{
		package_info->http_type = HTTP_RESPONSE;
		aids_http_moveheader(&(package_info->http_package_info[AIDS_HTTP_RESP_VERSION]), package_info->data, pmatch[1].rm_so, pmatch[1].rm_eo);
		aids_http_moveheader(&(package_info->http_package_info[AIDS_HTTP_RESP_CODE]), package_info->data, pmatch[2].rm_so, pmatch[2].rm_eo);
		aids_http_moveheader(&(package_info->http_package_info[AIDS_HTTP_RESP_DESCRIPTION]), package_info->data, pmatch[3].rm_so, pmatch[3].rm_eo);
		aids_http_moveheader(&(package_info->http_header_info[AIDS_Body_INTERNAL_ONLY]), package_info->data, pmatch[5].rm_so, pmatch[5].rm_eo);
		
		if(aids_http_header_match(package_info, &(package_info->data[pmatch[4].rm_so]), pmatch[4].rm_eo - pmatch[4].rm_so))
			goto http_match_end;
		
		package_info->is_http = 1;
		
		goto http_match_end;
	}
	
	http_match_end:
	
	_re_http_request.re_pcre2_code = NULL;
	_re_http_response.re_pcre2_code = NULL;
	
	regfree(&_re_http_request);
	regfree(&_re_http_response);
}

void aids_init_appinfo(u16 max_seq_t)
{
	max_seq = max_seq_t;
	u32 i;
	for(i = 0; i < 65537; i++)
		port_index[i] = NULL;
}

void aids_deinit_appinfo(void)
{
	u32 i;
	for(i = 0; i < 65537; i++)
		if (port_index[i] != NULL)
			aids_del_port_list(port_index[i]);
}

void aids_del_app_info(struct aids_app_info* app_info)
{
	int i;
	if(app_info->is_http)
	{
		for(i = 0; i < app_info->http_match_info_count; i ++)
		{
			if(app_info->http_match_info[i].data != NULL)
				kfree(app_info->http_match_info[i].data);
			switch(app_info->http_match_info[i].match_method)
			{
				case REGULAR_MATCH:
					regfree(&(app_info->http_match_info[i].re));
					break;
				case BM_MATCH_STR:
					aids_bm_deinit(app_info->http_match_info[i].bm);
					break;
			}
		}
		kfree(app_info->http_match_info);
	}
	else
	{
		if (app_info->port_range != NULL)
			kfree(app_info->port_range);
		if (app_info->len_range != NULL)
			kfree(app_info->len_range);
		kfree(app_info->pkt_seq);
		if (app_info->multi_dst_addr != NULL)
			kfree(app_info->multi_dst_addr);
		if (app_info->multi_subnet != NULL)
			kfree(app_info->multi_subnet);
		if (app_info->data != NULL)
			kfree(app_info->data);
		switch(app_info->match_method)
		{
			case REGULAR_MATCH:
				regfree(&(app_info->re));
				break;
			case BM_MATCH_STR:
				aids_bm_deinit(app_info->bm);
				break;
		}
	}
}

struct aids_app_info_list* aids_create_info_list_node(struct aids_app_info appinfo)
{
	struct aids_app_info_list* new_node;
	new_node = kmalloc(sizeof(struct aids_app_info_list), GFP_ATOMIC);
	if (new_node == NULL)
	{
		pr_warning("[AngelIDS][DPI] aids_create_info_list_node: aids_app_info_list alloc fail!\n");
		return NULL;
	}
	new_node->app_info = appinfo;
	new_node->next = NULL;
	return new_node;
}

void aids_set_info_list_node(struct aids_app_info_list** position, struct aids_app_info appinfo)
{
	struct aids_app_info_list* new_node = aids_create_info_list_node(appinfo);
	if (new_node == NULL)
		return;
	new_node->next = *position;
	(*position) = new_node;
	
	u16 i;
	u8 set_to_other;
	set_to_other = 0;
	if (appinfo.port_range_count != 0)
	{
		for (i = 0; i < appinfo.port_range_count; i++)
			if (appinfo.port_range[i * 2 + 1] == appinfo.port_range[i * 2])
				aids_set_port_list_node(&port_index[appinfo.port_range[i * 2]], new_node);
			else
			{
				if (!set_to_other)
				{
					aids_set_port_list_node(&port_index[65536], new_node);
					set_to_other = 1;
				}
			}
	}
	else
		aids_set_port_list_node(&port_index[65536], new_node);
}

void aids_del_info_list(struct aids_app_info_list* position)
{
	struct aids_app_info_list* pointer;
	while(position!=NULL)
	{
		pointer=position;
		position=position->next;
		aids_del_app_info(&pointer->app_info);
		kfree(pointer);
	}
}

struct aids_info_list_port* aids_create_port_list_node(struct aids_app_info_list* appinfo)
{
	struct aids_info_list_port* new_node;
	new_node = kmalloc(sizeof(struct aids_info_list_port), GFP_ATOMIC);
	if (new_node == NULL)
	{
		pr_warning("[AngelIDS][DPI] aids_create_port_list_node: aids_info_list_port alloc fail!\n");
		return NULL;
	}
	new_node->appinfo = appinfo;
	new_node->next = NULL;
	return new_node;
}

void aids_set_port_list_node(struct aids_info_list_port** position, struct aids_app_info_list* appinfo)
{
	struct aids_info_list_port* new_node = aids_create_port_list_node(appinfo);
	if (new_node == NULL)
		return;
	new_node->next = *position;
	(*position) = new_node;
}

void aids_del_port_list(struct aids_info_list_port* position)
{
	struct aids_info_list_port* pointer;
	while(position != NULL){
		pointer = position;
		position = position->next;
		kfree(pointer);
	}
}

struct aids_seg_tree_list* aids_create_seg_list_node(struct aids_app_info_list* appinfo)
{
	struct aids_seg_tree_list* new_node;
	new_node = kmalloc(sizeof(struct aids_seg_tree_list), GFP_ATOMIC);
	if (new_node == NULL)
	{
		pr_warning("[AngelIDS][DPI] aids_create_seg_list_node: aids_seg_tree_list alloc fail!\n");
		return NULL;
	}
	new_node->appinfo = appinfo;
	new_node->next = NULL;
	return new_node;
}

void aids_set_seg_list_node(struct aids_seg_tree_list** position, struct aids_app_info_list* appinfo)
{
	struct aids_seg_tree_list* new_node = aids_create_seg_list_node(appinfo);
	if (new_node == NULL)
		return;
	new_node->next = *position;
	(*position) = new_node;
}

void aids_del_seg_list(struct aids_seg_tree_list* position)
{
	struct aids_seg_tree_list* pointer;
	while(position != NULL)
	{
		pointer = position;
		position = position->next;
		kfree(pointer);
	}
}

struct aids_seg_tree_node* aids_create_seg_tree(u16 min, u16 max)
{
	struct aids_seg_tree_node *left = NULL, *right = NULL;
	struct aids_seg_tree_node* head = kmalloc(sizeof(struct aids_seg_tree_node), GFP_ATOMIC);
	if (head == NULL)
	{
		pr_warning("[AngelIDS][DPI] aids_create_seg_tree: aids_seg_tree_node alloc fail!\n");
		return NULL;
	}
	if (max - min != 1)
	{
		u16 mid;
		u32 offset = 1;
		while (offset + min < max)
			offset = offset << 1;
		mid = min + offset >> 1;
		left = aids_create_seg_tree(min, mid);
		right = aids_create_seg_tree(mid, max);
		head->mid_num = mid;
	}
	else
		head->mid_num = max;
	head->left = left;
	head->right = right;
	head->min_num = min;
	head->max_num = max;
	head->list = NULL;
	return head;
}

void aids_add_seg_tree_rule(u16 min, u16 max, struct aids_seg_tree_node* head, struct aids_app_info_list* appinfo)
{
	if (head->max_num - head->min_num == 1)
	{
		aids_set_seg_list_node(&(head->list), appinfo);
		return;
	}
	if (min == head->min_num && max == head->max_num - 1)
	{
		aids_set_seg_list_node(&(head->list), appinfo);
		return;
	}
	if (min < head->mid_num)
	{
		if (max >= head->mid_num)
		{
			aids_add_seg_tree_rule(min, head->mid_num-1, head->left, appinfo);
			aids_add_seg_tree_rule(head->mid_num, max, head->right, appinfo);
		}
		else
		{
			aids_add_seg_tree_rule(min, max, head->left, appinfo);
		}
	}
	else
	{
		aids_add_seg_tree_rule(min, max, head->right, appinfo);
	}
}

void aids_init_seg_tree(struct aids_seg_tree_node* head, struct aids_app_info_list* info_list)
{
	while (info_list != NULL)
	{
		u16 i;
		if (info_list->app_info.len_range_count)
			for (i = 0; i < info_list->app_info.len_range_count; i++)
				aids_add_seg_tree_rule(info_list->app_info.len_range[i * 2], info_list->app_info.len_range[i * 2 + 1], head, info_list);
		else
			aids_add_seg_tree_rule(0, 1500, head, info_list);
		info_list = info_list->next;
	}
}

struct aids_seg_tree_list* aids_seg_tree_get_query_list(struct aids_seg_tree_node* head, u16 length)
{
	struct aids_seg_tree_list* list;
	struct aids_seg_tree_list* pointer1; 
	struct aids_seg_tree_list* pointer2; 
	struct aids_seg_tree_list* temp;
	pointer1 = head->list;
	list = kmalloc(sizeof(struct aids_seg_tree_list), GFP_ATOMIC);
	if (!list)
	{
		pr_warning("[AngelIDS][DPI] aids_seg_tree_get_query_list: aids_seg_tree_list alloc fail #1!\n");
		return NULL;
	}
	list->next = NULL;
	
	while(pointer1!=NULL)
	{
		temp = kmalloc(sizeof(struct aids_seg_tree_list), GFP_ATOMIC);
		if (!temp)
		{
			pr_warning("[AngelIDS][DPI] aids_seg_tree_get_query_list: aids_seg_tree_list alloc fail #2!\n");
			goto END_ADDING_QUERY;
		}
		temp->appinfo = pointer1->appinfo;
		temp->next = list->next;
		list->next=temp;
		pointer1=pointer1->next;
	}
	
	pointer1 = (head->max_num - head->min_num == 1 ? NULL : aids_seg_tree_get_query_list((length < head->mid_num ? head->left : head->right), length));
	pointer2 = list;
	while (pointer1 != NULL)
	{
		while (pointer2->next != NULL && pointer2->next->appinfo->app_info.rule_id > pointer1->appinfo->app_info.rule_id)
			pointer2 = pointer2->next;
		temp = pointer1->next;
		pointer1->next = pointer2->next;
		pointer2->next = pointer1;
		pointer2 = pointer1;
		pointer1 = temp;
	}
END_ADDING_QUERY:
	pointer1 = list->next;
	kfree(list);
	return pointer1;
}

u32 aids_seg_tree_get_appid(struct aids_seg_tree_node* head, struct aids_package_info* conn_info)
{
	struct aids_seg_tree_list* list = aids_seg_tree_get_query_list(head, conn_info->length);
	struct aids_seg_tree_list* pointer;
	u32 ans;

	ans = aids_check_if_app(list, conn_info);
	
	while (list != NULL)
	{
		pointer = list;
		list = list->next;
		kfree(pointer);
	}
	return ans;
}

void aids_delete_seg_tree(struct aids_seg_tree_node* head)
{
	if (head->left != NULL)
		aids_delete_seg_tree(head->left);
	if (head->right != NULL)
		aids_delete_seg_tree(head->right);
	if (head->list != NULL)
		aids_del_seg_list(head->list);
	kfree(head);
}

static u8 aids_data_match(char *data, u16 length, struct aids_app_info* app_info)
{
	regex_t _re_temp;
	
	switch(app_info->match_method)
	{
		case EXACT_MATCH:
			if (length != app_info->data_len)
				return 0;
		case PART_EXACT_MATCH:
			if (length < app_info->data_len)
				return 0;
			u32 i;
			for (i = 0; i < length && i < app_info->data_len; i++)
				if (data[i] != app_info->data[i])
					return 0;
			break;
		case NO_FIXED_DATA_MATCH:
			break;
		case REGULAR_MATCH:
			_re_temp = app_info->re;
			_re_temp.re_match_data = NULL;
			
			if(regexec_s(&_re_temp, data, length, 0, NULL, 0) != 0)
			{
				_re_temp.re_pcre2_code = NULL;
				regfree(&_re_temp);
				return 0;
			}
			
			_re_temp.re_pcre2_code = NULL;
			regfree(&_re_temp);
			break;
		case BM_MATCH_STR:
			if(AIDS_BM_NOTFIND(aids_bm_find(app_info->bm, data, length, 0)))
				return 0;
			break;
	}
	return 1;
}

static u8 aids_http_match(char *data, u16 length, struct aids_http_match_info* http_info)
{
	regex_t _re_temp;
	
	switch(http_info->match_method)
	{
		case EXACT_MATCH:
			if (length != http_info->data_len)
				return 0;
		case PART_EXACT_MATCH:
			if (length < http_info->data_len)
				return 0;
			u32 i;
			for (i = 0; i < length && i < http_info->data_len; i++)
				if (data[i] != http_info->data[i])
					return 0;
			break;
		case NO_FIXED_DATA_MATCH:
			break;
		case REGULAR_MATCH:
			_re_temp = http_info->re;
			_re_temp.re_match_data = NULL;
			
			if(regexec_s(&_re_temp, data, length, 0, NULL, 0) != 0)
			{
				_re_temp.re_pcre2_code = NULL;
				regfree(&_re_temp);
				return 0;
			}
			
			_re_temp.re_pcre2_code = NULL;
			regfree(&_re_temp);
			break;
		case BM_MATCH_STR:
			if(AIDS_BM_NOTFIND(aids_bm_find(http_info->bm, data, length, 0)))
				return 0;
			break;
	}
	return 1;
}

u32 aids_check_if_app(struct aids_seg_tree_list* pointer, struct aids_package_info * conn_info)
{
	u16 i, j;
	struct aids_info_list_port* temp[2];
	struct aids_app_info* info;
	u8 max;
	temp[0] = port_index[conn_info->port];
	temp[1] = port_index[65536];
	while (pointer != NULL && (temp[0] != NULL || temp[1] != NULL))
	{
		if (temp[0] == NULL)
			max = 1;
		else if (temp[1] == NULL)
			max = 0;
		else if (temp[0]->appinfo->app_info.rule_id < temp[1]->appinfo->app_info.rule_id)
			max = 1;
		else
			max = 0;
		if (pointer->appinfo->app_info.rule_id > temp[max]->appinfo->app_info.rule_id)
			pointer = pointer->next;
		else if (pointer->appinfo->app_info.rule_id < temp[max]->appinfo->app_info.rule_id)
			temp[max] = temp[max]->next;
		else
		{
			if (max && temp[max]->appinfo->app_info.port_range_count)
			{
				j = 1;
				for(i=0;i< temp[max]->appinfo->app_info.port_range_count;i++)
					if (temp[max]->appinfo->app_info.port_range[i * 2] <= conn_info->port && temp[max]->appinfo->app_info.port_range[i * 2 + 1] >= conn_info->port)
					{
						j = 0;
						break;
					}
				if (j)
				{
					temp[max] = temp[max]->next;
					continue;
				}
			}
			
			info = &pointer->appinfo->app_info;
			
			if (info->is_http)
			{
				if(!(conn_info->is_http && (info->dir == BOTH || (int)info->dir == (int)conn_info->http_type + 1) && (info->pkt_seq[0] || info->pkt_seq[conn_info->pkt_seq])))
					goto INCORRECT_AND_CONTINUE;
				for (i = 0; i < info->http_match_info_count; i ++)
				{
					if (conn_info->http_header_info[info->http_match_info[i].index].buffer == NULL)
						goto INCORRECT_AND_CONTINUE;
					
					if (!aids_http_match(conn_info->http_header_info[info->http_match_info[i].index].buffer, conn_info->http_header_info[info->http_match_info[i].index].length, &(info->http_match_info[i])))
						goto INCORRECT_AND_CONTINUE;
				}
				return info->appid;
			}
			
			if ((info->proto != _ANY && info->proto != conn_info->proto) || (info->dir != BOTH && info->dir != conn_info->dir) || (!info->pkt_seq[0] && !info->pkt_seq[conn_info->pkt_seq]))
				goto INCORRECT_AND_CONTINUE;
			j = 1;
			for (i = 0; i < info->multi_dst_addr_count; i++)
				if (info->multi_dst_addr[i] == conn_info->dst_addr)
				{
					j = 0;
					break;
				}
			if (j && info->multi_dst_addr_count)
				goto INCORRECT_AND_CONTINUE;
			j = 1;
			for (i = 0; i < info->multi_subnet_count; i++)
				if ((info->multi_subnet[i].net & info->multi_subnet[i].mask) == (conn_info->dst_addr & info->multi_subnet[i].mask))
				{
					j = 0;
					break;
				}
			if (j && info->multi_subnet_count)
				goto INCORRECT_AND_CONTINUE;
			
			if (!aids_data_match(conn_info->data, conn_info->length, info))
				goto INCORRECT_AND_CONTINUE;
			
			return info->appid;
			
		INCORRECT_AND_CONTINUE:
			temp[max] = temp[max]->next;
		}
	}
	return 0;
}
