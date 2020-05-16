#include "kernel_ver.h"
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "rulesfile.h"
#include "cJSON.h"
#include "appinfo.h"
#include "kpcre2.h"

#ifdef AIDS_OLDER_KERNEL
static ssize_t aids_kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	ssize_t result;

	old_fs = get_fs();
	set_fs(get_ds());
	
	result = vfs_read(file, (void __user *)buf, count, pos);
	set_fs(old_fs);
	return result;
}
#endif

static int aids_rulesfile_open(char **buf, loff_t *file_size)
{
	struct file *f;
	u64 readed = 0;
	size_t readsize;
	f = filp_open(AIDS_RULESFILE_PATH, O_RDONLY, 0);
	if(IS_ERR(f))
	{
		pr_warning("[AngelIDS][DPI] Failed to load rules file: %s\n", AIDS_RULESFILE_PATH);
		return -EINVAL;
	}
	*file_size = f->f_inode->i_size;
	*buf = (char *)vmalloc(*file_size + 1);
	if(!(*buf))
	{
		pr_warning("[AngelIDS][DPI] Memory not enough while loading file: %s\n", AIDS_RULESFILE_PATH);
		filp_close(f, NULL);
		return -ENOMEM;
	}
	
	memset(*buf, 0, *file_size + 1);
	
	while(readed < *file_size)
	{
		readsize = *file_size - readed;
		if(readsize > 1024)
			readsize = 1024;
		#ifdef AIDS_OLDER_KERNEL
		readsize = aids_kernel_read(f, *buf + readed, readsize, &f->f_pos);
		#else
		readsize = kernel_read(f, *buf + readed, readsize, &f->f_pos);
		#endif
		if(readsize > 0)
		{
			readed += readsize;
		}
		else
		{
			pr_warning("[AngelIDS][DPI] Failed to read rules file, readed: %lld, need: %lld\n", readed, *file_size);
			goto readfail;
		}
	}
	filp_close(f, NULL);
	pr_info("[AngelIDS][DPI] Loaded %llu bytes rules file\n", *file_size);
	return 0;
	
	readfail:
	filp_close(f, NULL);
	return -EINVAL;
}

static void aids_rulesfile_free(char *buf)
{
	vfree(buf);
}

static int aids_rulesfile_doreload(char *buf, loff_t file_size, struct aids_app_info** app_info, u32* info_count, u16* max_seq)
{
	
	#define cJSON_GetAndCheck(jsonobj, tempvar, strname, jsontype) { tempvar = cJSON_GetObjectItem(jsonobj, strname); \
		if(tempvar == NULL || tempvar->type != jsontype) \
		{ \
			pr_warning("[AngelIDS][DPI] Malformed rules file %s, %s parse failed\n", AIDS_RULESFILE_PATH, strname); \
			goto ERROR_WHEN_READING; \
		} \
	}
	#define cJSON_GetItemAndCheck(jsonobj, tempvar, strname, jsontype, id) { tempvar = cJSON_GetObjectItem(jsonobj, strname); \
		if(tempvar == NULL || tempvar->type != jsontype) \
		{ \
			pr_warning("[AngelIDS][DPI] Malformed rules at line %d, %s parse failed\n", id, strname); \
			continue;\
		} \
	}
	
	cJSON *rulefile_json, *read_data_array_temp, *read_temp, *read_temp_array, *read_temp_array_item, *rules_data, *rules_item;
	int rules_array_item = 0;
	int rules_array_item_count;
	int i,j,k;
	int re_result;
	rulefile_json = cJSON_Parse(buf);
	
	if(!rulefile_json)
	{
		pr_warning("[AngelIDS][DPI] Malformed rules file %s, rules load failed\n", AIDS_RULESFILE_PATH);
		return -EINVAL; 
	}
	
	cJSON_GetAndCheck(rulefile_json, read_temp, "maxseq", cJSON_Number);
	*max_seq = read_temp->valueint;
	
	cJSON_GetAndCheck(rulefile_json, rules_data, "data", cJSON_Array);
	rules_array_item_count = cJSON_GetArraySize(rules_data);
	*info_count = 0;
	*app_info = (struct aids_app_info *)vmalloc(sizeof(struct aids_app_info) * rules_array_item_count);
	if(!(*app_info))
	{
		pr_warning("[AngelIDS][DPI] Error while processing rules file %s, memory not enough\n", AIDS_RULESFILE_PATH);
		goto ERROR_WHEN_NO_MEM;
	}
	for(rules_array_item = 0; rules_array_item < rules_array_item_count; rules_array_item ++)
	{
		// rules data item
		rules_item = cJSON_GetArrayItem(rules_data, rules_array_item);
		if(!rules_item || rules_item->type != cJSON_Object)
		{
			pr_warning("[AngelIDS][DPI] Malformed rules at line %d, object not available\n", rules_array_item);
			continue;
		}
		
		// http
		cJSON_GetItemAndCheck(rules_item, read_temp, "http", cJSON_Number, rules_array_item);
		(*app_info)[*info_count].is_http = read_temp->valueint;
		
		// appid
		cJSON_GetItemAndCheck(rules_item, read_temp, "appid", cJSON_Number, rules_array_item);
		(*app_info)[*info_count].appid = read_temp->valueint;
		
		// dir
		cJSON_GetItemAndCheck(rules_item, read_temp, "direction", cJSON_Number, rules_array_item);
		(*app_info)[*info_count].dir = read_temp->valueint;
		
		// rule_id
		cJSON_GetItemAndCheck(rules_item, read_temp, "ruleid", cJSON_Number, rules_array_item);
		(*app_info)[*info_count].rule_id = read_temp->valueint;
			
		// pkt_seq
		cJSON_GetItemAndCheck(rules_item, read_temp_array, "seq", cJSON_Array, rules_array_item);
		(*app_info)[*info_count].pkt_seq = (u8 *)kmalloc(*max_seq + 1, GFP_KERNEL);
		if((*app_info)[*info_count].pkt_seq == NULL)
		{
			pr_warning("[AngelIDS][DPI] Error while processing rules file pkt_seq at line %d, memory not enough\n", rules_array_item);
			continue;
		}
		memset((*app_info)[*info_count].pkt_seq, 0, *max_seq + 1);
		for(i = 0; i < cJSON_GetArraySize(read_temp_array); i ++)
		{
			read_temp_array_item = cJSON_GetArrayItem(read_temp_array, i);
			if(read_temp_array_item == NULL || read_temp_array_item->type != cJSON_Number)
			{
				pr_warning("[AngelIDS][DPI] Error while processing rules file pkt_seq at line %d:%d, seq not valid\n", rules_array_item, i);
				continue;
			}
			if(read_temp_array_item->valueint < 0 || read_temp_array_item->valueint > *max_seq)
			{
				pr_warning("[AngelIDS][DPI] Error while processing rules file pkt_seq at line %d:%d, seq not in range\n", rules_array_item, i);
				continue;
			}
			(*app_info)[*info_count].pkt_seq[read_temp_array_item->valueint] = 1;
		}
		
		if((*app_info)[*info_count].is_http)
		{
			// len range & count
			(*app_info)[*info_count].len_range_count = 0;
			(*app_info)[*info_count].len_range = NULL;
			
			// port range & count
			(*app_info)[*info_count].port_range_count = 0;
			(*app_info)[*info_count].port_range = NULL;
			
			// http match info
			read_temp_array = cJSON_GetObjectItem(rules_item, "match_info");
			if(read_temp_array == NULL || read_temp_array->type != cJSON_Array)
			{
				pr_warning("[AngelIDS][DPI] Error while processing rules file http match_info at line %d:%d, array not valid\n", rules_array_item, i);
				continue;
			}
			(*app_info)[*info_count].http_match_info_count = cJSON_GetArraySize(read_temp_array);
			(*app_info)[*info_count].http_match_info = (struct aids_http_match_info *)kmalloc((*app_info)[*info_count].http_match_info_count * sizeof(struct aids_http_match_info), GFP_KERNEL);
			
			j = 0;
			for(i = 0; i < cJSON_GetArraySize(read_temp_array); i ++)
			{
				read_temp_array_item = cJSON_GetArrayItem(read_temp_array, i);
				if(read_temp_array_item == NULL || read_temp_array_item->type != cJSON_Object)
				{
					pr_warning("[AngelIDS][DPI] Error while processing rules file http match_info at line %d:%d, match_info object not valid\n", rules_array_item, i);
					(*app_info)[*info_count].http_match_info_count -= 1;
					continue;
				}
				
				read_temp = cJSON_GetObjectItem(read_temp_array_item, "index");
				if(read_temp == NULL || read_temp->type != cJSON_Number || read_temp->valueint >= HTTP_HEADER_ID_MAX || read_temp->valueint < 0)
				{
					pr_warning("[AngelIDS][DPI] Error while processing rules file http match_info at line %d:%d, match_info object index not valid\n", rules_array_item, i);
					(*app_info)[*info_count].http_match_info_count -= 1;
					continue;
				}
				(*app_info)[*info_count].http_match_info[j].index = read_temp->valueint;
				
				read_temp = cJSON_GetObjectItem(read_temp_array_item, "match_method");
				if(read_temp == NULL || read_temp->type != cJSON_Number)
				{
					pr_warning("[AngelIDS][DPI] Error while processing rules file http match_info at line %d:%d, match_info object match_method not valid\n", rules_array_item, i);
					(*app_info)[*info_count].http_match_info_count -= 1;
					continue;
				}
				(*app_info)[*info_count].http_match_info[j].match_method = read_temp->valueint;
				
				// no fixed data
				if((*app_info)[*info_count].http_match_info[j].match_method == 2)
				{
					(*app_info)[*info_count].http_match_info[j].data = NULL;
					(*app_info)[*info_count].http_match_info[j].data_len = 0;
					j += 1;
					continue;
				}
				
				read_data_array_temp = cJSON_GetObjectItem(read_temp_array_item, "data");
				if(read_data_array_temp == NULL || read_data_array_temp->type != cJSON_Array)
				{
					pr_warning("[AngelIDS][DPI] Error while processing rules file http match_info at line %d:%d, match_info object data not valid\n", rules_array_item, i);
					(*app_info)[*info_count].http_match_info_count -= 1;
					continue;
				}
				
				(*app_info)[*info_count].http_match_info[j].data_len = cJSON_GetArraySize(read_data_array_temp);
				(*app_info)[*info_count].http_match_info[j].data = (char *)kmalloc(((*app_info)[*info_count].http_match_info[j].data_len + 1) * sizeof(char), GFP_KERNEL);
				if((*app_info)[*info_count].http_match_info[j].data == NULL)
				{
					pr_warning("[AngelIDS][DPI] Error while processing rules file http match_info at line %d:%d, initalize match data at line %d failed with memory not enough\n", rules_array_item, i);
					(*app_info)[*info_count].http_match_info_count -= 1;
					continue;
				}
				for(k = 0; k < cJSON_GetArraySize(read_data_array_temp); k++)
				{
					read_temp = cJSON_GetArrayItem(read_data_array_temp, k);
					if(read_temp == NULL || read_temp->type != cJSON_Number)
					{
						pr_warning("[AngelIDS][DPI] Initalize match data at line %d:%d failed, data not valid\n", rules_array_item, i);
						kfree((*app_info)[*info_count].http_match_info[j].data);
						(*app_info)[*info_count].http_match_info[j].data = NULL;
						(*app_info)[*info_count].http_match_info[j].data_len = 0;
						break;
					}
					else if(read_temp->valueint < 0 || read_temp->valueint > 255)
					{
						pr_warning("[AngelIDS][DPI] Initalize match data at line %d:%d failed, data not in range\n", rules_array_item, i);
						kfree((*app_info)[*info_count].http_match_info[j].data);
						(*app_info)[*info_count].http_match_info[j].data = NULL;
						(*app_info)[*info_count].http_match_info[j].data_len = 0;
						break;
					}
					(*app_info)[*info_count].http_match_info[j].data[k] = read_temp->valueint;
				}
				if((*app_info)[*info_count].http_match_info[j].data == NULL) {
					(*app_info)[*info_count].http_match_info_count -= 1;
					continue;
				}
				(*app_info)[*info_count].http_match_info[j].data[(*app_info)[*info_count].http_match_info[j].data_len] = '\x00';
				
				// process match_method
				switch((*app_info)[*info_count].http_match_info[j].match_method)
				{
					case REGULAR_MATCH:
						re_result = regcomp_s(&((*app_info)[*info_count].http_match_info[j].re), (*app_info)[*info_count].http_match_info[j].data, (*app_info)[*info_count].http_match_info[j].data_len, REG_DOTALL);
						if(re_result)
						{
							pr_warning("[AngelIDS][DPI] Initalize http match data at line %d:%d failed, regex compile failed with code %d, match_method fallback to NO_FIXED_DATA_MATCH\n", rules_array_item, i, re_result);
							kfree((*app_info)[*info_count].http_match_info[j].data);
							(*app_info)[*info_count].http_match_info[j].data = NULL;
							(*app_info)[*info_count].http_match_info[j].data_len = 0;
							(*app_info)[*info_count].http_match_info[j].match_method = 2;
						}
						break;
					case BM_MATCH_STR:
						// pr_info("[AngelIDS][DPI] Initalize http bm, data: [%s], length: %d\n", (*app_info)[*info_count].http_match_info[j].data, (*app_info)[*info_count].http_match_info[j].data_len);
						(*app_info)[*info_count].http_match_info[j].bm = aids_bm_init((*app_info)[*info_count].http_match_info[j].data, (*app_info)[*info_count].http_match_info[j].data_len, 0);
						if((*app_info)[*info_count].http_match_info[j].bm == NULL)
						{
							pr_warning("[AngelIDS][DPI] Initalize http match data at line %d:%d failed, bm memory not enough, match_method fallback to NO_FIXED_DATA_MATCH\n", rules_array_item, i);
							kfree((*app_info)[*info_count].http_match_info[j].data);
							(*app_info)[*info_count].http_match_info[j].data = NULL;
							(*app_info)[*info_count].http_match_info[j].data_len = 0;
							(*app_info)[*info_count].http_match_info[j].match_method = 2;
						}
						break;
				}
				
				// finish
				j += 1;
			}
		}
		else
		{	
			// proto
			cJSON_GetItemAndCheck(rules_item, read_temp, "proto", cJSON_Number, rules_array_item);
			(*app_info)[*info_count].proto = read_temp->valueint;
			
			// match_method
			cJSON_GetItemAndCheck(rules_item, read_temp, "match_method", cJSON_Number, rules_array_item);
			(*app_info)[*info_count].match_method = read_temp->valueint;
			
			// port range & count
			read_temp_array = cJSON_GetObjectItem(rules_item, "port_range");
			if(read_temp_array == NULL || read_temp_array->type != cJSON_Array)
			{
				(*app_info)[*info_count].port_range_count = 0;
				(*app_info)[*info_count].port_range = NULL;
			}
			else
			{
				(*app_info)[*info_count].port_range_count = cJSON_GetArraySize(read_temp_array);
				(*app_info)[*info_count].port_range = (u16 *)kmalloc((*app_info)[*info_count].port_range_count * sizeof(u16) * 2, GFP_KERNEL);
				if((*app_info)[*info_count].port_range == NULL)
				{
					pr_warning("[AngelIDS][DPI] Initalize port_range at line %d failed, memory not enough, fallback it to zero\n", rules_array_item);
					(*app_info)[*info_count].port_range_count = 0;
				}
				else
				{
					j = 0;
					for(i = 0; i < cJSON_GetArraySize(read_temp_array); i++)
					{
						read_temp_array_item = cJSON_GetArrayItem(read_temp_array, i);
						if(read_temp_array_item == NULL || read_temp_array_item->type != cJSON_Array)
						{
							pr_warning("[AngelIDS][DPI] Initalize port_range at line %d:%d failed, object not available\n", rules_array_item, i);
							(*app_info)[*info_count].port_range_count -= 1;
							continue;
						}
						read_temp = cJSON_GetArrayItem(read_temp_array_item, 0);
						if(read_temp == NULL || read_temp->type != cJSON_Number)
						{
							pr_warning("[AngelIDS][DPI] Initalize port_range at line %d:%d failed, data not valid #1\n", rules_array_item, i);
							(*app_info)[*info_count].port_range_count -= 1;
							continue;
						}
						(*app_info)[*info_count].port_range[j * 2] = read_temp->valueint;
						if((*app_info)[*info_count].port_range[j * 2] < 0 || (*app_info)[*info_count].port_range[j * 2] > 65535)
						{
							pr_warning("[AngelIDS][DPI] Initalize port_range at line %d:%d failed, data not in range #1, fallback it to zero\n", rules_array_item, i);
							(*app_info)[*info_count].port_range[j * 2] = 0;
						}
						read_temp = cJSON_GetArrayItem(read_temp_array_item, 1);
						if(read_temp == NULL || read_temp->type != cJSON_Number)
						{
							pr_warning("[AngelIDS][DPI] Initalize port_range at line %d:%d failed, data not valid #2\n", rules_array_item, i);
							(*app_info)[*info_count].port_range_count -= 1;
							continue;
						}
						(*app_info)[*info_count].port_range[j * 2 + 1] = read_temp->valueint;
						if((*app_info)[*info_count].port_range[j * 2 + 1] < (*app_info)[*info_count].port_range[j * 2] || (*app_info)[*info_count].port_range[j * 2 + 1] > 65535)
						{
							pr_warning("[AngelIDS][DPI] Initalize port_range at line %d:%d failed, data not in range #2, fallback it to %u\n", rules_array_item, i, (*app_info)[*info_count].port_range[j * 2]);
							(*app_info)[*info_count].port_range[j * 2 + 1] = (*app_info)[*info_count].port_range[j * 2];
						}
						j += 1;
					}
				}
			}
			
			// len range & count
			read_temp_array = cJSON_GetObjectItem(rules_item, "len_range");
			if(read_temp_array == NULL || read_temp_array->type != cJSON_Array)
			{
				(*app_info)[*info_count].len_range_count = 0;
				(*app_info)[*info_count].len_range = NULL;
			}
			else
			{
				(*app_info)[*info_count].len_range_count = cJSON_GetArraySize(read_temp_array);
				(*app_info)[*info_count].len_range = (u16 *)kmalloc((*app_info)[*info_count].len_range_count * sizeof(u16) * 2, GFP_KERNEL);
				if((*app_info)[*info_count].len_range == NULL)
				{
					pr_warning("[AngelIDS][DPI] Initalize len_range at line %d failed, memory not enough, fallback it to zero\n", rules_array_item);
					(*app_info)[*info_count].len_range_count = 0;
				}
				else
				{
					j = 0;
					for(i = 0; i < cJSON_GetArraySize(read_temp_array); i++)
					{
						read_temp_array_item = cJSON_GetArrayItem(read_temp_array, i);
						if(read_temp_array_item == NULL || read_temp_array_item->type != cJSON_Array)
						{
							pr_warning("[AngelIDS][DPI] Initalize len_range at line %d:%d failed, object not available\n", rules_array_item, i);
							(*app_info)[*info_count].len_range_count -= 1;
							continue;
						}
						read_temp = cJSON_GetArrayItem(read_temp_array_item, 0);
						if(read_temp == NULL || read_temp->type != cJSON_Number)
						{
							pr_warning("[AngelIDS][DPI] Initalize len_range at line %d:%d failed, data not valid #1\n", rules_array_item, i);
							(*app_info)[*info_count].len_range_count -= 1;
							continue;
						}
						(*app_info)[*info_count].len_range[j * 2] = read_temp->valueint;
						if((*app_info)[*info_count].len_range[j * 2] < 0 || (*app_info)[*info_count].len_range[j * 2] > 1500)
						{
							pr_warning("[AngelIDS][DPI] Initalize len_range at line %d:%d failed, data not in range #1, fallback it to zero\n", rules_array_item, i);
							(*app_info)[*info_count].len_range[j * 2] = 0;
						}
						read_temp = cJSON_GetArrayItem(read_temp_array_item, 1);
						if(read_temp == NULL || read_temp->type != cJSON_Number)
						{
							pr_warning("[AngelIDS][DPI] Initalize len_range at line %d:%d failed, data not valid #2\n", rules_array_item, i);
							(*app_info)[*info_count].len_range_count -= 1;
							continue;
						}
						(*app_info)[*info_count].len_range[j * 2 + 1] = read_temp->valueint;
						if((*app_info)[*info_count].len_range[j * 2 + 1] < (*app_info)[*info_count].len_range[j * 2] || (*app_info)[*info_count].len_range[j * 2 + 1] > 1500)
						{
							pr_warning("[AngelIDS][DPI] Initalize len_range at line %d:%d failed, data not in range #2, fallback it to %u\n", rules_array_item, i, (*app_info)[*info_count].len_range[j * 2]);
							(*app_info)[*info_count].len_range[j * 2 + 1] = (*app_info)[*info_count].len_range[j * 2];
						}
						j += 1;
					}
				}
			}
			
			// multi_dst_addr & count
			read_temp_array = cJSON_GetObjectItem(rules_item, "dst_addr");
			if(read_temp_array == NULL || read_temp_array->type != cJSON_Array)
			{
				(*app_info)[*info_count].multi_dst_addr_count = 0;
				(*app_info)[*info_count].multi_dst_addr = NULL;
			}
			else
			{
				(*app_info)[*info_count].multi_dst_addr_count = cJSON_GetArraySize(read_temp_array);
				(*app_info)[*info_count].multi_dst_addr = (u32 *)kmalloc((*app_info)[*info_count].multi_dst_addr_count * sizeof(u32), GFP_KERNEL);
				if((*app_info)[*info_count].multi_dst_addr == NULL)
				{
					pr_warning("[AngelIDS][DPI] Initalize multi_dst_addr at line %d failed, memory not enough, fallback it to zero\n", rules_array_item);
					(*app_info)[*info_count].multi_dst_addr_count = 0;
				}
				else
				{
					j = 0;
					for(i = 0; i < cJSON_GetArraySize(read_temp_array); i++)
					{
						read_temp_array_item = cJSON_GetArrayItem(read_temp_array, i);
						if(read_temp_array_item == NULL || read_temp_array_item->type != cJSON_Number)
						{
							pr_warning("[AngelIDS][DPI] Initalize multi_dst_addr at line %d:%d failed, data not available\n", rules_array_item, i);
							(*app_info)[*info_count].multi_dst_addr_count -= 1;
							continue;
						}
						(*app_info)[*info_count].multi_dst_addr[j] = read_temp_array_item->valueint;
						j += 1;
					}
				}
			}
			
			// multi_subnet & count
			read_temp_array = cJSON_GetObjectItem(rules_item, "subnet");
			if(read_temp_array == NULL || read_temp_array->type != cJSON_Array)
			{
				(*app_info)[*info_count].multi_subnet_count = 0;
				(*app_info)[*info_count].multi_subnet = NULL;
			}
			else
			{
				(*app_info)[*info_count].multi_subnet_count = cJSON_GetArraySize(read_temp_array);
				(*app_info)[*info_count].multi_subnet = (struct MultiSubnet *)kmalloc((*app_info)[*info_count].multi_subnet_count * sizeof(struct MultiSubnet), GFP_KERNEL);
				if((*app_info)[*info_count].multi_subnet == NULL)
				{
					pr_warning("[AngelIDS][DPI] Initalize multi_subnet at line %d failed, memory not enough, fallback it to zero\n", rules_array_item);
					(*app_info)[*info_count].multi_subnet_count = 0;
				}
				else
				{
					j = 0;
					for(i = 0; i < cJSON_GetArraySize(read_temp_array); i++)
					{
						read_temp_array_item = cJSON_GetArrayItem(read_temp_array, i);
						if(read_temp_array_item == NULL || read_temp_array_item->type != cJSON_Object)
						{
							pr_warning("[AngelIDS][DPI] Initalize multi_subnet at line %d:%d failed, object not available\n", rules_array_item, i);
							(*app_info)[*info_count].multi_subnet_count -= 1;
							continue;
						}
						read_temp = cJSON_GetObjectItem(read_temp_array_item, "net");
						if(read_temp == NULL || read_temp->type != cJSON_Number)
						{
							pr_warning("[AngelIDS][DPI] Initalize multi_subnet at line %d:%d failed, net not available\n", rules_array_item, i);
							(*app_info)[*info_count].multi_subnet_count -= 1;
							continue;
						}
						(*app_info)[*info_count].multi_subnet[j].net = read_temp->valueint;
						read_temp = cJSON_GetObjectItem(read_temp_array_item, "mask");
						if(read_temp == NULL || read_temp->type != cJSON_Number)
						{
							pr_warning("[AngelIDS][DPI] Initalize multi_subnet at line %d:%d failed, mask not available\n", rules_array_item, i);
							(*app_info)[*info_count].multi_subnet_count -= 1;
							continue;
						}
						(*app_info)[*info_count].multi_subnet[j].mask = read_temp->valueint;
						j += 1;
					}
				}
			}
			
			// data
			read_temp_array = cJSON_GetObjectItem(rules_item, "data");
			if(read_temp_array == NULL || read_temp_array->type != cJSON_Array)
			{
				(*app_info)[*info_count].data = NULL;
				(*app_info)[*info_count].data_len = 0;
				if((*app_info)[*info_count].match_method != 2)
				{
					pr_warning("[AngelIDS][DPI] Initalize match data at line %d failed, match_method fallback to NO_FIXED_DATA_MATCH\n", rules_array_item);
					(*app_info)[*info_count].match_method = 2;
				}
			}
			else
			{
				(*app_info)[*info_count].data_len = cJSON_GetArraySize(read_temp_array);
				(*app_info)[*info_count].data = (char *)kmalloc(((*app_info)[*info_count].data_len + 1) * sizeof(char), GFP_KERNEL);
				if((*app_info)[*info_count].data == NULL)
				{
					pr_warning("[AngelIDS][DPI] Initalize match data at line %d failed with memory not enough, match_method fallback to NO_FIXED_DATA_MATCH\n", rules_array_item);
					(*app_info)[*info_count].data_len = 0;
					(*app_info)[*info_count].match_method = 2;
				}
				else
				{
					for(i = 0; i < cJSON_GetArraySize(read_temp_array); i++)
					{
						read_temp_array_item = cJSON_GetArrayItem(read_temp_array, i);
						if(read_temp_array_item == NULL || read_temp_array_item->type != cJSON_Number)
						{
							pr_warning("[AngelIDS][DPI] Initalize match data at line %d:%d failed, data not valid, match_method fallback to NO_FIXED_DATA_MATCH\n", rules_array_item, i);
							kfree((*app_info)[*info_count].data);
							(*app_info)[*info_count].data = NULL;
							(*app_info)[*info_count].data_len = 0;
							(*app_info)[*info_count].match_method = 2;
							break;
						}
						else if(read_temp_array_item->valueint < 0 || read_temp_array_item->valueint > 255)
						{
							pr_warning("[AngelIDS][DPI] Initalize match data at line %d:%d failed, data not in range, match_method fallback to NO_FIXED_DATA_MATCH\n", rules_array_item, i);
							kfree((*app_info)[*info_count].data);
							(*app_info)[*info_count].data = NULL;
							(*app_info)[*info_count].data_len = 0;
							(*app_info)[*info_count].match_method = 2;
							break;
						}
						(*app_info)[*info_count].data[i] = read_temp_array_item->valueint;
					}
					(*app_info)[*info_count].data[(*app_info)[*info_count].data_len] = '\x00';
				}
			}
			
			// process match_method
			switch((*app_info)[*info_count].match_method)
			{
				case REGULAR_MATCH:
					re_result = regcomp_s(&((*app_info)[*info_count].re), (*app_info)[*info_count].data, (*app_info)[*info_count].data_len, REG_DOTALL);
					if(re_result)
					{
						pr_warning("[AngelIDS][DPI] Initalize match data at line %d failed, regex compile failed with code %d, match_method fallback to NO_FIXED_DATA_MATCH\n", rules_array_item, re_result);
						kfree((*app_info)[*info_count].data);
						(*app_info)[*info_count].data = NULL;
						(*app_info)[*info_count].data_len = 0;
						(*app_info)[*info_count].match_method = 2;
					}
					break;
				case BM_MATCH_STR:
					(*app_info)[*info_count].bm = aids_bm_init((*app_info)[*info_count].data, (*app_info)[*info_count].data_len, 0);
					if((*app_info)[*info_count].bm == NULL)
					{
						pr_warning("[AngelIDS][DPI] Initalize match data at line %d failed, bm memory not enough, match_method fallback to NO_FIXED_DATA_MATCH\n", rules_array_item);
						kfree((*app_info)[*info_count].data);
						(*app_info)[*info_count].data = NULL;
						(*app_info)[*info_count].data_len = 0;
						(*app_info)[*info_count].match_method = 2;
					}
					break;
			}
		}
		
		// finish
		*info_count += 1;
	}
	
	cJSON_Delete(rulefile_json);
	return 0;
ERROR_WHEN_READING:
	cJSON_Delete(rulefile_json);
	return -EINVAL;
ERROR_WHEN_NO_MEM:
	cJSON_Delete(rulefile_json);
	return -ENOMEM;
}

int aids_reload_rules_file(struct aids_app_info** app_info, u32* info_count, u16* max_seq)
{
	char *buf;
	loff_t file_size;
	int status;
	if(status = aids_rulesfile_open(&buf, &file_size))
	{
		pr_warning("[AngelIDS][DPI] Failed to load rules file: %d\n", status);
		return status;
	}
	pr_info("[AngelIDS][DPI] Parsing rules configuration file...\n");
	if(status = aids_rulesfile_doreload(buf, file_size, app_info, info_count, max_seq))
	{
		pr_warning("[AngelIDS][DPI] Failed to parse rules file: %d\n", status);
		aids_rulesfile_free(buf);
		return status;
	}
	pr_info("[AngelIDS][DPI] Rules configuration file initalized with %u rules, max_seq: %u\n", *info_count, *max_seq);
	aids_rulesfile_free(buf);
	return 0;
}
