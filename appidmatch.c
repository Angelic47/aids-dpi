#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "appidmatch.h"
#include "packageinfo.h"
#include "appinfo.h"
#include "rulesfile.h"
#include "http_header_id.h"

static struct aids_app_info_list* app_info_list;
static struct aids_seg_tree_node* seg_tree_head;

struct kmem_cache *aids_cache_packageinfo __read_mostly;

void aids_package_info_cleanup(struct aids_package_info* package_info)
{
	aids_package_info_http_cleanup(package_info);
	kmem_cache_free(aids_cache_packageinfo, package_info);
}

int aids_init_app_match(void){
	struct aids_app_info* info;
	u32 info_count;
	u16 max_seq;
	
	int status;
	
	aids_cache_packageinfo = kmem_cache_create("aids_packageinfo", sizeof(struct aids_package_info), 0, 0, NULL);
	if(!aids_cache_packageinfo)
	{
		pr_err("[AngelIDS][DPI] Failed to kmem_cache_create aids_cache_packageinfo\n");
		return -ENOMEM;
	}
	
	if(status = aids_init_reg_http())
		return status;
	
	if(status = aids_httpheader_id_init()) {
		aids_deinit_reg_http();
		return status;
	}
	
	if(status = aids_reload_rules_file(&info, &info_count, &max_seq))
	{
		aids_httpheader_id_deinit();
		aids_deinit_reg_http();
		return status;
	}
	
	seg_tree_head = aids_create_seg_tree(0, 1501);
	app_info_list = NULL;
	
	aids_init_appinfo(max_seq);
	int i;
	for (i = 0; i < info_count; i++)
		aids_set_info_list_node(&app_info_list, info[i]);
	aids_init_seg_tree(seg_tree_head, app_info_list);
	
	vfree(info);
	return 0;
}

u32 aids_get_app_id(struct aids_package_info* package_info){
	u32 result;
	if (seg_tree_head == NULL || app_info_list == NULL) {
		pr_warning("[AngelIDS][DPI] aids_get_app_id: seg_tree_head %p,  app_info_list %p, can't match appid\n", seg_tree_head, app_info_list);
		return 0;
	}
	aids_http_reg_match(package_info);
	result = aids_seg_tree_get_appid(seg_tree_head, package_info);
	return result;
}

void aids_clean_app_match(void){
	if (seg_tree_head != NULL)
		aids_delete_seg_tree(seg_tree_head);
	if (app_info_list != NULL)
		aids_del_info_list(app_info_list);
}

void aids_app_match_deinit(void){
	aids_clean_app_match();
	aids_deinit_appinfo();
	aids_httpheader_id_deinit();
	aids_deinit_reg_http();
	kmem_cache_destroy(aids_cache_packageinfo);
}