#ifndef AIDS_APPIDMATCH_H
#define AIDS_APPIDMATCH_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include "appinfo.h"
#include "packageinfo.h"

extern struct kmem_cache *aids_cache_packageinfo __read_mostly;

int aids_init_app_match(void);
u32 aids_get_app_id(struct aids_package_info* package_info);
void aids_clean_app_match(void);
void aids_app_match_deinit(void);
void aids_package_info_cleanup(struct aids_package_info* package_info);

#endif