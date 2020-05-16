#ifndef AIDS_RULESFILE_H
#define AIDS_RULESFILE_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include "appinfo.h"

#define AIDS_RULESFILE_PATH "/etc/aids/aids_rules.json"

int aids_reload_rules_file(struct aids_app_info** app_info, u32* info_count, u16* max_seq);

#endif
