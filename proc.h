#ifndef AIDS_PROC_H
#define AIDS_PROC_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#define AIDS_PROC_DIR_NAME "aids_dpi"
#define AIDS_PROC_FILE_NAME_CONNCOUNT "conncount"
#define AIDS_PROC_FILE_NAME_CONNLIST "connlist"

extern struct proc_dir_entry *g_aids_proc_dir;

int proc_init(void);
void proc_deinit(void);

#endif
