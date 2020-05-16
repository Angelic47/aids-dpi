#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "aids.h"
#include "connlist.h"
#include "proc.h"

struct proc_dir_entry *g_aids_proc_dir = NULL;
struct proc_dir_entry *g_aids_proc_file_conncount = NULL;
struct proc_dir_entry *g_aids_proc_file_connlist = NULL;

static void *aids_seq_connlist_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	loff_t position;
	
	if (*pos == 0)
		return SEQ_START_TOKEN;
	
	position = *pos;
	aids_connlist_entry* entry = NULL;
	
	rcu_read_lock();
	
	list_for_each_entry_rcu(entry, &g_aids_connlist_head, link) {
		position -= 1;
		if(!position)
			break;
	}
	
	if(position)
		return NULL;
	return entry;
}

static void *aids_seq_connlist_next(struct seq_file *seq, void *v, loff_t *pos)
{
	aids_connlist_entry* entry = (aids_connlist_entry* )v;
	(*pos)++;
	if(v == SEQ_START_TOKEN)
		return aids_connlist_next(&g_aids_connlist_head);
	return aids_connlist_next(&entry->link);
}

static void aids_seq_connlist_stop(struct seq_file *seq, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

static int aids_seq_connlist_show(struct seq_file *seq, void *v)
{
	aids_connlist_entry* entry = (aids_connlist_entry*)v;
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "direct\tsrc\tdst\tprotocol\thttp\tstatus\tappid\tbegin\ttimeout\n");
		return 0;
	}
	seq_printf(seq, "%u\t%u.%u.%u.%u:%u\t%u.%u.%u.%u:%u\t%s\t%u\t%s\t%u\t%llu\t%llu\n", 
		entry->conn_info.direct,
		NIPQUAD(entry->conn_info.saddr), entry->conn_info.sport,
		NIPQUAD(entry->conn_info.daddr), entry->conn_info.dport,
		aids_get_proto_message(entry->conn_info.protocol),
		entry->conn_info.is_http,
		aids_get_connection_status_message(entry->conn_info.conn_status),
		entry->conn_info.appid,
		entry->conn_info.begintime,
		entry->conn_info.timeout
	);
	return 0;
}

static struct seq_operations aids_seq_connlist_ops = {
    .start = aids_seq_connlist_start,
    .next  = aids_seq_connlist_next,
    .stop  = aids_seq_connlist_stop,
    .show  = aids_seq_connlist_show
};

static int aids_connlist_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &aids_seq_connlist_ops);
}

static const struct file_operations g_aids_connlist_ops = {
	.owner   = THIS_MODULE,
	.open    = aids_connlist_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static void *aids_seq_conncount_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;

	return NULL;
}

static void *aids_seq_conncount_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

static void aids_seq_conncount_stop(struct seq_file *seq, void *v)
{
	// nothing
}

static int aids_seq_conncount_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%u\n", aids_connlist_get_count());
		return 0;
	}
	return 0;
}

static struct seq_operations aids_seq_conncount_ops = {
    .start = aids_seq_conncount_start,
    .next  = aids_seq_conncount_next,
    .stop  = aids_seq_conncount_stop,
    .show  = aids_seq_conncount_show
};

static int aids_conncount_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &aids_seq_conncount_ops);
}

static const struct file_operations g_aids_conncount_ops = {
	.owner   = THIS_MODULE,
	.open    = aids_conncount_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

int proc_init(void)
{
	pr_info("[AngelIDS][DPI] Creating proc directory\n");
	g_aids_proc_dir = proc_mkdir(AIDS_PROC_DIR_NAME, NULL);
	if(!g_aids_proc_dir)
	{
		pr_warning("[AngelIDS][DPI] Creating proc directory %s failed\n", AIDS_PROC_DIR_NAME);
		return -EINVAL;
	}
	g_aids_proc_file_conncount = proc_create(AIDS_PROC_FILE_NAME_CONNCOUNT, 0440, g_aids_proc_dir, &g_aids_conncount_ops);
	if(!g_aids_proc_file_conncount)
	{
		proc_remove(g_aids_proc_dir);
		pr_warning("[AngelIDS][DPI] Creating proc file %s/%s failed\n", AIDS_PROC_DIR_NAME, AIDS_PROC_FILE_NAME_CONNCOUNT);
		return -EINVAL;
	}
	g_aids_proc_file_connlist = proc_create(AIDS_PROC_FILE_NAME_CONNLIST, 0440, g_aids_proc_dir, &g_aids_connlist_ops);
	if(!g_aids_proc_file_connlist)
	{
		proc_remove(g_aids_proc_file_conncount);
		proc_remove(g_aids_proc_dir);
		pr_warning("[AngelIDS][DPI] Creating proc file %s/%s failed\n", AIDS_PROC_DIR_NAME, AIDS_PROC_FILE_NAME_CONNLIST);
		return -EINVAL;
	}
	return 0;
}

void proc_deinit(void)
{
	pr_info("[AngelIDS][DPI] Unlinking proc directory\n");
	if(g_aids_proc_file_connlist)
		proc_remove(g_aids_proc_file_connlist);
	if(g_aids_proc_file_conncount)
		proc_remove(g_aids_proc_file_conncount);
	if(g_aids_proc_dir)
		proc_remove(g_aids_proc_dir);
}
