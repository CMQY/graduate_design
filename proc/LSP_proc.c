#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include "../netfilter/LSP_rule.h"

#define BUFF_LEN 128
extern struct rule_chain filter_rule_chain;

char buff[BUFF_LEN];
int seq;
struct list_head *list;

void * LSP_start(struct seq_file *m, loff_t *ops)
{
    if(*ops > 0)
        return NULL;
    seq = 1;

    snprintf(buff, BUFF_LEN, "seq    flag    re    start    end    dport    protocol\n");
    list = filter_rule_chain.head.next;
    return buff;
}

void LSP_stop(struct seq_file *m, void *v)
{
}

void * LSP_next(struct seq_file *m, void *v, loff_t *ops)
{
    struct LSP_filter_rule *rule = NULL;

    if(list != &filter_rule_chain.head)
    {
        rule = container_of(list, struct LSP_filter_rule, list);
        snprintf(buff, BUFF_LEN, "%d %d %d %pI4 %pI4 %d %d\n", seq, rule->flag, rule->re, &rule->start, &rule->end, \
                    rule->dport, rule->protocol);
        seq++;
        list = list->next;
        return buff;
    }
    else
    {
        return NULL;
    }
}

int LSP_show(struct seq_file *m, void *v)
{
    seq_printf(m, (char *)v);
    return 0;
}

static struct seq_operations proc_seq_ops = 
{
    .start = LSP_start,
    .show = LSP_show,
    .next = LSP_next,
    .stop = LSP_stop,
};

int proc_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &proc_seq_ops);
}

static struct file_operations fops = 
{
    .owner = THIS_MODULE,
    .llseek = seq_lseek,
    .read = seq_read,
    .open = proc_open,
    .release = seq_release,
};

#define PROC_DIR_NAME "lsp_firewall"
#define PROC_RULE_NAME "rule"
#define PROC_ENABLE_NAME "enable"

struct proc_dir_entry *LSP_proc_dir;
struct proc_dir_entry *LSP_proc_rule_entry;

void LSP_proc_init(void)
{
    LSP_proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    LSP_proc_rule_entry = proc_create(PROC_RULE_NAME, S_IRUSR, LSP_proc_dir, &fops);
}

void LSP_proc_exit(void)
{
    proc_remove(LSP_proc_rule_entry);
    proc_remove(LSP_proc_dir);
}

