#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <asm/uaccess.h>
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

    snprintf(buff, BUFF_LEN, "seq   flag   re        start           end       dport    protocol\n");
    list = filter_rule_chain.head.next;
    return buff;
}

void LSP_stop(struct seq_file *m, void *v)
{
}

void * LSP_next(struct seq_file *m, void *v, loff_t *ops)
{
    struct LSP_filter_rule *rule = NULL;
        __be32 start;
        __be32 end;
        __be16 dport;

    if(list != &filter_rule_chain.head)
    {
        rule = container_of(list, struct LSP_filter_rule, list);
        start = htonl(rule->start);
        end = htonl(rule->end);
        dport = rule->dport;
        snprintf(buff, BUFF_LEN, " %d\t%d\t%d\t%pI4\t%pI4\t%d\t%d\n", seq, rule->flag, rule->re, &start, &end, \
                    dport, rule->protocol);
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

static struct file_operations rule_fops = 
{
    .owner = THIS_MODULE,
    .llseek = seq_lseek,
    .read = seq_read,
    .open = proc_open,
    .release = seq_release,
};

extern int lsp_switch;
ssize_t read(struct file *fp, char __user *user, size_t size, loff_t *off)
{
    int re = 0;
    if(*off == 0)
    {
        if(lsp_switch == 1)
            re = copy_to_user(user, "1\n", 2);
        else
            re = copy_to_user(user, "0\n", 2);
        *off = 2;
        return 2;
    }
    else 
        return 0;
}

ssize_t write(struct file *fp, const char __user *user, size_t count, loff_t *off)
{
    int re = 0;
    char buff;
    if(count > 2)
        return count;

    re = copy_from_user(&buff, user, 1);
    if(buff == '1')
    {
        lsp_switch = 1;
    }
    else if(buff == '0')
    {
        lsp_switch = 0;
    }
    return count;
    
}

static struct file_operations enable_fops =
{
    .owner = THIS_MODULE,
    .write = write,
    .read = read,
};

#define PROC_DIR_NAME "lsp_firewall"
#define PROC_RULE_NAME "rule"
#define PROC_ENABLE_NAME "enable"

struct proc_dir_entry *LSP_proc_dir;
struct proc_dir_entry *LSP_proc_rule_entry;
struct proc_dir_entry *LSP_proc_enable_entry;

void LSP_proc_init(void)
{
    LSP_proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    LSP_proc_rule_entry = proc_create(PROC_RULE_NAME, S_IRUSR, LSP_proc_dir, &rule_fops);
    LSP_proc_enable_entry = proc_create(PROC_ENABLE_NAME, S_IRUSR|S_IWUSR, LSP_proc_dir, &enable_fops);
}

void LSP_proc_exit(void)
{
    proc_remove(LSP_proc_rule_entry);
    proc_remove(LSP_proc_enable_entry);
    proc_remove(LSP_proc_dir);
}

