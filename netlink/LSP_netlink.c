#include <linux/module.h>
#include <linux/init.h>
#include <net/genetlink.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include "LSP_netlink.h"


int add_rule(struct sk_buff *skb, struct genl_info *info)
{
    int remaining;
    printk(KERN_ALERT "[LSP] recv LSP_NL_ADD cmd, seq:%d pid:%d, nlmsg_len:%d, nlmsg_pid:%d, cmd:%d\n",info->snd_seq,
                        info->snd_portid, info->nlhdr->nlmsg_len, info->nlhdr->nlmsg_pid, info->genlhdr->cmd);

    struct nlattr *nla1, *nla2;
    if(NULL == (nla1 = info->attrs[0]))
        printk(KERN_ALERT "[LSP] first is NULL\n");
    if(NULL == (nla2 = info->attrs[1]))
        printk(KERN_ALERT "[LSP] second is NULL\n");

    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    struct nlattr *gnla;
    
    nlh = (struct nlmsghdr *)skb->data;
    gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    gnla = (struct nlattr *)genlmsg_data(gnlh);
    
    remaining = genlmsg_len(gnlh);
    

    if(info->attrs[2] == NULL)
    {
        printk(KERN_ALERT "[LSP] end by NULL");
    }
    printk(KERN_ALERT "[LSP] first: %s second: %s \n", (char *)NLA_DATA(gnla), (char *)NLA_DATA((char *)gnla + NLA_ALIGN(gnla->nla_len)));

    return 0;
}

int del_rule(struct sk_buff *skb, struct genl_info *info)
{
    return 0;
}
int del_all_rule(struct sk_buff *skb, struct genl_info *info)
{
   return 0;
}
struct genl_family LSP_genl_family = {
    .id = GENL_ID_GENERATE,
    .hdrsize = 0,
    .maxattr = MAXATTR,
    .netnsok = true,
    .name = "test_family",
};

struct genl_ops LSP_genl_ops[MAXATTR] = {
{
    .cmd = LSP_NL_ADD,
    .flags = GENL_CMD_CAP_DO,
    .doit = add_rule,
},

{
    .cmd = LSP_NL_DEL,
    .flags = GENL_CMD_CAP_DO,
    .doit = del_rule,
},

{
    .cmd = LSP_NL_DEL_ALL,
    .flags = GENL_CMD_CAP_DO,
    .doit = del_all_rule,
}
};

static int LSP_register_netlink(void)
{
    int re = 0;

    re = genl_register_family_with_ops(&LSP_genl_family, LSP_genl_ops);
    
    return re;
}

static int test_init(void)
{
    int re = 0;
    re = LSP_register_netlink();
    
    if(re < 0)
        printk(KERN_ALERT "register netlink error\n");
    
    return re;
}

static void test_exit(void)
{
    genl_unregister_family(&LSP_genl_family);
}

module_init(test_init)
module_exit(test_exit)

