#include <linux/module.h>
#include <linux/init.h>
#include <net/genetlink.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include "LSP_netlink.h"
#include "../netfilter/LSP_rule.h"


extern struct rule_chain filter_rule_chain;

void add_rule_chain(struct LSP_filter_rule * rule, struct rule_chain *chain)
{
    down_write(&chain->rw_sem);

    list_add_tail(&rule->list, &chain->head);

    up_write(&chain->rw_sem);
}

int add_rule(struct sk_buff *skb, struct genl_info *info)
{
    struct nlmsghdr * nlh;
    struct nlattr * nla;
    struct LSP_filter_rule * rule;
    __be32 start = 0;
    __be32 end = 0;
    __be16 sport = 0;
    __be16 dport = 0;
    __u8 protocol= 0;
    unsigned int re;
    int flag;
    
    nlh = (struct nlmsghdr *)(skb->data);
    nla = (struct nlattr *)GENLMSG_DATA(nlh);
    
    flag = *(__u8 *)NLA_DATA(nla);
    nla = NLA_NEXT(nla);
    re = *(unsigned int *)NLA_DATA(nla);
    
    switch(flag)
    {

        case LSP_FLTPLC_S_ADDR_S:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_S_ADDR_M:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            end = *(__be32 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_D_ADDR_S:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_D_ADDR_M:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            end = *(__be32 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_DPORT:
            nla = NLA_NEXT(nla);
            dport = *(__be16 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_PROTO:
            nla = NLA_NEXT(nla);
            protocol = *(__u8 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_S_ADDR_AND_DPORT_S:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            dport = *(__u8 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_S_ADDR_AND_DPORT_M:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            end = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            dport = *(__u8 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_S_ADDR_AND_PROTO_S:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            protocol = *(__u8 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_S_ADDR_AND_PROTO_M:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            end = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            protocol = *(__u8 *)NLA_DATA(nla);
            break;
  
        case LSP_FLTPLC_D_ADDR_AND_DPORT_S:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            dport = *(__u8 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_D_ADDR_AND_DPORT_M:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            end = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            dport = *(__u8 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_D_ADDR_AND_PROTO_S:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            protocol = *(__u8 *)NLA_DATA(nla);
            break;

        case LSP_FLTPLC_D_ADDR_AND_PROTO_M:
            nla = NLA_NEXT(nla);
            start = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            end = *(__be32 *)NLA_DATA(nla);
            nla = NLA_NEXT(nla);
            protocol = *(__u8 *)NLA_DATA(nla);
            break;

        default:
            printk(KERN_ALERT "[LSP] unknown flag\n");
            return -1;
            break;
    }

    rule = (struct LSP_filter_rule *)kmalloc(sizeof(struct LSP_filter_rule),GFP_KERNEL);
    rule->re = re;
    rule->flag = flag;
    rule->start = start;
    rule->end = end;
    rule->sport = sport;
    rule->dport = dport;
    rule->protocol = protocol;
    
    add_rule_chain(rule, &filter_rule_chain);

    return 1;

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

int LSP_netlink_init(void)
{
    int re = 0;
    re = LSP_register_netlink();
    
    if(re < 0)
        printk(KERN_ALERT "register netlink error\n");
    
    return re;
}

void LSP_netlink_exit(void)
{
    genl_unregister_family(&LSP_genl_family);
}

//module_init(netlink_init)
//module_exit(netlink_exit)

