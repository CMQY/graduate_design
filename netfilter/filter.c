#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <uapi/linux/in.h>      /*      protocol defined here */
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>

#include "LSP_rule.h"
#include "LSP_utils.h"

MODULE_AUTHOR("liaosp");
MODULE_LICENSE("Dual BSD/GPL");

#define PREFIX "[LSP]"
#define FILTER_DEF_RE NF_ACCEPT


unsigned int LSP_filterIn(struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    unsigned int re = FILTER_DEF_RE;
    struct LSP_filter_rule * rule = NULL;

    struct iphdr *iph = NULL;
    void *l4hdr = NULL;

    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;

    iph=ip_hdr(skb);

    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    protocol = iph->protocol;

    l4hdr = (void *)tcp_hdr(skb);
    sport = ntohs(((struct tcphdr *)l4hdr)->source);
    dport = ntohs(((struct tcphdr *)l4hdr)->dest);
    
    
    down_read(&(filter_rule_chain.rw_sem));
    list_for_each_entry(rule,&(filter_rule_chain.head),list)
    {
        switch(rule->flag)
        {
        case LSP_FLTPLC_S_ADDR_S:
            if(saddr == rule->start)
                re = rule->re;
            break;
    
        case LSP_FLTPLC_S_ADDR_M:
            if(saddr >= rule->start && saddr <= rule->end)
                re = rule->re;
            break;
    
        case LSP_FLTPLC_D_ADDR_S:
            if(daddr == rule->start)
                re = rule->re;
            break;
    
        case LSP_FLTPLC_D_ADDR_M:
            if(daddr >= rule->start && daddr <= rule->end)
                re = rule->re;
            break;
    
        case LSP_FLTPLC_DPORT:
            if(dport == rule->dport)
                re = rule->re;
            break;
    
        case LSP_FLTPLC_PROTO:
            if(protocol == rule->protocol)
                re = rule->re;
            break;
    
        case LSP_FLTPLC_S_ADDR_AND_DPORT_S:
            if(saddr == rule->start)
                if(dport == rule->dport)
                    re = rule->re;
            break;
    
        case LSP_FLTPLC_S_ADDR_AND_DPORT_M:
            if(saddr >= rule->start && saddr <= rule->end)
                if(dport == rule->dport)
                    re = rule->re;
            break;
    
        case LSP_FLTPLC_S_ADDR_AND_PROTO_S:
            if(saddr == rule->start)
                if(protocol == rule->protocol)
                    re = rule->re;
            break;
    
        case LSP_FLTPLC_S_ADDR_AND_PROTO_M:
            if(saddr >= rule->start && saddr <= rule->end)
                if(protocol == rule->protocol)
                    re = rule->re;
            break;
    
        case LSP_FLTPLC_D_ADDR_AND_DPORT_S:
            if(daddr == rule->start)
                if(dport == rule->dport)
                    re = rule->re;
            break;
    
        case LSP_FLTPLC_D_ADDR_AND_DPORT_M:
            if(daddr >= rule->start && daddr <= rule->end)
                if(dport == rule->dport)
                    re = rule->re;
            break;
    
        case LSP_FLTPLC_D_ADDR_AND_PROTO_S:
            if(daddr == rule->start)
                if(protocol == rule->protocol)
                    re = rule->re;
            break;
    
        case LSP_FLTPLC_D_ADDR_AND_PROTO_M:
            if(daddr >= rule->start && daddr <= rule->end)
                if(protocol == rule->protocol)
                    re = rule->re;
            break;
    
        default:
            break;
        }
    }
    up_read(&(filter_rule_chain.rw_sem));

    return re;
}

static unsigned int nf_pre_routing_fn(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
//    LSP_natPrerouting();
	return NF_ACCEPT;
}

static unsigned int nf_post_routing_fn(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{	
//    LSP_natPostrouting();
	return NF_ACCEPT;
}

static unsigned int nf_local_in_fn(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{	
    unsigned int re;
    struct iphdr *iph;
    iph=ip_hdr(skb);
    re = FILTER_DEF_RE;
    re = LSP_filterIn(skb, in, out);
	return re;
}

static unsigned int nf_local_out_fn(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{	
//    LSP_natOut();
//    LSP_filterOut();
	return NF_ACCEPT;
}

static unsigned int nf_forward_fn(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{	
//    LSP_filterForward();
    return NF_ACCEPT;
}



static struct nf_hook_ops hops[5] = {
{
	.hook=nf_pre_routing_fn,
	.owner=THIS_MODULE,
	.pf=NFPROTO_IPV4,	//uapi/linux/netfilter.h
	.hooknum=NF_INET_PRE_ROUTING,		//uapi/linux/netfilter_ipv4.h
	.priority=NF_IP_PRI_FILTER		//uapi/linux/netfilter_ipv4.h
},

{
	.hook=nf_post_routing_fn,
	.owner=THIS_MODULE,
	.pf=NFPROTO_IPV4,
	.hooknum=NF_INET_POST_ROUTING,		
	.priority=NF_IP_PRI_FILTER
},	

{
	.hook=nf_local_in_fn,
	.owner=THIS_MODULE,
	.pf=NFPROTO_IPV4,
	.hooknum=NF_INET_LOCAL_IN,		
	.priority=NF_IP_PRI_FILTER
},
	
{
	.hook=nf_local_out_fn,
	.owner=THIS_MODULE,
	.pf=NFPROTO_IPV4,
	.hooknum=NF_INET_LOCAL_OUT,		
	.priority=NF_IP_PRI_FILTER
},
	
{
	.hook=nf_forward_fn,
	.owner=THIS_MODULE,
	.pf=NFPROTO_IPV4,
	.hooknum=NF_INET_FORWARD,		
	.priority=NF_IP_PRI_FILTER
}
};


static int test_init(void)
{
    INIT_LIST_HEAD(&(filter_rule_chain.head));
    init_rwsem(&(filter_rule_chain.rw_sem));

	nf_register_hooks(hops,5);
	return 0;
}

static void test_exit(void)
{
	nf_unregister_hooks(hops,5);
}

module_init(test_init)
module_exit(test_exit)
