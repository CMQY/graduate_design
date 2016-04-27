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

LIST_HEAD(filterListChain);     /*      filter rule list head  */

unsigned int LSP_filterIn(struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    int i = 0;
    unsigned int re = FILTER_DEF_RE;
    struct LSP_filterRule * rule = NULL;

    struct iphdr *iph = NULL;
    void *l4hdr = NULL;

    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;

    iph=ip_hdr(skb);

    saddr = iph->saddr;
    daddr = iph->daddr;
    protocol = iph->protocol;

    switch(protocol)
    {
    case IPPROTO_TCP:
        printk(KERN_ALERT PREFIX"TCP\n");
        l4hdr = (void *)tcp_hdr(skb);
        sport = ((struct tcphdr *)l4hdr)->source;
        dport = ((struct tcphdr *)l4hdr)->dest;
        break;
    case IPPROTO_UDP:
        printk(KERN_ALERT PREFIX"UDP\n");
        l4hdr = (void *)udp_hdr(skb);
        sport = ((struct udphdr *)l4hdr)->source;
        dport = ((struct udphdr *)l4hdr)->dest;
        break;
    default:
        return FILTER_DEF_RE;
    }
    
    
    printk(KERN_ALERT PREFIX"should be execute, and executed\n");
    
    list_for_each_entry(rule,&filterListChain,list)
    {
        printk(KERN_ALERT PREFIX"shouldn't be execute, but executed\n");

        i=1;

        if(IS_SADDR_SING(rule->flag))
        {
            if(saddr == rule->saddrStart)
                re = rule->re;
        }
        if(IS_DADDR_SING(rule->flag))
        {
            if(daddr == rule->daddrStart)
                re = rule->re;
        }
        if(IS_SADDR_MULT(rule->flag))
        {
            if(saddr >= ntohl(rule->saddrStart) && saddr <= ntohl(rule->saddrEnd))
            {
                re = rule->re;
            }
        }
        if(IS_DADDR_MULT(rule->flag))
        {
            if(daddr >= ntohl(rule->daddrStart) && daddr <= ntohl(rule->daddrEnd))
            re = rule->re;
        }
        if(IS_SPORT(rule->flag))
        {
            if(sport == rule->sport)
            re = rule->re;
        }
        if(IS_DPORT(rule->flag))
        {
            if(dport == rule->dport)
            re = rule->re;
        }

    }
    
    if(i == 1)
    {
        printk(KERN_ALERT PREFIX"shouldn't be execute, but executed\n");
    }

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
	nf_register_hooks(hops,5);
	return 0;
}

static void test_exit(void)
{
	nf_unregister_hooks(hops,5);
}

module_init(test_init)
module_exit(test_exit)
