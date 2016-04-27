#ifndef _LSP_RULE_
#define _LSP_RULE_

#include <linux/types.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>

#define S_ADDR_SING 1
#define S_ADDR_MULT 2
#define D_ADDR_SING 4
#define D_ADDR_MULT 8
#define S_PORT  16
#define D_PORT 32

#define IS_SADDR_SING(flag) (((flag) & S_ADDR_SING))
#define IS_DADDR_SING(flag) (((flag) & D_ADDR_SING))
#define IS_SADDR_MULT(flag) (((flag) & S_ADDR_MULT))
#define IS_DADDR_MULT(flag) (((flag) & D_ADDR_MULT))
#define IS_SPORT(flag) (((flag) & S_PORT))
#define IS_DPORT(flag) (((flag) & D_PORT))


struct LSP_filterRule {
    struct list_head list;
    unsigned int re;
    __be32 saddrStart;
    __be32 saddrEnd;
    __be32 daddrStart;
    __be32 daddrEnd; 
    __be16 dport;
    __be16 sport;
    __u8 protocol;
    __u8 flag;
};




#endif
