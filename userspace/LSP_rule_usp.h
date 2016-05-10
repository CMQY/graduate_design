#ifndef _LSP_RULE_
#define _LSP_RULE_

#include <linux/types.h>



/**
 * filter policy
 */
enum {
    LSP_FLTPLC_UNSPEC,
    LSP_FLTPLC_S_ADDR_S,
    LSP_FLTPLC_S_ADDR_M,
    LSP_FLTPLC_D_ADDR_S,
    LSP_FLTPLC_D_ADDR_M,
    LSP_FLTPLC_DPORT_AND_PROTO,
    LSP_FLTPLC_PROTO,
    LSP_FLTPLC_S_ADDR_AND_DPORT_AND_PROTO_S,
    LSP_FLTPLC_S_ADDR_AND_DPORT_AND_PROTO_M,
    LSP_FLTPLC_S_ADDR_AND_PROTO_S,
    LSP_FLTPLC_S_ADDR_AND_PROTO_M,
    LSP_FLTPLC_D_ADDR_AND_DPORT_AND_PROTO_S,
    LSP_FLTPLC_D_ADDR_AND_DPORT_AND_PROTO_M,
    LSP_FLTPLC_D_ADDR_AND_PROTO_S,
    LSP_FLTPLC_D_ADDR_AND_PROTO_M,
    __LSP_FLTPLC_MAX,
};
#define LSP_FLTPLC_MAX (__LSP_FLTPLC_MAX - 1)


/*************************************
 * user space controller commond 
 ************************************/

#define     LSP_RULE_DEL        (LSP_FLTPLC_MAX + 16)
#define     LSP_RULE_DEL_ALL    (LSP_FLTPLC_MAX + 17)


struct list_head {
        struct list_head *next, *prev;
};


struct LSP_filter_rule {
    struct list_head list;
    unsigned int re;
    __be32 start;
    __be32 end;
    __be16 dport;
    __be16 sport;
    __u8 protocol;
    __u8 flag;
};




#endif
