#ifndef _LSP_NETLINK_ 
#define _LSP_NETLINK_

/**
 * generic netlink commond
 */
enum {
    LSP_UNSPEC,
    LSP_NL_ADD,
    LSP_NL_DEL,
    LSP_NL_DEL_ALL,
    __LSP_CMD_MAX,
};

#define MAXATTR 3
#define LSP_CMD_MAX (__LSP_CMD_MAX-1)

#define NL_FML_NAME "test_family"


/**
 * struct operate
 */
#define GENLMSG_DATA(glh)       ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)    (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)            ((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)        (len - NLA_HDRLEN)
#define NLA_NEXT(nla)           ((void *)((char *)nla + NLA_ALIGN(nla->nla_len)))
#define NLA_LEN(payload_len)    (NLMSG_ALIGN(payload_len) + NLA_HDRLEN)


/**
 * generic netlink attribute type
 */
enum {
    LSP_ATTR_UNSPEC,
    LSP_ATTR_32,
    LSP_ATTR_16,
    LSP_ATTR_8,
    LSP_ATTR_STR,
    __LSP_ATTR_MAX,
};
#define LSP_ATTR_MAX (__LSP_ATTR_MAX-1)


/**
 * netfilter rule list head
 */
extern struct list_head filter_chain;


#endif
