#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/genetlink.h>
#include <errno.h>

#include "LSP_netlink.h"
#include "LSP_genl_utils.h"
#include "../netfilter/LSP_rule.h"
#define BUFF_LEN 128

/************************************************************************************
 * send rule to kernel, must be called by user space shell, call this program 
 * carefully, it didn't check argments
 * 
 * arguments sequece
 * flag re start end dport protocol
 ************************************************************************************/
int main(int argc, char *argv[])
{
    char buff[BUFF_LEN];
    __be32 start;
    __be32 end;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    
    __be32 *start_p = NULL;
    __be32 *end_p = NULL;
    __be16 *sport_p = NULL;
    __be16 *dport_p = NULL;
    __u8 *protocol_p = NULL;

    unsigned int re;
    int flag;
    
    int ret = 0;
   
    int fm_id;
    int sk;
    struct sockaddr_nl dest_addr;
    
    sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    
    zero(&sockaddr_nl, sizeof(struct sockaddr_nl));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    if( (fm_id = get_family_id(sk, NL_FML_NAME, getpid())) < 0)
    {
        printf("get family id error\n");
        return -1;
    }

    re = atoi(argv[2]);
    flag = atoi(argv[1]);

    switch(flag)
    {
        case LSP_FLTPLC_S_ADDR_S:
            start = ntohl(inet_addr(argv[3]));
            start_p = &start;
            break;

        case LSP_FLTPLC_S_ADDR_M:
            start = ntohl(inet_addr(argv[3]));
            start_p = &start;
            end = ntohl(inet_addr(argv[4]));
            end_p = &end;
            break;

        case LSP_FLTPLC_D_ADDR_S:
            start = ntohl(inet_addr(argv[3]));
            start_p = &start;
            break;

        case LSP_FLTPLC_D_ADDR_M:
            start = ntohl(inet_addr(argv[3]));
            start_p = &start;
            end = ntohl(inet_addr(argv[4]));
            end_p = &end;
            break;

        case LSP_FLTPLC_DPORT:
            dport = ntohs((__u16)atoi(argv[3]));
            dport_p = &dport;
            break;

        case LSP_FLTPLC_PROTO:
            protocol = (__u8)atoi(argv[3]);
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_S_ADDR_AND_DPORT_S:
            start = ntohl(inet_addr(argv[3]));
            dport = ntohs((__u16)atoi(argv[4]));
            start_p = &start;
            dport_p = &dport;
            break;

        case LSP_FLTPLC_S_ADDR_AND_DPORT_M:
            start = ntohl(inet_addr(argv[3]));
            end = ntohl(inet_addr(argv[4]));
            dport = ntohs((__u16)atoi(argv[5]));
            start_p = &start;
            end_p = &end;
            dport_p = &dport;
            break;

        case LSP_FLTPLC_S_ADDR_AND_PROTO_S:
            start = ntohl(inet_addr(argv[3]));
            protocol = (__u16)atoi(argv[4]);
            start_p = &start;
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_S_ADDR_AND_PROTO_M:
            start = ntohl(inet_addr(argv[3]));
            end = ntohl(inet_addr(argv[4]));
            protocol = (__u16)atoi(argv[5]);
            start_p = &start;
            end_p = &end;
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_D_ADDR_AND_DPORT_S:
            start = ntohl(inet_addr(argv[3]));
            dport = ntohs((__u16)atoi(argv[4]));
            start_p = &start;
            dport_p = &dport;
            break;

        case LSP_FLTPLC_D_ADDR_AND_DPORT_M:
            start = ntohl(inet_addr(argv[3]));
            end = ntohl(inet_addr(argv[4]));
            dport = ntohs((__u16)atoi(argv[5]));
            start_p = &start;
            end_p = &end;
            dport_p = &dport;
            break;

        case LSP_FLTPLC_D_ADDR_AND_PROTO_S:
            start = ntohl(inet_addr(argv[3]));
            protocol = (__u16)atoi(argv[4]);
            start_p = &start;
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_D_ADDR_AND_PROTO_M:
            start = ntohl(inet_addr(argv[3]));
            end = ntohl(inet_addr(argv[4]));
            protocol = (__u16)atoi(argv[5]);
            start_p = &start;
            end_p = &end;
            protocol_p = &protocol;
            break;

        default:
            printf("unknow flag\n");
            return -1;
            break;
    }

    bzero(buff, BUFF_LEN);
    if( (ret = mk_rule(buff, BUFF_LEN, flag, start_p, end_p, sport_p, dport_p, protocol_p, re)) < 0)
    {
        printf("make rule error \n");
        return -1;
    }

    
    if( (ret = nl_send(sk, fm_id, NLM_F_REQUEST, 0, getpid(), LSP_NL_ADD, 1, buff, BUFF_LEN, &dest_addr, sizeof(dest_addr))) < 0)
    {
        printf("nl_send error\n");
        return -1;
    }

    return 0;

}
