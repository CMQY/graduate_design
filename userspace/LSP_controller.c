#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/genetlink.h>
#include <errno.h>


#include "../netlink/LSP_netlink.h"
#include "LSP_genl_utils.h"
#include "LSP_rule_usp.h"
#define BUFF_LEN 128

/************************************************************************************
 * send rule to kernel, must be called by user space shell, call this program 
 * carefully, it didn't check argments
 * 
 * arguments sequece
 * flag re start end dport protocol
 ************************************************************************************/

static int del_rule(char *buff, unsigned int num, int sk, int fm_id, struct sockaddr *dest_addr)
{
    int re = 0;

    if( (re = mk_rule(buff, BUFF_LEN, LSP_RULE_DEL, NULL, NULL, NULL, NULL, NULL, num)) < 0)
    {
        printf("mk_rule error\n");
        return -1;
    }
    
    if( (re = nl_send(sk, fm_id, NLM_F_REQUEST, 0, getpid(), LSP_NL_DEL, 1, buff, BUFF_LEN, dest_addr, sizeof(struct sockaddr))) < 0 )
    {
        printf("nl_send\n");
        return -1;
    }

    return 0;
}

static int del_all_rule(char *buff, int sk, int fm_id, struct sockaddr *dest_addr)
{
    int re = 0;
    if( (re = mk_rule(buff, BUFF_LEN, LSP_RULE_DEL_ALL, NULL, NULL, NULL, NULL, NULL, -1)) < 0)
    {
        printf("mk_rule error\n");
        return -1;
    }
    
    if( (re = nl_send(sk, fm_id, NLM_F_REQUEST, 0, getpid(), LSP_NL_DEL_ALL, 1, buff, BUFF_LEN, dest_addr, sizeof(struct sockaddr))) < 0 )
    {
        printf("nl_send\n");
        return -1;
    }

    return 0;

}


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
    
    bzero(buff, BUFF_LEN);

    bzero(&dest_addr, sizeof(struct sockaddr_nl));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    if( (fm_id = get_family_id(sk, NL_FML_NAME, getpid())) < 0)
    {
        printf("get family id error\n");
        return -1;
    }

    if(argc > 2)
    {
        re = atoi(argv[2]);
    }
    flag = atoi(argv[1]);

    switch(flag)
    {
        case LSP_RULE_DEL:          /* del rule from the chain, i didn't concern about it before, so i can only implement here  */
            return del_rule(buff, re, sk, fm_id, (struct sockaddr *)&dest_addr);

        case LSP_RULE_DEL_ALL:
            return del_all_rule(buff, sk, fm_id, (struct sockaddr *)&dest_addr);


        case LSP_FLTPLC_S_ADDR_S:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            start_p = &start;
            break;

        case LSP_FLTPLC_S_ADDR_M:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            start_p = &start;
            end = ntohl(inet_addr(argv[4]));
            //end = inet_addr(argv[4]);
            end_p = &end;
            printf("%s %s\n", argv[3], argv[4]);
            break;

        case LSP_FLTPLC_D_ADDR_S:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            start_p = &start;
            break;

        case LSP_FLTPLC_D_ADDR_M:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            start_p = &start;
            end = ntohl(inet_addr(argv[4]));
            //end = inet_addr(argv[4]);
            end_p = &end;
            break;

        case LSP_FLTPLC_DPORT_AND_PROTO:
            //dport = htons((__be16)atoi(argv[3]));
            dport = (__be16)atoi(argv[3]);
            dport_p = &dport;
            protocol = (__u8)atoi(argv[4]);
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_PROTO:
            protocol = (__u8)atoi(argv[3]);
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_S_ADDR_AND_DPORT_AND_PROTO_S:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            //dport = htons((__be16)atoi(argv[4]));
            dport = (__be16)atoi(argv[4]);
            protocol = (__u8)atoi(argv[5]);
            protocol_p = &protocol;
            start_p = &start;
            dport_p = &dport;
            break;

        case LSP_FLTPLC_S_ADDR_AND_DPORT_AND_PROTO_M:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            end = ntohl(inet_addr(argv[4]));
            //end = inet_addr(argv[4]);
            //dport = htons((__be16)atoi(argv[5]));
            dport = (__be16)atoi(argv[5]);
            protocol = (__u8)atoi(argv[6]);
            protocol_p = &protocol;
            start_p = &start;
            end_p = &end;
            dport_p = &dport;
            break;

        case LSP_FLTPLC_S_ADDR_AND_PROTO_S:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            protocol = (__u8)atoi(argv[4]);
            start_p = &start;
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_S_ADDR_AND_PROTO_M:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            end = ntohl(inet_addr(argv[4]));
            //end = inet_addr(argv[4]);
            protocol = (__u8)atoi(argv[5]);
            start_p = &start;
            end_p = &end;
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_D_ADDR_AND_DPORT_AND_PROTO_S:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            //dport = htons((__be16)atoi(argv[4]));
            dport = (__be16)atoi(argv[4]);
            protocol = (__u8)atoi(argv[5]);
            protocol_p = &protocol;
            start_p = &start;
            dport_p = &dport;
            break;

        case LSP_FLTPLC_D_ADDR_AND_DPORT_AND_PROTO_M:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            end = ntohl(inet_addr(argv[4]));
            //end = inet_addr(argv[4]);
            //dport = htons((__be16)atoi(argv[5]));
            dport = (__be16)atoi(argv[5]);
            protocol = (__u8)atoi(argv[6]);
            protocol_p = &protocol;
            start_p = &start;
            end_p = &end;
            dport_p = &dport;
            break;

        case LSP_FLTPLC_D_ADDR_AND_PROTO_S:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            protocol = (__u8)atoi(argv[4]);
            start_p = &start;
            protocol_p = &protocol;
            break;

        case LSP_FLTPLC_D_ADDR_AND_PROTO_M:
            start = ntohl(inet_addr(argv[3]));
            //start = inet_addr(argv[3]);
            end = ntohl(inet_addr(argv[4]));
            //end = inet_addr(argv[4]);
            protocol = (__u8)atoi(argv[5]);
            start_p = &start;
            end_p = &end;
            protocol_p = &protocol;
            break;

        default:
            printf("unknow flag\n");
            return -1;
            break;
    }

    
//    printf("[LSP] %d %d %s %s %d %d %d\n", re, flag, inet_ntoa(&start), inet_ntoa(&end), sport, dport, protocol);
    if( (ret = mk_rule(buff, BUFF_LEN, flag, start_p, end_p, sport_p, dport_p, protocol_p, re)) < 0)
    {
        printf("make rule error \n");
        return -1;
    }

    
    if( (ret = nl_send(sk, fm_id, NLM_F_REQUEST, 0, getpid(), LSP_NL_ADD, 1, buff, BUFF_LEN, (struct sockaddr *)&dest_addr, sizeof(dest_addr))) < 0)
    {
        printf("nl_send error\n");
        return -1;
    }

    return 0;

}
