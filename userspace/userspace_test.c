#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/genetlink.h>
#include <errno.h>

#include "LSP_netlink.h"
#include "LSP_genl_utils.h"


int main()
{
    int fm_id;
    int sk;
    char attrs[256];
    struct nlattr *nla, *nla2;

    struct sockaddr_nl dest_addr;
    
    sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    
    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    fm_id = get_family_id(sk, NL_FML_NAME, getpid());

    printf("family id is %d",fm_id);
    
    nla = (struct nlattr *)attrs;
    nla->nla_type = 1;
    nla->nla_len = NLMSG_ALIGN(sizeof("hello")) + NLA_HDRLEN;
    bcopy("hello", NLA_DATA(nla), sizeof("hello"));

    nla2 = NLA_NEXT(nla);
    nla2->nla_type = 1;
    nla2->nla_len = NLMSG_ALIGN(sizeof("world")) + NLA_HDRLEN;
    bcopy("world",NLA_DATA(nla2),sizeof("world"));
    
    if(nl_send(sk, fm_id, NLM_F_REQUEST, 0, getpid(), LSP_NL_ADD, 1, attrs, nla->nla_len + nla2->nla_len, &dest_addr, sizeof(dest_addr)) < 0)
        printf("send error\n");
   

    return 0;
}


