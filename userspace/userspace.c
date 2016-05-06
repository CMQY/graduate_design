#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/genetlink.h>
#include <errno.h>

#include "LSP_netlink.h"

int main()
{
    int fm_id;
    int sk;
    int retval;
    int len;
    char buffer[256];
    char *buff = buffer;
    
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    struct nlattr *gnla;
    struct sockaddr_nl dest_addr;
    sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;
    
    bzero(buff, sizeof(buffer));
    nlh = (struct nlmsghdr *)buff;
    len = 256; //NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_len = len;
    nlh->nlmsg_type = GENL_ID_CTRL;     /* generic netlink specific, for get user specific family id */
    nlh->nlmsg_flags = NLM_F_REQUEST;  
    nlh->nlmsg_pid = getpid();
  
    gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    gnlh->cmd = CTRL_CMD_GETFAMILY;     /* generic netlink specific, for get user specific family id */
    gnlh->version = 1;

    gnla = (struct nlattr *)GENLMSG_DATA(buff);
    gnla->nla_type = CTRL_ATTR_FAMILY_NAME;
    gnla->nla_len = sizeof(NL_FML_NAME)+NLA_HDRLEN;
    bcopy(NL_FML_NAME, NLA_DATA(gnla), sizeof(NL_FML_NAME));
    
    while( (retval = sendto(sk, buff, sizeof(buffer), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr))) < len)
    {
        if( retval > 0)
        {
            buff+=retval;
            len-=retval;
        }
        else if(errno != EAGAIN)
        {
            perror("sendto");
            return -1;
        }
    }
    
    retval = recv(sk, buff, sizeof(buffer), 0);
    printf("send length %d, recive length %d\n", len, retval);

    if(nlh->nlmsg_type == NLMSG_ERROR)
    {
        struct nlmsgerr *nlerr = (struct nlmsgerr *)NLMSG_DATA(nlh);
        printf("not our expect data, error code %d ,len %d,\n", nlerr->error, nlerr->msg.nlmsg_len);
        
        return -1;
    }
    if(!NLMSG_OK(nlh, retval))
    {
        printf("not our expect data no OK \n");
        return -1;
    }


    gnla = (struct nlattr *)GENLMSG_DATA(buff);
    printf("the first responce %s\n",(char *)NLA_DATA(gnla));
    gnla = (struct nlattr *)((char *)gnla + NLA_ALIGN(gnla->nla_len));

    if(gnla->nla_type == CTRL_ATTR_FAMILY_ID)
    {
        printf("the family id is %d\n",*(__u16 *)NLA_DATA(gnla));
    }
    else
    {
        printf("can't get family id\n");
    }
    
    return 0;
}

