#ifndef _LSP_GENL_UTILS_
#define _LSP_GENL_UTILS_

int set_attr(char *buff, size_t buf_len, __u16 type, __u16 len, void *value, size_t size)
{
    if((NLA_DATA(0) + size) > buf_len)
    {
        return -1;
    }
    struct nlattr * nla = (struct nlattr *)buff;
    nla->nla_len = len;
    nla->nla_type = type;
    bcopy(value, NLA_DATA(nal), size);
    return 1;
}

int mk_rule(char *buff, __u8 flag, __be32 *start, __be32 *end, __be16 *sport， __be16 *dport __u8 *protocol, unsigned int re)
{
    struct nlattr *nla = NULL;
    nla = (struct nlattr *)buff;

    nla->nla_type = LSP_ATTR_8;
    nla->nla_len = NLMSG_ALIGN(sizeof(__u8)) + NLA_HDRLEN;
    bcopy(&flag, NLA_DATA(nla), sizeof(__u8));
    
    if(NULL != start)
    {
        

int nl_send(int sk, __u16 nlmsg_type, __u16 nlmsg_flags, __u32 nlmsg_seq, __u32 nlmsg_pid, __u8 cmd, __u8 version, char *attrs, size_t len, const struct sockaddr * dest_addr, socklen_t addrlen)
{
    char *send_buff = NULL;
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    struct nlattr *gnla;
    int ret;
    int send_len = len + GENLMSG_DATA(0);

    send_buff = malloc(send_len);
    if(NULL == send_buff)
        return -1;
    bzero(send_buff, send_len);

    nlh = (struct nlmsghdr *)send_buff;
    nlh->nlmsg_len = send_len;
    nlh->nlmsg_type = nlmsg_type;
    nlh->nlmsg_flags = nlmsg_flags;
    nlh->nlmsg_pid = nlmsg_pid;
    
    gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    gnlh->cmd = cmd;
    gnlh->version =version;
    
    gnla = GENLMSG_DATA(nlh);
    bcopy(attrs, gnla, len);

    printf("first: %s, second %s\n",NLA_DATA(gnla), NLA_DATA(NLA_NEXT(gnla)));
    
    while( (ret = sendto(sk, send_buff, send_len, 0, dest_addr, addrlen)) < send_len)
    {
        if(ret > 0)
        {
            send_buff += ret;
            send_len -= ret;
        }
        else if(errno != EAGAIN)
        {
            perror("send to");
            return -1;
        }
    }
    
    return 1;
}

    
    

__u16 get_family_id(int sk, const char *familyname, __u32 pid)
{
    char buff[256];
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    struct nlattr *gnla;
    int ret;
    char *buffer = buff;
    int len = sizeof(buff);
    struct sockaddr_nl dest_addr;
    
    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    bzero(buff,sizeof(buff));
    nlh = (struct nlmsghdr *)buff;
    nlh->nlmsg_len = 256;
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_pid = pid;

    gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    gnlh->cmd = CTRL_CMD_GETFAMILY;
    gnlh->version = 1;

    gnla = (struct nlattr *)GENLMSG_DATA(nlh);
    gnla->nla_type = CTRL_ATTR_FAMILY_NAME;
    gnla->nla_len = strlen(familyname)+NLA_HDRLEN+1;
    bcopy(familyname, NLA_DATA(gnla), strlen(familyname));


    while( (ret = sendto(sk, buffer, len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr))) < len)
    {
        if(ret > 0)
        {
            buffer += ret;
            len -= ret;
        }
        else if(errno != EAGAIN)
        {
            perror("sento");
            return -1;
        }
    }

    ret = recv(sk, buff, sizeof(buff), 0);
    
    if(nlh->nlmsg_type == NLMSG_ERROR   ||  !NLMSG_OK(nlh, ret))
    {
        printf("recv data error %d\n", ret);
        return -1;
    }

    gnla = (struct nlattr *)GENLMSG_DATA(buff);
    gnla = (struct nlattr *)((char *)gnla + NLA_ALIGN(gnla->nla_len));
    
    if(gnla->nla_type == CTRL_ATTR_FAMILY_ID)
    {
        return *(__u16 *)NLA_DATA(gnla);
    }
    
    return -1;
}
#endif
