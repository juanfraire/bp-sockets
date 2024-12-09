#ifndef NETLINK_H
#define NETLINK_H

#include <linux/socket.h>

// Attributes
enum
{
        SSA_NL_A_UNSPEC,
        SSA_NL_A_ID,
        SSA_NL_A_RETURN,
        SSA_NL_A_OPTVAL,
        __SSA_NL_A_MAX,
};

#define SSA_NL_A_MAX (__SSA_NL_A_MAX - 1)

// Operations
enum
{
        SSA_NL_C_UNSPEC,
        SSA_NL_C_BUNDLE_NOTIFY,
        SSA_NL_C_RETURN,

        __SSA_NL_C_MAX,
};

#define SSA_NL_C_MAX (__SSA_NL_C_MAX - 1)

// Multicast group
enum ssa_nl_groups
{
        SSA_NL_NOTIFY,
};

int nl_fail(struct sk_buff *skb, struct genl_info *info);
int register_netlink(void);
int send_bundle_notification(unsigned long id, void *optval, int optlen, int port_id);
void unregister_netlink(void);
int nl_receive(struct sk_buff *skb, struct genl_info *info);

#endif