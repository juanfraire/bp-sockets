#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/fs.h>
#include <net/sock.h>
#include "netlink.h"
#include "proto_sock.h"

extern struct proto bp_proto;
extern const struct net_proto_family bp_net_proto;

static int __init bp_init(void)
{
    int rc;

    pr_info("bp_init: initializing module\n");
    register_netlink();
    rc = proto_register(&bp_proto, 0);
    if (rc)
    {
        pr_err("bp_init: failed to register proto\n");
        return rc;
    }

    rc = sock_register(&bp_net_proto);
    if (rc)
    {
        pr_err("bp_init: failed to register socket family\n");
        proto_unregister(&bp_proto);
        return rc;
    }

    pr_info("bp_init: module initialized successfully\n");
    return 0;
}

static void __exit bp_exit(void)
{
    pr_info("bp_exit: unloading module\n");
    sock_unregister(AF_BP);
    proto_unregister(&bp_proto);
    unregister_netlink();
    pr_info("bp_exit: module unloaded successfully\n");
}

module_init(bp_init);
module_exit(bp_exit);

// Module metadata
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Custom socket protocol module");