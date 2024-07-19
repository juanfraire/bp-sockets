#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <net/sock.h>
#include "netlink.h"

#define CUSTOM_PROTO_FAMILY 28


static int testcustom(struct sock *sk)
{
    pr_info("in the .init");
    // Initialization logic specific to your protocol
    // Typically involves initializing socket specific data structures

    return 0; // Return 0 for success, or an error code
}

static struct proto_ops custom_proto_ops;

static struct proto custom_proto = {
    .name       = "custom_proto",      // Name of your protocol
    .owner      = THIS_MODULE,         // Owner module (if any)
    .obj_size   = sizeof(struct sock), // Size of the protocol's socket structure
    .init       = testcustom   // Initialization function for the protocol
};



static int custom_create(struct net *net, struct socket *sock, int protocol, int kern)
{
   pr_info("custom_create: entering function\n");

    struct sock * sk;

    int rc;

    sock->ops = &custom_proto_ops;
    sk = sk_alloc(net, CUSTOM_PROTO_FAMILY, GFP_KERNEL, &custom_proto, 1);
    pr_info("sk allocated\n");
    if (!sk) {
        printk("error  at sk check ");
        return -ENOMEM;
    }

    sock_init_data(sock, sk);
    pr_info("sock initiated\n");
    sk->sk_protocol = protocol;


    pr_info("custom_create: exiting function\n");
    return 0;
}

static int custom_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    sock_put(sk);
    sock->sk = NULL;

    return 0;
}
/*static int custom_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{


    ssize_t written;
    void *data;

    pr_info("custom_sendmsg: entering function 2.0\n");

    data = kmalloc(size, GFP_KERNEL);
    if (!data) {
        pr_err("custom_sendmsg: failed to allocate memory\n");
        return -ENOMEM;
    }

    if (copy_from_iter(data, size, &msg->msg_iter) != size) {
        pr_err("custom_sendmsg: failed to copy data from user\n");
        kfree(data);
        return -EFAULT;
    }

    printk(KERN_INFO "msg : %zu \n", size);

    unsigned long id = (unsigned long) sock->sk->sk_socket;
    send_bundle_notification(id, data, size, 8443);


    kfree(data);
    pr_info("custom_sendmsg: exiting function 2.0\n");

    return -EOPNOTSUPP;
}
*/

static int custom_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{


    ssize_t written;
    void *data;

    struct sockaddr *addr;
    int addr_len, total_size;

    addr = (struct sockaddr *)msg->msg_name;
    addr_len = strlen(addr->sa_data);
    total_size = size +  addr_len + 1;
    pr_info("custom_sendmsg: entering function 2.0\n");

    data = kmalloc(total_size, GFP_KERNEL);

    if (!data) {
        pr_err("custom_sendmsg: failed to allocate memory\n");
        return -ENOMEM;
    }

    // kernel guys would not necessarily like this..
    // manually concat addr and msg separated with backslash with memcpy and pointer arithmetic..
    memcpy(data, addr->sa_data, addr_len);
    char *char_addr = (char *) data;
    char_addr += addr_len;
    *char_addr ='\\';
    char_addr ++;
    
    if (copy_from_iter((void*) char_addr, size, &msg->msg_iter) != size ) {
        pr_err("custom_sendmsg: failed to copy data from user\n");
        kfree(data);
        return -EFAULT;
    }

    // Get the sockaddr from the msghdr

    printk(KERN_INFO "addr & addrlen= %s %d",  addr->sa_data, addr_len);
    printk(KERN_INFO "msg size : %zu \n", size);
    printk(KERN_INFO "total size : %zu %s \n", total_size, data);

    unsigned long id = (unsigned long) sock->sk->sk_socket;
    send_bundle_notification(id, data, total_size, 8443);


    kfree(data);
    pr_info("custom_sendmsg: exiting function 2.0\n");

    return 0;
}


static int custom_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    return -EOPNOTSUPP;
}

static const struct net_proto_family custom_family_ops = {
    .family = CUSTOM_PROTO_FAMILY,
    .create = custom_create,
    .owner  = THIS_MODULE,
};

static struct proto_ops custom_proto_ops = {
    .family     = CUSTOM_PROTO_FAMILY,
    .owner      = THIS_MODULE,
    .release    = custom_release,
    .bind =  sock_no_bind,
    .connect = sock_no_connect,
    .socketpair = sock_no_socketpair,
    .accept = sock_no_accept,
    .getname = sock_no_getname,
    .poll = datagram_poll,
    .ioctl = sock_no_ioctl,
    .listen = sock_no_listen,
    .shutdown = sock_no_shutdown,
    .sendmsg = custom_sendmsg,
    .sendmsg_locked = sock_no_sendmsg_locked,
    .recvmsg = custom_recvmsg,
    .mmap = sock_no_mmap,
    .getsockopt = sock_common_getsockopt,
    .recvmsg = sock_common_recvmsg,
    .setsockopt = sock_common_setsockopt
};

static int __init custom_proto_init(void)
{
    int rc;

    pr_info("custom_proto_init: initializing module\n");
    register_netlink();
    rc = proto_register(&custom_proto, 0);
    if (rc) {
        pr_err("custom_proto_init: failed to register proto\n");
        return rc;
    }

    rc = sock_register(&custom_family_ops);
    if (rc) {
        pr_err("custom_proto_init: failed to register socket family\n");
        proto_unregister(&custom_proto);
        return rc;
    }

    pr_info("custom_proto_init: module initialized successfully\n");
    return 0;
}

static void __exit custom_proto_exit(void)
{
    pr_info("custom_proto_exit: unloading module\n");
    sock_unregister(CUSTOM_PROTO_FAMILY);
    proto_unregister(&custom_proto);
    unregister_netlink();
    pr_info("custom_proto_exit: module unloaded successfully\n");
}

module_init(custom_proto_init);
module_exit(custom_proto_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Custom socket protocol module");


