#include <linux/module.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include "proto_sock.h"
#include "netlink.h"

#define AF_BP 28

struct proto bp_proto = {
    .init = bp_init_sock,            // Initialization function for the protocol
    .obj_size = sizeof(struct sock), // Size of the protocol's socket structure
    .owner = THIS_MODULE,            // Owner module (if any)
    .name = "BP",                    // Name of your protocol
};

const struct net_proto_family bp_net_proto = {
    .family = AF_BP,
    .create = bp_create_socket,
    .owner = THIS_MODULE,
};

struct proto_ops bp_proto_ops = {
    .family = AF_BP,
    .owner = THIS_MODULE,
    .release = bp_release,
    .bind = sock_no_bind,
    .connect = sock_no_connect,
    .socketpair = sock_no_socketpair,
    .sendmsg_locked = sock_no_sendmsg_locked,
    .mmap = sock_no_mmap,
    .accept = sock_no_accept,
    .getname = sock_no_getname,
    // .poll = datagram_poll,
    .ioctl = sock_no_ioctl,
    .listen = sock_no_listen,
    .shutdown = sock_no_shutdown,
    .setsockopt = sock_common_setsockopt,
    .getsockopt = sock_common_getsockopt,
    .sendmsg = bp_sendmsg,
    .recvmsg = bp_recvmsg};

int bp_init_sock(struct sock *sk)
{
    pr_info("in the .init");
    // Initialization logic specific to your protocol
    // Typically involves initializing socket specific data structures

    return 0; // Return 0 for success, or an error code
}

int bp_create_socket(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    // int rc;

    sk = sk_alloc(net, AF_BP, GFP_KERNEL, &bp_proto, 1);
    if (!sk)
    {
        printk("failed to allocate socket.\n");
        return -ENOMEM;
    }

    sock_init_data(sock, sk);
    sk->sk_protocol = protocol;

    sock->ops = &bp_proto_ops;

    /* Do the protocol specific socket object initialization */
    return 0;
}

int bp_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    sock_put(sk);
    sock->sk = NULL;

    return 0;
}
/* int bp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{


    ssize_t written;
    void *data;

    pr_info("bp_sendmsg: entering function 2.0\n");

    data = kmalloc(size, GFP_KERNEL);
    if (!data) {
        pr_err("bp_sendmsg: failed to allocate memory\n");
        return -ENOMEM;
    }

    if (copy_from_iter(data, size, &msg->msg_iter) != size) {
        pr_err("bp_sendmsg: failed to copy data from user\n");
        kfree(data);
        return -EFAULT;
    }

    printk(KERN_INFO "msg : %zu \n", size);

    unsigned long id = (unsigned long) sock->sk->sk_socket;
    send_bundle_notification(id, data, size, 8443);


    kfree(data);
    pr_info("bp_sendmsg: exiting function 2.0\n");

    return -EOPNOTSUPP;
}
*/

int bp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
    struct sockaddr *addr;
    char *eid;
    void *payload;
    int eid_size;
    unsigned long sockid;

    addr = (struct sockaddr *)msg->msg_name;
    eid = addr->sa_data;
    eid_size = strlen(addr->sa_data) + 1;

    pr_info("bp_sendmsg: entering function 2.0\n");

    payload = kmalloc(size, GFP_KERNEL);
    if (!payload)
    {
        pr_err("bp_sendmsg: failed to allocate memory\n");
        return -ENOMEM;
    }
    if (copy_from_iter((void *)payload, size, &msg->msg_iter) != size)
    {
        pr_err("bp_sendmsg: failed to copy data from user\n");
        kfree(payload);
        return -EFAULT;
    }

    // Get the sockaddr from the msghdr
    pr_info("[size=%zu] eid: %s\n", eid_size, eid);
    pr_info("[size=%zu] payload: %s\n", size, (char *)payload);

    sockid = (unsigned long)sock->sk->sk_socket;
    send_bundle_doit(sockid, (char *)payload, size, eid, eid_size, 8443);

    kfree(payload);
    pr_info("bp_sendmsg: exiting function 2.0\n");

    return 0;
}

int bp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    return -EOPNOTSUPP;
}
