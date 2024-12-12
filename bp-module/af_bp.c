#include <linux/module.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include "af_bp.h"
#include "genl_bp.h"
#include "../common.h"

struct proto bp_proto = {
    .name = "BP",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct sock),
};

const struct net_proto_family bp_family_ops = {
    .family = AF_BP,
    .create = bp_create,
    .owner = THIS_MODULE,
};

struct proto_ops bp_proto_ops = {
    .family = AF_BP,
    .owner = THIS_MODULE,
    .release = bp_release,
    .bind = bp_bind,
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

int bp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    int rc = -EAFNOSUPPORT;

    if (!net_eq(net, &init_net))
        goto out;

    rc = -ENOMEM;
    if ((sk = sk_alloc(net, AF_BP, GFP_KERNEL, &bp_proto, 1)) == NULL)
        goto out;

    sock_init_data(sock, sk);
    sock->ops = &bp_proto_ops;
    sk->sk_protocol = protocol;

    rc = 0;
out:
    return rc;
}

int bp_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
    // struct sock *sk = sock->sk;
    struct sockaddr_bp *bp_addr = (struct sockaddr_bp *)addr;
    int rc = 0;

    if (addr_len != sizeof(struct sockaddr_bp) ||
        bp_addr->sbp_family != AF_BP || bp_addr->sbp_agent_id < 1)
    {
        rc = -EINVAL;
        goto out;
    }

out:
    return rc;
}

int bp_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    if (!sk)
        return 0;
    sock_hold(sk);
    sock_put(sk);
    return 0;
}

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
    pr_info("[size=%d] eid: %s\n", eid_size, eid);
    pr_info("[size=%zu] payload: %s\n", size, (char *)payload);

    sockid = (unsigned long)sock->sk->sk_socket;
    send_bundle_doit(sockid, (char *)payload, size, eid, eid_size, 8443);

    kfree(payload);
    pr_info("bp_sendmsg: exiting function 2.0\n");

    return 0;
}

int bp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    unsigned long sockid;

    pr_info("bp_recvmsg: entering function 2.0\n");

    sockid = (unsigned long)sock->sk->sk_socket;
    pr_info("bp_recvmsg: Hello from bp_recvmsg\n");

    pr_info("bp_recvmsg: exiting function 2.0\n");

    return 0;
}
