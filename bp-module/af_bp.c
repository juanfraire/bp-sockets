#include <linux/module.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include "af_bp.h"
#include "bp_nl_gen.h"
#include "../common.h"

#define bp_sk(ptr) container_of(ptr, struct bp_sock, sk)

HLIST_HEAD(bp_list);
DEFINE_RWLOCK(bp_list_lock);

struct bp_sock
{
    struct sock sk;
    u_int8_t bp_agent_id;
    struct sk_buff_head ack_queue;
    struct sk_buff_head fragment_queue;
    struct sk_buff_head interrupt_in_queue;
    struct sk_buff_head interrupt_out_queue;
};

struct proto bp_proto = {
    .name = "BP",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct sock),
};

static struct sock *bp_alloc_socket(struct net *net, int kern)
{
    struct bp_sock *bp;
    struct sock *sk = sk_alloc(net, AF_BP, GFP_KERNEL, &bp_proto, 1);

    if (!sk)
        goto out;

    sock_init_data(NULL, sk);

    bp = bp_sk(sk);
    skb_queue_head_init(&bp->ack_queue);
    skb_queue_head_init(&bp->fragment_queue);
    skb_queue_head_init(&bp->interrupt_in_queue);
    skb_queue_head_init(&bp->interrupt_out_queue);
out:
    return sk;
}

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
    struct bp_sock *bp;
    int rc = -EAFNOSUPPORT;

    if (!net_eq(net, &init_net))
        goto out;

    rc = -ENOMEM;
    if ((sk = bp_alloc_socket(net, kern)) == NULL)
        goto out;

    bp = bp_sk(sk);

    sock_init_data(sock, sk);

    sock->ops = &bp_proto_ops;
    sk->sk_protocol = protocol;

    rc = 0;
out:
    return rc;
}

int bp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    struct sock *sk = sock->sk;
    struct sockaddr_bp *addr = (struct sockaddr_bp *)uaddr;
    int rc = 0;

    if (addr_len < sizeof(struct sockaddr_bp) ||
        addr->bp_family != AF_BP || addr->bp_agent_id < 1)
    {
        rc = -EINVAL;
        goto out;
    }

    lock_sock(sk);
    bp_sk(sk)->bp_agent_id = addr->bp_agent_id;
    write_lock_bh(&bp_list_lock);
    sk_add_node(sk, &bp_list);
    write_unlock_bh(&bp_list_lock);
    release_sock(sk);
    net_dbg_ratelimited("bp_bind: socket is bound\n");
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
    struct sock *sk = sock->sk;
    struct bp_sock *bp = bp_sk(sk);

    pr_info("bp_recvmsg: entering function 2.0\n");

    lock_sock(sk);
    pr_info("bp_recvmsg: %d\n", bp->bp_agent_id);
    release_sock(sk);

    pr_info("bp_recvmsg: exiting function 2.0\n");

    return 0;
}
