#ifndef AF_BP_H
#define AF_BP_H

#include <linux/net.h>
#include <net/sock.h>

extern struct hlist_head bp_list;
extern rwlock_t bp_list_lock;
extern struct proto bp_proto;
extern const struct net_proto_family bp_family_ops;

int bp_bind(struct socket *sock, struct sockaddr *addr, int addr_len);
int bp_create(struct net *net, struct socket *sock, int protocol, int kern);
int bp_release(struct socket *sock);
int bp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);
int bp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags);

#endif
