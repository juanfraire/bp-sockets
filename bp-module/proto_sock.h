#ifndef PROTO_SOCK_H
#define PROTO_SOCK_H

#include <linux/net.h> // For socket structures
#include <net/sock.h>  // For sock structures

#define AF_BP 28 // Custom address family number

static int bp_init_sock(struct sock *sk);
static int bp_create_socket(struct net *net, struct socket *sock, int protocol, int kern);
static int bp_release(struct socket *sock);
static int bp_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);
static int bp_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags);

extern struct proto bp_proto;                      // Protocol definition
static struct proto_ops bp_proto_ops;              // Protocol operations
extern const struct net_proto_family bp_net_proto; // Address family definition

#endif // PROTO_SOCK_H
