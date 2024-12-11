/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/limits.h>
#include <event2/util.h>
#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include "netlink.h"
#include "daemon.h"
#include "log.h"
#include "../common.h"

struct nl_sock *nl_connect_and_configure(tls_daemon_ctx_t *ctx)
{
	int mcgrp, fam, ret;
	struct nl_sock *sk;

	sk = nl_socket_alloc();
	if (!sk)
	{
		log_printf(LOG_ERROR, "failed to allocate socket\n");
		return NULL;
	}
	nl_socket_disable_seq_check(sk);
	nl_socket_set_local_port(sk, ctx->port);
	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, nl_recvmsg_cb, (void *)ctx);
	genl_connect(sk);

	/* Resolve the genl family. One family for both unicast and multicast. */
	fam = genl_ctrl_resolve(sk, GENL_BP_NAME);
	if (fam < 0)
	{
		log_printf(LOG_ERROR, "failed to resolve generic netlink family: %s\n",
				   strerror(-fam));
		return NULL;
	}

	nl_socket_set_peer_port(sk, 0);

	/* Resolve the multicast group. */
	mcgrp = genl_ctrl_resolve_grp(sk, GENL_BP_NAME, GENL_BP_MC_GRP_NAME);
	if (mcgrp < 0)
	{
		log_printf(LOG_ERROR, "failed to resolve generic netlink multicast group: %s\n",
				   strerror(-mcgrp));
		return NULL;
	}

	/* Join the multicast group. */
	if ((ret = nl_socket_add_membership(sk, mcgrp) < 0))
	{
		log_printf(LOG_ERROR, "failed to join multicast group: %s\n", strerror(-ret));
		return NULL;
	}

	ctx->netlink_sock = sk;
	ctx->netlink_family = fam;

	return sk;
}

void nl_recvmsg(evutil_socket_t fd, short events, void *arg)
{
	log_printf(LOG_INFO, "listening for messages\n");
	nl_recvmsgs_default((struct nl_sock *)arg);
	return;
}

int nl_recvmsg_cb(struct nl_msg *msg, void *arg)
{
	tls_daemon_ctx_t *ctx = (tls_daemon_ctx_t *)arg;
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	struct nlattr *attrs[GENL_BP_A_MAX + 1];

	unsigned long sockid;
	// char comm[PATH_MAX];
	// int addr_internal_len;
	// int addr_external_len;
	// int addr_remote_len;
	// struct sockaddr_in addr_internal;
	// struct sockaddr_in addr_external;
	// struct sockaddr_in addr_remote;

	// int level;
	// int blocking;
	// int optname;
	// int commlen;
	char *payload, *eid;
	int payload_size, eid_size;

	// Get Message
	nlh = nlmsg_hdr(msg);
	gnlh = (struct genlmsghdr *)nlmsg_data(nlh);
	genlmsg_parse(nlh, 0, attrs, GENL_BP_A_MAX, nla_policy);
	log_printf(LOG_INFO, "Received command of type %d\n", gnlh->cmd);
	switch (gnlh->cmd)
	{
	case GENL_BP_CMD_SEND_BUNDLE:
		sockid = nla_get_u64(attrs[GENL_BP_A_SOCKID]);
		log_printf(LOG_INFO, "Received setsockopt notification for socket ID %lu\n", sockid);

		payload_size = nla_len(attrs[GENL_BP_A_PAYLOAD]);
		payload = malloc(payload_size);
		if (payload == NULL)
		{
			log_printf(LOG_ERROR, "Failed to allocate optval\n");
			return 1;
		}
		memcpy(payload, nla_data(attrs[GENL_BP_A_PAYLOAD]), payload_size);

		eid_size = nla_len(attrs[GENL_BP_A_EID]);
		eid = malloc(eid_size);
		if (eid == NULL)
		{
			log_printf(LOG_ERROR, "Failed to allocate optval\n");
			return 1;
		}
		memcpy(eid, nla_data(attrs[GENL_BP_A_EID]), eid_size);

		bp_send_cb(ctx, payload, payload_size, eid, eid_size);

		free(payload);
		break;
	case GENL_BP_CMD_RECV_BUNDLE:

	default:
		log_printf(LOG_ERROR, "unrecognized command\n");
		break;
	}
	return 0;
}

int nl_disconnect(struct nl_sock *sock)
{
	nl_socket_free(sock);
	return 0;
}

void netlink_notify_kernel(tls_daemon_ctx_t *ctx, unsigned long id, int response)
{
	int ret;
	struct nl_msg *msg;
	void *msg_head;
	int msg_size = NLMSG_HDRLEN + GENL_HDRLEN +
				   nla_total_size(sizeof(id)) + nla_total_size(sizeof(response));
	msg = nlmsg_alloc_size(msg_size);
	if (msg == NULL)
	{
		log_printf(LOG_ERROR, "Failed to allocate message buffer\n");
		return;
	}
	msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->netlink_family, 0, 0, GENL_BP_CMD_RETURN, 1);
	if (msg_head == NULL)
	{
		log_printf(LOG_ERROR, "Failed in genlmsg_put\n");
		return;
	}
	ret = nla_put_u64(msg, GENL_BP_A_SOCKID, id);
	if (ret != 0)
	{
		log_printf(LOG_ERROR, "Failed to insert ID in netlink msg\n");
		return;
	}
	ret = nla_put_u32(msg, GENL_BP_A_RETURN, response);
	if (ret != 0)
	{
		log_printf(LOG_ERROR, "Failed to insert response in netlink msg\n");
		return;
	}
	ret = nl_send_auto(ctx->netlink_sock, msg);
	if (ret < 0)
	{
		log_printf(LOG_ERROR, "Failed to send netlink msg\n");
		return;
	}
	// log_printf(LOG_INFO, "Sent msg to kernel\n");
	nlmsg_free(msg);
	return;
}

void netlink_send_and_notify_kernel(tls_daemon_ctx_t *ctx, char *data, unsigned int len)
{
	int ret;
	struct nl_msg *msg;
	void *msg_head;
	struct nlattr *attrs[GENL_BP_A_MAX + 1];

	unsigned long id = nla_get_u64(attrs[GENL_BP_A_SOCKID]);
	log_printf(LOG_INFO, "MESSAGE: %s, LENGTH: %d", data, len);

	// Calculate message size
	int msg_size = NLMSG_HDRLEN + GENL_HDRLEN +
				   nla_total_size(sizeof(id)) + nla_total_size(len);

	// Allocate message
	msg = nlmsg_alloc_size(msg_size);
	if (msg == NULL)
	{
		log_printf(LOG_ERROR, "Failed to allocate Netlink message buffer.\n");
		return;
	}

	// Construct the Generic Netlink message header
	msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->netlink_family, 0, 0, GENL_BP_CMD_RETURN, 1);
	if (msg_head == NULL)
	{
		log_printf(LOG_ERROR, "Failed in genlmsg_put.\n");
		nlmsg_free(msg);
		return;
	}

	// Add the ID attribute
	ret = nla_put_u64(msg, GENL_BP_A_SOCKID, id);
	if (ret != 0)
	{
		log_printf(LOG_ERROR, "Failed to add ID attribute to Netlink message.\n");
		nlmsg_free(msg);
		return;
	}

	// Add the data attribute
	ret = nla_put(msg, GENL_BP_A_PAYLOAD, len, data);
	if (ret != 0)
	{
		log_printf(LOG_ERROR, "Failed to add data attribute to Netlink message.\n");
		nlmsg_free(msg);
		return;
	}

	// Send the message
	ret = nl_send_auto(ctx->netlink_sock, msg);
	if (ret < 0)
	{
		log_printf(LOG_ERROR, "Failed to send Netlink message (error %d).\n", ret);
		nlmsg_free(msg);
		return;
	}

	log_printf(LOG_INFO, "Successfully sent data message to kernel.\n");

	// Free the message
	nlmsg_free(msg);
	return;
}
