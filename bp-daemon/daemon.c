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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <assert.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "daemon.h"
#include "hashmap.h"
#include "netlink.h"
#include "log.h"
#include "bp.h"
#include "../genl_bp.h"

#define HASHMAP_NUM_BUCKETS 100

typedef struct receiver_context
{
	BpSAP txSap;	// The SAP handle for the Bundle Protocol
	BpDelivery dlv; // Delivery struct for received data
	tls_daemon_ctx_t daemon_ctx;
} receiver_context_t;

int mainloop(int port)
{
	int ret;
	// evutil_socket_t server_sock;
	// struct evconnlistener* listener;
	struct event_base *base;
	struct event *event_on_sigpipe, *event_on_sigint, *event_on_nl_sock;
	struct nl_sock *netlink_sock;
	receiver_context_t *recv_ctx;
	char ownEid[64];
#ifndef NO_LOG
	const char *ev_version = event_get_version();
#endif

	base = event_base_new();
	log_printf(LOG_INFO, "Using libevent version %s with %s behind the scenes\n", ev_version, event_base_get_method(base));

	event_on_sigpipe = evsignal_new(base, SIGPIPE, signal_cb, NULL);
	event_on_sigint = evsignal_new(base, SIGINT, signal_cb, base);

	evsignal_add(event_on_sigpipe, NULL);
	evsignal_add(event_on_sigint, NULL);

	tls_daemon_ctx_t daemon_ctx = {
		.base = base,
		.netlink_sock = NULL,
		.port = port,
		.sock_map = hashmap_create(HASHMAP_NUM_BUCKETS),
		.sock_map_port = hashmap_create(HASHMAP_NUM_BUCKETS),
	};

	/* Set up server socket with event base */
	// server_sock =
	create_server_socket(port, PF_INET, SOCK_STREAM);
	// listener = evconnlistener_new(base, accept_cb, &daemon_ctx,
	// 	LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, server_sock);
	// if (listener == NULL) {
	// 	log_printf(LOG_ERROR, "Couldn't create evconnlistener\n");
	// 	return 1;
	// }
	// evconnlistener_set_error_cb(listener, accept_error_cb);

	/* Set up netlink socket with event base */
	netlink_sock = netlink_connect(&daemon_ctx);
	if (netlink_sock == NULL)
	{
		log_printf(LOG_ERROR, "Couldn't create Netlink socket\n");
		return 1;
	}
	ret = evutil_make_socket_nonblocking(nl_socket_get_fd(netlink_sock));
	if (ret == -1)
	{
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
				   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	}
	event_on_nl_sock = event_new(base, nl_socket_get_fd(netlink_sock), EV_READ | EV_PERSIST, netlink_recv, netlink_sock);
	if (event_add(event_on_nl_sock, NULL) == -1)
	{
		log_printf(LOG_ERROR, "Couldn't add Netlink event\n");
		return 1;
	}

	if (bp_attach() < 0)
	{
		log_printf(LOG_ERROR, "Can't attach to BP.\n");
		/* user inser error handling code */
		return 1;
	}

	recv_ctx = malloc(sizeof(receiver_context_t));
	recv_ctx->daemon_ctx = daemon_ctx;
	isprintf(ownEid, sizeof ownEid, "ipn:%d.1", getOwnNodeNbr());
	log_printf(LOG_INFO, "My own EID is \"%s\".\n", ownEid);
	if (bp_open(ownEid, &recv_ctx->txSap) < 0)
	{
		log_printf(LOG_ERROR, "bptrace can't open own endpoint.\n");
		/* user's error handling function here */
		return 1;
	}
	if (recv_ctx->txSap == NULL)
	{
		log_printf(LOG_ERROR, "can't get Bundle Protocol SAP.");
		return 1;
	}

	log_printf(LOG_INFO, "Before mainloop\n");

	/* Main event loop */
	event_base_dispatch(base);
	log_printf(LOG_INFO, "Main event loop terminated\n");
	netlink_disconnect(netlink_sock);

	/* Cleanup */
	// evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */
	hashmap_free(daemon_ctx.sock_map_port);
	hashmap_deep_free(daemon_ctx.sock_map, (void (*)(void *))free_sock_ctx);
	event_free(event_on_nl_sock);
	event_free(event_on_sigpipe);
	event_free(event_on_sigint);
	event_base_free(base);
	free(recv_ctx);
/* This function hushes the wails of memory leak
 * testing utilities, but was not introduced until
 * libevent 2.1
 */
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	libevent_global_shutdown();
#endif

	return 0;
}

/* Creates a listening socket that binds to local IPv4 and IPv6 interfaces.
 * It also makes the socket nonblocking (since this software uses libevent)
 * @param port numeric port for listening
 * @param type SOCK_STREAM or SOCK_DGRAM
 */
evutil_socket_t create_server_socket(ev_uint16_t port, int family, int type)
{
	evutil_socket_t sock;
	char port_buf[6];
	int ret;

	struct evutil_addrinfo hints;
	struct evutil_addrinfo *addr_ptr;
	struct evutil_addrinfo *addr_list;
	struct sockaddr_un bind_addr = {
		.sun_family = AF_UNIX,
	};

	/* Convert port to string for getaddrinfo */
	evutil_snprintf(port_buf, sizeof(port_buf), "%d", (int)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = type;

	if (family == PF_UNIX)
	{
		sock = socket(AF_UNIX, type, 0);
		if (sock == -1)
		{
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
					   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
					   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}

		strcpy(bind_addr.sun_path + 1, port_buf);
		ret = bind(sock, (struct sockaddr *)&bind_addr, sizeof(sa_family_t) + 1 + strlen(port_buf));
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			exit(EXIT_FAILURE);
		}
		return sock;
	}

	/* AI_PASSIVE for filtering out addresses on which we
	 * can't use for servers
	 *
	 * AI_ADDRCONFIG to filter out address types the system
	 * does not support
	 *
	 * AI_NUMERICSERV to indicate port parameter is a number
	 * and not a string
	 *
	 * */
	hints.ai_flags = EVUTIL_AI_PASSIVE | EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_NUMERICSERV;
	/*
	 *  On Linux binding to :: also binds to 0.0.0.0
	 *  Null is fine for TCP, but UDP needs both
	 *  See https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
	 */
	ret = evutil_getaddrinfo(type == SOCK_DGRAM ? "::" : NULL, port_buf, &hints, &addr_list);
	if (ret != 0)
	{
		log_printf(LOG_ERROR, "Failed in evutil_getaddrinfo: %s\n", evutil_gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next)
	{
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1)
		{
			log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
			continue;
		}

		ret = evutil_make_listen_socket_reuseable(sock);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
					   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = evutil_make_socket_nonblocking(sock);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
					   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}

		ret = bind(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
		if (ret == -1)
		{
			log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
			EVUTIL_CLOSESOCKET(sock);
			continue;
		}
		break;
	}
	evutil_freeaddrinfo(addr_list);
	if (addr_ptr == NULL)
	{
		log_printf(LOG_ERROR, "Failed to find a suitable address for binding\n");
		exit(EXIT_FAILURE);
	}

	return sock;
}

void bp_receive_cb(evutil_socket_t fd, short events, void *arg)
{
	receiver_context_t *recv_ctx = (receiver_context_t *)arg;
	Sdr sdr = getIonsdr();
	vast contentLength;
	vast len;
	char *content;
	ZcoReader reader;
	// netlink
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	struct nlattr *attrs[GENL_BP_A_MAX + 1];
	unsigned long id;

	if (bp_receive(recv_ctx->txSap, &recv_ctx->dlv, BP_BLOCKING) < 0)
	{
		log_printf(LOG_ERROR, "bpsink bundle reception failed.\n");
		/* user code to handle error or timeout*/
		return;
	}

	switch (recv_ctx->dlv.result)
	{
	case BpPayloadPresent:
		CHKVOID(sdr_begin_xn(sdr));
		log_printf(LOG_INFO, "BUNDLE RECEIVE!!\n");

		contentLength = zco_source_data_length(sdr, recv_ctx->dlv.adu);
		content = malloc((size_t)contentLength);

		zco_start_receiving(recv_ctx->dlv.adu, &reader);
		len = zco_receive_source(sdr, &reader, contentLength, content);

		if (sdr_end_xn(sdr) < 0 || len < 0)
		{
			sdr_exit_xn(sdr);
			log_printf(LOG_ERROR, "Can't handle delivery. len = %d\n", len);
			return;
		}

		log_printf(LOG_INFO, "PAYLOAD: %s\n", content);

		netlink_send_and_notify_kernel(&recv_ctx->daemon_ctx, content, len);
		// if (zco_receive_headers(sdr, &reader, contentLength, (char *)buffer) < 0)
		// {
		// 	sdr_cancel_xn(sdr);
		// 	log_printf(LOG_ERROR, "can't receive ADU header.\n");
		// 	MRELEASE(buffer);
		// 	continue;
		// }

		bp_release_delivery(&recv_ctx->dlv, 0);
	}
	return;
}

int send_adu(char *value)
{
	Sdr sdr;
	char *end;
	char *destEid;
	char *text;
	int length;
	Object bundlePayload;
	Object bundleZco;

	sdr = bp_get_sdr();
	if (sdr == NULL)
	{
		puts("*** Failed to get sdr.");
		return 0;
	}

	end = strchr(value, '\\');
	if (end == NULL)
	{
		putErrmsg("No EID.", NULL);
		return 0;
	}

	destEid = value;
	*end = 0;
	text = end + 1;

	length = strlen(text);
	if (length == 0)
	{
		putErrmsg("Zero-length text.", NULL);
		return 0;
	}

	oK(sdr_begin_xn(sdr));
	bundlePayload = sdr_string_create(sdr, text);
	if (bundlePayload == 0)
	{
		sdr_end_xn(sdr);
		putErrmsg("No text object.", NULL);
		return 0;
	}

	bundleZco = zco_create(sdr, ZcoSdrSource, bundlePayload, 0,
						   length + 1, ZcoOutbound);
	if (bundleZco == 0 || bundleZco == (Object)ERROR)
	{
		sdr_end_xn(sdr);
		putErrmsg("No text object.", NULL);
		return 0;
	}

	if (bp_send(NULL, destEid, NULL, 86400, BP_STD_PRIORITY, 0, 0, 0, NULL,
				bundleZco, NULL) <= 0)
	{
		sdr_end_xn(sdr);
		putErrmsg("No text object.", NULL);
		putErrmsg("bpsockets daemon can't send bundle.", NULL);
		return 0;
	}

	sdr_end_xn(sdr);
	return 1;
}

void bundle_cb(tls_daemon_ctx_t *ctx, unsigned long id,
			   void *value, socklen_t len)
{
	// sock_ctx_t* sock_ctx;
	// int response = 0; /* Default is success */

	// sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
	// if (sock_ctx == NULL) {
	// response = -EBADF;
	// netlink_notify_kernel(ctx, id, response);
	//	return;
	//}

	send_adu(value);

	// netlink_notify_kernel(ctx, id, response);
	// return;
}

// void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
// 	struct sockaddr *address, int socklen, void *arg) {
// 	log_printf(LOG_INFO, "Received connection!\n");
//
// 	int port;
// 	sock_ctx_t* sock_ctx;
// 	tls_daemon_ctx_t* ctx = arg;
//
// 	if (address->sa_family == AF_UNIX) {
// 		port = strtol(((struct sockaddr_un*)address)->sun_path+1, NULL, 16);
// 		log_printf(LOG_INFO, "unix port is %05x", port);
// 	}
// 	else {
// 		port = (int)ntohs(((struct sockaddr_in*)address)->sin_port);
// 	}
// 	sock_ctx = hashmap_get(ctx->sock_map_port, port);
// 	if (sock_ctx == NULL) {
// 		log_printf(LOG_ERROR, "Got an unauthorized connection on port %d\n", port);
// 		EVUTIL_CLOSESOCKET(fd);
// 		return;
// 	}
// 	log_printf_addr(&sock_ctx->rem_addr);
//
// 	if (evutil_make_socket_nonblocking(fd) == -1) {
// 		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
// 			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
// 		EVUTIL_CLOSESOCKET(fd);
// 		return;
// 	}
// 	hashmap_del(ctx->sock_map_port, port);
// 	//sock_ctx->tls_conn = tls_client_wrapper_setup(sock_ctx->fd, ctx,
// 	//			sock_ctx->rem_hostname, sock_ctx->is_accepting, sock_ctx->tls_opts);
//
// 	return;
// }
//
// void accept_error_cb(struct evconnlistener *listener, void *ctx) {
//         struct event_base *base = evconnlistener_get_base(listener);
// #ifndef NO_LOG
//         int err = EVUTIL_SOCKET_ERROR();
//         log_printf(LOG_ERROR, "Got an error %d (%s) on the listener\n",
// 				err, evutil_socket_error_to_string(err));
// #endif
//         event_base_loopexit(base, NULL);
// 	return;
// }
//
// void listener_accept_cb(struct evconnlistener *listener, evutil_socket_t efd,
// 	struct sockaddr *address, int socklen, void *arg) {
// 	struct sockaddr_in int_addr = {
// 		.sin_family = AF_INET,
// 		.sin_port = 0,
// 		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)
// 	};
// 	socklen_t intaddr_len = sizeof(int_addr);
// 	sock_ctx_t* sock_ctx = (sock_ctx_t*)arg;
// 	evutil_socket_t ifd;
// 	int port;
// 	sock_ctx_t* new_sock_ctx;
//         //struct event_base *base = evconnlistener_get_base(listener);
//
// 	//log_printf(LOG_DEBUG, "Got a connection on a vicarious listener\n");
// 	//log_printf_addr(&sock_ctx->int_addr);
// 	if (evutil_make_socket_nonblocking(efd) == -1) {
// 		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
// 			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
// 		EVUTIL_CLOSESOCKET(efd);
// 		return;
// 	}
//
// 	new_sock_ctx = (sock_ctx_t*)calloc(1, sizeof(sock_ctx_t));
// 	if (new_sock_ctx == NULL) {
// 		return;
// 	}
// 	new_sock_ctx->fd = efd;
// 	//new_sock_ctx->daemon = sock_ctx->daemon;
// 	//new_sock_ctx->tls_opts = sock_ctx->tls_opts;
// 	//new_sock_ctx->int_addr = sock_ctx->int_addr;
// 	//new_sock_ctx->int_addrlen = sock_ctx->int_addrlen;
//
// 	ifd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
// 	if (ifd == -1) {
// 		return;
// 	}
//
// 	if (bind(ifd, (struct sockaddr*)&int_addr, sizeof(int_addr)) == -1) {
// 		perror("bind");
// 		EVUTIL_CLOSESOCKET(ifd);
// 		return;
// 	}
//
// 	if (getsockname(ifd, (struct sockaddr*)&int_addr, &intaddr_len) == -1) {
// 		perror("getsockname");
// 		EVUTIL_CLOSESOCKET(ifd);
// 		return;
// 	}
//
// 	if (evutil_make_socket_nonblocking(ifd) == -1) {
// 		log_printf(LOG_ERROR, "Failed in ifd evutil_make_socket_nonblocking: %s\n",
// 			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
// 		EVUTIL_CLOSESOCKET(ifd);
// 		return;
// 	}
//
// 	port = (int)ntohs((&int_addr)->sin_port);
// 	hashmap_add(sock_ctx->daemon->sock_map_port, port, (void*)new_sock_ctx);
// 	return;
// }
//
// void listener_accept_error_cb(struct evconnlistener *listener, void *ctx) {
//         struct event_base *base = evconnlistener_get_base(listener);
// #ifndef NO_LOG
//         int err = EVUTIL_SOCKET_ERROR();
//         log_printf(LOG_ERROR, "Got an error %d (%s) on a server listener\n",
// 				err, evutil_socket_error_to_string(err));
// #endif
//         event_base_loopexit(base, NULL);
// 	return;
// }
//
void signal_cb(evutil_socket_t fd, short event, void *arg)
{
	int signum = fd; /* why is this fd? */
	switch (signum)
	{
	case SIGPIPE:
		log_printf(LOG_DEBUG, "Caught SIGPIPE and ignored it\n");
		break;
	case SIGINT:
		log_printf(LOG_DEBUG, "Caught SIGINT\n");
		event_base_loopbreak(arg);
		break;
	default:
		break;
	}
	return;
}
//
// void socket_cb(tls_daemon_ctx_t* ctx, unsigned long id, char* comm) {
// 	sock_ctx_t* sock_ctx;
// 	evutil_socket_t fd;
// 	int ret;
// 	int response = 0;
//
// 	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
// 	if (sock_ctx != NULL) {
// 		log_printf(LOG_ERROR, "We have created a socket with this ID already: %lu\n", id);
// 		netlink_notify_kernel(ctx, id, response);
// 		return;
// 	}
//
// 	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
// 	if (fd == -1) {
// 		response = -errno;
// 	}
// 	else {
// 		sock_ctx = (sock_ctx_t*)calloc(1, sizeof(sock_ctx_t));
// 		if (sock_ctx == NULL) {
// 			response = -ENOMEM;
// 		}
// 		else {
// 			sock_ctx->id = id;
// 			sock_ctx->fd = fd;
// 			//sock_ctx->tls_opts = tls_opts_create(comm);
// 			hashmap_add(ctx->sock_map, id, (void*)sock_ctx);
// 		}
// 	}
// 	ret = evutil_make_socket_nonblocking(sock_ctx->fd);
// 	if (ret == -1) {
// 		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
// 			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
// 	}
//
// 	log_printf(LOG_INFO, "Socket created on behalf of application %s\n", comm);
// 	netlink_notify_kernel(ctx, id, response);
// 	return;
// }
//
// void setsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level,
// 		int option, void* value, socklen_t len) {
// 	sock_ctx_t* sock_ctx;
// 	int response = 0; /* Default is success */
//
// 	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
// 	if (sock_ctx == NULL) {
// 		response = -EBADF;
// 		netlink_notify_kernel(ctx, id, response);
// 		return;
// 	}
//
// 	// TODO: Call send_peer_auth_req with value: "dest-eid\\text"
//
// 	switch (option) {
// 	default:
// 		if (setsockopt(sock_ctx->fd, level, option, value, len) == -1) {
// 			response = -errno;
// 		}
// 		break;
// 	}
// 	netlink_notify_kernel(ctx, id, response);
// 	return;
// }
//
// void getsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level, int option) {
// 	sock_ctx_t* sock_ctx;
// 	long value;
// 	int response = 0;
// 	char* data = NULL;
// 	unsigned int len = 0;
// 	int need_free = 0;
//
// 	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
// 	if (sock_ctx == NULL) {
// 		netlink_notify_kernel(ctx, id, -EBADF);
// 		return;
// 	}
// 	switch (option) {
// 	default:
// 		log_printf(LOG_ERROR, "Default case for getsockopt hit: should never happen\n");
// 		response = -EBADF;
// 		break;
// 	}
// 	if (response != 0) {
// 		netlink_notify_kernel(ctx, id, response);
// 		return;
// 	}
// 	netlink_send_and_notify_kernel(ctx, id, data, len);
// 	if (need_free == 1) {
// 		free(data);
// 	}
// 	return;
// }
//
// void bind_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr,
// 	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen) {
//
// 	int ret;
// 	sock_ctx_t* sock_ctx;
// 	int response = 0;
//
// 	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
// 	if (sock_ctx == NULL) {
// 		response = -EBADF;
// 	}
// 	else {
// 		ret = evutil_make_listen_socket_reuseable(sock_ctx->fd);
// 		if (ret == -1) {
// 			log_printf(LOG_ERROR, "Failed in evutil_make_listen_socket_reuseable: %s\n",
// 				 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
// 			EVUTIL_CLOSESOCKET(sock_ctx->fd);
// 			return;
// 		}
//
// 		ret = bind(sock_ctx->fd, ext_addr, ext_addrlen);
// 		if (ret == -1) {
// 			perror("bind");
// 			response = -errno;
// 		}
// 		else {
// 			sock_ctx->has_bound = 1;
// 			sock_ctx->int_addr = *int_addr;
// 			sock_ctx->int_addrlen = int_addrlen;
// 			sock_ctx->ext_addr = *ext_addr;
// 			sock_ctx->ext_addrlen = ext_addrlen;
// 		}
// 	}
// 	netlink_notify_kernel(ctx, id, response);
// 	return;
// }
//
// void connect_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr,
// 	int int_addrlen, struct sockaddr* rem_addr, int rem_addrlen, int blocking) {
//
// 	sock_ctx_t* sock_ctx;
// 	int port;
//
// 	if (int_addr->sa_family == AF_UNIX) {
// 		port = strtol(((struct sockaddr_un*)int_addr)->sun_path+1, NULL, 16);
// 		log_printf(LOG_INFO, "unix port is %05x", port);
// 	}
// 	else {
// 		port = (int)ntohs(((struct sockaddr_in*)int_addr)->sin_port);
// 	}
//
// 	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
// 	if (sock_ctx == NULL) {
// 		netlink_notify_kernel(ctx, id, -EBADF);
// 		return;
// 	}
//
// 	// do something here
//
// 	if (sock_ctx->has_bound == 0) {
// 		sock_ctx->int_addr = *int_addr;
// 		sock_ctx->int_addrlen = int_addrlen;
// 	}
// 	log_printf(LOG_INFO, "Placing sock_ctx for port %d\n", port);
// 	hashmap_add(ctx->sock_map_port, port, sock_ctx);
// 	sock_ctx->rem_addr = *rem_addr;
// 	sock_ctx->rem_addrlen = rem_addrlen;
// 	sock_ctx->is_connected = 1; /* is this a lie? */
//
// 	if (blocking == 0) {
// 		log_printf(LOG_INFO, "Nonblocking connect requested\n");
// 		netlink_notify_kernel(ctx, id, -EINPROGRESS);
// 	}
// 	return;
// }
//
// void listen_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr,
// 	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen) {
//
// 	int ret;
// 	sock_ctx_t* sock_ctx;
// 	int response = 0;
//
// 	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
// 	if (sock_ctx == NULL) {
// 		response = -EBADF;
// 	}
// 	else {
// 		ret = listen(sock_ctx->fd, SOMAXCONN);
// 		if (ret == -1) {
// 			response = -errno;
// 		}
// 	}
// 	netlink_notify_kernel(ctx, id, response);
// 	if (response != 0) {
// 		return;
// 	}
//
// 	/* We're done gathering info, let's set up a server */
// 	ret = evutil_make_socket_nonblocking(sock_ctx->fd);
// 	if (ret == -1) {
// 		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
// 			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
// 		EVUTIL_CLOSESOCKET(sock_ctx->fd);
// 		return;
// 	}
//
// 	//tls_opts_server_setup(sock_ctx->tls_opts);
// 	sock_ctx->daemon = ctx; /* XXX I don't want this here */
// 	sock_ctx->listener = evconnlistener_new(ctx->base, listener_accept_cb, sock_ctx,
// 		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, 0, sock_ctx->fd);
//
// 	evconnlistener_set_error_cb(sock_ctx->listener, listener_accept_error_cb);
// 	return;
// }
//
// void associate_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, int int_addrlen) {
// 	sock_ctx_t* sock_ctx;
// 	int response = 0;
// 	int port;
//
// 	if (int_addr->sa_family == AF_UNIX) {
// 		port = strtol(((struct sockaddr_un*)int_addr)->sun_path+1, NULL, 16);
// 		log_printf(LOG_INFO, "unix port is %05x", port);
// 	}
// 	else {
// 		port = (int)ntohs(((struct sockaddr_in*)int_addr)->sin_port);
// 	}
// 	sock_ctx = hashmap_get(ctx->sock_map_port, port);
// 	hashmap_del(ctx->sock_map_port, port);
// 	if (sock_ctx == NULL) {
// 		log_printf(LOG_ERROR, "port provided in associate_cb not found");
// 		response = -EBADF;
// 		netlink_notify_kernel(ctx, id, response);
// 		return;
// 	}
//
// 	sock_ctx->id = id;
// 	sock_ctx->is_connected = 1;
// 	hashmap_add(ctx->sock_map, id, (void*)sock_ctx);
//
// 	//set_netlink_cb_params(sock_ctx->tls_conn, ctx, id);
// 	//log_printf(LOG_INFO, "Socket %lu accepted\n", id);
// 	netlink_notify_kernel(ctx, id, response);
// 	return;
// }
//
// void close_cb(tls_daemon_ctx_t* ctx, unsigned long id) {
// 	sock_ctx_t* sock_ctx;
//
// 	sock_ctx = (sock_ctx_t*)hashmap_get(ctx->sock_map, id);
// 	if (sock_ctx == NULL) {
// 		return;
// 	}
// 	/* close things here */
// 	if (sock_ctx->is_accepting == 1) {
// 		/* This is an ophan server connection.
// 		 * We don't host its corresponding listen socket
// 		 * But we were given control of the remote peer
// 		 * connection */
// 		hashmap_del(ctx->sock_map, id);
// 		//tls_opts_free(sock_ctx->tls_opts);
// 		//free_tls_conn_ctx(sock_ctx->tls_conn);
// 		free(sock_ctx);
// 		return;
// 	}
// 	if (sock_ctx->is_connected == 1) {
// 		/* connections under the control of the tls_wrapper code
// 		 * clean up themselves as a result of the close event
// 		 * received from one of the endpoints. In this case we
// 		 * only need to clean up the sock_ctx */
// 		//netlink_notify_kernel(ctx, id, 0);
// 		hashmap_del(ctx->sock_map, id);
// 		//tls_opts_free(sock_ctx->tls_opts);
// 		//free_tls_conn_ctx(sock_ctx->tls_conn);
// 		free(sock_ctx);
// 		return;
// 	}
// 	if (sock_ctx->listener != NULL) {
// 		hashmap_del(ctx->sock_map, id);
// 		evconnlistener_free(sock_ctx->listener);
// 		//tls_opts_free(sock_ctx->tls_opts);
// 		free(sock_ctx);
// 		//netlink_notify_kernel(ctx, id, 0);
// 		return;
// 	}
// 	hashmap_del(ctx->sock_map, id);
// 	EVUTIL_CLOSESOCKET(sock_ctx->fd);
// 	free(sock_ctx);
// 	//netlink_notify_kernel(ctx, id, 0);
// 	return;
// }
//
/* This function is provided to the hashmap implementation
 * so that it can correctly free all held data */
void free_sock_ctx(sock_ctx_t *sock_ctx)
{
	if (sock_ctx->listener != NULL)
	{
		evconnlistener_free(sock_ctx->listener);
	}
	else if (sock_ctx->is_connected == 1)
	{
		/* connections under the control of the tls_wrapper code
		 * clean up themselves as a result of the close event
		 * received from one of the endpoints. In this case we
		 * only need to clean up the sock_ctx */
	}
	else
	{
		EVUTIL_CLOSESOCKET(sock_ctx->fd);
	}
	// tls_opts_free(sock_ctx->tls_opts);
	// if (sock_ctx->tls_conn != NULL) {
	//	free_tls_conn_ctx(sock_ctx->tls_conn);
	// }
	free(sock_ctx);
	return;
}
//
// /* Modified read_fd taken from various online sources. Found without copyright or
//  * attribution. Examples also in manpages so we could use that if needed */
// ssize_t recv_fd_from(int fd, void *ptr, size_t nbytes, int *recvfd, struct sockaddr_un* addr, int addr_len) {
// 	struct msghdr msg;
// 	struct iovec iov[1];
// 	ssize_t	n;
//
// 	union {
// 		struct cmsghdr cm;
// 		char control[CMSG_SPACE(sizeof(int))];
// 	} control_un;
// 	struct cmsghdr* cmptr;
//
// 	msg.msg_control = control_un.control;
// 	msg.msg_controllen = sizeof(control_un.control);
// 	msg.msg_name = addr;
// 	msg.msg_namelen = addr_len;
//
// 	iov[0].iov_base = ptr;
// 	iov[0].iov_len = nbytes;
// 	msg.msg_iov = iov;
// 	msg.msg_iovlen = 1;
//
// 	if ((n = recvmsg(fd, &msg, 0)) <= 0) {
// 		// message length of error or 0
// 		*recvfd = -1;
// 		return n;
// 	}
//
// 	if ((cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
// 	    cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
// 		if (cmptr->cmsg_level != SOL_SOCKET) {
// 			log_printf(LOG_ERROR, "control level != SOL_SOCKET\n");
// 			*recvfd = -1;
// 			return -1;
// 		}
// 		if (cmptr->cmsg_type != SCM_RIGHTS) {
// 			log_printf(LOG_ERROR, "control type != SCM_RIGHTS\n");
// 			*recvfd = -1;
// 			return -1;
// 		}
// 		*recvfd = *((int *) CMSG_DATA(cmptr));
// 	}
// 	else {
// 		*recvfd = -1; /* descriptor was not passed */
// 	}
// 	return n;
// }
//
