/*
 * octoi_sock.c - OCTOI Socket handling code
 *
 * (C) 2022 by Harald Welte <laforge@osmocom.org>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <osmocom/octoi/e1oip_proto.h>

#include "octoi_sock.h"
#include "e1oip.h"

/* determine domain / AF of socket */
static int sock_get_domain(int fd)
{
	int domain;
	socklen_t dom_len = sizeof(domain);
	int rc;

	rc = getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &dom_len);
	if (rc < 0)
		return rc;

	return domain;
}

/* typical number of bytes in IP + UDP header for given socket */
static int sock_get_iph_udph_overhead(int fd)
{
	int rc = sock_get_domain(fd);
	if (rc < 0) {
		LOGP(DLINP, LOGL_ERROR, "Unable to determine domain of socket %d: %s\n",
		     fd, strerror(errno));
		goto assume_ipv4;
	}

	switch (rc) {
	case AF_INET6:
		return 40 + 8;
	case AF_INET:
		return 20 + 8;
	default:
		LOGP(DLINP, LOGL_ERROR, "Unknown domain %d of socket %d\n", rc, fd);
		break;
	}

assume_ipv4:
	return 20 + 8;
}

/***********************************************************************
 * transmit to remote peer
 ***********************************************************************/

/* transmit something to an octoi peer */
int octoi_tx(struct octoi_peer *peer, uint8_t msg_type, uint8_t flags,
	     const void *data, size_t len)
{
	struct e1oip_hdr hdr = {
		.version = E1OIP_VERSION,
		.flags = flags & 0xf,
		.msg_type = msg_type,
	};
	struct iovec iov[2] = {
		{
			.iov_base = (void *) &hdr,
			.iov_len = sizeof(hdr),
		}, {
			.iov_base = (void *) data,
			.iov_len = len,
		}
	};
	struct msghdr msgh = {
		.msg_name = &peer->remote,
		.msg_namelen = sizeof(peer->remote),
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	int rc;

	rc = sendmsg(peer->sock->ofd.fd, &msgh, 0);
	if (rc < 0)
		LOGPEER(peer, LOGL_ERROR, "Error in sendmsg: %s\n", strerror(errno));
	else if (rc != (int) (sizeof(hdr) + len))
		LOGPEER(peer, LOGL_ERROR, "Short write in  sendmsg: %d != %zu\n", rc, sizeof(hdr)+len);

	return rc;
}

static int _octoi_tx_echo(struct octoi_peer *peer, bool is_req, uint16_t seq_nr,
			  const uint8_t *data, size_t data_len)
{
	enum e1oip_msgtype msgt;
	struct {
		struct e1oip_echo echo;
		uint8_t buf[data_len];
	} u;

	u.echo.seq_nr = htons(seq_nr);
	memcpy(u.echo.data, data, data_len);

	if (is_req)
		msgt = E1OIP_MSGT_ECHO_REQ;
	else
		msgt = E1OIP_MSGT_ECHO_RESP;

	return octoi_tx(peer, msgt, 0, &u, sizeof(u));
}

int octoi_tx_echo_req(struct octoi_peer *peer, uint16_t seq_nr, const uint8_t *data, size_t data_len)
{
	LOGPEER(peer, LOGL_DEBUG, "Tx ECHO_REQ\n");
	return _octoi_tx_echo(peer, true, seq_nr, data, data_len);
}

int octoi_tx_echo_resp(struct octoi_peer *peer, uint16_t seq_nr, const uint8_t *data, size_t data_len)
{
	LOGPEER(peer, LOGL_DEBUG, "Tx ECHO_RESP\n");
	return _octoi_tx_echo(peer, false, seq_nr, data, data_len);
}

int octoi_tx_service_req(struct octoi_peer *peer, uint32_t service, const char *subscr_id,
			 const char *software_id, const char *software_version,
			 uint32_t capability_flags)
{
	struct e1oip_service_req service_req;

	memset(&service_req, 0, sizeof(service_req));
	service_req.requested_service = htonl(service);
	OSMO_STRLCPY_ARRAY(service_req.subscriber_id, subscr_id);
	OSMO_STRLCPY_ARRAY(service_req.software_id, software_id);
	OSMO_STRLCPY_ARRAY(service_req.software_version, software_version);
	service_req.capability_flags = htonl(capability_flags);

	LOGPEER(peer, LOGL_INFO, "Tx SERVICE_REQ\n");
	return octoi_tx(peer, E1OIP_MSGT_SERVICE_REQ, 0, &service_req, sizeof(service_req));
}

int octoi_tx_redir_cmd(struct octoi_peer *peer, const char *server_ip, uint16_t server_port)
{
	struct e1oip_redir_cmd redir;

	memset(&redir, 0, sizeof(redir));
	OSMO_STRLCPY_ARRAY(redir.server_ip, server_ip);
	redir.server_port = htons(server_port);

	LOGPEER(peer, LOGL_INFO, "Tx REDIR_CMD\n");
	return octoi_tx(peer, E1OIP_MSGT_REDIR_CMD, 0, &redir, sizeof(redir));
}

int octoi_tx_auth_req(struct octoi_peer *peer, uint8_t rand_len, const uint8_t *rand,
		      uint8_t autn_len, const uint8_t *autn)
{
	struct e1oip_auth_req areq;

	memset(&areq, 0, sizeof(areq));

	OSMO_ASSERT(rand_len <= sizeof(areq.rand));
	OSMO_ASSERT(autn_len <= sizeof(areq.autn));

	areq.rand_len = rand_len;
	memcpy(areq.rand, rand, rand_len);
	areq.autn_len = autn_len;
	memcpy(areq.autn, autn, autn_len);

	LOGPEER(peer, LOGL_INFO, "Tx AUTH_REQ\n");
	return octoi_tx(peer, E1OIP_MSGT_AUTH_REQ, 0, &areq, sizeof(areq));
}


int octoi_tx_auth_resp(struct octoi_peer *peer, uint8_t res_len, const uint8_t *res,
		      uint8_t auts_len, const uint8_t *auts)
{
	struct e1oip_auth_resp aresp;

	memset(&aresp, 0, sizeof(aresp));

	OSMO_ASSERT(res_len <= sizeof(aresp.res));
	OSMO_ASSERT(auts_len <= sizeof(aresp.auts));

	aresp.res_len = res_len;
	memcpy(aresp.res, res, res_len);
	aresp.auts_len = auts_len;
	memcpy(aresp.auts, auts, auts_len);

	LOGPEER(peer, LOGL_INFO, "Tx AUTH_RESP\n");
	return octoi_tx(peer, E1OIP_MSGT_AUTH_RESP, 0, &aresp, sizeof(aresp));
}

int octoi_tx_service_ack(struct octoi_peer *peer, uint32_t assigned_service,
			 const char *server_id, const char *software_id,
			 const char *software_version, uint32_t capability_flags)
{
	struct e1oip_service_ack service_ack;

	memset(&service_ack, 0, sizeof(service_ack));
	service_ack.assigned_service = htonl(assigned_service);
	OSMO_STRLCPY_ARRAY(service_ack.server_id, server_id);
	OSMO_STRLCPY_ARRAY(service_ack.software_id, software_id);
	OSMO_STRLCPY_ARRAY(service_ack.software_version, software_version);
	service_ack.capability_flags = htonl(capability_flags);

	LOGPEER(peer, LOGL_INFO, "Tx SERVICE_ACK\n");
	return octoi_tx(peer, E1OIP_MSGT_SERVICE_ACK, 0, &service_ack, sizeof(service_ack));
}

int octoi_tx_service_rej(struct octoi_peer *peer, uint32_t rejected_service, const char *message)
{
	struct e1oip_service_rej service_rej;

	memset(&service_rej, 0, sizeof(service_rej));
	service_rej.rejected_service = htonl(rejected_service);
	OSMO_STRLCPY_ARRAY(service_rej.reject_message, message);

	LOGPEER(peer, LOGL_INFO, "Tx SERVICE_REJ\n");
	return octoi_tx(peer, E1OIP_MSGT_SERVICE_REJ, 0, &service_rej, sizeof(service_rej));
}

int octoi_tx_error_ind(struct octoi_peer *peer, uint32_t cause, const char *message,
		       const uint8_t *orig, size_t orig_len)
{
	struct {
		struct e1oip_error_ind error_ind;
		uint8_t orig[orig_len];
	} u;

	u.error_ind.cause = htonl(cause);
	OSMO_STRLCPY_ARRAY(u.error_ind.error_message, message);
	memcpy(&u.orig, orig, orig_len);

	LOGPEER(peer, LOGL_INFO, "Tx ERROR_IND\n");
	return octoi_tx(peer, E1OIP_MSGT_ERROR_IND, 0, &u, sizeof(u));
}


/***********************************************************************
 * socket
 ***********************************************************************/

static int sockaddr_cmp(const struct sockaddr *x, const struct sockaddr *y)
{
	if (x->sa_family != y->sa_family)
		return -1;

	if (x->sa_family == AF_UNIX) {
		const struct sockaddr_un *xun = (void *)x, *yun = (void *)y;
		int r = strcmp(xun->sun_path, yun->sun_path);
		if (r != 0)
			return r;
	} else if (x->sa_family == AF_INET) {
		const struct sockaddr_in *xin = (void *)x, *yin = (void *)y;
		if (xin->sin_addr.s_addr != yin->sin_addr.s_addr)
			return -1;
		if (xin->sin_port != yin->sin_port)
			return -1;
	} else if (x->sa_family == AF_INET6) {
		const struct sockaddr_in6 *xin6 = (void *)x, *yin6 = (void *)y;
		int r = memcmp(xin6->sin6_addr.s6_addr, yin6->sin6_addr.s6_addr, sizeof(xin6->sin6_addr.s6_addr));
		if (r != 0)
			return r;
		if (xin6->sin6_port != yin6->sin6_port)
			return -1;
		if (xin6->sin6_flowinfo != yin6->sin6_flowinfo)
			return -1;
		if (xin6->sin6_scope_id != yin6->sin6_scope_id)
			return -1;
	} else {
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct octoi_peer *find_peer_by_sockaddr(struct octoi_sock *sock, const struct sockaddr *sa)
{
	struct octoi_peer *peer;

	llist_for_each_entry(peer, &sock->peers, list) {
		if (!sockaddr_cmp(sa, (struct sockaddr *) &peer->remote))
			return peer;
	}
	return NULL;
}

static struct octoi_peer *
alloc_peer(struct octoi_sock *sock, const struct sockaddr *sa, socklen_t sa_len)
{
	struct octoi_peer *peer = talloc_zero(sock, struct octoi_peer);

	if (!peer)
		return NULL;

	OSMO_ASSERT(sa_len <= sizeof(peer->remote));
	memcpy(&peer->remote, sa, sa_len);

	peer->sock = sock;
	llist_add_tail(&peer->list, &sock->peers);

	return peer;
}

static int octoi_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct octoi_sock *sock = ofd->data;
	struct msgb *msg;
	struct sockaddr_storage ss_remote;
	socklen_t ss_remote_len = sizeof(ss_remote);
	struct octoi_peer *peer;
	int rc;

	if (what & OSMO_FD_WRITE) {
		LOGP(DLINP, LOGL_INFO, "non-blocking connect succeeded\n");
		osmo_fd_write_disable(ofd);
	}


	if (what & OSMO_FD_READ) {
		msg = msgb_alloc_c(sock, 2048, "OCTOI Rx");
		OSMO_ASSERT(msg);
		rc = recvfrom(ofd->fd, msgb_data(msg), msgb_tailroom(msg), 0,
				(struct sockaddr *) &ss_remote, &ss_remote_len);
		if (rc <= 0) {
			msgb_free(msg);
			return -1;
		}
		msgb_put(msg, rc);
		msg->l1h = msg->data;
		if (msgb_l1len(msg) < sizeof(struct e1oip_hdr)) {
			msgb_free(msg);
			return -2;
		}
		msg->l2h = msg->l1h + sizeof(struct e1oip_hdr);

		/* look-up octoi_peer based on remote address */
		peer = find_peer_by_sockaddr(sock, (struct sockaddr *) &ss_remote);
		if (!peer) {
			peer = alloc_peer(sock, (struct sockaddr *) &ss_remote, ss_remote_len);
			if (peer) {
				osmo_sockaddr_str_from_sockaddr(&peer->cfg.remote, &ss_remote);
				osmo_talloc_replace_string_fmt(peer, &peer->name, OSMO_SOCKADDR_STR_FMT,
								OSMO_SOCKADDR_STR_FMT_ARGS(&peer->cfg.remote));
				LOGPEER(peer, LOGL_INFO, "peer created\n");
			}
		}
		OSMO_ASSERT(peer);

		/* dispatch received message to peer */
		rc = sock->rx_cb(peer, msg);
		if (rc < 0)
			return rc;
	}

	return 0;
}

void octoi_peer_destroy(struct octoi_peer *peer)
{
	if (!peer)
		return;

	peer->tdm_permitted = false;
	peer->sock = NULL;
	e1oip_line_destroy(peer->iline);

	llist_del(&peer->list);
	talloc_free(peer);
}

static struct octoi_sock *octoi_sock_create(void *ctx)
{
	struct octoi_sock *sock = talloc_zero(ctx, struct octoi_sock);

	if (!sock)
		return NULL;

	INIT_LLIST_HEAD(&sock->peers);
	osmo_fd_setup(&sock->ofd, -1, OSMO_FD_READ, octoi_fd_cb, sock, 0);

	return sock;
}

struct octoi_sock *octoi_sock_create_server(void *ctx, void *priv, const struct osmo_sockaddr_str *local)
{
	struct octoi_sock *sock = octoi_sock_create(ctx);
	struct sockaddr_storage sa_local;
	int rc;

	OSMO_ASSERT(sock);

	sock->priv = priv;
	sock->cfg.server_mode = true;
	sock->cfg.local = *local;

	/* bind to local addr/port; don't connect to any remote as we have many */
	osmo_sockaddr_str_to_sockaddr(&sock->cfg.local, &sa_local);
	rc = osmo_sock_init_osa_ofd(&sock->ofd, SOCK_DGRAM, IPPROTO_UDP,
				    (struct osmo_sockaddr *) &sa_local, NULL,
				    OSMO_SOCK_F_BIND | OSMO_SOCK_F_NONBLOCK);

	if (rc < 0) {
		LOGP(DLINP, LOGL_ERROR, "Unable to create OCTOI server socket\n");
		talloc_free(sock);
		return NULL;
	}

	LOGP(DLINP, LOGL_NOTICE, "OCTOI server socket at "OSMO_SOCKADDR_STR_FMT"\n",
		OSMO_SOCKADDR_STR_FMT_ARGS(local));

	sock->iph_udph_size = sock_get_iph_udph_overhead(sock->ofd.fd);

	return sock;
}

struct octoi_sock *octoi_sock_create_client(void *ctx, void *priv, const struct osmo_sockaddr_str *local,
					    const struct osmo_sockaddr_str *remote)
{
	struct octoi_sock *sock = octoi_sock_create(ctx);
	struct sockaddr_storage sa_remote;
	struct octoi_peer *peer;
	int rc;

	OSMO_ASSERT(sock);

	sock->priv = priv;
	sock->cfg.server_mode = false;
	if (local)
		sock->cfg.local = *local;

	/* bind to local addr/port; don't connect to any remote as we have many */
	osmo_sockaddr_str_to_sockaddr(remote, &sa_remote);
	if (local) {
		struct sockaddr_storage sa_local;
		osmo_sockaddr_str_to_sockaddr(&sock->cfg.local, &sa_local);
		rc = osmo_sock_init_osa_ofd(&sock->ofd, SOCK_DGRAM, IPPROTO_UDP,
					    (struct osmo_sockaddr *) &sa_local,
					    (struct osmo_sockaddr *) &sa_remote,
					    OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_BIND | OSMO_SOCK_F_NONBLOCK);
	} else {
		rc = osmo_sock_init_osa_ofd(&sock->ofd, SOCK_DGRAM, IPPROTO_UDP,
					    NULL, (struct osmo_sockaddr *) &sa_remote,
					    OSMO_SOCK_F_CONNECT | OSMO_SOCK_F_NONBLOCK);
	}
	if (rc < 0) {
		LOGP(DLINP, LOGL_ERROR, "Unable to create OCTOI client socket\n");
		talloc_free(sock);
		return NULL;
	}

	LOGP(DLINP, LOGL_NOTICE, "OCTOI client socket to "OSMO_SOCKADDR_STR_FMT"\n",
		OSMO_SOCKADDR_STR_FMT_ARGS(remote));

	sock->iph_udph_size = sock_get_iph_udph_overhead(sock->ofd.fd);

	/* create [the only] peer */
	peer = alloc_peer(sock, (struct sockaddr *) &sa_remote, sizeof(sa_remote));
	peer->cfg.remote = *remote;
	osmo_talloc_replace_string_fmt(peer, &peer->name, OSMO_SOCKADDR_STR_FMT,
					OSMO_SOCKADDR_STR_FMT_ARGS(remote));

	return sock;
}

int octoi_sock_set_dscp(struct octoi_sock *sock, uint8_t dscp)
{
	return osmo_sock_set_dscp(sock->ofd.fd, dscp);
}

int octoi_sock_set_priority(struct octoi_sock *sock, uint8_t priority)
{
	return osmo_sock_set_priority(sock->ofd.fd, priority);
}

void octoi_sock_destroy(struct octoi_sock *sock)
{
	struct octoi_peer *p1, *p2;

	if (!sock)
		return;

	llist_for_each_entry_safe(p1, p2, &sock->peers, list) {
		OSMO_ASSERT(p1->sock == sock);
		p1->sock = NULL;
		/* FIXME: destroy FSM / priv */
		llist_del(&p1->list);
		talloc_free(p1);
	}

	osmo_fd_unregister(&sock->ofd);
	close(sock->ofd.fd);

	LOGP(DLINP, LOGL_NOTICE, "OCTOI %s socket destroyed\n",
		sock->cfg.server_mode ? "server" : "client");

	talloc_free(sock);
}

/* return the (only) peer of a octoi_sock client */
struct octoi_peer *octoi_sock_client_get_peer(struct octoi_sock *sock)
{
	if (!sock)
		return NULL;
	OSMO_ASSERT(!sock->cfg.server_mode);
	OSMO_ASSERT(llist_count(&sock->peers) == 1);
	return llist_entry(sock->peers.next, struct octoi_peer, list);
}
