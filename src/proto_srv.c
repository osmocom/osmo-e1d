/*
 * proto_srv.c
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <talloc.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>

#include <osmocom/e1d/proto.h>
#include <osmocom/e1d/proto_srv.h>

#include "log.h"


struct osmo_e1dp_server {
	void *ctx;
	struct osmo_fd ctl_fd;
	struct llist_head conns;
	struct osmo_e1dp_server_handler *handlers;
	void *handler_data;
};

struct osmo_e1dp_server_conn {
	struct llist_head list;
	struct osmo_e1dp_server *srv;
	struct osmo_fd fd;
};


static int
_e1dp_server_request(struct osmo_e1dp_server_conn *conn, struct msgb *msgb)
{
	struct osmo_e1dp_msg_hdr *hdr = msgb_l1(msgb);
	struct osmo_e1dp_msg_hdr *rhdr;
	struct osmo_e1dp_server_handler *h;
	struct msgb *rmsgb;
	int rfd, rc;

	/* Find handler */
	h = conn->srv->handlers;

	while (h->fn) {
		if (h->type == hdr->type)
			break;
		h++;
	}

	if (!h->fn) {
		LOGP(DE1D, LOGL_ERROR, "Unhandled message type: %d.\n", hdr->type);
		return -1;
	}

	/* Check flags */
	if (((hdr->intf == E1DP_INVALID) ?
		(h->flags & E1DP_SF_INTF_REQ) : !(h->flags & (E1DP_SF_INTF_OPT | E1DP_SF_INTF_REQ))) ||
	    ((hdr->line == E1DP_INVALID) ?
		(h->flags & E1DP_SF_LINE_REQ) : !(h->flags & (E1DP_SF_LINE_OPT | E1DP_SF_LINE_REQ))) ||
	    ((hdr->ts == E1DP_INVALID) ?
		(h->flags & E1DP_SF_TS_REQ)   : !(h->flags & (E1DP_SF_TS_OPT   | E1DP_SF_TS_REQ))))
	{
		LOGP(DE1D, LOGL_ERROR, "Invalid type/intf/line for message type: %d / (%d/%d/%d) %d.\n",
			hdr->type, hdr->intf, hdr->line, hdr->ts, h->flags);
		return -1;
	}

	/* Check payload length */
	if ((h->payload_len >= 0) &&
	    (h->payload_len != (int)(msgb_length(msgb) - sizeof(struct osmo_e1dp_msg_hdr))))
	{
		LOGP(DE1D, LOGL_ERROR, "Invalid payload for message type: %d / (%d/%d/%d).\n",
			hdr->type, hdr->intf, hdr->line, hdr->ts);
		return -1;
	}

	/* Call handler */
	rmsgb = msgb_alloc(E1DP_MAX_LEN, "e1d proto tx message");
	rfd = -1;

	rmsgb->l1h = msgb_put(rmsgb, sizeof(struct osmo_e1dp_msg_hdr));
	rhdr = msgb_l1(rmsgb);

	rc = h->fn(conn->srv->handler_data, msgb, rmsgb, &rfd);

	if (rc) {
		msgb_trim(rmsgb, msgb_l1len(rmsgb));
		rhdr->type = E1DP_ERR_TYPE | (rc & 0x3f);
	} else {
		rhdr->type =  hdr->type | E1DP_RESP_TYPE;
	}

	rhdr->magic = E1DP_MAGIC;
	rhdr->len = msgb_length(rmsgb);

	/* Send response */
	rc = osmo_e1dp_send(&conn->fd, rmsgb, rfd);
	rc = (rc <= 0) ? -EPIPE : 0;

	/* Done */
	msgb_free(rmsgb);

	return rc;
}

static void
_e1dp_server_disconnect(struct osmo_e1dp_server_conn *conn)
{
	osmo_fd_close(&conn->fd);
	llist_del(&conn->list);
	talloc_free(conn);
}

static int
_e1dp_server_read(struct osmo_fd *fd, unsigned int flags)
{
	struct osmo_e1dp_server_conn *conn = fd->data;
	struct msgb *msgb;
	int rc;

	msgb = osmo_e1dp_recv(fd, NULL);
	if (!msgb)
		goto err;

	rc = _e1dp_server_request(conn, msgb);
	if (rc)
		goto err;

	msgb_free(msgb);

	return 0;

err:
	/* Disconnect client */
	msgb_free(msgb);
	_e1dp_server_disconnect(conn);

	return -1;
}


static int
_e1dp_server_accept(struct osmo_fd *fd, unsigned int flags)
{
	struct osmo_e1dp_server *srv = fd->data;
	struct osmo_e1dp_server_conn *conn;
	struct sockaddr_un un_addr;
	socklen_t len;
	int rc;

	len = sizeof(un_addr);
	rc = accept(fd->fd, (struct sockaddr *) &un_addr, &len);
	if (rc < 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to accept a new connection.\n");
		return -1;
	}

	conn = talloc_zero(srv->ctx, struct osmo_e1dp_server_conn);
	if (!conn) {
		LOGP(DE1D, LOGL_ERROR, "Failed to create incoming connection.\n");
		return -1;
	}

	conn->srv = srv;

	conn->fd.fd = rc;
	conn->fd.when = OSMO_FD_READ;
	conn->fd.cb = _e1dp_server_read;
	conn->fd.data = conn;

	if (osmo_fd_register(&conn->fd) != 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to register incoming fd.\n");
		return -1;
	}

	llist_add(&conn->list, &srv->conns);

	LOGP(DE1D, LOGL_DEBUG, "New incoming connection.\n");

	return 0;
}


struct osmo_e1dp_server *
osmo_e1dp_server_create(void *ctx, const char *path,
                        struct osmo_e1dp_server_handler *handlers, void *handler_data)
{
	struct osmo_e1dp_server *srv;
	int rc;

	/* Base structure init */
	srv = talloc_zero(ctx, struct osmo_e1dp_server);
	OSMO_ASSERT(srv);

	srv->ctx = ctx;
	srv->handlers = handlers;
	srv->handler_data = handler_data;

	INIT_LLIST_HEAD(&srv->conns);

	/* Server socket */
	rc = osmo_sock_unix_init_ofd(&srv->ctl_fd, SOCK_SEQPACKET, 0, path, OSMO_SOCK_F_BIND);
	if (rc < 0)
		goto err;

	srv->ctl_fd.cb = _e1dp_server_accept;
	srv->ctl_fd.data = srv;

	return srv;

err:
	talloc_free(srv);
	return NULL;
}

void
osmo_e1dp_server_destroy(struct osmo_e1dp_server *srv)
{
	struct osmo_e1dp_server_conn *conn, *tmp;

	if (!srv)
		return;

	/* Disconnect all clients */
	llist_for_each_entry_safe(conn, tmp, &srv->conns, list) {
		_e1dp_server_disconnect(conn);
	}

	/* Resource release */
	osmo_fd_close(&srv->ctl_fd);
	talloc_free(srv);
}
