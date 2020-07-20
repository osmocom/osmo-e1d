/*
 * proto_clnt.c
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
 * (C) 2020 by Harald Welte <laforge@gnumonks.org>
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
#include <fcntl.h>
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
#include <osmocom/e1d/proto_clnt.h>

#include "log.h"


struct osmo_e1dp_client {
	void *ctx;
	struct osmo_fd ctl_fd;
};


static int
_e1dp_client_event(struct osmo_e1dp_client *clnt, struct msgb *msgb)
{
	/* FIXME */
	return 0;
}


static int
_e1dp_client_read(struct osmo_fd *ofd, unsigned int flags)
{
	struct osmo_e1dp_client *clnt = ofd->data;
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr *hdr;

	msgb = osmo_e1dp_recv(ofd, NULL);
	if (!msgb)
		goto err;

	hdr = msgb_l1(msgb);
	if ((hdr->type & E1DP_TYPE_MSK) != E1DP_EVT_TYPE)
		goto err;

	_e1dp_client_event(clnt, msgb);

	msgb_free(msgb);

	return 0;

err:
	msgb_free(msgb);

	return -1;
}


struct osmo_e1dp_client *
osmo_e1dp_client_create(void *ctx, const char *path)
{
	struct osmo_e1dp_client *clnt;
	int rc;

	/* Base structure init */
	clnt = talloc_zero(ctx, struct osmo_e1dp_client);
	OSMO_ASSERT(clnt);

	clnt->ctx = ctx;

	/* Client socket */
	rc = osmo_sock_unix_init_ofd(&clnt->ctl_fd, SOCK_SEQPACKET, 0, path, OSMO_SOCK_F_CONNECT);
	if (rc < 0)
		goto err;

	clnt->ctl_fd.cb = _e1dp_client_read;
	clnt->ctl_fd.data = clnt;

	return clnt;

err:
	talloc_free(clnt);
	return NULL;
}


void
osmo_e1dp_client_destroy(struct osmo_e1dp_client *clnt)
{
	if (!clnt)
		return;

	osmo_fd_close(&clnt->ctl_fd);
	talloc_free(clnt);
}


static int
_e1dp_client_query_base(struct osmo_e1dp_client *clnt,
	struct osmo_e1dp_msg_hdr *hdr, void *payload, int payload_len,
	struct msgb **resp, int *rfd)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr *msg_hdr;
	int rc, fd;

	/* Request */
	msgb = msgb_alloc(E1DP_MAX_LEN, "e1dp client request");
	OSMO_ASSERT(msgb);

	msg_hdr = (struct osmo_e1dp_msg_hdr *)msgb_put(msgb, sizeof(struct osmo_e1dp_msg_hdr));
	memcpy(msg_hdr, hdr, sizeof(struct osmo_e1dp_msg_hdr));

	msg_hdr->magic = E1DP_MAGIC;
	msg_hdr->len   = sizeof(struct osmo_e1dp_msg_hdr) + payload_len;

	if (payload_len) {
		msgb->l2h = msgb_put(msgb, payload_len);
		memcpy(msgb_l2(msgb), payload, payload_len);
	}

	rc = osmo_e1dp_send(&clnt->ctl_fd, msgb, -1);
	if (rc < 0)
		return rc;

	msgb_free(msgb);

	/* Response */
	int flags = fcntl(clnt->ctl_fd.fd, F_GETFL, 0);
	fcntl(clnt->ctl_fd.fd, F_SETFL, flags & ~O_NONBLOCK);

	while (1) {
		fd = -1;
		msgb = osmo_e1dp_recv(&clnt->ctl_fd, &fd);
		if (!msgb) {
			rc = -EPIPE;
			goto err;
		}

		msg_hdr = msgb_l1(msgb);
		if ((msg_hdr->type & E1DP_TYPE_MSK) != E1DP_EVT_TYPE)
			break;

		_e1dp_client_event(clnt, msgb);
		msgb_free(msgb);
	}

	fcntl(clnt->ctl_fd.fd, F_SETFL, flags);

	if (msg_hdr->type != (hdr->type | E1DP_RESP_TYPE)) {
		rc = -EPIPE;
		goto err;
	}

	*resp = msgb;
	if (rfd)
		*rfd = fd;

	return 0;
err:
	fcntl(clnt->ctl_fd.fd, F_SETFL, flags);
	msgb_free(msgb);
	return rc;
}

int
osmo_e1dp_client_intf_query(struct osmo_e1dp_client *clnt,
	struct osmo_e1dp_intf_info **ii, int *n,
	uint8_t intf)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr hdr;
	int rc;

	memset(&hdr, 0x00, sizeof(struct osmo_e1dp_msg_hdr));
	hdr.type = E1DP_CMD_INTF_QUERY;
	hdr.intf = intf;
	hdr.line = E1DP_INVALID;
	hdr.ts   = E1DP_INVALID;

	rc = _e1dp_client_query_base(clnt, &hdr, NULL, 0, &msgb, NULL);
	if (rc)
		return rc;

	*n  = msgb_l2len(msgb) / sizeof(struct osmo_e1dp_intf_info);

	if (*n) {
		*ii = talloc_array(clnt->ctx, struct osmo_e1dp_intf_info, *n);
		memcpy(*ii, msgb_l2(msgb), *n * sizeof(struct osmo_e1dp_intf_info));
	}

	msgb_free(msgb);

	return 0;
}

int
osmo_e1dp_client_line_query(struct osmo_e1dp_client *clnt,
	struct osmo_e1dp_line_info **li, int *n,
	uint8_t intf, uint8_t line)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr hdr;
	int rc;

	memset(&hdr, 0x00, sizeof(struct osmo_e1dp_msg_hdr));
	hdr.type = E1DP_CMD_LINE_QUERY;
	hdr.intf = intf;
	hdr.line = line;
	hdr.ts   = E1DP_INVALID;

	rc = _e1dp_client_query_base(clnt, &hdr, NULL, 0, &msgb, NULL);
	if (rc)
		return rc;

	*n  = msgb_l2len(msgb) / sizeof(struct osmo_e1dp_line_info);

	if (*n) {
		*li = talloc_array(clnt->ctx, struct osmo_e1dp_line_info, *n);
		memcpy(*li, msgb_l2(msgb), *n * sizeof(struct osmo_e1dp_line_info));
	}

	msgb_free(msgb);

	return 0;
}

int
osmo_e1dp_client_ts_query(struct osmo_e1dp_client *clnt,
	struct osmo_e1dp_ts_info **ti, int *n,
	uint8_t intf, uint8_t line, uint8_t ts)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr hdr;
	int rc;

	memset(&hdr, 0x00, sizeof(struct osmo_e1dp_msg_hdr));
	hdr.type = E1DP_CMD_TS_QUERY;
	hdr.intf = intf;
	hdr.line = line;
	hdr.ts   = ts;

	rc = _e1dp_client_query_base(clnt, &hdr, NULL, 0, &msgb, NULL);
	if (rc)
		return rc;

	*n  = msgb_l2len(msgb) / sizeof(struct osmo_e1dp_ts_info);

	if (*n) {
		*ti = talloc_array(clnt->ctx, struct osmo_e1dp_ts_info, *n);
		memcpy(*ti, msgb_l2(msgb), *n * sizeof(struct osmo_e1dp_ts_info));
	}

	msgb_free(msgb);

	return 0;
}

int
osmo_e1dp_client_line_config(struct osmo_e1dp_client *clnt,
	uint8_t intf, uint8_t line, enum osmo_e1dp_line_mode mode)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr hdr;
	struct osmo_e1dp_line_config cfg;
	int rc;

	memset(&hdr, 0x00, sizeof(struct osmo_e1dp_msg_hdr));
	hdr.type = E1DP_CMD_LINE_CONFIG;
	hdr.intf = intf;
	hdr.line = line;
	hdr.ts = E1DP_INVALID;

	memset(&cfg, 0x00, sizeof(struct osmo_e1dp_line_config));
	cfg.mode = mode;

	rc = _e1dp_client_query_base(clnt, &hdr, &cfg, sizeof(struct osmo_e1dp_line_config), &msgb, NULL);
	if (rc)
		return rc;

	if (msgb_l2len(msgb) != sizeof(struct osmo_e1dp_line_info))
		return -EPIPE;

	msgb_free(msgb);

	return 0;
}

int
osmo_e1dp_client_ts_open(struct osmo_e1dp_client *clnt,
	uint8_t intf, uint8_t line, uint8_t ts,
	enum osmo_e1dp_ts_mode mode, uint16_t read_bufsize)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr hdr;
	struct osmo_e1dp_ts_config cfg;
	int rc, tsfd;

	memset(&hdr, 0x00, sizeof(struct osmo_e1dp_msg_hdr));
	hdr.type = E1DP_CMD_TS_OPEN;
	hdr.intf = intf;
	hdr.line = line;
	hdr.ts   = ts;

	memset(&cfg, 0x00, sizeof(struct osmo_e1dp_ts_config));
	cfg.mode = mode;
	cfg.read_bufsize = read_bufsize;

	tsfd = -1;

	rc = _e1dp_client_query_base(clnt, &hdr, &cfg, sizeof(struct osmo_e1dp_ts_config), &msgb, &tsfd);
	if (rc)
		return rc;

	if ((tsfd < 0) || (msgb_l2len(msgb) != sizeof(struct osmo_e1dp_ts_info)))
		return -EPIPE;

	msgb_free(msgb);

	return tsfd;
}
