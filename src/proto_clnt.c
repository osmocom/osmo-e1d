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

/*! \file proto_clnt.c
 * e1d protocol client library (libosmo-e1d).
 *
 * This library implements ways how an external client (application
 * program) can talk to osmo-e1d.  The primary purpose is to open
 * specific E1 timeslots in order to receive and/or transmit data on
 * them.
 *
 * Each such open timeslot is represented to the client program as a
 * file descriptor, which the client can read and/or write as usual.
 * This is implemented using underlying UNIX domain sockets and file
 * descriptor passing.
 *
 * In addition to opening timeslots, client applications can also query
 * osmo-e1d for information about its E1 interfaces, E1 lines and E1 timeslots.
 *
 * The functions provided by this client library are implemented as
 * synchronous/blocking calls to osmo-e1d.  This means that an API call
 * will be blocking until there is a response received from osmo-e1d.
 *
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

typedef void (*osmo_e1dp_event_cb_t)(enum osmo_e1dp_msg_type, uint8_t, uint8_t, uint8_t, uint8_t *, int);

/*! Internal representation of client program connected to the CTL socket */
struct osmo_e1dp_client {
	void *ctx;		/*!< talloc context */
	struct osmo_fd ctl_fd;	/*!< osmo-fd wrapped unix domain (CTL) socket to @osmo-e1d@ */
	osmo_e1dp_event_cb_t event_cb;
				/*!< callback function for incoming events */
};


static int
_e1dp_client_event(struct osmo_e1dp_client *clnt, struct msgb *msgb)
{
	struct osmo_e1dp_msg_hdr *hdr = msgb_l1(msgb);

	if (!clnt->event_cb)
		return -EINVAL;

	clnt->event_cb(hdr->type, hdr->intf, hdr->line, hdr->ts, msgb_l2(msgb), msgb_l2len(msgb));
	return 0;
}


static int
_e1dp_client_read(struct osmo_fd *ofd, unsigned int flags)
{
	struct osmo_e1dp_client *clnt = ofd->data;
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr *hdr;

	msgb = osmo_e1dp_recv(ofd, NULL);
	if (!msgb) {
		LOGP(DE1D, LOGL_ERROR, "Lost connection with osmo-e1d control socket.\n");
		osmo_fd_close(&clnt->ctl_fd);
		goto err;
	}

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


/*! Create a new client talking to the CTL server socket of osmo-e1d.
 *  \param[in] ctx talloc context from which this client is allocated
 *  \param[in] path path of the CTL unix domain socket of osmo-e1d
 *  \returns handle to newly-created client; NULL in case of errors */
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


/*! Destroy a previously created client. Closes socket and releases memory.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 */
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
	if (rc < 0) {
		msgb_free(msgb);
		return rc;
	}

	msgb_free(msgb);
	msgb = NULL;

	/* Response */
	int flags = fcntl(clnt->ctl_fd.fd, F_GETFL, 0);
	if (flags < 0)
		return -EIO;

	rc = fcntl(clnt->ctl_fd.fd, F_SETFL, flags & ~O_NONBLOCK);
	if (rc < 0)
		goto err;

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

	rc = fcntl(clnt->ctl_fd.fd, F_SETFL, flags);
	if (rc < 0) {
		rc = -EIO;
		goto err;
	}

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

/*! Query osmo-e1d for information about a specific E1 interface.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 *  \param[out] ii callee-allocated array of interface information structures.
 *  \param[out] n caller-provided pointer to integer. Will contain number of entries in ii.
 *  \param[in] intf E1 interface number to query, or E1DP_INVALID to query all interfaces.
 *  \returns zero in case of success; negative in case of error. */
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

/*! Query osmo-e1d for information about a specific E1 line.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 *  \param[out] li callee-allocated array of line information structures.
 *  \param[out] n caller-provided pointer to integer. Will contain number of entries in li.
 *  \param[in] intf E1 interface number to query.
 *  \param[in] line E1 line number (within interface) to query, or E1DP_INVALID to query all lines within the
 *  interface.
 *  \returns zero in case of success; negative in case of error. */
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

/*! Query osmo-e1d for information about a specific E1 timeslot.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 *  \param[out] ti callee-allocated array of timeslot information structures.
 *  \param[out] n caller-provided pointer to integer. Will contain number of entries in ti.
 *  \param[in] intf E1 interface number to query.
 *  \param[in] line E1 line number (within interface) to query.
 *  \param[in] ts E1 timeslot numer (within line) to query, or E1DP_INVALID to query all of the timeslots
 *  within the line.
 *  \returns zero in case of success; negative in case of error. */
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

/*! Configure a specific E1 line in osmo-e1d.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 *  \param[in] intf E1 interface number to configure.
 *  \param[in] line E1 line number (within interface) to configure.
 *  \param[in] mode E1 line mode to set on line.
 *  \returns zero in case of success; negative in case of error. */
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

	if (msgb_l2len(msgb) != sizeof(struct osmo_e1dp_line_info)) {
		msgb_free(msgb);
		return -EPIPE;
	}

	msgb_free(msgb);

	return 0;
}

/*! Set Sa-bits of a specific E1 line in osmo-e1d.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 *  \param[in] intf E1 interface number to configure.
 *  \param[in] line E1 line number (within interface) to configure.
 *  \param[in] sa_bits Sa bits to set on line.
 *  \returns zero in case of success; negative in case of error. */
int
osmo_e1dp_client_set_sa_bits(struct osmo_e1dp_client *clnt, uint8_t intf, uint8_t line, uint8_t sa_bits)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr hdr;
	int rc;

	memset(&hdr, 0x00, sizeof(struct osmo_e1dp_msg_hdr));
	hdr.type = E1DP_CMD_SABITS;
	hdr.intf = intf;
	hdr.line = line;
	hdr.ts = E1DP_INVALID;

	rc = _e1dp_client_query_base(clnt, &hdr, &sa_bits, 1, &msgb, NULL);
	if (rc)
		return rc;

	if (msgb_l2len(msgb) != 0) {
		msgb_free(msgb);
		return -EPIPE;
	}

	msgb_free(msgb);

	return 0;
}

/*! Set CAS bits of a specific time-slot on E1 line in osmo-e1d.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 *  \param[in] intf E1 interface number to configure.
 *  \param[in] line E1 line number (within interface) to configure.
 *  \param[in] time-slot number (within line) to configure.
 *  \param[in] CAS bits associated to this time-slot.
 *  \returns zero in case of success; negative in case of error. */
int
osmo_e1dp_client_set_cas(struct osmo_e1dp_client *clnt, uint8_t intf, uint8_t line, uint8_t ts,
			 struct osmo_e1dp_cas_bits *cas)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr hdr;
	int rc;

	memset(&hdr, 0x00, sizeof(struct osmo_e1dp_msg_hdr));
	hdr.type = E1DP_CMD_CAS;
	hdr.intf = intf;
	hdr.line = line;
	hdr.ts = ts;

	rc = _e1dp_client_query_base(clnt, &hdr, cas, sizeof(*cas), &msgb, NULL);
	if (rc)
		return rc;

	if (msgb_l2len(msgb) != 0) {
		msgb_free(msgb);
		return -EPIPE;
	}

	msgb_free(msgb);

	return 0;
}

static int
_client_ts_open(struct osmo_e1dp_client *clnt,
	uint8_t intf, uint8_t line, uint8_t ts,
	enum osmo_e1dp_ts_mode mode, uint16_t read_bufsize, uint8_t flags)
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
	cfg.flags = flags;
	cfg.read_bufsize = read_bufsize;

	tsfd = -1;

	rc = _e1dp_client_query_base(clnt, &hdr, &cfg, sizeof(struct osmo_e1dp_ts_config), &msgb, &tsfd);
	if (rc)
		return rc;

	if ((tsfd < 0) || (msgb_l2len(msgb) != sizeof(struct osmo_e1dp_ts_info))) {
		msgb_free(msgb);
		return -EPIPE;
	}

	msgb_free(msgb);

	return tsfd;
}

/*! Open a specific E1 timeslot of osmo-e1d.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 *  \param[in] intf E1 interface number of line containing timeslot.
 *  \param[in] line E1 line number (within interface) of line containing timeslot.
 *  \param[in] ts E1 timeslot number (within line) to open.
 *  \param[in] mode timeslot mode (RAW, HDLC-FCE) in which to open timeslot.
 *  \param[in] read_bufsize size of read buffer (in octets) to use.
 *  \returns file descriptor of opened timeslot in case of success; negative in case of error. */
int
osmo_e1dp_client_ts_open(struct osmo_e1dp_client *clnt,
	uint8_t intf, uint8_t line, uint8_t ts,
	enum osmo_e1dp_ts_mode mode, uint16_t read_bufsize)
{
	return _client_ts_open(clnt, intf, line, ts, mode, read_bufsize, 0);
}

/*! Force-Open a specific E1 timeslot of osmo-e1d.
 *  The normal (non-force) opening of a timeslot will fail in case the given timeslot is already
 *  open (by either this or some other client).  Using the open_force variant you can force osmo-e1d
 *  to disregard the existing client/timeslot and transfer ownership of the timeslot to this client.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create().
 *  \param[in] intf E1 interface number of line containing timeslot.
 *  \param[in] line E1 line number (within interface) of line containing timeslot.
 *  \param[in] ts E1 timeslot number (within line) to open.
 *  \param[in] mode timeslot mode (RAW, HDLC-FCE) in which to open timeslot.
 *  \param[in] read_bufsize size of read buffer (in octets) to use.
 *  \returns file descriptor of opened timeslot in case of success; negative in case of error. */
int
osmo_e1dp_client_ts_open_force(struct osmo_e1dp_client *clnt,
	uint8_t intf, uint8_t line, uint8_t ts,
	enum osmo_e1dp_ts_mode mode, uint16_t read_bufsize)
{
	return _client_ts_open(clnt, intf, line, ts, mode, read_bufsize, E1DP_TS_OPEN_F_FORCE);
}

/*! Register event handler for incoming event messages.
 *  \param[in] clnt Client previously returned from osmo_e1dp_client_create(). */
void
osmo_e1dp_client_event_register(struct osmo_e1dp_client *clnt,
	void (*cb)(enum osmo_e1dp_msg_type event, uint8_t intf, uint8_t line, uint8_t ts, uint8_t *data, int len))
{
	clnt->event_cb = cb;
}
