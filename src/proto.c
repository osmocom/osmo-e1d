/*
 * proto.c
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

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>

#include <osmocom/e1d/proto.h>

#include "log.h"

const struct value_string osmo_e1dp_msg_type_names[] = {
	{ E1DP_CMD_INTF_QUERY,	"CMD_INTF_QUERY" },
	{ E1DP_CMD_LINE_QUERY,	"CMD_LINE_QUERY" },
	{ E1DP_CMD_TS_QUERY,	"CMD_TS_QUERY" },
	{ E1DP_CMD_TS_OPEN,	"CMD_TS_OPEN" },
	{ E1DP_CMD_SABITS,	"CMD_SABITS" },
	{ E1DP_EVT_LOS_ON,	"EVT_LOS_ON" },
	{ E1DP_EVT_LOS_OFF,	"EVT_LOS_OFF" },
	{ E1DP_EVT_AIS_ON,	"EVT_AIS_ON" },
	{ E1DP_EVT_AIS_OFF,	"EVT_AIS_OFF" },
	{ E1DP_EVT_RAI_ON,	"EVT_RAI_ON" },
	{ E1DP_EVT_RAI_OFF,	"EVT_RAI_OFF" },
	{ E1DP_EVT_LOF_ON,	"EVT_LOF_ON" },
	{ E1DP_EVT_LOF_OFF,	"EVT_LOF_OFF" },
	{ E1DP_EVT_SABITS,	"EVT_SABITS" },
	{ E1DP_RESP_TYPE,	"RESP_TYPE" },
	{ E1DP_ERR_TYPE,	"ERR_TYPE" },
	{ 0, NULL }
};
const struct value_string osmo_e1dp_line_mode_names[] = {
	{ E1DP_LMODE_OFF,		"OFF" },
	{ E1DP_LMODE_CHANNELIZED,	"CHANNELIZED" },
	{ E1DP_LMODE_SUPERCHANNEL,	"SUPERCHANNEL" },
	{ 0, NULL }
};
const struct value_string osmo_e1dp_ts_mode_names[] = {
	{ E1DP_TSMODE_OFF,	"OFF" },
	{ E1DP_TSMODE_RAW,	"RAW" },
	{ E1DP_TSMODE_HDLCFCS,	"HDLC-FCS" },
	{ 0, NULL }
};

struct msgb *
osmo_e1dp_recv(struct osmo_fd *ofd, int *fd)
{
	struct msgb *msgb;
	struct osmo_e1dp_msg_hdr *hdr;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cms[CMSG_SPACE(sizeof(int))];
	int rc;

	msgb = msgb_alloc(E1DP_MAX_LEN, "e1d proto rx message");

	memset(&msg, 0x00, sizeof(msg));

	iov.iov_base = msgb->data;
	iov.iov_len = E1DP_MAX_LEN;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = (caddr_t) cms;
	msg.msg_controllen = sizeof(cms);

	rc = recvmsg(ofd->fd, &msg, MSG_WAITALL | MSG_CMSG_CLOEXEC);
	if (rc == 0)
		goto err;
	if (rc < (int)sizeof(struct osmo_e1dp_msg_hdr)) {
		LOGP(DE1D, LOGL_ERROR, "Failed to read packet header.\n");
		goto err;
	}

	msgb->l1h = msgb_put(msgb, sizeof(struct osmo_e1dp_msg_hdr));
	hdr = msgb_l1(msgb);

	if ((hdr->magic != E1DP_MAGIC) || (hdr->len < sizeof(struct osmo_e1dp_msg_hdr))) {
		LOGP(DE1D, LOGL_ERROR, "Invalid packet header.\n");
		goto err;
	}

	if (hdr->len > sizeof(struct osmo_e1dp_msg_hdr))
		msgb->l2h = msgb_put(msgb, hdr->len - sizeof(struct osmo_e1dp_msg_hdr));
	else
		msgb->l2h = msgb->tail;

	if (fd) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg) {
			memmove(fd, CMSG_DATA(cmsg), sizeof(int));
		} else {
			*fd = -1;
		}
	}

	LOGP(DE1D, LOGL_DEBUG, "rx pkt: %d %s\n", fd ? *fd : -2, msgb_hexdump(msgb));

	return msgb;

err:
	msgb_free(msgb);
	return NULL;
}

int
osmo_e1dp_send(struct osmo_fd *ofd, struct msgb *msgb, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	int rc;

	memset(&msg, 0x00, sizeof(msg));

	iov.iov_base = msgb->data;
	iov.iov_len  = msgb_length(msgb);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	if (fd >= 0) {
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = CMSG_LEN(sizeof(int));

		struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));

		memmove(CMSG_DATA(cmsg), &fd, sizeof(int));
	}

	rc = sendmsg(ofd->fd, &msg, 0);
	if (rc < 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to send packet.\n");
		perror("tx");
	}

	if (fd >= 0)
		close(fd);

	LOGP(DE1D, LOGL_DEBUG, "tx pkt: %d %s\n", msgb_length(msgb), msgb_hexdump(msgb));

	return rc;
}
