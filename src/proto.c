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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 ** 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

		*(int*) CMSG_DATA(cmsg) = fd;
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
