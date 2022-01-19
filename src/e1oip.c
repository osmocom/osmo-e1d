/*
 * e1oip.c
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

#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <talloc.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/utils.h>

#include <osmocom/octoi/octoi.h>

#include "e1d.h"
#include "log.h"

/***********************************************************************
 * internal helper functions
 ***********************************************************************/

/* convenience helper function finding a e1_line for given serial_str + id */
static struct e1_line *
find_line_by_usb_serial(struct e1_daemon *e1d, const char *serial_str, uint8_t id)
{
	struct e1_intf *e1i = e1d_find_intf_by_usb_serial(e1d, serial_str);
	if (!e1i)
		return NULL;
	return e1_intf_find_line(e1i, id);
}

static struct e1_line *
find_line_for_account(struct e1_daemon *e1d, const struct octoi_account *acc)
{
	switch (acc->mode) {
	case ACCOUNT_MODE_ICE1USB:
		return find_line_by_usb_serial(e1d, acc->u.ice1usb.usb_serial,
						acc->u.ice1usb.line_nr);
	case ACCOUNT_MODE_DAHDI:
		OSMO_ASSERT(0);		/* TODO */
		break;
	default:
		return NULL;
	}
}


/***********************************************************************
 * e1d integration
 ***********************************************************************/

/* physical E1 interface has received some E1 frames (E1->IP) */
int
e1oip_line_demux_in(struct e1_line *line, const uint8_t *buf, int ftr)
{
	OSMO_ASSERT(line->mode == E1_LINE_MODE_E1OIP);

	if (!line->octoi_peer)
		return -ENODEV;

	octoi_peer_e1o_in(line->octoi_peer, buf, ftr);

	return 0;
}

/* physical E1 interface needs some E1 fames (E1<-IP) */
int
e1oip_line_mux_out(struct e1_line *line, uint8_t *buf, int fts)
{
	OSMO_ASSERT(line->mode == E1_LINE_MODE_E1OIP);

	if (!line->octoi_peer) {
		memset(buf, 0xff, 32*fts);
		return -ENODEV;
	}

	octoi_peer_e1t_out(line->octoi_peer, buf, fts);

	return 0;
}


/* OCTOI server FSM has detected an (authenticated) client connection */
static void *
_e1d_octoi_client_connected_cb(struct octoi_server *srv, struct octoi_peer *peer,
			      struct octoi_account *acc)
{
	struct e1_daemon *e1d = g_octoi->priv;
	struct e1_line *line;

	/* resolve the line for the just-connected subscriber account */
	line = find_line_for_account(e1d, acc);
	if (!line) {
		LOGP(DE1D, LOGL_NOTICE, "Could not find E1 line for client %s\n",
			acc->user_id);
		return NULL;
	}

	if (line->octoi_peer) {
		LOGPLI(line, DE1D, LOGL_NOTICE, "New OCTOI client connection for %s, "
			"but we already have a client connection!\n", acc->user_id);
		/* FIXME: properly get rid of the old client */
	}
	line->octoi_peer = peer;

	LOGPLI(line, DE1D, LOGL_INFO, "New OCTOI client connection for %s\n", acc->user_id);

	return line;
}

/* OCTOI has detected that a given peer has vanished; delete reference to it */
static void
_e1d_octoi_peer_disconnected_cb(struct octoi_peer *peer)
{
	struct e1_daemon *e1d = g_octoi->priv;
	struct e1_intf *intf;

	llist_for_each_entry(intf, &e1d->interfaces, list) {
		struct e1_line *line;
		llist_for_each_entry(line, &intf->lines, list) {
			if (line->octoi_peer == peer) {
				LOGPLI(line, DE1D, LOGL_NOTICE, "Peer disconnected\n");
				line->octoi_peer = NULL;
				return;
			}
		}
	}
}

const struct octoi_ops e1d_octoi_ops = {
	.client_connected = &_e1d_octoi_client_connected_cb,
	.peer_disconnected = &_e1d_octoi_peer_disconnected_cb,
};
