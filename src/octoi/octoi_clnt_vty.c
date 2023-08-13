/*
 * octoi_clnt_vty.c - VTY code for OCTOI client role
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
#include <stdio.h>
#include <string.h>

#include <talloc.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/misc.h>

#include "octoi.h"
#include "octoi_sock.h"
#include "octoi_fsm.h"
#include "octoi_vty.h"

/***********************************************************************
 * core data structures
 ***********************************************************************/

static struct octoi_client *octoi_client_alloc(void *ctx, const char *ip, uint16_t port)
{
	struct octoi_client *clnt = talloc_zero(ctx, struct octoi_client);
	int rc;

	if (!clnt)
		return NULL;

	rc = osmo_sockaddr_str_from_str(&clnt->cfg.remote, ip, port);
	if (rc < 0) {
		talloc_free(clnt);
		return NULL;
	}

	return clnt;
}

/* find a client for given remote IP + port */
struct octoi_client *octoi_client_find(const char *ip, uint16_t port)
{
	struct octoi_client *clnt;

	llist_for_each_entry(clnt, &g_octoi->clients, list) {
		if (!strcmp(ip, clnt->cfg.remote.ip) && clnt->cfg.remote.port == port)
			return clnt;
	}
	return NULL;
}

/***********************************************************************
 * VTY
 ***********************************************************************/

static struct cmd_node clnt_node = {
	(enum node_type) OCTOI_CLNT_NODE,
	"%s(config-octoi-client)# ",
	1,
};

static struct cmd_node clnt_account_node = {
	(enum node_type) OCTOI_CLNT_ACCOUNT_NODE,
	"%s(config-octoi-client-account)# ",
	1,
};

DEFUN(cfg_client, cfg_client_cmd,
	"octoi-client (A.B.C.D|X:X::X:X) <0-65535>",
	"Configure an OCTOI client\n"
	"Remote IPv4 address of OCTOI server\n"
	"Remote IPv6 address of OCTOI server\n"
	"Remote UDP port number of OCTOI server\n")
{
	const char *ip = argv[0];
	int port = atoi(argv[1]);
	struct octoi_client *clnt = octoi_client_find(ip, port);

	if (!clnt) {
		clnt = octoi_client_alloc(g_octoi, ip, port);
		OSMO_ASSERT(clnt);
		llist_add_tail(&clnt->list, &g_octoi->clients);
	}

	vty->node = OCTOI_CLNT_NODE;
	vty->index = clnt;

	return CMD_SUCCESS;
}

#if 0
DEFUN(cfg_no_client, cfg_no_client_cmd,
	"no octoi-client (A.B.C.D|X:X::X:X) <0-65535>",
	NO_STR "Remove an OCTOI client\n")
	"Remote IPv4 address of OCTOI server\n"
	"Remote IPv6 address of OCTOI server\n"
	"Remote UDP port number of OCTOI server\n")
{
}
#endif


DEFUN(cfg_clnt_local, cfg_clnt_local_cmd,
	"local-bind (A.B.C.D|X:X::X:X) <0-65535>",
	"Local OCTOI socket bind address/port\n"
	"Local OCTOI IPv4 Address\n"
	"Local OCTOI IPv6 Address\n"
	"Local OCTOI UDP Port Number\n")
{
	struct octoi_client *clnt = vty->index;
	int rc;

	rc = osmo_sockaddr_str_from_str(&clnt->cfg.local, argv[0], atoi(argv[1]));
	if (rc < 0) {
		vty_out(vty, "%% sockaddr Error: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (clnt->sock)
		octoi_sock_destroy(clnt->sock);

	clnt->sock = octoi_sock_create_client(clnt, clnt, &clnt->cfg.local, &clnt->cfg.remote);
	if (!clnt->sock) {
		vty_out(vty, "%% failed to create/bind socket: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}
	clnt->sock->rx_cb = octoi_clnt_fsm_rx_cb;

	if (clnt->cfg.dscp) {
		rc = octoi_sock_set_dscp(clnt->sock, clnt->cfg.dscp);
		if (rc < 0) {
			vty_out(vty, "%% failed to set DSCP on socket: %s%s", strerror(errno), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (clnt->cfg.priority) {
		rc = octoi_sock_set_priority(clnt->sock, clnt->cfg.priority);
		if (rc < 0) {
			vty_out(vty, "%% failed to set priority on socket: %s%s", strerror(errno), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_clnt_dscp, cfg_clnt_dscp_cmd,
	"ip-dscp <0-63>",
	"Set IP DSCP value for outbound packets\n"
	"IP DSCP Value to use\n")
{
	struct octoi_client *clnt = vty->index;
	int rc;

	clnt->cfg.dscp = atoi(argv[0]);

	if (!clnt->sock)
		return CMD_SUCCESS;

	/* apply to already-existing server */
	rc = octoi_sock_set_dscp(clnt->sock, clnt->cfg.dscp);
	if (rc < 0) {
		vty_out(vty, "%% failed to set DSCP on socket: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_clnt_prio, cfg_clnt_prio_cmd,
	"socket-priority <0-255>",
	"Set socket priority value for outbound packets\n"
	"Socket Priority\n")
{
	struct octoi_client *clnt = vty->index;
	int rc;

	clnt->cfg.priority = atoi(argv[0]);

	if (!clnt->sock)
		return CMD_SUCCESS;

	/* apply to already-existing server */
	rc = octoi_sock_set_priority(clnt->sock, clnt->cfg.priority);
	if (rc < 0) {
		vty_out(vty, "%% failed to set priority on socket: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_clnt_account, cfg_clnt_account_cmd,
	"account USER_ID",
	"Configure a local user account\n")
{
	struct octoi_client *clnt = vty->index;
	const char *user_id = argv[0];
	struct octoi_account *ac = clnt->cfg.account;

	if (!ac) {
		ac = octoi_client_account_create(clnt, user_id);
		OSMO_ASSERT(ac);
	} else
		osmo_talloc_replace_string(ac, &ac->user_id, user_id);

	vty->node = OCTOI_CLNT_ACCOUNT_NODE;
	vty->index = ac;

	return CMD_SUCCESS;
}

DEFUN(show_clnt, show_clnt_cmd,
	"show octoi-clients",
	SHOW_STR "Display information about the OCTOI Clients\n")
{
	struct octoi_client *clnt;

	llist_for_each_entry(clnt, &g_octoi->clients, list) {
		struct octoi_sock *sock = clnt->sock;

		octoi_vty_show_one_account(vty, "", clnt->cfg.account);
		vty_show_octoi_sock(vty, sock);
	}

	return CMD_SUCCESS;
}

static int config_write_octoi_clnt(struct vty *vty)
{
	struct octoi_client *clnt;

	llist_for_each_entry(clnt, &g_octoi->clients, list) {
		vty_out(vty, "octoi-client %s %u%s", clnt->cfg.remote.ip, clnt->cfg.remote.port,
			VTY_NEWLINE);
		if (strlen(clnt->cfg.local.ip)) {
			vty_out(vty, " local-bind %s %u%s", clnt->cfg.local.ip, clnt->cfg.local.port,
				VTY_NEWLINE);
		}
		if (clnt->cfg.dscp)
			vty_out(vty, " ip-dscp %u%s", clnt->cfg.dscp, VTY_NEWLINE);
		if (clnt->cfg.priority)
			vty_out(vty, " socket-priority %u%s", clnt->cfg.priority, VTY_NEWLINE);

		octoi_vty_write_one_account(vty, clnt->cfg.account);
	}

	return 0;
}

void octoi_client_vty_init(void)
{
	install_element_ve(&show_clnt_cmd);

	install_node(&clnt_account_node, NULL);
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_ice1_serno_cmd);
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_ice1_line_cmd);
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_mode_cmd);
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_batching_factor_cmd);
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_force_all_ts_cmd);
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_no_force_all_ts_cmd);
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_prefill_frame_count_cmd);
#ifdef HAVE_DAHDI_TRUNKDEV
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_trunkdev_name_cmd);
	install_element(OCTOI_CLNT_ACCOUNT_NODE, &cfg_account_trunkdev_line_cmd);
#endif /* HAVE_DAHDI_TRUNKDEV */

	install_node(&clnt_node, config_write_octoi_clnt);
	install_element(CONFIG_NODE, &cfg_client_cmd);
	install_element(OCTOI_CLNT_NODE, &cfg_clnt_local_cmd);
	install_element(OCTOI_CLNT_NODE, &cfg_clnt_dscp_cmd);
	install_element(OCTOI_CLNT_NODE, &cfg_clnt_prio_cmd);
	install_element(OCTOI_CLNT_NODE, &cfg_clnt_account_cmd);
}
