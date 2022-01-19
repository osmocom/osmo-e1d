/*
 * octoi_srv_vty.c - VTY interface for OCTOI server side
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
#include <osmocom/core/fsm.h>

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

const struct value_string octoi_account_mode_name[] = {
	{ ACCOUNT_MODE_NONE,		"none" },
	{ ACCOUNT_MODE_ICE1USB,		"ice1usb" },
	{ ACCOUNT_MODE_REDIRECT,	"redirect" },
	{ ACCOUNT_MODE_DAHDI,		"dahdi" },
	{ 0, NULL }
};

static struct octoi_account *_account_create(void *ctx, const char *user_id)
{
	struct octoi_account *ac = talloc_zero(ctx, struct octoi_account);
	if (!ac)
		return NULL;

	ac->user_id = talloc_strdup(ac, user_id);
	if (!ac->user_id) {
		talloc_free(ac);
		return NULL;
	}

	return ac;
}

static struct octoi_account *octoi_server_account_create(struct octoi_server *srv, const char *user_id)
{
	struct octoi_account *ac = _account_create(srv, user_id);
	if (!ac)
		return NULL;

	llist_add_tail(&ac->list, &srv->cfg.accounts);

	return ac;
}

struct octoi_account *octoi_client_account_create(struct octoi_client *clnt, const char *user_id)
{

	struct octoi_account *ac = _account_create(clnt, user_id);
	if (!ac)
		return NULL;

	OSMO_ASSERT(!clnt->cfg.account);
	clnt->cfg.account = ac;

	ac->mode = ACCOUNT_MODE_ICE1USB;

	return ac;
}

struct octoi_account *octoi_account_find(struct octoi_server *srv, const char *user_id)
{
	struct octoi_account *ac;

	llist_for_each_entry(ac, &srv->cfg.accounts, list) {
		if (!strcmp(ac->user_id, user_id))
			return ac;
	}
	return NULL;
}

static struct octoi_server *octoi_server_alloc(void *ctx)
{
	struct octoi_server *srv = talloc_zero(ctx, struct octoi_server);
	if (!srv)
		return NULL;

	INIT_LLIST_HEAD(&srv->cfg.accounts);

	return srv;
}

/***********************************************************************
 * VTY
 ***********************************************************************/

static struct cmd_node srv_node = {
	(enum node_type) OCTOI_SRV_NODE,
	"%s(config-octoi-server)# ",
	1,
};

static struct cmd_node account_node = {
	(enum node_type) OCTOI_ACCOUNT_NODE,
	"%s(config-octoi-server-account)# ",
	1,
};

DEFUN(cfg_server, cfg_server_cmd,
	"octoi-server",
	"Configure the OCTOI server\n")
{
	struct octoi_server *srv = g_octoi->server;

	if (!srv)
		srv = g_octoi->server = octoi_server_alloc(g_octoi);
	OSMO_ASSERT(srv);

	vty->node = OCTOI_SRV_NODE;
	vty->index = srv;

	return CMD_SUCCESS;
}

#if 0
DEFUN(cfg_no_server, cfg_no_server_cmd,
	"no octoi-server",
	NO_STR "Disable OCTOI server\n")
{
	/* we'd need to iterate over all accounts and terminate any
	 * octoi_server_fsm that might exist for each account */
}
#endif

DEFUN(cfg_srv_local, cfg_srv_local_cmd,
	"local-bind (A.B.C.D|X:X::X:X) <0-65535>",
	"Local OCTOI socket bind address/port\n"
	"Local OCTOI IPv4 Address\n"
	"Local OCTOI IPv6 Address\n"
	"Local OCTOI UDP Port Number\n")
{
	struct octoi_server *srv = vty->index;
	int rc;

	rc = osmo_sockaddr_str_from_str(&srv->cfg.local, argv[0], atoi(argv[1]));
	if (rc < 0) {
		vty_out(vty, "%% sockaddr Error: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (srv->sock)
		octoi_sock_destroy(srv->sock);

	srv->sock = octoi_sock_create_server(srv, srv, &srv->cfg.local);
	if (!srv->sock) {
		vty_out(vty, "%% failed to create/bind socket: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}
	srv->sock->rx_cb = octoi_srv_fsm_rx_cb;

	return CMD_SUCCESS;
}

DEFUN(cfg_srv_account, cfg_srv_account_cmd,
	"account USER_ID",
	"Configure a local user account\n"
	"User ID\n")
{
	struct octoi_server *srv = vty->index;
	const char *user_id = argv[0];
	struct octoi_account *ac = octoi_account_find(srv, user_id);
	if (!ac)
		ac = octoi_server_account_create(srv, user_id);
	if (!ac)
		return CMD_WARNING;

	vty->node = OCTOI_ACCOUNT_NODE;
	vty->index = ac;

	return CMD_SUCCESS;
}

#if 0
DEFUN(cfg_srv_no_account, cfg_serv_no_account_cmd,
	"no account USER_ID",
	NO_STR "Remove a local user account\n"
	"User ID\n")
{
	struct octoi_server *srv = vty->index;
	const char *user_id = argv[0];
	struct octoi_account *ac = octoi_account_find(srv, user_id);
	if (!ac)
		return CMD_WARNING;

	/* we'd need to iterate all octoi_server_fsm instances and terminate any
	 * pointing to this account */
}
#endif

gDEFUN(cfg_account_mode, cfg_account_mode_cmd,
	"mode (ice1usb|redirect)",
	"Operational mode of account\n"
	"Connect to local icE1usb (identified by USB serial + line number)\n"
	"Redirect to other IP/Port\n")
{
	struct octoi_account *acc = vty->index;

	/* leave old mode */
	switch (acc->mode) {
	case ACCOUNT_MODE_ICE1USB:
		talloc_free(acc->u.ice1usb.usb_serial);
		break;
	default:
		break;
	}
	memset(&acc->u, 0, sizeof(acc->u));

	if (!strcmp(argv[0], "ice1usb")) {
		acc->mode = ACCOUNT_MODE_ICE1USB;
	} else if (!strcmp(argv[0], "redirect")) {
		acc->mode = ACCOUNT_MODE_REDIRECT;
	} else
		OSMO_ASSERT(0);

	return CMD_SUCCESS;
}

#define ICE1_STR "icE1usb settings\n"

gDEFUN(cfg_account_ice1_serno, cfg_account_ice1_serno_cmd,
	"ice1usb serial-number SERNO",
	ICE1_STR "USB Serial Number String\n" "USB Serial Number String\n")
{
	struct octoi_account *acc = vty->index;

	if (acc->mode != ACCOUNT_MODE_ICE1USB) {
		vty_out(vty, "%% Error: Not in icE1usb mode!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_talloc_replace_string(acc, &acc->u.ice1usb.usb_serial, argv[0]);
	return CMD_SUCCESS;
}

gDEFUN(cfg_account_ice1_line, cfg_account_ice1_line_cmd,
	"ice1usb line-number <0-1>",
	ICE1_STR "E1 Line number\n" "E1 Line number\n")
{
	struct octoi_account *acc = vty->index;

	if (acc->mode != ACCOUNT_MODE_ICE1USB) {
		vty_out(vty, "%% Error: Not in icE1usb mode!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	acc->u.ice1usb.line_nr = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_account_redir, cfg_account_redir_cmd,
	"redirect (A.B.C.D|X:X::X:X) <0-65535>",
	"Redirect to other IP/Port\n"
	"Destination IPv4 address\n"
	"Destination IPv6 address\n"
	"Destination UDP port\n")
{
	struct octoi_account *acc = vty->index;
	int rc;

	if (acc->mode != ACCOUNT_MODE_REDIRECT) {
		vty_out(vty, "%% Error: Not in redirect mode!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = osmo_sockaddr_str_from_str(&acc->u.redirect.to, argv[0], atoi(argv[1]));
	if (rc < 0) {
		vty_out(vty, "%% sockaddr Error: %s%s", strerror(errno), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

void octoi_vty_write_one_account(struct vty *vty, const struct octoi_account *acc)
{
	if (!acc)
		return;

	vty_out(vty, " account %s%s", acc->user_id, VTY_NEWLINE);
	vty_out(vty, "  mode %s%s", get_value_string(octoi_account_mode_name, acc->mode),
		VTY_NEWLINE);

	switch (acc->mode) {
	case ACCOUNT_MODE_NONE:
		break;
	case ACCOUNT_MODE_ICE1USB:
		if (acc->u.ice1usb.usb_serial)
			vty_out(vty, "  ice1usb serial-number %s%s", acc->u.ice1usb.usb_serial,
				VTY_NEWLINE);

		vty_out(vty, "  ice1usb line-number %u%s", acc->u.ice1usb.line_nr, VTY_NEWLINE);
		break;
	case ACCOUNT_MODE_REDIRECT:
		vty_out(vty, "  redirect %s %u%s", acc->u.redirect.to.ip, acc->u.redirect.to.port,
			VTY_NEWLINE);
		break;
	case ACCOUNT_MODE_DAHDI:
		OSMO_ASSERT(0);
		break;
	}
}

static int config_write_octoi_srv(struct vty *vty)
{
	struct octoi_account *acc;
	struct octoi_server *srv = g_octoi->server;

	if (!srv)
		return 0;

	vty_out(vty, "octoi-server%s", VTY_NEWLINE);
	if (strlen(srv->cfg.local.ip)) {
		vty_out(vty, " local-bind %s %u%s", srv->cfg.local.ip, srv->cfg.local.port,
			VTY_NEWLINE);
	}

	llist_for_each_entry(acc, &srv->cfg.accounts, list)
		octoi_vty_write_one_account(vty, acc);

	return 0;
}

DEFUN(show_server, show_server_cmd,
	"show octoi-server",
	SHOW_STR "Display information about the OCTOI Server\n")
{
	struct octoi_server *srv = g_octoi->server;
	struct octoi_sock *sock = srv->sock;

	vty_show_octoi_sock(vty, sock);

	return CMD_SUCCESS;
}

void octoi_server_vty_init(void)
{

	install_element_ve(&show_server_cmd);

	install_node(&account_node, NULL);
	install_element(OCTOI_ACCOUNT_NODE, &cfg_account_mode_cmd);
	install_element(OCTOI_ACCOUNT_NODE, &cfg_account_ice1_serno_cmd);
	install_element(OCTOI_ACCOUNT_NODE, &cfg_account_ice1_line_cmd);
	install_element(OCTOI_ACCOUNT_NODE, &cfg_account_redir_cmd);

	install_node(&srv_node, config_write_octoi_srv);
	install_element(CONFIG_NODE, &cfg_server_cmd);
	//install_element(CONFIG_NODE, &cfg_no_server_cmd);
	install_element(OCTOI_SRV_NODE, &cfg_srv_local_cmd);
	install_element(OCTOI_SRV_NODE, &cfg_srv_account_cmd);
	//install_element(CONFIG_SRV_NODE, &cfg_srv_no_account_cmd);
}
