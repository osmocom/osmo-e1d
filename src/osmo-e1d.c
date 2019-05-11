/*
 * osmo-e1d.c
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <talloc.h>

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>

#include <osmocom/e1d/proto_srv.h>

#include "e1d.h"
#include "log.h"


extern struct osmo_e1dp_server_handler e1d_ctl_handlers[];
extern int e1_usb_probe(struct e1_daemon *e1d);
extern int e1_usb_poll(void);



static void *g_e1d_ctx = NULL;
static int g_shutdown = 0;


static void sig_handler(int signo)
{
	fprintf(stdout, "signal %d received\n", signo);
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		fprintf(stdout, "shutting down\n");
		g_shutdown = 1;
		break;
	case SIGABRT:
	case SIGUSR1:
		talloc_report(g_e1d_ctx, stderr);
		talloc_report_full(g_e1d_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(g_e1d_ctx, stderr);
		break;
	default:
		break;
	}
}


int main(int argc, char *argv[])
{
	struct e1_daemon *e1d = NULL;
	struct osmo_e1dp_server *srv = NULL;
	struct sched_param sp;
	int rv;

	/* talloc init */
	g_e1d_ctx = talloc_named_const(NULL, 0, "osmo-e1d");
	msgb_talloc_ctx_init(g_e1d_ctx, 0);

	/* logging init */
	osmo_init_logging2(g_e1d_ctx, &log_info);

	/* signals init */
	signal(SIGINT, &sig_handler);
	signal(SIGTERM, &sig_handler);
	signal(SIGABRT, &sig_handler);
	signal(SIGUSR1, &sig_handler);
	signal(SIGUSR2, &sig_handler);
	osmo_init_ignore_signals();

	/* rt prio */
	memset(&sp, 0x00, sizeof(sp));
        sp.sched_priority = 50;
        rv = sched_setscheduler(0, SCHED_RR, &sp);
	if (rv != 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to set Real-Time priority. USB comms might be unstable.\n");
		perror("sched_setscheduler");
	}

	/* main state */
	e1d = talloc_zero(g_e1d_ctx, struct e1_daemon);
	OSMO_ASSERT(e1d);

	INIT_LLIST_HEAD(&e1d->interfaces);

	/* probe devices */
	rv = e1_usb_probe(e1d);
	if (rv != 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to prove usb devices\n");
	}

	/* server init */
	srv = osmo_e1dp_server_create(g_e1d_ctx, "/tmp/osmo-e1d.ctl", e1d_ctl_handlers, e1d);
	OSMO_ASSERT(srv);

	/* main loop */
	while (!g_shutdown) {
		osmo_select_main(1);
		e1_usb_poll();
	}

	/* cleanup */
	if (srv)
		osmo_e1dp_server_destroy(srv);
	
	talloc_free(e1d);

	return 0;
}
