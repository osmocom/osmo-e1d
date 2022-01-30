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

#define _GNU_SOURCE
#include <getopt.h>

#include <talloc.h>

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>

#include <osmocom/e1d/proto_srv.h>
#include <osmocom/e1d/proto.h>

#include "e1d.h"
#include "usb.h"
#include "log.h"

#ifndef OSMO_VTY_PORT_E1D
#define OSMO_VTY_PORT_E1D	4269
#endif

extern struct osmo_e1dp_server_handler e1d_ctl_handlers[];

static const char *g_config_file = "osmo-e1d.cfg";
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

static struct vty_app_info vty_info = {
	.name = "osmo-e1d",
	.version = PACKAGE_VERSION,
	.copyright =
	"(C) 2019 by Sylvain Munaut <tnt@246tNt.com>\r\n",
	"License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl-2.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n",
};

static void print_help(void)
{
	printf("  Some useful help...\n");
	printf("  -h --help			This text.\n");
	printf("  -d --debug option		--debug=DE1D:DXFR enable debugging.\n");
	printf("  -c --config-file filename	The config file to use.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static const struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"config-file", 1, 0, 'c'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:c:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'c':
			g_config_file = optarg;
			break;
		default:
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
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
	vty_info.tall_ctx = g_e1d_ctx;

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
	vty_init(&vty_info);
	logging_vty_add_cmds();
	e1d_vty_init(e1d);
	rate_ctr_init(e1d);

	handle_options(argc, argv);

	rv = vty_read_config_file(g_config_file, NULL);
	if (rv < 0) {
		LOGP(DE1D, LOGL_FATAL, "Failed to parse the config file '%s'\n", g_config_file);
		exit(2);
	}

	rv = telnet_init_dynif(g_e1d_ctx, e1d, vty_get_bind_addr(), OSMO_VTY_PORT_E1D);
	if (rv != 0) {
		LOGP(DE1D, LOGL_FATAL, "Failed to bind VTY interface to %s:%u\n",
			vty_get_bind_addr(), OSMO_VTY_PORT_E1D);
		exit(1);
	}

	/* probe devices */
	rv = e1_usb_probe(e1d);
	if (rv != 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to prove usb devices\n");
	}

	/* server init */
	srv = osmo_e1dp_server_create(g_e1d_ctx, E1DP_DEFAULT_SOCKET, e1d_ctl_handlers, e1d);
	OSMO_ASSERT(srv);

	/* main loop */
	while (!g_shutdown) {
		osmo_select_main(0);
	}

	/* cleanup */
	if (srv)
		osmo_e1dp_server_destroy(srv);
	
	talloc_free(e1d);

	return 0;
}
