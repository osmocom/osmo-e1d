/*
 * osmo-e1gen.c
 *
 * (C) 2020 by Harald Welte <laforge@gnumonks.org>
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
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

#include "e1d.h"
#include "usb.h"
#include "log.h"

#include "e1gen/osmo_e1f.h"

#ifndef OSMO_VTY_PORT_E1D
#define OSMO_VTY_PORT_E1D	4269
#endif

/***********************************************************************
 * global variables
 ***********************************************************************/

extern struct e1_daemon *vty_e1d;
static const char *g_config_file = "osmo-e1d.cfg";
static void *g_e1d_ctx = NULL;
static int g_shutdown = 0;

/***********************************************************************
 * stubs for external linkage of normal osmo-e1d
 ***********************************************************************/

void e1_ts_stop(struct e1_ts *ts) {}
int e1d_vpair_create(struct e1_daemon *e1d, unsigned int num_lines) { return -1; }
struct e1_intf *e1d_vpair_intf_peer(struct e1_intf *intf) { return NULL; }



struct e1gen_line_data {
	struct ice1usb_tx_config tx_config;
	struct ice1usb_rx_config rx_config;
	struct osmo_e1f_instance e1f;
};

static void e1f_notify_cb(struct osmo_e1f_instance *e1f, enum osmo_e1f_notify_event evt,
			  bool present, void *data)
{
	struct e1_line *line = e1f->priv;
	LOGPLI(line, DE1D, LOGL_NOTICE, "NOTIFY: %s %s\n",
		osmo_e1f_notify_event_name(evt), present ? "PRESENT" : "ABSENT");
}

static const struct e1gen_line_data default_ld = {
	.tx_config = {
		.mode = ICE1USB_TX_MODE_TRANSP,
		.timing = ICE1USB_TX_TIME_SRC_LOCAL,
		.ext_loopback = ICE1USB_TX_EXT_LOOPBACK_OFF,
		.alarm = 0,
	},
	.rx_config = {
		.mode = ICE1USB_RX_MODE_MULTIFRAME,
		//.mode = ICE1USB_RX_MODE_TRANSP,
	},
};

struct e1gen_line_data *ensure_gld(struct e1_line *line)
{
	struct e1gen_line_data *gld = (struct e1gen_line_data *) line->e1gen_priv;

	if (gld)
		return gld;

	LOGPLI(line, DE1D, LOGL_INFO, "Creating e1gen structures\n");

	line->e1gen_priv = gld = talloc_zero(line, struct e1gen_line_data);
	gld->tx_config = default_ld.tx_config;
	gld->rx_config = default_ld.rx_config;
	osmo_e1f_instance_init(&gld->e1f, "LINE", e1f_notify_cb, true, line);

	/* set the default configuration */
	e1_usb_ctrl_set_tx_cfg(line, gld->tx_config.mode, gld->tx_config.timing,
				gld->tx_config.ext_loopback, gld->tx_config.alarm);
	e1_usb_ctrl_set_rx_cfg(line, gld->rx_config.mode);

	return gld;
}

/*! process (demultiplex) input data for the specified e1_line.
 *  \param[in] line E1 line for which to genrate output data
 *  \param[in] buf input buffer of multiplexed data received on line
 *  \param[in] size size of buf in octets */
int e1_line_demux_in(struct e1_line *line, const uint8_t *buf, int size,  int frame_base)
{
	struct e1gen_line_data *gld = ensure_gld(line);
	int offs;

	for (offs = 0; offs + 32 <= size; offs += 32) {
		//printf("Rx "OSMO_BIT_SPEC"\n", OSMO_BIT_PRINT(buf[offs]));
		//printf("Rx %s\n", osmo_hexdump(buf + offs, 32));
		osmo_e1f_rx_frame(&gld->e1f, buf + offs);
	}
	return 0;
}

/*! generate (multiplex) output data for the specified e1_line
 *  \param[in] line E1 line for which to genrate output data
 *  \param[in] buf caller-allocated output buffer for multiplexed data
 *  \param[in] fts number of E1 frames (32 bytes each) to generate
 *  \return number of bytes written to buf */
int e1_line_mux_out(struct e1_line *line, uint8_t *buf, int fts)
{
	struct e1gen_line_data *gld = ensure_gld(line);
	int f;

	//printf("FRAME:\n");
	for (f = 0; f < fts; f++) {
		osmo_e1f_pull_tx_frame(&gld->e1f, buf + f*32);
		//printf("Tx "OSMO_BIT_SPEC"\n", OSMO_BIT_PRINT(buf[f*32]));
		//printf("Tx %s\n", osmo_hexdump(buf + f*32, 32));
	}

	return 32*fts;
}

static struct cmd_node line_node = {
	(enum node_type) LINE_NODE,
	"%s(line)# ",
	1,
};

#define TX_STR "Transmitter\n"
#define OFF_ON_STR "Off\n" "On\n"

DEFUN(line_tx_alarm, line_tx_alarm_cmd,
	"tx report-alarm (0|1)",
	TX_STR "Report Alarm (A-Bits)\n" OFF_ON_STR)
{
	struct e1_line *line = vty->index;
	struct e1gen_line_data *gld = ensure_gld(line);
	int on = atoi(argv[0]);

	gld->e1f.tx.remote_alarm = on ? true : false;

	return CMD_SUCCESS;
}

DEFUN(line_tx_crc4, line_tx_crc4_cmd,
	"tx generate-crc4 (0|1)",
	TX_STR "Generate CRC4\n" OFF_ON_STR)
{
	struct e1_line *line = vty->index;
	struct e1gen_line_data *gld = ensure_gld(line);
	int on = atoi(argv[0]);

	gld->e1f.crc4_enabled = on ? true : false;

	return CMD_SUCCESS;
}

DEFUN(line_tx_report_crc4, line_tx_report_crc4_cmd,
	"tx report-crc4-error (0|1)",
	TX_STR "Report a CRC4 Error\n" OFF_ON_STR)
{
	struct e1_line *line = vty->index;
	struct e1gen_line_data *gld = ensure_gld(line);
	int on = atoi(argv[0]);

	gld->e1f.tx.crc4_error = on ? true : false;

	return CMD_SUCCESS;
}

DEFUN(line_tx_sa48, line_tx_sa48_cmd,
	"tx sa4 <0-31>",
	TX_STR "Set the SA4..SA8 bit content\n")
{
	struct e1_line *line = vty->index;
	struct e1gen_line_data *gld = ensure_gld(line);

	gld->e1f.tx.sa4_sa8 = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(line_tx_ais, line_tx_ais_cmd,
	"tx ais (0|1)",
	TX_STR "Transmit AIS (All-1)\n" OFF_ON_STR)
{
	struct e1_line *line = vty->index;
	struct e1gen_line_data *gld = ensure_gld(line);
	int on = atoi(argv[0]);

	gld->e1f.tx.ais = on ? true : false;

	return CMD_SUCCESS;
}

DEFUN(line_show, line_show_cmd,
	"show", "Show Line status\n")
{
	struct e1_line *line = vty->index;
	struct e1gen_line_data *gld = ensure_gld(line);
	struct osmo_e1f_instance *e1f = &gld->e1f;

	vty_out(vty, "Rx RemoteAlarm=%u, RemoteCrcErr=%u%s",
		e1f->rx.remote_alarm, e1f->rx.remote_crc4_error, VTY_NEWLINE);
	vty_out(vty, "Tx RemoteAlarm=%u, CrcErr=%u%s",
		e1f->tx.remote_alarm, e1f->tx.crc4_error, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(line, line_cmd,
	"interface <0-255> line <0-225>",
	"E1 Interface\n" "E1 Interface\n"
	"E1 Line number\n" "E1 Line number\n")
{
	struct e1_intf *intf;
	struct e1_line *line;

	intf = e1d_find_intf(vty_e1d, atoi(argv[0]));
	if (!intf) {
		vty_out(vty, "No such interface %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	line = e1_intf_find_line(intf, atoi(argv[1]));
	if (!line) {
		vty_out(vty, "No such line %s in interface %s%s", argv[1], argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = LINE_NODE;
	vty->index = line;

	return CMD_SUCCESS;
}

static void e1gen_init(void)
{
	install_element(ENABLE_NODE, &line_cmd);
	install_node(&line_node, NULL);
	install_element(LINE_NODE, &line_tx_alarm_cmd);
	install_element(LINE_NODE, &line_tx_crc4_cmd);
	install_element(LINE_NODE, &line_tx_report_crc4_cmd);
	install_element(LINE_NODE, &line_tx_sa48_cmd);
	install_element(LINE_NODE, &line_tx_ais_cmd);
	install_element(LINE_NODE, &line_show_cmd);
}

/***********************************************************************
 * initialization (mostly shared with osmo-e1d.c
 ***********************************************************************/

static struct vty_app_info vty_info = {
	.name = "osmo-e1gen",
	.version = PACKAGE_VERSION,
	.copyright =
	"(C) 2019-2020 by Sylvain Munaut and Harald Welte\r\n",
	"License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl-2.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n",
};

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

int main(int argc, char **argv)
{
	struct e1_daemon *e1d = NULL;
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
	vty_init(&vty_info);
	logging_vty_add_cmds();
	e1d_vty_init(e1d);

	handle_options(argc, argv);

	rv = vty_read_config_file(g_config_file, NULL);
	if (rv < 0) {
		LOGP(DE1D, LOGL_FATAL, "Failed to parse the config file '%s'\n", g_config_file);
		exit(2);
	}

	rv = telnet_init_default(g_e1d_ctx, e1d, OSMO_VTY_PORT_E1D);
	if (rv != 0) {
		LOGP(DE1D, LOGL_FATAL, "Failed to bind VTY interface to %s:%u\n",
			vty_get_bind_addr(), OSMO_VTY_PORT_E1D);
		exit(1);
	}

	osmo_e1f_init();
	e1gen_init();

	/* probe devices */
	rv = e1_usb_init(e1d);
	if (rv != 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to prove usb devices\n");
	}

	/* main loop */
	while (!g_shutdown) {
		osmo_select_main(0);
	}

	talloc_free(e1d);

	return 0;
}
