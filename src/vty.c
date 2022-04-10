/* osmo-e1d VTY interface */
/* (C) 2020 by Harald Welte <laforge@osmocom.org>
 * All Rights Reserved
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _GNU_SOURCE	/* struct ucred */
#include <sys/socket.h>

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/tdef_vty.h>

#include <osmocom/octoi/octoi.h>
#include <osmocom/e1d/proto.h>

#include "e1d.h"
#include "usb.h"

struct e1_daemon *vty_e1d;

static struct cmd_node e1d_node = {
	(enum node_type) E1D_NODE,
	"%s(config-e1d)# ",
	1,
};

static struct cmd_node intf_node = {
	(enum node_type) INTF_NODE,
	"%s(config-e1d-intf)# ",
	1,
};

static struct cmd_node line_node = {
	(enum node_type) LINE_NODE,
	"%s(config-e1d-intf-line)# ",
	1,
};

int e1d_vty_go_parent(struct vty *vty)
{
	struct e1_line *line;

	switch (vty->node) {
	case LINE_NODE:
		line = vty->index;
		vty->node = INTF_NODE;
		vty->index = line->intf;
		break;
	default:
		return octoi_vty_go_parent(vty);
	}

	return 0;
}

#if 0
static void vty_dump_ts(struct vty *vty, const struct e1_ts *ts)
{
}
#endif

static const char *intf_serno(const struct e1_intf *intf)
{
	if (intf->usb.serial_str)
		return intf->usb.serial_str;
	else
		return "unnamed";
}

static void vty_dump_intf(struct vty *vty, const struct e1_intf *intf)
{
	char buf[128];

	vty_out(vty, "Interface #%u (%s), Driver: %s%s", intf->id, intf_serno(intf),
		get_value_string(e1_driver_names, intf->drv), VTY_NEWLINE);

	/* TODO: put this behind some call-back */
	switch (intf->drv) {
	case E1_DRIVER_USB:
		e1_usb_intf_gpsdo_state_string(buf, sizeof(buf), intf);
		vty_out(vty, " GPS-DO: %s%s", buf, VTY_NEWLINE);
		break;
	default:
		break;
	}
}

DEFUN(show_intf, show_intf_cmd, "show interface [<0-255>]",
	SHOW_STR "Display information about an E1 Interface/Card\n")
{
	struct e1_intf *intf;

	if (argc) {
		int id = atoi(argv[0]);
		intf = e1d_find_intf(vty_e1d, id);
		if (!intf) {
			vty_out(vty, "%% Unknown interface %u%s\n", id, VTY_NEWLINE);
			return CMD_WARNING;
		}
		vty_dump_intf(vty, intf);
	} else {
		llist_for_each_entry(intf, &vty_e1d->interfaces, list)
			vty_dump_intf(vty, intf);
	}

	return CMD_SUCCESS;
}

static int get_remote_pid(int fd)
{
	struct ucred uc;
	socklen_t len = sizeof(uc);
	int rc;

	rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len);
	if (rc != 0)
		return -1;
	return uc.pid;
}

const struct value_string e1_ts_mode_names[] = {
	{ E1_TS_MODE_OFF,	"off" },
	{ E1_TS_MODE_RAW,	"raw" },
	{ E1_TS_MODE_HDLCFCS,	"hdlc-fcs" },
	{ 0, NULL }
};

const struct value_string e1_line_mode_names[] = {
	{ E1_LINE_MODE_CHANNELIZED,	"channelized" },
	{ E1_LINE_MODE_SUPERCHANNEL,	"superchannel" },
	{ E1_LINE_MODE_E1OIP,		"e1oip" },
	{ 0, NULL }
};

static void vty_dump_line(struct vty *vty, const struct e1_line *line)
{
	unsigned int tn;

	vty_out(vty, "Interface #%u (%s), Line #%u, Mode %s%s%s:%s", line->intf->id,
		intf_serno(line->intf), line->id,
		osmo_str_toupper(get_value_string(e1_line_mode_names, line->mode)),
		line->ts0.cur_errmask & E1L_TS0_RX_ALARM ? " [REMOTE-ALARM]" : "",
		line->ts0.cur_errmask & E1L_TS0_RX_CRC4_ERR ? " [REMOTE-CRC-ERROR]" : "",
		VTY_NEWLINE);

	switch (line->mode) {
	case E1_LINE_MODE_CHANNELIZED:
		for (tn = 0; tn < ARRAY_SIZE(line->ts); tn++) {
			const struct e1_ts *ts = &line->ts[tn];
			vty_out(vty, " TS%02u: Mode %s, FD %d, Peer PID %d%s",
				ts->id, get_value_string(e1_ts_mode_names, ts->mode),
				ts->fd, get_remote_pid(ts->fd), VTY_NEWLINE);
		}
		break;
	case E1_LINE_MODE_SUPERCHANNEL:
		vty_out(vty, " SC: Mode %s, FD %d, Peer PID %d%s",
			get_value_string(e1_ts_mode_names, line->superchan.mode),
			line->superchan.fd, get_remote_pid(line->superchan.fd), VTY_NEWLINE);
		break;
	case E1_LINE_MODE_E1OIP:
		/* TODO: dump some information about E1oIP */
		break;
	}

	vty_out_rate_ctr_group(vty, " ", line->ctrs);
}

DEFUN(show_line, show_line_cmd, "show line [<0-255>]",
	SHOW_STR "Display information about an E1 Line\n")
{
	struct e1_line *line;
	struct e1_intf *intf;

	if (argc) {
		int id = atoi(argv[0]);
		intf = e1d_find_intf(vty_e1d, id);
		if (!intf) {
			vty_out(vty, "%% Unknown interface %u%s\n", id, VTY_NEWLINE);
			return CMD_WARNING;
		}
		llist_for_each_entry(line, &intf->lines, list)
			vty_dump_line(vty, line);
	} else {
		llist_for_each_entry(intf, &vty_e1d->interfaces, list) {
			llist_for_each_entry(line, &intf->lines, list)
				vty_dump_line(vty, line);
		}
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_e1d, cfg_e1d_cmd, "e1d",
	"E1 Daemon specific configuration\n")
{
	vty->node = E1D_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_vpair, cfg_vpair_cmd, "virtual-e1-pair <1-255>",
	"Create a virtual E1 interface pair\n"
	"Number of E1 lines in virtual E1 interface pair\n")
{
	int num_lines = atoi(argv[0]);
	int rc;

	rc = e1d_vpair_create(vty_e1d, num_lines);
	if (rc < 0) {
		vty_out(vty, "%% Error creating virtual-e1-pair: %d%s", rc, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_e1d_if_icE1usb, cfg_e1d_if_icE1usb_cmd, "interface <0-255> icE1usb",
	"Configure an icE1usb E1 interface\n"
	"E1 Interface Number\n")
{
	struct e1_intf *intf;
	int intf_nr = atoi(argv[0]);

	intf = e1d_find_intf(vty_e1d, intf_nr);
	if (!intf) {
		intf = e1_intf_new(vty_e1d, intf_nr, NULL);
	}
	if (!intf) {
		vty_out(vty, "%% Could not create interface%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	intf->drv = E1_DRIVER_USB;
	intf->vty_created = true;

	vty->index = intf;
	vty->node = INTF_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_e1d_if_vpair, cfg_e1d_if_vpair_cmd, "interface <0-255> vpair",
	"Configure a vpair member interface\n"
	"E1 Interface Number\n")
{
	struct e1_intf *intf;
	int intf_nr = atoi(argv[0]);

	intf = e1d_find_intf(vty_e1d, intf_nr);
	if (!intf) {
		vty_out(vty, "%% Could not find E1 interface %u, ddi you create it "
			"using viertual-e1-pair?%s", intf_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (intf->drv != E1_DRIVER_VPAIR) {
		vty_out(vty, "%% Interface %u is not a vpair interface%s", intf_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	intf->vty_created = true;

	vty->index = intf;
	vty->node = INTF_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_e1d_if_usb_serial, cfg_e1d_if_usb_serial_cmd,
	"usb-serial SERNO",
	"Configure the USB serial number of an E1 interface device\n"
	"iSerial string\n")
{
	struct e1_intf *intf = vty->index;

	if (intf->drv != E1_DRIVER_USB)
		return CMD_WARNING;

	osmo_talloc_replace_string(intf, &intf->usb.serial_str, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_e1d_if_line, cfg_e1d_if_line_cmd, "line <0-255>",
	"Configure an E1 line\n"
	"E1 Interface Number\n")
{
	struct e1_intf *intf = vty->index;
	struct e1_line *line;
	int line_nr = atoi(argv[0]);

	line = e1_intf_find_line(intf, line_nr);
	if (!line)
		line = e1_line_new(intf, line_nr, NULL);
	if (!line) {
		vty_out(vty, "%% Could not create line%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = line;
	vty->node = LINE_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_e1d_if_line_mode, cfg_e1d_if_line_mode_cmd,
	"mode (channelized|superchannel|e1oip)",
	"Configure the mode of the E1 line\n"
	"Channelized (64kBps timeslot) mode\n"
	"Superchannel (1xHDLC over 31x64kBps) mode\n")
{
	struct e1_line *line = vty->index;
	enum e1_line_mode new_mode = get_string_value(e1_line_mode_names, argv[0]);
	if (line->mode != new_mode) {
		/* FIXME: clean up any old state */
		line->mode = new_mode;
	}
	return CMD_SUCCESS;
}


static int config_write_line(struct vty *vty, struct e1_line *line)
{
	vty_out(vty, "  line %u%s", line->id, VTY_NEWLINE);
	vty_out(vty, "   mode %s%s", get_value_string(e1_line_mode_names, line->mode), VTY_NEWLINE);

	return 0;
}

static int config_write_e1d(struct vty *vty)
{
	struct e1_intf *intf;

	vty_out(vty, "e1d%s", VTY_NEWLINE);

	/* find all vpair interfaces */
	llist_for_each_entry(intf, &vty_e1d->interfaces, list) {
		struct e1_intf *peer;
		unsigned int line_count = 0;
		struct e1_line *line;

		if (intf->drv != E1_DRIVER_VPAIR)
			continue;

		peer = e1d_vpair_intf_peer(intf);
		OSMO_ASSERT(peer);

		/* skip the 'mirror' interfaces */
		if (intf->id > peer->id)
			continue;

		llist_for_each_entry(line, &intf->lines, list)
			line_count++;

		vty_out(vty, " virtual-e1-pair %u%s", line_count, VTY_NEWLINE);
	}

	/* dump line config for those lines that were created by the vty */
	llist_for_each_entry(intf, &vty_e1d->interfaces, list) {
		struct e1_line *line;

		if (!intf->vty_created)
			continue;

		switch (intf->drv) {
		case E1_DRIVER_USB:
			vty_out(vty, " interface %u icE1usb%s", intf->id, VTY_NEWLINE);
			if (intf->usb.serial_str && strlen(intf->usb.serial_str))
				vty_out(vty, "  usb-serial %s%s", intf->usb.serial_str, VTY_NEWLINE);
			break;
		case E1_DRIVER_VPAIR:
			vty_out(vty, " interface %u vpair%s", intf->id, VTY_NEWLINE);
			break;
		default:
			break;
		}

		llist_for_each_entry(line, &intf->lines, list)
			config_write_line(vty, line);
	}

	return 0;
}

void e1d_vty_init(struct e1_daemon *e1d)
{
	vty_e1d = e1d;
	install_element_ve(&show_intf_cmd);
	install_element_ve(&show_line_cmd);

	install_node(&e1d_node, config_write_e1d);
	install_element(CONFIG_NODE, &cfg_e1d_cmd);
	install_element(E1D_NODE, &cfg_vpair_cmd);

	install_node(&intf_node, NULL);
	install_element(E1D_NODE, &cfg_e1d_if_icE1usb_cmd);
	install_element(E1D_NODE, &cfg_e1d_if_vpair_cmd);
	install_element(INTF_NODE, &cfg_e1d_if_line_cmd);
	install_element(INTF_NODE, &cfg_e1d_if_usb_serial_cmd);

	install_node(&line_node, NULL);
	install_element(LINE_NODE, &cfg_e1d_if_line_mode_cmd);
}
