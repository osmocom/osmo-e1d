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

#include <osmocom/core/linuxlist.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/tdef_vty.h>

#include <osmocom/e1d/proto.h>
#include "e1d.h"

static struct e1_daemon *vty_e1d;

#if 0
static void vty_dump_ts(struct vty *vty, const struct e1_ts *ts)
{
}
#endif

static void vty_dump_intf(struct vty *vty, const struct e1_intf *intf)
{
	vty_out(vty, "Interface #%u, Driver: FIXME%s", intf->id, VTY_NEWLINE);
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

static const struct value_string e1_ts_mode_names[] = {
	{ E1_TS_MODE_OFF,	"OFF" },
	{ E1_TS_MODE_RAW,	"RAW" },
	{ E1_TS_MODE_HDLCFCS,	"HDLC-FCS" },
	{ 0, NULL }
};

static void vty_dump_line(struct vty *vty, const struct e1_line *line)
{
	int tn;

	vty_out(vty, "Interface #%u, Line #%u:%s", line->intf->id, line->id, VTY_NEWLINE);

	for (tn = 0; tn < ARRAY_SIZE(line->ts); tn++) {
		const struct e1_ts *ts = &line->ts[tn];
		vty_out(vty, " TS%02u: Mode %s, FD %d, Peer PID %d%s",
			ts->id, get_value_string(e1_ts_mode_names, ts->mode),
			ts->fd, get_remote_pid(ts->fd), VTY_NEWLINE);
	}
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

void e1d_vty_init(struct e1_daemon *e1d)
{
	vty_e1d = e1d;
	install_element_ve(&show_intf_cmd);
	install_element_ve(&show_line_cmd);

	install_element(CONFIG_NODE, &cfg_vpair_cmd);
}
