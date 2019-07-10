/*
 * usb.c
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
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <talloc.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/utils.h>

#include <libusb.h>

#include "e1d.h"
#include "log.h"


#define USB_VID		0x1d50
#define USB_PID		0xe1e1

libusb_context *g_usb = NULL;


struct e1_usb_flow;


/* Driver data */

struct e1_usb_line_data {
	/* Interface */
	uint8_t if_num;

	/* End Points */
	uint8_t ep_in;
	uint8_t ep_out;
	uint8_t ep_fb;

	/* Max packet size */
	int pkt_size;

	/* Flow */
	struct e1_usb_flow *flow_in;
	struct e1_usb_flow *flow_out;
	struct e1_usb_flow *flow_fb;

	/* Rate regulation */
	uint32_t r_acc;
	uint32_t r_sw;
};

struct e1_usb_intf_data {
	libusb_device_handle *devh;
};


/* Flow */

struct e1_usb_flow_entry {
	uint8_t *buf;
	struct libusb_transfer *xfr;
};

typedef int (*xfer_cb_t)(struct e1_usb_flow *flow, uint8_t *buf, int size);

struct e1_usb_flow {
	struct e1_line *line;
	xfer_cb_t cb;

	uint8_t ep;

	int count;
	int size;
	int ppx;

	struct e1_usb_flow_entry *entries;
};



// ---------------------------------------------------------------------------
// USB data transfer
// ---------------------------------------------------------------------------

static int
_e1_rx_hdlcfs(struct e1_ts *ts, uint8_t *buf, int len)
{
	int rv, cl, oi;

	oi = 0;

	while (oi < len) {
		rv = osmo_isdnhdlc_decode(&ts->hdlc_rx,
			&buf[oi], len-oi, &cl,
			ts->rx_buf, sizeof(ts->rx_buf)
		);

		if (rv > 0) {
			printf("RX Message: %d %d [ %s]\n", ts->id, rv, osmo_hexdump(ts->rx_buf, rv));
			write(ts->fd, ts->rx_buf, rv);
		} else  if (rv < 0 && ts->id == 4) {
			printf("ERR RX: %d %d %d [ %s]\n",rv,oi,cl, osmo_hexdump(buf, len));
		}

		oi += cl;
	}

	return 0;
}

static int
_e1_tx_hdlcfs(struct e1_ts *ts, uint8_t *buf, int len)
{
	int rv, oo, cl;

	oo = 0;

	while (oo < len) {
		/* Pending message ? */
		if (!ts->tx_len) {
			rv = read(ts->fd, ts->tx_buf, sizeof(ts->tx_buf));
			if (rv > 0) {
				printf("TX Message: %d %d [ %s]\n", ts->id, rv, osmo_hexdump(ts->tx_buf, rv));
				ts->tx_len = rv; 
				ts->tx_ofs = 0;
			}
		}

		/* */
		rv = osmo_isdnhdlc_encode(&ts->hdlc_tx,
			&ts->tx_buf[ts->tx_ofs], ts->tx_len - ts->tx_ofs, &cl,
			&buf[oo], len - oo
		);

		if (rv < 0)
			printf("ERR TX: %d\n", rv);

		if (ts->tx_ofs < ts->tx_len)
			printf("TX chunk %d/%d %d [ %s]\n", ts->tx_ofs, ts->tx_len, cl, osmo_hexdump(&buf[ts->tx_ofs], rv));

		if (rv > 0)
			oo += rv;

		ts->tx_ofs += cl;
		if (ts->tx_ofs >= ts->tx_len) {
			ts->tx_len = 0;
			ts->tx_ofs = 0;
		}
	}

	return len;
}

static int
e1_usb_xfer_in(struct e1_usb_flow *flow, uint8_t *buf, int size)
{
	struct e1_line *line = flow->line;
	int ftr;

	if (size <= 0) {
		printf("IN ERROR: %d\n", size);
		return -1;
	}

	ftr = (size - 4) / 32;

	for (int tsn=1; tsn<32; tsn++)
	{
		struct e1_ts *ts = &line->ts[tsn];
		uint8_t buf_ts[32];

		if (ts->mode == E1_TS_MODE_OFF)
			continue;

		for (int i=0; i<ftr; i++)
			buf_ts[i] = buf[4+tsn+(i*32)];

		switch (ts->mode) {
		case E1_TS_MODE_RAW:
			write(ts->fd, buf_ts, ftr);
			break;
		case E1_TS_MODE_HDLCFCS:
			_e1_rx_hdlcfs(ts, buf_ts, ftr);
			break;
		default:
			continue;
		}
	}

	return 0;
}

static int
e1_usb_xfer_out(struct e1_usb_flow *flow, uint8_t *buf, int size)
{
	struct e1_line *line = flow->line;
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	int fts, tsz;

	if (size <= 0) {
		printf("OUT ERROR: %d\n", size);
		return -1;
	}

	/* Flow regulation */
	ld->r_acc += ld->r_sw;

	fts = ld->r_acc >> 10;
	if      (fts <  4) fts = 4;
	else if (fts > 12) fts = 12;

	ld->r_acc -= fts << 10;
	if (ld->r_acc & 0x80000000)
		ld->r_acc = 0;

	/* Prepare */
	tsz = 4 + 32 * fts;
	memset(buf, 0xff, tsz);

	/* Header */
		/* FIXME */

	/* Scan timeslots */
	for (int tsn=1; tsn<32; tsn++)
	{
		struct e1_ts *ts = &line->ts[tsn];
		uint8_t buf_ts[32];
		int l;

		if (ts->mode == E1_TS_MODE_OFF)
			continue;

		switch (ts->mode) {
		case E1_TS_MODE_RAW:
			l = read(ts->fd, buf_ts, fts);
			break;
		case E1_TS_MODE_HDLCFCS:
			l = _e1_tx_hdlcfs(ts, buf_ts, fts);
			break;
		default:
			continue;
		}

		if (l <= 0)
			continue;

		for (int i=0; i<l; i++)
			buf[4+tsn+(i*32)] = buf_ts[i];
	}

	return tsz;
}

static int
e1_usb_xfer_fb(struct e1_usb_flow *flow, uint8_t *buf, int size)
{
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) flow->line->drv_data;

	if (size < 0) {
		LOGP(DE1D, LOGL_ERROR, "Feedback transfer error\n");
		return 0;
	} else if (size != 3) {
		LOGP(DE1D, LOGL_ERROR, "Feedback packet invalid size (%d)\n", size);
		return 0;
	}

	ld->r_sw = (buf[2] << 16) | (buf[1] << 8) | buf[0];

	return 0;
}


// ---------------------------------------------------------------------------
// USB flow
// ---------------------------------------------------------------------------

static void LIBUSB_CALL
_e1uf_xfr(struct libusb_transfer *xfr)
{
	struct e1_usb_flow *flow = (struct e1_usb_flow *) xfr->user_data;
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) flow->line->intf->drv_data;
	int j, rv, len;

	len = 0;

	/* FIXME: Check transfer status ? Error handling ? */

	if (flow->ep & 0x80) {
		for (j=0; j<flow->ppx; j++) {
			flow->cb(flow,
				libusb_get_iso_packet_buffer_simple(xfr, j),
				(xfr->iso_packet_desc[j].status == LIBUSB_TRANSFER_COMPLETED) ?
					xfr->iso_packet_desc[j].actual_length : -1
			);
			len += (xfr->iso_packet_desc[j].length = flow->size);
		}
	} else {
		for (j=0; j<flow->ppx; j++)
			len += (xfr->iso_packet_desc[j].length = flow->cb(flow, &xfr->buffer[len], flow->size));
	}

	libusb_fill_iso_transfer(xfr, id->devh, flow->ep,
		xfr->buffer, len, flow->ppx,
		_e1uf_xfr, flow, 0
	);

	rv = libusb_submit_transfer(xfr);
	if (rv)
		LOGP(DE1D, LOGL_ERROR, "Failed to resubmit buffer for transfer\n");
}

static struct e1_usb_flow *
e1uf_create(struct e1_line *line, xfer_cb_t cb,
            int ep, int count, int size, int ppx)
{
	void *ctx = line->intf->e1d->ctx;
	struct e1_usb_flow *flow;

	flow = talloc_zero(ctx, struct e1_usb_flow);
	OSMO_ASSERT(flow);

	flow->line  = line;
	flow->cb    = cb;
	flow->ep    = ep;
	flow->count = count;
	flow->size  = size;
	flow->ppx   = ppx;
	flow->entries = talloc_zero_size(ctx, count * sizeof(struct e1_usb_flow_entry));

	for (int i=0; i<count; i++)
		flow->entries[i].buf = talloc_zero_size(ctx, size * ppx);

	return flow;
}

static void __attribute__((unused))
e1uf_destroy(struct e1_usb_flow *flow)
{
	if (!flow)
		return;

	/* FIXME: stop pending transfers */
	for (int i=0; i<flow->count; i++)
		talloc_free(flow->entries[i].buf);

	talloc_free(flow->entries);
	talloc_free(flow);
}

static int
e1uf_start(struct e1_usb_flow *flow)
{
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) flow->line->intf->drv_data;
	struct libusb_transfer *xfr;
	int i, j, rv, len;

	for (i=0; i<flow->count; i++)
	{
		xfr = libusb_alloc_transfer(flow->ppx);
		if (!xfr)
			return -ENOMEM;

		len = 0;

		if (flow->ep & 0x80) {
			for (j=0; j<flow->ppx; j++)
				len += (xfr->iso_packet_desc[j].length = flow->size);
		} else {
			for (j=0; j<flow->ppx; j++)
				len += (xfr->iso_packet_desc[j].length = flow->cb(flow, &flow->entries[i].buf[len], flow->size));
		}

		libusb_fill_iso_transfer(xfr, id->devh, flow->ep,
			flow->entries[i].buf, len, flow->ppx,
			_e1uf_xfr, flow, 0
		);

		rv = libusb_submit_transfer(xfr);

		if (rv)
			return rv;

		flow->entries[i].xfr = xfr;
	}

	return 0;
}


// ---------------------------------------------------------------------------
// e1d structures
// ---------------------------------------------------------------------------

struct e1_intf *
_e1_intf_new(struct e1_daemon *e1d, void *drv_data)
{
	struct e1_intf *intf;

	intf = talloc_zero(e1d->ctx, struct e1_intf);
	OSMO_ASSERT(intf);

	intf->e1d = e1d;
	intf->drv_data = drv_data;

	INIT_LLIST_HEAD(&intf->list);
	INIT_LLIST_HEAD(&intf->lines);

	if (!llist_empty(&e1d->interfaces)) {
		struct e1_intf *f = llist_first_entry(&e1d->interfaces, struct e1_intf, list);
		intf->id = f->id + 1;
	}

	llist_add(&intf->list, &e1d->interfaces);

	return intf;
}

struct e1_line *
_e1_line_new(struct e1_intf *intf, void *drv_data)
{
	struct e1_line *line;

	line = talloc_zero(intf->e1d->ctx, struct e1_line);
	OSMO_ASSERT(line);

	line->intf = intf;
	line->drv_data = drv_data;

	for (int i=0; i<32; i++)
		line->ts[i].id = i;

	INIT_LLIST_HEAD(&line->list);

	if (!llist_empty(&intf->lines)) {
		struct e1_line *l = llist_first_entry(&intf->lines, struct e1_line, list);
		line->id = l->id + 1;
	}

	llist_add(&line->list, &intf->lines);

	return line;
}



// ---------------------------------------------------------------------------
// Init / Probing
// ---------------------------------------------------------------------------

int
_e1_usb_open_device(struct e1_daemon *e1d, struct libusb_device *dev)
{
	struct e1_intf *intf;
	struct e1_line *line;
	struct e1_usb_intf_data *intf_data;
	struct e1_usb_line_data *line_data;
	struct libusb_config_descriptor *cd;
	const struct libusb_interface_descriptor *id;
	libusb_device_handle *devh;
	int i, j, ret;

	ret = libusb_open(dev, &devh);
	if (ret) {
		LOGP(DE1D, LOGL_ERROR, "Failed to open usb device\n");
		return ret;
	}

	intf_data = talloc_zero(e1d->ctx, struct e1_usb_intf_data);
	intf_data->devh = devh;

	intf = _e1_intf_new(e1d, intf_data);

	ret = libusb_get_active_config_descriptor(dev, &cd);
	if (ret) {
		LOGP(DE1D, LOGL_ERROR, "Failed to talk to usb device\n");
		return ret;
	}

	for (i=0; i<cd->bNumInterfaces; i++) {
		/* Expect 2 altsettings with proper class/subclass/eps */
		if (cd->interface[i].num_altsetting != 2)
			continue;

		id = &cd->interface[i].altsetting[1];
		if ((id->bInterfaceClass != 0xff) || (id->bInterfaceSubClass != 0xe1) || (id->bNumEndpoints != 3))
			continue;

		/* Get interface and set it up */
		ret = libusb_claim_interface(devh, id->bInterfaceNumber);
		if (ret) {
			LOGP(DE1D, LOGL_ERROR, "Failed to claim interface %d\n", id->bInterfaceNumber);
			return ret;
		}

		ret = libusb_set_interface_alt_setting(devh, id->bInterfaceNumber, 1);
		if (ret) {
			LOGP(DE1D, LOGL_ERROR, "Failed to set interface %d altsetting\n", id->bInterfaceNumber);
			return ret;
		}

		/* Setup driver data and find endpoints */
		line_data = talloc_zero(e1d->ctx, struct e1_usb_line_data);

		line_data->if_num = id->bInterfaceNumber;
		line_data->r_acc  = 0;
		line_data->r_sw   = 8192;

		for (j=0; j<id->bNumEndpoints; j++) {
			if (id->endpoint[j].bmAttributes == 0x11) {
				line_data->ep_fb = id->endpoint[j].bEndpointAddress;
			} else if (id->endpoint[j].bmAttributes == 0x05) {
				if (id->endpoint[j].bEndpointAddress & 0x80)
					line_data->ep_in = id->endpoint[j].bEndpointAddress;
				else
					line_data->ep_out = id->endpoint[j].bEndpointAddress;

				if (!line_data->pkt_size)
					line_data->pkt_size = id->endpoint[j].wMaxPacketSize;
				else if (line_data->pkt_size != id->endpoint[j].wMaxPacketSize)
					LOGP(DE1D, LOGL_ERROR, "Inconsistent max packet size %d vs %d\n",
						line_data->pkt_size, (int)id->endpoint[j].wMaxPacketSize);
			} else {
				LOGP(DE1D, LOGL_ERROR, "Invalid EP %02x\n", id->endpoint[j].bEndpointAddress);
			}
		}

		if (!line_data->ep_in || !line_data->ep_out || !line_data->ep_fb || !line_data->pkt_size) {
			LOGP(DE1D, LOGL_ERROR, "Failed to use interface %d\n", id->bInterfaceNumber);
			return -EINVAL;
		}

		line = _e1_line_new(intf, line_data);

		line_data->flow_in  = e1uf_create(line, e1_usb_xfer_in,  line_data->ep_in,  2, line_data->pkt_size, 4);
		line_data->flow_out = e1uf_create(line, e1_usb_xfer_out, line_data->ep_out, 2, line_data->pkt_size, 4);
		line_data->flow_fb  = e1uf_create(line, e1_usb_xfer_fb,  line_data->ep_fb,  2, 8, 1);

		e1uf_start(line_data->flow_in);
		e1uf_start(line_data->flow_out);
		e1uf_start(line_data->flow_fb);
	}

	return 0;
}

int
e1_usb_probe(struct e1_daemon *e1d)
{
	struct libusb_device **dev_list;
	ssize_t n_dev;
	int i, ret;

	if (!g_usb) {
		ret = libusb_init(&g_usb);
		if (ret) {
			LOGP(DE1D, LOGL_ERROR, "Failed to initialize libusb\n");
			return -EIO;
		}
	}

	n_dev = libusb_get_device_list(g_usb, &dev_list);
	if (n_dev < 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to list devices\n");
		return -EIO;
	}

	for (i=0; i<n_dev; i++) {
		struct libusb_device_descriptor desc;

		ret = libusb_get_device_descriptor(dev_list[i], &desc);
		if (ret)
			continue;

		if ((desc.idVendor != USB_VID) || (desc.idProduct != USB_PID))
			continue;

		_e1_usb_open_device(e1d, dev_list[i]);
	}

	libusb_free_device_list(dev_list, 1);

	return 0;
}

int
e1_usb_poll(void)
{
	int rv;

	rv = libusb_handle_events(g_usb);
	if (rv != LIBUSB_SUCCESS)
		return -EIO;

	return 0;
}
