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
#include <osmocom/usb/libusb.h>

#include <libusb.h>

#include "e1d.h"
#include "log.h"
#include "ice1usb_proto.h"


#define USB_VID		0x1d50
#define USB_PID		0x6145

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
	uint8_t ep_int;

	/* Max packet size */
	int pkt_size;

	/* Flow */
	struct e1_usb_flow *flow_in;
	struct e1_usb_flow *flow_out;
	struct e1_usb_flow *flow_fb;

	/* Interrupt */
	struct {
		uint8_t buf[10];
		struct ice1usb_irq_err last_errcnt;
	} irq;

	/* Rate regulation */
	uint32_t r_acc;
	uint32_t r_sw;

	/* list of in-progress CTRL operations */
	struct llist_head ctrl_inprogress;
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
e1_usb_xfer_in(struct e1_usb_flow *flow, uint8_t *buf, int size)
{
	if (size == 0)
		return 0;
	return e1_line_demux_in(flow->line, buf + 4, size - 4, buf[3] & 0xf);
}

static int
e1_usb_xfer_out(struct e1_usb_flow *flow, uint8_t *buf, int size)
{
	struct e1_line *line = flow->line;
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	int fm, fts;

	if (size <= 0) {
		LOGPLI(line, DXFR, LOGL_ERROR, "OUT ERROR: %d\n", size);
		return -1;
	}

	/* Flow regulation */
	ld->r_acc += ld->r_sw;

	fm = (ld->pkt_size - 4) / 32;
	fts = ld->r_acc >> 10;
	if      (fts <  4) fts = 4;
	else if (fts > fm) fts = fm;

	ld->r_acc -= fts << 10;
	if (ld->r_acc & 0x80000000)
		ld->r_acc = 0;

	memset(buf, 0xff, 4);

	return e1_line_mux_out(line, buf+4, fts) + 4;
}

static int
e1_usb_xfer_fb(struct e1_usb_flow *flow, uint8_t *buf, int size)
{
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) flow->line->drv_data;

	if (size < 0) {
		LOGPLI(flow->line, DE1D, LOGL_ERROR, "Feedback transfer error\n");
		return 0;
	} else if (size != 3) {
		LOGPLI(flow->line, DE1D, LOGL_ERROR, "Feedback packet invalid size (%d)\n", size);
		return 0;
	}

	ld->r_sw = (buf[2] << 16) | (buf[1] << 8) | buf[0];

	return 0;
}


// ---------------------------------------------------------------------------
// USB flow
// ---------------------------------------------------------------------------

/* strings for enum libusb_transfer_status */
static const struct value_string libusb_status_str[] = {
	{ LIBUSB_TRANSFER_COMPLETED,	"COMPLETED" },
	{ LIBUSB_TRANSFER_ERROR,	"ERROR" },
	{ LIBUSB_TRANSFER_TIMED_OUT,	"TIMED_OUT" },
	{ LIBUSB_TRANSFER_CANCELLED,	"CANCELLED" },
	{ LIBUSB_TRANSFER_STALL,	"STALL" },
	{ LIBUSB_TRANSFER_NO_DEVICE,	"NO_DEVICE" },
	{ LIBUSB_TRANSFER_OVERFLOW,	"OVERFLOW" },
	{ 0, NULL }
};

static void LIBUSB_CALL
_e1uf_xfr(struct libusb_transfer *xfr)
{
	struct e1_usb_flow *flow = (struct e1_usb_flow *) xfr->user_data;
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) flow->line->intf->drv_data;
	int j, rv, len;

	len = 0;

	/* FIXME: Check transfer status ? Error handling ? */


	if (flow->ep & 0x80) {
		for (j = 0; j < flow->ppx; j++) {
			struct libusb_iso_packet_descriptor *iso_pd = &xfr->iso_packet_desc[j];
			if (iso_pd->status != LIBUSB_TRANSFER_COMPLETED) {
				LOGPLI(flow->line, DE1D, LOGL_ERROR, "IN EP %02x ISO packet %d failed with status %s\n",
					flow->ep, j, get_value_string(libusb_status_str, iso_pd->status));
			}
			flow->cb(flow,
				libusb_get_iso_packet_buffer_simple(xfr, j),
				(iso_pd->status == LIBUSB_TRANSFER_COMPLETED) ?  (int)iso_pd->actual_length : -1
			);
			len += (iso_pd->length = flow->size);
		}
	} else {
		for (j = 0; j < flow->ppx; j++) {
			struct libusb_iso_packet_descriptor *iso_pd = &xfr->iso_packet_desc[j];
			if (iso_pd->status != LIBUSB_TRANSFER_COMPLETED) {
				LOGPLI(flow->line, DE1D, LOGL_ERROR, "OUT EP %02x ISO packet %d failed with status %s\n",
					flow->ep, j, get_value_string(libusb_status_str, iso_pd->status));
			}
			len += (iso_pd->length = flow->cb(flow, &xfr->buffer[len], flow->size));
		}
	}

	libusb_fill_iso_transfer(xfr, id->devh, flow->ep,
		xfr->buffer, len, flow->ppx,
		_e1uf_xfr, flow, 0
	);

	rv = libusb_submit_transfer(xfr);
	if (rv)
		LOGPLI(flow->line, DE1D, LOGL_ERROR, "Failed to resubmit buffer for transfer\n");
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

	for (int i = 0; i < count; i++)
		flow->entries[i].buf = talloc_zero_size(ctx, size * ppx);

	return flow;
}

static void __attribute__((unused))
e1uf_destroy(struct e1_usb_flow *flow)
{
	if (!flow)
		return;

	/* FIXME: stop pending transfers */
	for (int i = 0; i < flow->count; i++)
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

	for (i = 0; i < flow->count; i++) {
		xfr = libusb_alloc_transfer(flow->ppx);
		if (!xfr)
			return -ENOMEM;

		len = 0;

		if (flow->ep & 0x80) {
			for (j = 0; j < flow->ppx; j++)
				len += (xfr->iso_packet_desc[j].length = flow->size);
		} else {
			for (j = 0; j < flow->ppx; j++)
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
// USB interrupt
// ---------------------------------------------------------------------------

static int resubmit_irq(struct e1_line *line);

/* compute how much advanced 'cur' is copared to 'prev', in modulo-0xffff for wraps */
static uint32_t delta_mod_u16(uint32_t cur, uint32_t prev)
{
	return ((cur + 0xffff) - prev) % 0xffff;
}

static void rx_interrupt_errcnt(struct e1_line *line, const struct ice1usb_irq_err *errcnt)
{
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	struct ice1usb_irq_err *last = &ld->irq.last_errcnt;

	if (errcnt->crc != last->crc) {
		LOGPLI(line, DE1D, LOGL_ERROR, "CRC error count %d (was %d)\n",
			errcnt->crc, last->crc);
		line_ctr_add(line, LINE_CTR_CRC_ERR, delta_mod_u16(errcnt->crc, last->crc));
	}

	if (errcnt->align != last->align) {
		LOGPLI(line, DE1D, LOGL_ERROR, "ALIGNMENT error count %d (was %d)\n",
			errcnt->align, last->align);
		line_ctr_add(line, LINE_CTR_LOA, delta_mod_u16(errcnt->align, last->align));
	}

	if (errcnt->ovfl != last->ovfl) {
		LOGPLI(line, DE1D, LOGL_ERROR, "OVERFLOW error count %d (was %d)\n",
			errcnt->ovfl, last->ovfl);
		line_ctr_add(line, LINE_CTR_RX_OVFL, delta_mod_u16(errcnt->ovfl, last->ovfl));
	}

	if (errcnt->unfl != last->unfl) {
		LOGPLI(line, DE1D, LOGL_ERROR, "UNDERFLOW error count %d (was %d)\n",
			errcnt->unfl, last->unfl);
		line_ctr_add(line, LINE_CTR_TX_UNFL, delta_mod_u16(errcnt->unfl, last->unfl));
	}

	if ((errcnt->flags & ICE1USB_ERR_F_ALIGN_ERR) != (last->flags & ICE1USB_ERR_F_ALIGN_ERR)) {
		LOGPLI(line, DE1D, LOGL_ERROR, "ALIGNMENT %s\n",
			errcnt->flags & ICE1USB_ERR_F_ALIGN_ERR ? "LOST" : "REGAINED");
	}

	if ((errcnt->flags & ICE1USB_ERR_F_LOS) != (last->flags & ICE1USB_ERR_F_LOS)) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Rx Clock %s\n",
			errcnt->flags & ICE1USB_ERR_F_LOS ? "LOST" : "REGAINED");
		if (errcnt->flags & ICE1USB_ERR_F_LOS)
			line_ctr_add(line, LINE_CTR_LOS, 1);
	}

	if ((errcnt->flags & ICE1USB_ERR_F_RAI) != (last->flags & ICE1USB_ERR_F_RAI)) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Remote Alarm (YELLOW) %s\n",
			errcnt->flags & ICE1USB_ERR_F_RAI ? "PRESENT" : "ABSENT");
		/* don't increment counter here, our TS0 code in mux_demux.c does this */
	}

	ld->irq.last_errcnt = *errcnt;
}

static void interrupt_ep_cb(struct libusb_transfer *xfer)
{
	struct e1_line *line = (struct e1_line *) xfer->user_data;
	const struct ice1usb_irq *irq = (const struct ice1usb_irq *) xfer->buffer;

	if (xfer->status != LIBUSB_TRANSFER_COMPLETED) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Error in Interrupt transfer\n");
		goto out;
	}

	if (!xfer->actual_length) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Zero-Length Interrupt transfer\n");
		goto out;
	}

	switch (irq->type) {
	case ICE1USB_IRQ_T_ERRCNT:
		if (xfer->actual_length < (int)sizeof(*irq)) {
			LOGPLI(line, DE1D, LOGL_ERROR, "Short ERRCNT interrupt: %u<%zu\n",
				xfer->actual_length, sizeof(*irq));
			break;
		}
		rx_interrupt_errcnt(line, &irq->u.errors);
		break;
	default:
		LOGPLI(line, DE1D, LOGL_INFO, "Unsupported interrupt 0x%02x\n", irq->type);
		break;
	}

out:
	resubmit_irq(line);
}

static int resubmit_irq(struct e1_line *line)
{
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) line->intf->drv_data;
	struct libusb_transfer *xfr = libusb_alloc_transfer(0);

	libusb_fill_interrupt_transfer(xfr, id->devh, ld->ep_int, ld->irq.buf, sizeof(ld->irq.buf),
					interrupt_ep_cb, line, 0);
	return libusb_submit_transfer(xfr);
}

// ---------------------------------------------------------------------------
// Control transfers
// ---------------------------------------------------------------------------

struct e1_usb_ctrl_xfer {
	struct e1_line *line;
	struct llist_head list;
	/* 8 bytes control setup packet, remainder for data */
	uint8_t buffer[8 + 8];
};


static void
ctrl_xfer_compl_cb(struct libusb_transfer *xfr)
{
	struct e1_usb_ctrl_xfer *ucx = xfr->user_data;

	switch (xfr->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		LOGPLI(ucx->line, DE1D, LOGL_INFO, "CTRL transfer completed successfully\n");
		break;
	default:
		LOGPLI(ucx->line, DE1D, LOGL_ERROR, "CTRL transfer completed unsuccessfully %d\n",
			xfr->status);
		break;
	}
	llist_del(&ucx->list);
	talloc_free(ucx);
	libusb_free_transfer(xfr);
}

/* generic helper for async transmission of control endpoint requests */
static int
_e1_usb_line_send_ctrl(struct e1_line *line, uint8_t bmReqType, uint8_t bReq, uint16_t wValue,
		       const uint8_t *data, size_t data_len)
{
	struct e1_usb_ctrl_xfer *ucx = talloc_zero(line, struct e1_usb_ctrl_xfer);
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) line->intf->drv_data;
	struct libusb_transfer *xfr;
	int rc;

	if (!ucx)
		return -ENOMEM;

	OSMO_ASSERT(sizeof(ucx->buffer) >= 8+data_len);
	ucx->line = line;
	libusb_fill_control_setup(ucx->buffer, bmReqType, bReq, wValue, ld->if_num, data_len);
	if (data && data_len)
		memcpy(ucx->buffer+8, data, data_len);

	xfr = libusb_alloc_transfer(0);
	if (!xfr) {
		rc = -ENOMEM;
		goto free_ucx;
	}

	libusb_fill_control_transfer(xfr, id->devh, ucx->buffer, ctrl_xfer_compl_cb, ucx, 3000);
	rc = libusb_submit_transfer(xfr);
	if (rc != 0)
		goto free_xfr;

	llist_add_tail(&ucx->list, &ld->ctrl_inprogress);

	return 0;

free_xfr:
	libusb_free_transfer(xfr);
free_ucx:
	talloc_free(ucx);

	return rc;
}

int
e1_usb_ctrl_set_tx_cfg(struct e1_line *line, enum ice1usb_tx_mode mode, enum ice1usb_tx_timing timing,
			enum ice1usb_tx_ext_loopback ext_loop, uint8_t alarm)
{
	const uint16_t bmReqType = LIBUSB_RECIPIENT_INTERFACE | LIBUSB_REQUEST_TYPE_VENDOR |
				   LIBUSB_ENDPOINT_OUT;
	struct ice1usb_tx_config tx_cfg = {
		.mode = mode,
		.timing = timing,
		.ext_loopback = ext_loop,
		.alarm = alarm,
	};

	return _e1_usb_line_send_ctrl(line, bmReqType, ICE1USB_INTF_SET_TX_CFG, 0, (uint8_t *)&tx_cfg,
				      sizeof(tx_cfg));
}

int
e1_usb_ctrl_set_rx_cfg(struct e1_line *line, enum ice1usb_rx_mode mode)
{
	const uint16_t bmReqType = LIBUSB_RECIPIENT_INTERFACE | LIBUSB_REQUEST_TYPE_VENDOR |
				   LIBUSB_ENDPOINT_OUT;
	struct ice1usb_rx_config rx_cfg = {
		.mode = mode,
	};

	return _e1_usb_line_send_ctrl(line, bmReqType, ICE1USB_INTF_SET_RX_CFG, 0, (uint8_t *)&rx_cfg,
				      sizeof(rx_cfg));
}

// ---------------------------------------------------------------------------
// Init / Probing
// ---------------------------------------------------------------------------

static int
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

	intf = e1_intf_new(e1d, intf_data);
	intf->drv = E1_DRIVER_USB;

	ret = libusb_get_active_config_descriptor(dev, &cd);
	if (ret) {
		LOGP(DE1D, LOGL_ERROR, "Failed to talk to usb device\n");
		return ret;
	}

	for (i = 0; i < cd->bNumInterfaces; i++) {
		/* Expect 2 altsettings with proper class/subclass/eps */
		if (cd->interface[i].num_altsetting != 2)
			continue;

		id = &cd->interface[i].altsetting[1];
		if ((id->bInterfaceClass != 0xff) || (id->bInterfaceSubClass != 0xe1) || (id->bNumEndpoints < 3))
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

		INIT_LLIST_HEAD(&line_data->ctrl_inprogress);
		line_data->if_num = id->bInterfaceNumber;
		line_data->r_acc  = 0;
		line_data->r_sw   = 8192;

		for (j = 0; j < id->bNumEndpoints; j++) {
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
			} else if (id->endpoint[j].bmAttributes == 0x03) {
				line_data->ep_int = id->endpoint[j].bEndpointAddress;
			} else {
				LOGP(DE1D, LOGL_ERROR, "Invalid EP %02x\n", id->endpoint[j].bEndpointAddress);
			}
		}

		if (!line_data->ep_in || !line_data->ep_out || !line_data->ep_fb || !line_data->pkt_size) {
			LOGP(DE1D, LOGL_ERROR, "Failed to use interface %d\n", id->bInterfaceNumber);
			return -EINVAL;
		}

		line = e1_line_new(intf, line_data);

		line_data->flow_in  = e1uf_create(line, e1_usb_xfer_in,  line_data->ep_in,  4, line_data->pkt_size, 4);
		line_data->flow_out = e1uf_create(line, e1_usb_xfer_out, line_data->ep_out, 4, line_data->pkt_size, 4);
		line_data->flow_fb  = e1uf_create(line, e1_usb_xfer_fb,  line_data->ep_fb,  2, 3, 1);

		e1uf_start(line_data->flow_in);
		e1uf_start(line_data->flow_out);
		e1uf_start(line_data->flow_fb);

		if (line_data->ep_int)
			resubmit_irq(line);
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
		ret = osmo_libusb_init(&g_usb);
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

	for (i = 0; i < n_dev; i++) {
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
