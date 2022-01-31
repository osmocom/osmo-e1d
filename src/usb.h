#pragma once

#include "ice1usb_proto.h"

struct e1d_line;
struct e1_daemon;
struct libusb_device;

int e1_usb_ctrl_set_tx_cfg(struct e1_line *line, enum ice1usb_tx_mode mode,
			   enum ice1usb_tx_timing timing, enum ice1usb_tx_ext_loopback ext_loop,
			   uint8_t alarm);

int e1_usb_ctrl_set_rx_cfg(struct e1_line *line, enum ice1usb_rx_mode mode);

int e1_usb_ctrl_set_gpsdo_mode(struct e1_intf *intf, enum ice1usb_gpsdo_mode gpsdo_mode);
int e1_usb_ctrl_set_gpsdo_tune(struct e1_intf *intf, const struct e1usb_gpsdo_tune *gpsdo_tune);
int e1_usb_ctrl_get_gpsdo_status(struct e1_intf *intf);

int e1_usb_intf_gpsdo_state_string(char *buf, size_t len, const struct e1_intf *intf);

int e1_usb_init(struct e1_daemon *e1d);
