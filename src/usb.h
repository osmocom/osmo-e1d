#pragma once

#include "ice1usb_proto.h"

struct e1d_line;
struct e1_daemon;
struct libusb_device;

int e1_usb_ctrl_set_tx_cfg(struct e1_line *line, enum ice1usb_tx_mode mode,
			   enum ice1usb_tx_timing timing, enum ice1usb_tx_ext_loopback ext_loop,
			   uint8_t alarm);

int e1_usb_ctrl_set_rx_cfg(struct e1_line *line, enum ice1usb_rx_mode mode);

int _e1_usb_open_device(struct e1_daemon *e1d, struct libusb_device *dev);

int e1_usb_probe(struct e1_daemon *e1d);
