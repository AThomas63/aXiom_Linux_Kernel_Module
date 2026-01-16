/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TouchNetix aXiom Touchscreen Driver
 *
 * Copyright (C) 2020-2023 TouchNetix Ltd.
 *
 * Author(s): Mark Satterthwaite <mark.satterthwaite@touchnetix.com>
 *            Pedro Torruella <pedro.torruella@touchnetix.com>
 *            Bart Prescott <bartp@baasheep.co.uk>
 *            Hannah Rossiter <hannah.rossiter@touchnetix.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#ifndef __AXIOM_CORE_H
#define __AXIOM_CORE_H

////////////////////////////////////////////////////////////////////////////////
//USER OPTIONS

#define AXIOM_USE_TOUCHSCREEN_INTERFACE // registers the axiom device as a touch screen instead of as a mouse pointer
#define U46_ENABLE_RAW_FORCE_DATA // enables the raw data for up to 4 force channels to be sent to the input subsystem
////////////////////////////////////////////////////////////////////////////////

// u31 has 2 pages for usage table entries. (2 * AX_COMMS_PAGE_SIZE) / U31_BYTES_PER_USAGE = 85
#define U31_MAX_USAGES (85U)
#define U41_MAX_TARGETS (10U)
#define U41_PROX_LEVEL (-128)
#define MAX_REPORT_LEN (58)

#define AXIOM_HOLDOFF_DELAY_US (40)

#include <linux/input.h>

enum ax_comms_op_e { AX_WR_OP = 0, AX_RD_OP = 1 };

enum report_ids_e {
	AX_HB_REPORT_ID = 0x01,
	AX_2DCTS_REPORT_ID = 0x41,
	AX_AUX_REPORT_ID = 0x46,
};

enum axiom_mode_e {
	AX_RUNTIME_STATE = 0,
	AX_BOOTLOADER_STATE = 1,
};

enum usage_type_e {
	UNKNOWN = 0,
	OTHER = 1,
	REPORT = 2,
	REGISTER = 3,
	REGISTER_READ_ONLY_ = 4,
	CDU = 5,
	CDU_READ_ONLY_ = 6,
};

struct axiom_device_info {
	u16 device_id : 15;
	u16 mode : 1;
	u16 runtime_fw_rev_minor : 8;
	u16 runtime_fw_rev_major : 8;
	u16 device_build_variant : 6;
	u16 pad_bit6 : 1;
	u16 runtime_fw_status : 1;
	u16 tcp_revision : 8;
	u16 bootloader_fw_rev_minor : 8;
	u16 bootloader_fw_rev_major : 8;
	u16 jedec_id;
	u16 num_usages : 8;
	u16 silicon_revision : 4;
	u16 runtime_fw_rev_patch : 4;
};

_Static_assert(sizeof(struct axiom_device_info) == 12,
	       "axiom_device_info must be 12 bytes");

struct u31_usage_entry {
	u16 usage_num : 8;
	u16 start_page : 8;
	u16 num_pages : 8;
	u16 max_offset : 7;
	u16 offset_type : 1;
	u16 uifrevision : 8;
	u16 usage_type : 8;
};

_Static_assert(sizeof(struct u31_usage_entry) == 6,
	       "u31_usage_entry must be 6 bytes");

struct axiom_cmd_header {
	u16 target_address;
	u16 length : 15;
	u16 read : 1;
	u8 writeData[];
};

struct axiom_bus_ops {
	u16 bustype;
	int (*write)(struct device *dev, u16 addr, u16 length, void *values);
	int (*read)(struct device *dev, u16 addr, u16 length, void *values);
};

enum u41_target_state_e {
	Target_State_Not_Present = 0,
	Target_State_Prox = 1,
	Target_State_Hover = 2,
	Target_State_Touching = 3,
};

struct u41_target {
	int index;
	enum u41_target_state_e state;
	u16 x;
	u16 y;
	s8 z;
	bool insert;
};

struct axiom {
	struct device *dev;
	int irq;
	struct input_dev *input;
	const struct axiom_bus_ops *bus_ops;
	struct axiom_device_info dev_info;
	struct u31_usage_entry usage_table[U31_MAX_USAGES];
	u16 max_report_len;
	u16 u34_address;

	struct u41_target u41_targets[U41_MAX_TARGETS];

	u8 report_buf[MAX_REPORT_LEN] ____cacheline_aligned;
};

struct u34_report_header {
	u16 report_length : 7;
	u16 overflow : 1;
	u16 report_usage : 8;

	/* all other reports derive from this buffer */
	u8 payload_buf[];
};

_Static_assert(sizeof(struct u34_report_header) == 2,
	       "u34_report_header must be 2 bytes");

struct u41_report { // Revision 6
	u16 target_present : 10;
	u16 unused : 6;

	struct {
		u16 x;
		u16 y;
	} coord[U41_MAX_TARGETS];

	s8 z[U41_MAX_TARGETS];
};

_Static_assert(sizeof(struct u41_report) == (2 + (5 * U41_MAX_TARGETS)),
	       "u41_report size mismatch");

struct axiom *axiom_probe(const struct axiom_bus_ops *bus_ops,
			  struct device *dev, int irq);

#endif /* __AXIOM_CORE_H */
