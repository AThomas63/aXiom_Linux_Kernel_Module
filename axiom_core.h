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

#include <linux/input.h>


#define AXIOM_USE_TOUCHSCREEN_INTERFACE // registers the axiom device as a touch screen instead of as a mouse pointer
#define U46_ENABLE_RAW_FORCE_DATA // enables the raw data for up to 4 force channels to be sent to the input subsystem

#define AXIOM_PAGE_SIZE (256)
// u31 has 2 pages for usage table entries. (2 * PAGE_SIZE) / U31_BYTES_PER_USAGE = 85
#define AXIOM_MAX_READ_SIZE (2 * AXIOM_PAGE_SIZE)
#define SIZE_U31_DEVICE_INFO (12)
#define SIZE_U31_USAGE_ENTRY (6)
#define U31_MAX_USAGES (85U)
#define U41_MAX_TARGETS (10U)
#define U41_PROX_LEVEL (-128)

#define AXIOM_HOLDOFF_DELAY_US (40)


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
	u16 device_id;
	u8 mode;
	u8 runtime_fw_rev_minor;
	u8 runtime_fw_rev_major;
	u8 device_build_variant;
	u8 runtime_fw_status;
	u8 tcp_revision;
	u8 bootloader_fw_rev_minor;
	u8 bootloader_fw_rev_major;
	u8 jedec_id;
	u8 num_usages;
	u8 silicon_revision;
	u8 runtime_fw_rev_patch;
};

struct u31_usage_entry {
	u8 usage_num;
	u8 start_page;
	u8 num_pages;
	u8 max_offset;
	u8 offset_type;
	u8 uifrevision;
	u8 usage_type;
};

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

	u8 read_buf[AXIOM_MAX_READ_SIZE];
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
