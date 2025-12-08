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

#ifndef __AXIOM_CORE_NEW_H
#define __AXIOM_CORE_NEW_H


////////////////////////////////////////////////////////////////////////////////
//USER OPTIONS

#define AXIOM_USE_TOUCHSCREEN_INTERFACE     //registers the axiom device as a touch screen instead of as a mouse pointer
//#define AXIOM_USE_KERNEL_SLOT_ASSIGNMENT    //uses the multitouch protocol for target tracking/assignment instead of axiom
#define U46_ENABLE_RAW_FORCE_DATA             //enables the raw data for up to 4 force channels to be sent to the input subsystem
////////////////////////////////////////////////////////////////////////////////

// u31 has 2 pages for usage table entries. (2 * AX_COMMS_PAGE_SIZE) / U31_BYTES_PER_USAGE = 85
#define U31_MAX_USAGES              (85U)
#define U41_MAX_TARGETS             (10U)
#define U46_AUX_CHANNELS            (4U)
#define U46_AUX_MASK                (0xFFFU)
#define U31_BYTES_PER_USAGE         (6U)
#define USAGE_2DCTS_REPORT_ID       (0x41U)
#define USAGE_2AUX_REPORT_ID        (0x46U)
#define USAGE_2HB_REPORT_ID         (0x01U)
#define PROX_LEVEL                  (-128)
#define AX_U31_PAGE0_LENGTH         (0x0C)
// For details check TNxAN00035: "aXiom_Touch_Controller_Comms_Protocol"
#define AX_COMMS_WRITE              (0x00U)
#define AX_COMMS_READ               (0x80U)
#define AX_COMMS_BYTES_MASK         (0xFFU)

#define COMMS_MAX_USAGE_PAGES       (3)
#define AX_COMMS_PAGE_SIZE          (256)

#define COMMS_OVERFLOW_MSK          (0x80)
#define COMMS_REPORT_LEN_MSK        (0x7F)

#include <linux/input.h>

// purpose: Holds device specific information
struct axiom_device_info {
	u8 bootloader_mode;
	u16 device_id;
	u8 fw_major;
	u8 fw_minor;
	u16 fw_info_extra;
	u8 bootloader_fw_ver_major;
	u8 bootloader_fw_ver_minor;
	u16 jedec_id;
	u8 num_usages;
	u8 silicon_revision;
};


// purpose: Describes parameters of a specific usage, essenstially a single
//          element of the "Usage Table"
// struct usage_Entry {
// 	u8 id;
// 	u8 is_report;
// 	u8 start_page;
// 	u8 num_pages;
// };

struct axiom_bus_ops {
	u16 bustype;
	int (*write)(struct device *dev, u8 *xfer_buf, u16 addr, u8 length,
			const void *values);
	int (*read)(struct device *dev, u8 *xfer_buf, u16 addr, u8 length,
			void *values);
};

enum axiom_state {
	AX_ACTIVE_STATE,
	AX_BL_STATE,
};

struct axiom {
	struct device *dev;
	int irq;
	struct input_dev *input;
	const struct axiom_bus_ops *bus_ops;
	struct axiom_device_info dev_info;
	enum axiom_state state;

	u8 xfer_buf[] ____cacheline_aligned;
};

struct axiom *axiom_probe(const struct axiom_bus_ops *bus_ops,
			    struct device *dev, int irq, size_t xfer_buf_size);

// extern void axiom_get_dev_info(struct axiom_data_core *data_core, u8 *data);
// extern u8 axiom_populate_usage_table(struct axiom_data_core *data_core, u8 *pRX_data);
// extern u16 usage_to_target_address(struct axiom_data_core *data_core,
// 									u8 usage, u8 page, u8 offset);
// extern bool axiom_discover(struct axiom_data_core *data_core);
// extern void axiom_rebaseline(struct axiom_data_core *data_core);
// extern void axiom_init_data_core(struct axiom_data_core *data_core, struct device *pDev, void *pAxiomData, void *pAxiomReadUsage, void *pAxiomWriteUsage);
// extern void axiom_remove(struct axiom_data_core *data_core);
// extern void axiom_process_report(struct axiom_data_core *data_core, u8 *pReport);
// extern void axiom_process_u41_report(u8 *rx_buf, struct axiom_data_core *data_core);
// extern void axiom_process_u46_report(u8 *rx_buf, struct axiom_data_core *data_core);
// extern struct input_dev *axiom_register_input_subsystem(bool poll_enable, int poll_interval);

#endif  /* __AXIOM_CORE_H */
