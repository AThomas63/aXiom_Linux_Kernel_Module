// SPDX-License-Identifier: GPL-2.0
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

#define DEBUG   // Enable debug messages

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/crc16.h>
#include <linux/slab.h>

/**
 * aXiom devices are typically configured to report
 * touches at a rate of 100Hz (10ms). For systems
 * that require polling for reports, 100ms seems like
 * an acceptable polling rate.
 * When reports are polled, it will be expected to
 * occasionally observe the overflow bit being set
 * in the reports. This indicates that reports are not
 * being read fast enough.
 */
#define POLL_INTERVAL_DEFAULT_MS	100

#include "axiom_core_new.h"

static int axiom_init_dev_info(struct axiom *ax)
{
	// Read page 0 of u31
	ax->bus_ops->read(ax->dev, ax->xfer_buf, 0x0,
				sizeof(ax->dev_info), (u8 *) &ax->dev_info);
	
	dev_info(ax->dev, "Firmware Info:\n");
	dev_info(ax->dev, "  Bootloader Mode: %u\n", ax->dev_info.mode);
	dev_info(ax->dev, "  Device ID      : %04x\n", ax->dev_info.device_id);
	dev_info(ax->dev, "  Firmware Rev   : %02x.%02x\n", ax->dev_info.runtime_fw_rev_major, ax->dev_info.runtime_fw_rev_minor);
	dev_info(ax->dev, "  Bootloader Rev : %02x.%02x\n", ax->dev_info.bootloader_fw_rev_major, ax->dev_info.bootloader_fw_rev_minor);
	dev_info(ax->dev, "  Silicon        : %02x\n", ax->dev_info.jedec_id);
	dev_info(ax->dev, "  Num Usages     : %04x\n", ax->dev_info.num_usages);

	// Read the second page of u31 to get the usage table
	ax->bus_ops->read(ax->dev, ax->xfer_buf, 0x100,
				sizeof(ax->usage_table[0]) * ax->dev_info.num_usages, (u8 *) &ax->usage_table);

	dev_info(ax->dev, "Usage Table:\n");
	for (int i = 0; i < U31_MAX_USAGES; i++) {
		const struct u31_usage_entry *u = &ax->usage_table[i];
 
		dev_info(ax->dev, "  Usage: u%02x Rev: %3u    Page: 0x%02x00 Num Pages: %3u\n",
			u->usage_num,
			u->uifrevision,
			u->start_page,
			u->num_pages);
	}

	return 0;
}


static int axiom_set_capabilities(struct input_dev *input_dev)
{
	input_dev->name = "TouchNetix aXiom Touchscreen";
	input_dev->phys = "input/axiom_ts";

	// Single Touch
	input_set_abs_params(input_dev, ABS_X, 0, 65535, 0, 0);
	input_set_abs_params(input_dev, ABS_Y, 0, 65535, 0, 0);

	// Multi Touch
	// Min, Max, Fuzz (expected noise in px, try 4?) and Flat
	input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, 65535, 0, 0);
	// Min, Max, Fuzz (expected noise in px, try 4?) and Flat
	input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, 65535, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_TOOL_TYPE, 0, MT_TOOL_MAX, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_DISTANCE, 0, 127, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_PRESSURE, 0, 127, 0, 0);

#ifdef AXIOM_USE_TOUCHSCREEN_INTERFACE
	input_mt_init_slots(input_dev, U41_MAX_TARGETS, INPUT_MT_DIRECT);
#else //TABLET_INTERFACE (emulates mouse pointer as expected)
	input_abs_set_res(input_dev, ABS_MT_POSITION_X, 100);
	input_abs_set_res(input_dev, ABS_MT_POSITION_Y, 100);
	input_abs_set_res(input_dev, ABS_X, 100);
	input_abs_set_res(input_dev, ABS_Y, 100);
	input_mt_init_slots(input_dev, U41_MAX_TARGETS, INPUT_MT_POINTER);

	input_set_abs_params(input_dev, ABS_DISTANCE, 0, 127, 0, 0);
	input_set_abs_params(input_dev, ABS_PRESSURE, 0, 127, 0, 0);
	input_set_capability(input_dev, EV_KEY, BTN_TOOL_PEN);
#endif

	input_set_capability(input_dev, EV_KEY, BTN_LEFT);

	// Force
	set_bit(EV_REL, input_dev->evbit);
	set_bit(EV_MSC, input_dev->evbit);
	// Declare that we support "RAW" Miscellaneous events
	set_bit(MSC_RAW, input_dev->mscbit);

	return 0;
}

struct axiom *axiom_probe(const struct axiom_bus_ops *bus_ops,
			    struct device *dev, int irq, size_t xfer_buf_size)
{

	struct axiom *ax;
	struct input_dev *input_dev;
	int error;

	ax = devm_kzalloc(dev, sizeof(*ax) + xfer_buf_size, GFP_KERNEL);
	if (!ax)
		return ERR_PTR(-ENOMEM);

	input_dev = devm_input_allocate_device(dev);
	if (!input_dev) {
		pr_err("ERROR: aXiom-core: Failed to allocate memory for input device!\n");
		return ERR_PTR(-ENOMEM);
	}

	ax->dev = dev;
	ax->input = input_dev;
	ax->bus_ops = bus_ops;
	ax->irq = irq;

	dev_info(dev, "aXiom Probe\n");
	dev_info(dev, "Device IRQ: %u\n", ax->irq);

	axiom_set_capabilities(input_dev);

	axiom_init_dev_info(ax);








	error = input_register_device(input_dev);
	if (error) {
		dev_err(ax->dev, "failed to register input device: %d\n",
			error);
		return ERR_PTR(error);
	}
	
	return ax;
}

EXPORT_SYMBOL_GPL(axiom_probe);


MODULE_AUTHOR("TouchNetix <support@touchnetix.com>");
MODULE_DESCRIPTION("aXiom touchscreen core logic");
MODULE_LICENSE("GPL");
MODULE_ALIAS("axiom");
MODULE_VERSION("1.0.0");
