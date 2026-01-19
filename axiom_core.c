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

#define DEBUG // Enable debug messages

#include <linux/device.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/crc16.h>
#include <linux/interrupt.h>
#include "axiom_core.h"

/* u31 device info masks */
#define AX_DEV_ID_MASK      GENMASK(14, 0)
#define AX_MODE        BIT(15)
#define AX_FW_REV_MINOR_MASK    GENMASK(7, 0)
#define AX_FW_REV_MAJOR_MASK    GENMASK(15, 8)
#define AX_VARIANT_MASK     GENMASK(5, 0)
#define AX_FW_STATUS   BIT(7)
#define AX_TCP_REV_MASK            GENMASK(15, 8)
#define AX_BOOT_REV_MINOR_MASK     GENMASK(7, 0)
#define AX_BOOT_REV_MAJOR_MASK     GENMASK(15, 8)
#define AX_NUM_USAGES_MASK       GENMASK(7, 0)
#define AX_SILICON_REV_MASK GENMASK(11, 8)
#define AX_RUNTIME_FW_PATCH_MASK       GENMASK(15, 12)

/* u31 usage table entry masks */
#define AX_U31_USAGE_NUM_MASK      GENMASK(7, 0)
#define AX_U31_START_PAGE_MASK     GENMASK(15, 8)
#define AX_U31_NUM_PAGES_MASK      GENMASK(7, 0)
#define AX_U31_MAX_OFFSET_MASK     GENMASK(14, 8)
#define AX_U31_OFFSET_TYPE_BIT     BIT(15)
#define AX_U31_UIF_REV_MASK        GENMASK(7, 0)
#define AX_U31_USAGE_TYPE_MASK     GENMASK(15, 8)

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

	input_mt_init_slots(input_dev, U41_MAX_TARGETS, INPUT_MT_DIRECT);

	input_set_capability(input_dev, EV_KEY, BTN_LEFT);

	return 0;
}

static struct u31_usage_entry *usage_find_entry(struct axiom *ax, u16 usage)
{
	u16 i;

	for (i = 0; i < ax->dev_info.num_usages; i++) {
		if (ax->usage_table[i].usage_num == usage)
			return &ax->usage_table[i];
	}

	pr_err("aXiom-core: Usage u%02x not found in usage table\n", usage);
	return ERR_PTR(-EINVAL);
}

static void axiom_unpack_device_info(const u8 *buf, struct axiom_device_info *info)
{
    const __le16 *ptr = (const __le16 *)buf;
	u16 w;

    w = le16_to_cpu(ptr[0]);
    info->device_id = FIELD_GET(AX_DEV_ID_MASK, w);
    info->mode      = !!(w & AX_MODE);

    w = le16_to_cpu(ptr[1]);
	info->runtime_fw_rev_minor = FIELD_GET(AX_FW_REV_MINOR_MASK, w);
    info->runtime_fw_rev_major = FIELD_GET(AX_FW_REV_MAJOR_MASK, w);

    w = le16_to_cpu(ptr[2]);
    info->device_build_variant = FIELD_GET(AX_VARIANT_MASK, w);
    info->runtime_fw_status    = !!(w & AX_FW_STATUS);
    info->tcp_revision         = FIELD_GET(AX_TCP_REV_MASK, w);

    w = le16_to_cpu(ptr[3]);
	info->bootloader_fw_rev_minor = FIELD_GET(AX_BOOT_REV_MINOR_MASK, w);
    info->bootloader_fw_rev_major = FIELD_GET(AX_BOOT_REV_MAJOR_MASK, w);

    info->jedec_id = le16_to_cpu(ptr[4]);

    w = le16_to_cpu(ptr[5]);
    info->num_usages        = FIELD_GET(AX_NUM_USAGES_MASK, w);
    info->silicon_revision        = FIELD_GET(AX_SILICON_REV_MASK, w);
    info->runtime_fw_rev_patch = FIELD_GET(AX_RUNTIME_FW_PATCH_MASK, w);
}

static void axiom_unpack_usage_table(const u8 *buf, struct axiom *ax)
{	
	__le16 *ptr = (__le16 *) buf;
	struct u31_usage_entry *entry;
	int i;
	u16 w;
	u16 report_len;

	for (i = 0; i < ax->dev_info.num_usages && i < U31_MAX_USAGES; i++) {
		entry = &ax->usage_table[i];
		/* Calculate offset for this specific entry */
		ptr = (__le16 *) (buf + (i * SIZE_U31_USAGE_ENTRY));

		w = le16_to_cpu(ptr[0]);
		entry->usage_num  = FIELD_GET(AX_U31_USAGE_NUM_MASK, w);
		entry->start_page = FIELD_GET(AX_U31_START_PAGE_MASK, w);

		w = le16_to_cpu(ptr[1]);
		entry->num_pages  = FIELD_GET(AX_U31_NUM_PAGES_MASK, w);
		entry->max_offset = FIELD_GET(AX_U31_MAX_OFFSET_MASK, w);
		entry->offset_type = !!(w & AX_U31_OFFSET_TYPE_BIT);

		w = le16_to_cpu(ptr[2]);
		entry->uifrevision = FIELD_GET(AX_U31_UIF_REV_MASK, w);
		entry->usage_type  = FIELD_GET(AX_U31_USAGE_TYPE_MASK, w);
	
		// Convert words to bytes
		report_len = (entry->max_offset + 1) * 2;
		if ((entry->usage_type == REPORT) &&
			(report_len > ax->max_report_len)) {
				ax->max_report_len = report_len;
		}
	}
}

static int axiom_init_dev_info(struct axiom *ax)
{
	int i;
	struct u31_usage_entry *u;
	int err;

	/* Read page 0 of u31 */
	err = ax->bus_ops->read(ax->dev, 0x0, SIZE_U31_DEVICE_INFO,
				ax->read_buf);
	if (err)
		return -EIO;

	axiom_unpack_device_info(ax->read_buf, &ax->dev_info);

	dev_info(ax->dev, "Firmware Info:\n");
	dev_info(ax->dev, "  Bootloader Mode: %u\n", ax->dev_info.mode);
	dev_info(ax->dev, "  Device ID      : %04x\n", ax->dev_info.device_id);
	dev_info(ax->dev, "  Firmware Rev   : %02x.%02x\n",
		 ax->dev_info.runtime_fw_rev_major,
		 ax->dev_info.runtime_fw_rev_minor);
	dev_info(ax->dev, "  Bootloader Rev : %02x.%02x\n",
		 ax->dev_info.bootloader_fw_rev_major,
		 ax->dev_info.bootloader_fw_rev_minor);
	dev_info(ax->dev, "  Silicon        : %02x\n", ax->dev_info.jedec_id);
	dev_info(ax->dev, "  Num Usages     : %04x\n", ax->dev_info.num_usages);

	if (ax->dev_info.num_usages > U31_MAX_USAGES) {
		dev_err(ax->dev,
			"Num usages (%u) exceeds maximum supported (%u)\n",
			ax->dev_info.num_usages, U31_MAX_USAGES);
		return -EINVAL;
	}

	/* Read the second page of u31 to get the usage table */
	err = ax->bus_ops->read(ax->dev, 0x100,
				sizeof(ax->usage_table[0]) *
				ax->dev_info.num_usages,
				ax->read_buf);
	if (err)
		return -EIO;
	
	axiom_unpack_usage_table(ax->read_buf, ax);

	dev_info(ax->dev, "Usage Table:\n");
	for (i = 0; i < ax->dev_info.num_usages; i++) {
		u = &ax->usage_table[i];

		dev_info(ax->dev,
			"  Usage: u%02x  Rev: %3u  Page: 0x%02x00  Num Pages: %3u\n",
			u->usage_num, u->uifrevision, u->start_page,
			u->num_pages);
	}
	dev_info(ax->dev, "Max Report Length: %u\n", ax->max_report_len);

	if (ax->max_report_len > AXIOM_MAX_READ_SIZE) {
		dev_err(ax->dev,
			"aXiom maximum report length (%u) greater than allocated buffer size (%u).",
			ax->max_report_len, AXIOM_MAX_READ_SIZE);
		return -EINVAL;
	}

	/* Set u34 address to allow direct access to report reading address */
	u = usage_find_entry(ax, 0x34);
	if (IS_ERR(u))
		return PTR_ERR(u);
	ax->u34_address = u->start_page << 8;

	return 0;
}

static int axiom_rebaseline(struct axiom *ax)
{
	struct u31_usage_entry *u;
	u8 buffer[8] = { 0 };
	int err;

	u = usage_find_entry(ax, 0x02);
	if (IS_ERR(u))
		return PTR_ERR(u);

	/* Rebaseline request */
	buffer[0] = 0x03;

	err = ax->bus_ops->write(ax->dev, u->start_page << 8, sizeof(buffer),
				 buffer);
	if (err) {
		dev_err(ax->dev, "Rebaseline failed\n");
		return err;
	}

	dev_info(ax->dev, "Capture Baseline Requested\n");
	return 0;
}

static bool axiom_process_u41_target(struct axiom *ax, struct u41_target *prev,
				     const struct u41_target *target, int slot)
{
	bool update = false;

	switch (target->state) {
	case Target_State_Not_Present:
	case Target_State_Prox:
		if (prev->insert) {
			prev->insert = false;
			update = true;

			input_mt_slot(ax->input, slot);
			if (slot == 0)
				input_report_key(ax->input, BTN_LEFT, false);

			input_mt_report_slot_inactive(ax->input);

			/* Off-screen coordinates for next touch */
			prev->x = prev->y = 65535;
			prev->z = -128;
		}
		break;

	case Target_State_Hover:
	case Target_State_Touching:
		prev->insert = true;
		update = true;

		input_mt_slot(ax->input, slot);
		input_report_abs(ax->input, ABS_MT_TRACKING_ID, slot);
		input_report_abs(ax->input, ABS_MT_POSITION_X, target->x);
		input_report_abs(ax->input, ABS_X, target->x);
		input_report_abs(ax->input, ABS_MT_POSITION_Y, target->y);
		input_report_abs(ax->input, ABS_Y, target->y);

		if (target->state == Target_State_Touching) {
			input_report_abs(ax->input, ABS_MT_DISTANCE, 0);
			input_report_abs(ax->input, ABS_MT_PRESSURE, target->z);
		} else { /* Hover */
			input_report_abs(ax->input, ABS_MT_DISTANCE,
					 -target->z);
			input_report_abs(ax->input, ABS_DISTANCE, -target->z);
			input_report_abs(ax->input, ABS_MT_PRESSURE, 0);
			input_report_abs(ax->input, ABS_PRESSURE, 0);
		}

		if (slot == 0)
			input_report_key(ax->input, BTN_LEFT,
					 target->state ==
						 Target_State_Touching);

		break;

	default:
		break;
	}

	/* Update stored previous state */
	prev->state = target->state;
	prev->x = target->x;
	prev->y = target->y;
	prev->z = target->z;

	return update;
}

static int axiom_process_u41_report(struct axiom *ax, u8 *report)
{
	const struct u41_report *r = (const struct u41_report *)report;
	struct u41_target target;
	struct u41_target *prev;
	bool update = false;
	int slot;
	bool present;
	int i;

	dev_dbg(ax->dev, "=== u41 report data ===\n");

	for (i = 0; i < U41_MAX_TARGETS; i++) {
		prev = &ax->u41_targets[i];

		present = !!((r->target_present >> i) & 1);
		target.index = i;
		target.x = r->coord[i].x;
		target.y = r->coord[i].y;
		target.z = r->z[i];
		target.state = ((present == 0)	? Target_State_Not_Present :
				(target.z >= 0) ? Target_State_Touching :
				(target.z > U41_PROX_LEVEL) && (target.z < 0) ?
						  Target_State_Hover :
				(target.z == U41_PROX_LEVEL) ?
						  Target_State_Prox :
						  Target_State_Not_Present);
		dev_dbg(ax->dev, "Target %d: x=%u y=%u z=%d present=%d\n", i,
			target.x, target.y, target.z, present);

		slot = i;
		if ((prev->state != target.state) || (prev->x != target.x) ||
		    (prev->y != target.y) || (prev->z != target.z)) {
			update |= axiom_process_u41_target(ax, prev, &target,
							   slot);
		}
	}

	if (update) {
		input_mt_sync_frame(ax->input);
		input_sync(ax->input);
	}
	return 0;
}

static int check_revision(struct axiom *ax, u16 usage)
{
	struct u31_usage_entry *u;

	u = usage_find_entry(ax, usage);
	if (IS_ERR(u))
		return PTR_ERR(u);

	if (usage == AX_2DCTS_REPORT_ID) {
		if (u->uifrevision != 6) {
			dev_err(ax->dev,
				"Unsupported revision %u for usage u%02x!\n",
				u->uifrevision, u->usage_num);
			return -ENOTSUPP;
		}
	}

	return 0;
}

static int axiom_process_report(struct axiom *ax, u8 *report)
{
	int err;
	struct u34_report_header *u34_report =
		(struct u34_report_header *)report;
	u16 crc_calc;
	u16 crc_report;
	u8 len;

	dev_dbg(ax->dev, "Payload Data %*ph\n", ax->max_report_len, report);

	len = u34_report->report_length << 1;
	if (u34_report->report_length == 0) {
		dev_err(ax->dev, "Zero length report discarded.\n");
		return -EBADMSG;
	}

	// Length is 16 bit words and remove the size of the CRC16 itself
	crc_report = (report[len - 1] << 8) | (report[len - 2]);
	crc_calc = crc16(0, report, (len - 2));

	if (crc_calc != crc_report) {
		dev_err(ax->dev,
			"CRC mismatch! Expected: %04X, Calculated CRC: %04X. Report discarded.\n",
			crc_report, crc_calc);
		return -EBADMSG;
	}

	err = check_revision(ax, u34_report->report_usage);
	if (err)
		return -EBADMSG;

	switch (u34_report->report_usage) {
	case AX_2DCTS_REPORT_ID:
		err = axiom_process_u41_report(ax, u34_report->payload_buf);
		break;

	default:
		break;
	}

	return err;
}

static irqreturn_t axiom_irq(int irq, void *handle)
{
	struct axiom *ax = handle;
	int err;

	/* Read touch reports from u34 */
	err = ax->bus_ops->read(ax->dev, ax->u34_address, ax->max_report_len,
				ax->read_buf);
	if (err)
		goto out;

	err = axiom_process_report(ax, ax->read_buf);
	if (err)
		dev_err(ax->dev, "Failed to process report: %d\n", err);

out:
	return IRQ_HANDLED;
}

struct axiom *axiom_probe(const struct axiom_bus_ops *bus_ops,
			  struct device *dev, int irq)
{
	struct axiom *ax;
	struct input_dev *input_dev;
	int err;

	ax = devm_kzalloc(dev, sizeof(*ax), GFP_KERNEL);
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

	err = axiom_init_dev_info(ax);
	if (err) {
		dev_err(ax->dev, "Failed to read device info, err: %d\n", err);
		return ERR_PTR(err);
	}

	err = axiom_rebaseline(ax);
	if (err)
		return ERR_PTR(err);

	err = devm_request_threaded_irq(ax->dev, ax->irq, NULL, axiom_irq,
					IRQF_TRIGGER_LOW | IRQF_ONESHOT,
					"axiom_irq", ax);
	if (err)
		return ERR_PTR(err);

	err = input_register_device(input_dev);
	if (err) {
		dev_err(ax->dev, "Failed to register input device: %d\n", err);
		return ERR_PTR(err);
	}

	return ax;
}
EXPORT_SYMBOL_GPL(axiom_probe);

MODULE_AUTHOR("TouchNetix <support@touchnetix.com>");
MODULE_DESCRIPTION("aXiom touchscreen core logic");
MODULE_LICENSE("GPL");
MODULE_ALIAS("axiom");
MODULE_VERSION("1.0.0");
