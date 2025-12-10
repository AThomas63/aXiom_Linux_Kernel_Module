// SPDX-License-Identifier: GPL-2.0
/*
 * TouchNetix aXiom Touchscreen Driver
 *
 * Copyright (C) 2018-2023 TouchNetix Ltd.
 *
 * Author(s): Mark Satterthwaite <mark.satterthwaite@touchnetix.com>
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
#include <linux/kobject.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pm.h>
#include <linux/spi/spi.h>
#include <linux/string.h>
#include <linux/version.h>
#include "axiom_core_new.h"

#define SPI_DATA_SIZE 		128 // TODO determine best length here
#define SPI_PADDING_LEN 	32

static bool poll_enable;
module_param(poll_enable, bool, 0444);
MODULE_PARM_DESC(poll_enable, "Enable polling mode [default 0=no]");

static int poll_interval;
module_param(poll_interval, int, 0444);
MODULE_PARM_DESC(poll_interval, "Polling period in ms [default = 100]");

enum spi_op_e {
	AX_SPI_WR_OP,
	AX_SPI_RD_OP
};

static int axiom_spi_read_block_data(struct device *dev, u8 *xfer_buf,
				      u16 addr, u16 length, void *values)
{
	int retval;
	struct spi_device *spi = to_spi_device(dev);
	struct spi_transfer xfr_header;
	struct spi_transfer xfr_padding;
	struct spi_transfer xfr_payload;
	struct spi_message msg;
	struct axiom_cmd_header cmd_header = {
		.target_address = addr,
		.length = length,
		.read = 1
	};
	u8 pad_buf[SPI_PADDING_LEN] = {0};

	memset(&xfr_header,  0, sizeof(xfr_header));
	memset(&xfr_padding, 0, sizeof(xfr_padding));
	memset(&xfr_payload, 0, sizeof(xfr_payload));

	/* Setup the SPI transfer operations */
	xfr_header.tx_buf = &cmd_header;
	xfr_header.len    = sizeof(cmd_header);

	xfr_padding.tx_buf = pad_buf;
	xfr_padding.len    = sizeof(pad_buf);

	xfr_payload.rx_buf = values;
	xfr_payload.len    = length;

	spi_message_init(&msg);
	spi_message_add_tail(&xfr_header, &msg);
	spi_message_add_tail(&xfr_padding, &msg);
	spi_message_add_tail(&xfr_payload, &msg);

	retval = spi_sync(spi, &msg);
	if (retval < 0) {
		dev_err(&spi->dev, "Failed to SPI transfer, error: %d\n", retval);
		return 0;
	}

	// udelay(data->data_core.bus_holdoff_delay_us);
	udelay(250);

	dev_dbg(&spi->dev, "SPI Header (%lu bytes): %*ph\n", sizeof(cmd_header), (int)sizeof(cmd_header), &cmd_header);
	dev_dbg(&spi->dev, "SPI Padding (%lu bytes): %*ph\n", sizeof(pad_buf), (int)sizeof(pad_buf), pad_buf);
	dev_dbg(&spi->dev, "SPI Payload (%u bytes): %*ph\n", length, length, values);

	return 0;
}

static int axiom_spi_write_block_data(struct device *dev, u8 *xfer_buf,
				       u16 addr, u16 length, void *values)
{
	int retval;
	struct spi_device *spi = to_spi_device(dev);
	struct spi_transfer xfr_header;
	struct spi_transfer xfr_padding;
	struct spi_transfer xfr_payload;
	struct spi_message msg;
	struct axiom_cmd_header cmd_header = {
		.target_address = addr,
		.length = length,
		.read = 1
	};
	u8 pad_buf[SPI_PADDING_LEN] = {0};

	memset(&xfr_header,  0, sizeof(xfr_header));
	memset(&xfr_padding, 0, sizeof(xfr_padding));
	memset(&xfr_payload, 0, sizeof(xfr_payload));

	/* Setup the SPI transfer operations */
	xfr_header.tx_buf = &cmd_header;
	xfr_header.len    = sizeof(cmd_header);
	
	xfr_padding.tx_buf = pad_buf;
	xfr_padding.len    = sizeof(pad_buf);

	xfr_payload.tx_buf = values;
	xfr_payload.len    = length;

	spi_message_init(&msg);
	spi_message_add_tail(&xfr_header, &msg);
	spi_message_add_tail(&xfr_padding, &msg);
	spi_message_add_tail(&xfr_payload, &msg);

	retval = spi_sync(spi, &msg);
	if (retval < 0) {
		dev_err(&spi->dev, "Failed to SPI transfer, error: %d\n", retval);
		return 0;
	}

	// udelay(data->data_core.bus_holdoff_delay_us);
	udelay(250);
	
	return 0;
}

static int axiom_spi_read_block_data(struct device *dev, u8 *xfer_buf,
				      u16 addr, u16 length, void *values)
{
	
}

static int axiom_spi_write_block_data(struct device *dev, u8 *xfer_buf,
				       u16 addr, u16 length, void *values)
{

}
static const struct axiom_bus_ops axiom_spi_bus_ops = {
	.bustype	= BUS_SPI,
	.write		= axiom_spi_write_block_data,
	.read		= axiom_spi_read_block_data,
};

static int axiom_spi_probe(struct spi_device *spi)
{
	struct axiom *axiom;
	int error;

	/* Set up SPI */
	spi->bits_per_word = 8;
	spi->mode = SPI_MODE_0;
	spi->max_speed_hz = 4000000;

	if (spi->irq == 0)
		dev_err(&spi->dev, "No IRQ specified!\n");
	
	error = spi_setup(spi);
	if (error < 0) {
		dev_err(&spi->dev, "%s: SPI setup error %d\n",
			__func__, error);
		return error;
	}
	axiom = axiom_probe(&axiom_spi_bus_ops, &spi->dev, spi->irq,
			  SPI_DATA_SIZE * 2);
	
	if (IS_ERR(axiom))
		return PTR_ERR(axiom);

	spi_set_drvdata(spi, axiom);

	return 0;
}

static const struct spi_device_id axiom_spi_id_table[] = {
	{ "axiom" },
	{ },
};
MODULE_DEVICE_TABLE(spi, axiom_spi_id_table);

static const struct of_device_id axiom_spi_dt_ids[] = {
	{
		.compatible = "axiom_spi,axiom",
		.data = "axiom",
	},
	{ }
};
MODULE_DEVICE_TABLE(of, axiom_spi_dt_ids);

static struct spi_driver axiom_spi_driver = {
	.id_table = axiom_spi_id_table,
	.driver = {
		.name = "axiom_spi",
		.of_match_table = of_match_ptr(axiom_spi_dt_ids),
	},
	.probe = axiom_spi_probe,
	// .remove = axiom_spi_remove,
};

module_spi_driver(axiom_spi_driver);

MODULE_AUTHOR("TouchNetix <support@touchnetix.com>");
MODULE_DESCRIPTION("aXiom touchscreen SPI bus driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("axiom");
MODULE_VERSION("1.0.0");
