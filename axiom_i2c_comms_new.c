// SPDX-License-Identifier: GPL-2.0
/*
 * TouchNetix aXiom Touchscreen Driver
 *
 * Copyright (C) 2020-2023 TouchNetix Ltd.
 *
 * Author(s): Bart Prescott <bartp@baasheep.co.uk>
 *            Pedro Torruella <pedro.torruella@touchnetix.com>
 *            Mark Satterthwaite <mark.satterthwaite@touchnetix.com>
 *            Hannah Rossiter <hannah.rossiter@touchnetix.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#define DEBUG   // Enable debug messages

// TODO removed unneeded headers
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kobject.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pm.h>
#include <linux/i2c.h>
#include <linux/string.h>
#include "axiom_core_new.h"


#define I2C_DATA_SIZE 		128 // TODO determine best length here


static bool poll_enable;
module_param(poll_enable, bool, 0444);
MODULE_PARM_DESC(poll_enable, "Enable polling mode [default 0=no]");

static int poll_interval;
module_param(poll_interval, int, 0444);
MODULE_PARM_DESC(poll_interval, "Polling period in ms [default = 100]");

static int axiom_i2c_read_block_data(struct device *dev, u8 *xfer_buf,
				      u16 addr, u16 length, void *values)
{	
	int retval;
	struct i2c_client *client = to_i2c_client(dev);
	struct AxiomCmdHeader cmdHeader = {
		.target_address = addr,
		.length = length,
		.read = 1
	};

	struct i2c_msg msgs[] = {
		{
			.addr = client->addr,
			.flags = 0,
			.len = sizeof(cmdHeader),
			.buf = (u8 *)&cmdHeader,
		},
		{
			.addr = client->addr,
			.flags = I2C_M_RD,
			.len = length,
			.buf = values,
		},
	};

	retval = i2c_transfer(client->adapter, msgs, ARRAY_SIZE(msgs));
	if (retval < 0)
		return retval;

	for (int i = 0; i < 2; i++) {
		pr_debug("I2C msg[%d] buf (len %u): ", i, msgs[i].len);
		for (int j = 0; j < msgs[i].len; j++)
			pr_cont("%02x", ((u8 *)msgs[i].buf)[j]);
		pr_cont("\n");
	}
	dev_dbg(dev, "I2C Response (%u bytes): %*ph\n", length, length, values);

	return retval != ARRAY_SIZE(msgs) ? -EIO : 0;
}

static int axiom_i2c_write_block_data(struct device *dev, u8 *xfer_buf,
				       u16 addr, u16 length, const void *values)
{
	struct i2c_client *client = to_i2c_client(dev);
	u8 client_addr = client->addr | ((addr >> 8) & 0x1);
	u8 addr_lo = addr & 0xFF;
	struct i2c_msg msgs[] = {
		{
			.addr = client_addr,
			.flags = 0,
			.len = length + 1,
			.buf = xfer_buf,
		},
	};
	int retval;

	xfer_buf[0] = addr_lo;
	memcpy(&xfer_buf[1], values, length);

	retval = i2c_transfer(client->adapter, msgs, ARRAY_SIZE(msgs));
	if (retval < 0)
		return retval;

	return retval != ARRAY_SIZE(msgs) ? -EIO : 0;
}

static const struct axiom_bus_ops axiom_i2c_bus_ops = {
	.bustype	= BUS_I2C,
	.write		= axiom_i2c_write_block_data,
	.read		= axiom_i2c_read_block_data,
};

static int axiom_i2c_probe(struct i2c_client *client)
{
	struct axiom *axiom;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "I2C functionality not Supported\n");
		return -EIO;
	}

	axiom = axiom_probe(&axiom_i2c_bus_ops, &client->dev, client->irq,
			  I2C_DATA_SIZE);
	
	if (IS_ERR(axiom))
		return PTR_ERR(axiom);

	i2c_set_clientdata(client, axiom);

	return 0;
}


static const struct i2c_device_id axiom_i2c_id_table[] = {
	{ "axiom" },
	{ },
};
MODULE_DEVICE_TABLE(i2c, axiom_i2c_id_table);

static const struct of_device_id axiom_i2c_dt_ids[] = {
	{
		.compatible = "axiom_i2c,axiom",
		.data = "axiom",
	},
	{ }
};
MODULE_DEVICE_TABLE(of, axiom_i2c_dt_ids);

static struct i2c_driver axiom_i2c_driver = {
	.driver = {
		.name = "axiom_i2c",
		.of_match_table = of_match_ptr(axiom_i2c_dt_ids),
	},
	.id_table = axiom_i2c_id_table,
	.probe = axiom_i2c_probe,
	// .remove = axiom_i2c_remove,
};

module_i2c_driver(axiom_i2c_driver);

MODULE_AUTHOR("TouchNetix <support@touchnetix.com>");
MODULE_DESCRIPTION("aXiom touchscreen I2C bus driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("axiom");
MODULE_VERSION("1.0.0");
