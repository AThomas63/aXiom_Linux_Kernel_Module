// SPDX-License-Identifier: GPL-2.0
/*
 * TouchNetix aXiom Touchscreen Driver
 *
 * Copyright (C) 2020-2026 TouchNetix Ltd.
 *
 * Author(s): Mark Satterthwaite <mark.satterthwaite@touchnetix.com>
 *            Pedro Torruella <pedro.torruella@touchnetix.com>
 *            Bart Prescott <bartp@baasheep.co.uk>
 *            Hannah Rossiter <hannah.rossiter@touchnetix.com>
 *            Andrew Thomas <andrew.thomas@touchnetix.com>
 */

#include <linux/of.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/spi/spi.h>
#include <linux/input.h>
#include <linux/unaligned.h>
#include "axiom_core.h"

#define SPI_PADDING_LEN (32)

static int axiom_spi_transfer(struct device *dev, enum ax_comms_op_e op,
			      u16 addr, u16 length, void *values)
{
	struct spi_device *spi = to_spi_device(dev);
	struct spi_transfer xfr_header;
	struct spi_transfer xfr_padding;
	struct spi_transfer xfr_payload;
	struct spi_message msg;
	struct axiom_cmd_header cmd_header;
	u8 pad_buf[SPI_PADDING_LEN] = { 0 };
	int err;
	
	put_unaligned_le16(addr, &cmd_header.target_address);
	len_op = (length & 0x7FFF) | (AX_RD_OP << 15);
	put_unaligned_le16(len_op, &cmd_header.length_and_op);

	memset(&xfr_header, 0, sizeof(xfr_header));
	memset(&xfr_padding, 0, sizeof(xfr_padding));
	memset(&xfr_payload, 0, sizeof(xfr_payload));

	/* Setup the SPI transfer operations */
	xfr_header.tx_buf = &cmd_header;
	xfr_header.len = sizeof(cmd_header);

	xfr_padding.tx_buf = pad_buf;
	xfr_padding.len = sizeof(pad_buf);

	switch (op) {
	case AX_WR_OP:
		xfr_payload.tx_buf = values;
		break;
	case AX_RD_OP:
		xfr_payload.rx_buf = values;
		break;
	default:
		dev_err(dev, "%s: invalid operation: %d\n", __func__, op);
		return -EINVAL;
	}
	xfr_payload.len = length;

	spi_message_init(&msg);
	spi_message_add_tail(&xfr_header, &msg);
	spi_message_add_tail(&xfr_padding, &msg);
	spi_message_add_tail(&xfr_payload, &msg);

	err = spi_sync(spi, &msg);
	if (err < 0) {
		dev_err(&spi->dev, "Failed to SPI transfer, error: %d\n", err);
		return err;
	}

	udelay(AXIOM_HOLDOFF_DELAY_US);

	return 0;
}

static int axiom_spi_read_block_data(struct device *dev, u16 addr, u16 length,
				     void *values)
{
	return axiom_spi_transfer(dev, AX_RD_OP, addr, length, values);
}

static int axiom_spi_write_block_data(struct device *dev, u16 addr, u16 length,
				      void *values)
{
	return axiom_spi_transfer(dev, AX_WR_OP, addr, length, values);
}

static const struct axiom_bus_ops axiom_spi_bus_ops = {
	.bustype = BUS_SPI,
	.write = axiom_spi_write_block_data,
	.read = axiom_spi_read_block_data,
};

static int axiom_spi_probe(struct spi_device *spi)
{
	struct axiom *axiom;
	int err;

	/* Set up SPI */
	spi->bits_per_word = 8;
	spi->mode = SPI_MODE_0;
	spi->max_speed_hz = 4000000;

	if (spi->irq == 0)
		dev_err(&spi->dev, "No IRQ specified!\n");

	err = spi_setup(spi);
	if (err < 0) {
		dev_err(&spi->dev, "%s: SPI setup error %d\n", __func__, err);
		return err;
	}
	axiom = axiom_probe(&axiom_spi_bus_ops, &spi->dev, spi->irq);
	if (IS_ERR(axiom))
		return dev_err_probe(&spi->dev, PTR_ERR(axiom),
				     "failed to register input device\n");

	return 0;
}

static const struct spi_device_id axiom_spi_id_table[] = {
	{ "axiom-spi" },
	{},
};
MODULE_DEVICE_TABLE(spi, axiom_spi_id_table);

static const struct of_device_id axiom_spi_dt_ids[] = {
	{
		.compatible = "tnx,axiom-spi",
		.data = "axiom",
	},
	{}
};
MODULE_DEVICE_TABLE(of, axiom_spi_dt_ids);

static struct spi_driver axiom_spi_driver = {
	.id_table = axiom_spi_id_table,
	.driver = {
		.name = "axiom_spi",
		.of_match_table = axiom_spi_dt_ids,
	},
	.probe = axiom_spi_probe,
};

module_spi_driver(axiom_spi_driver);

MODULE_AUTHOR("TouchNetix <support@touchnetix.com>");
MODULE_DESCRIPTION("aXiom touchscreen SPI bus driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
