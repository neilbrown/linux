/*   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   Copyright (C) 2009-2016 John Crispin <blogic@openwrt.org>
 *   Copyright (C) 2009-2016 Felix Fietkau <nbd@openwrt.org>
 *   Copyright (C) 2013-2016 Michael Lee <igvtee@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_gpio.h>
#include <linux/clk.h>
#include <linux/mfd/syscon.h>
#include <linux/regulator/consumer.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>

#include "ra_eth_soc.h"
#include "gsw_mt7620.h"

void mtk_switch_w32(struct mt7620_gsw *gsw, u32 val, unsigned reg)
{
	iowrite32(val, gsw->base + reg);
}

u32 mtk_switch_r32(struct mt7620_gsw *gsw, unsigned reg)
{
	return ioread32(gsw->base + reg);
}

void mtk_switch_m32(struct mt7620_gsw *gsw, u32 mask, u32 set, unsigned reg)
{
	u32 val = ioread32(gsw->base + reg);

	val &= mask;
	val |= set;

	iowrite32(val, gsw->base + reg);
}

static irqreturn_t gsw_interrupt_mt7623(int irq, void *_eth)
{
	struct mtk_eth *eth = (struct mtk_eth *)_eth;
	struct mt7620_gsw *gsw = (struct mt7620_gsw *)eth->sw_priv;
	u32 reg, i;

	reg = mt7530_mdio_r32(gsw, MT7530_SYS_INT_STS);

	for (i = 0; i < 5; i++) {
		unsigned int link;

		if ((reg & BIT(i)) == 0)
			continue;

		link = mt7530_mdio_r32(gsw, MT7530_PMSR_P(i)) & 0x1;

		if (link == eth->link[i])
			continue;

		eth->link[i] = link;
		if (link)
			dev_info(gsw->dev, "port %d link up\n", i);
		else
			dev_info(gsw->dev, "port %d link down\n", i);
	}

	mt7530_mdio_w32(gsw, MT7530_SYS_INT_STS, 0x1f);

	return IRQ_HANDLED;
}

static void mt7623_hw_init(struct mtk_eth *eth, struct mt7620_gsw *gsw,
			   struct device_node *np)
{
	u32 i;
	u32 val, reg;
	u32 xtal_mode;

	regmap_update_bits(gsw->ethsys, ETHSYS_CLKCFG0,
			   ETHSYS_TRGMII_CLK_SEL362_5,
			   ETHSYS_TRGMII_CLK_SEL362_5);

	/* reset the TRGMII core */
	mtk_switch_m32(gsw, 0, INTF_MODE_TRGMII, GSW_INTF_MODE);
	mtk_switch_m32(gsw, 0, TRGMII_RCK_CTRL_RX_RST, GSW_TRGMII_RCK_CTRL);

	/* Hardware reset Switch */
	mtk_reset(eth, RST_CTRL_MCM);

	/* Wait for Switch Reset Completed*/
	for (i = 0; i < 100; i++) {
		mdelay(10);
		if (mt7530_mdio_r32(gsw, MT7530_HWTRAP))
			break;
	}

	/* turn off all PHYs */
	for (i = 0; i <= 4; i++) {
		val = _mt7620_mii_read(gsw, i, 0x0);
		val |= BIT(11);
		_mt7620_mii_write(gsw, i, 0x0, val);
	}

	/* reset the switch */
	mt7530_mdio_w32(gsw, MT7530_SYS_CTRL,
			SYS_CTRL_SW_RST | SYS_CTRL_REG_RST);
	udelay(100);

	/* GE1, Force 1000M/FD, FC ON */
	mtk_switch_w32(gsw, MAC_MCR_FIXED_LINK_FC, MTK_MAC_P1_MCR);
	mt7530_mdio_w32(gsw, MT7530_PMCR_P(6), PMCR_FIXED_LINK_FC);

	/* GE2, Force 1000M/FD, FC ON */
	mtk_switch_w32(gsw, MAC_MCR_FIXED_LINK_FC, MTK_MAC_P2_MCR);
	mt7530_mdio_w32(gsw, MT7530_PMCR_P(5), PMCR_FIXED_LINK_FC);

	regmap_read(gsw->ethsys, ETHSYS_SYSCFG0, &reg);
	/* clear the GE2_MODE bits, setting the port to RGMII */
	reg &= ~(0x3 << 14);
	/* clear the GE1_MODE bits, setting the port to RGMII */
	reg &= ~(0x3 << 12);
	regmap_write(gsw->ethsys, ETHSYS_SYSCFG0, reg);

	/* Enable Port 6, P5 as GMAC5, P5 disable */
	val = mt7530_mdio_r32(gsw, MT7530_MHWTRAP);
	/* Enable Port 6 */
	val &= ~MHWTRAP_P6_DIS;
	/* Enable Port 5 */
	val &= ~MHWTRAP_P5_DIS;
	/* Port 5 as GMAC */
	val |= MHWTRAP_P5_MAC_SEL;
	/* Port 5 Interface mode */
	val |= MHWTRAP_P5_RGMII_MODE;
	/* Set MT7530 phy direct access mode**/
	val &= ~MHWTRAP_PHY_ACCESS;
	/* manual override of HW-Trap */
	val |= MHWTRAP_MANUAL;
	mt7530_mdio_w32(gsw, MT7530_MHWTRAP, val);

	xtal_mode = mt7530_mdio_r32(gsw, MT7530_HWTRAP);
	xtal_mode >>= HWTRAP_XTAL_SHIFT;
	xtal_mode &= HWTRAP_XTAL_MASK;
	if (xtal_mode == MT7623_XTAL_40) {
		/* disable MT7530 core clock */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x410);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
		_mt7620_mii_write(gsw, 0, 14, 0x0);

		/* disable MT7530 PLL */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x40d);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
		_mt7620_mii_write(gsw, 0, 14, 0x2020);

		/* for MT7530 core clock = 500Mhz */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x40e);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
		_mt7620_mii_write(gsw, 0, 14, 0x119);

		/* enable MT7530 PLL */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x40d);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
		_mt7620_mii_write(gsw, 0, 14, 0x2820);

		udelay(20);

		/* enable MT7530 core clock */
		_mt7620_mii_write(gsw, 0, 13, 0x1f);
		_mt7620_mii_write(gsw, 0, 14, 0x410);
		_mt7620_mii_write(gsw, 0, 13, 0x401f);
	}

	/* RGMII */
	_mt7620_mii_write(gsw, 0, 14, 0x1);

	/* set MT7530 central align */
	mt7530_mdio_m32(gsw, ~BIT(0), BIT(1), MT7530_P6ECR);
	mt7530_mdio_m32(gsw, ~BIT(30), 0, MT7530_TRGMII_TXCTRL);
	mt7530_mdio_w32(gsw, MT7530_TRGMII_TCK_CTRL, 0x855);

	/* delay setting for 10/1000M */
	mt7530_mdio_w32(gsw, MT7530_P5RGMIIRXCR, 0x104);
	mt7530_mdio_w32(gsw, MT7530_P5RGMIITXCR, 0x10);

	/* lower Tx Driving */
	mt7530_mdio_w32(gsw, MT7530_TRGMII_TD0_ODT, 0x88);
	mt7530_mdio_w32(gsw, MT7530_TRGMII_TD1_ODT, 0x88);
	mt7530_mdio_w32(gsw, MT7530_TRGMII_TD2_ODT, 0x88);
	mt7530_mdio_w32(gsw, MT7530_TRGMII_TD3_ODT, 0x88);
	mt7530_mdio_w32(gsw, MT7530_TRGMII_TD4_ODT, 0x88);
	mt7530_mdio_w32(gsw, MT7530_TRGMII_TD5_ODT, 0x88);
	mt7530_mdio_w32(gsw, MT7530_IO_DRV_CR, 0x11);

	/* Set MT7623/MT7683 TX Driving */
	mtk_switch_w32(gsw, 0x88, GSW_TRGMII_TD0_ODT);
	mtk_switch_w32(gsw, 0x88, GSW_TRGMII_TD0_ODT);
	mtk_switch_w32(gsw, 0x88, GSW_TRGMII_TD0_ODT);
	mtk_switch_w32(gsw, 0x88, GSW_TRGMII_TD0_ODT);
	mtk_switch_w32(gsw, 0x88, GSW_TRGMII_TXCTL_ODT);
	mtk_switch_w32(gsw, 0x88, GSW_TRGMII_TCK_ODT);

	/* disable EEE */
	for (i = 0; i <= 4; i++) {
		_mt7620_mii_write(gsw, i, 13, 0x7);
		_mt7620_mii_write(gsw, i, 14, 0x3C);
		_mt7620_mii_write(gsw, i, 13, 0x4007);
		_mt7620_mii_write(gsw, i, 14, 0x0);

		/* Increase SlvDPSready time */
		_mt7620_mii_write(gsw, i, 31, 0x52b5);
		_mt7620_mii_write(gsw, i, 16, 0xafae);
		_mt7620_mii_write(gsw, i, 18, 0x2f);
		_mt7620_mii_write(gsw, i, 16, 0x8fae);

		/* Incease post_update_timer */
		_mt7620_mii_write(gsw, i, 31, 0x3);
		_mt7620_mii_write(gsw, i, 17, 0x4b);

		/* Adjust 100_mse_threshold */
		_mt7620_mii_write(gsw, i, 13, 0x1e);
		_mt7620_mii_write(gsw, i, 14, 0x123);
		_mt7620_mii_write(gsw, i, 13, 0x401e);
		_mt7620_mii_write(gsw, i, 14, 0xffff);

		/* Disable mcc */
		_mt7620_mii_write(gsw, i, 13, 0x1e);
		_mt7620_mii_write(gsw, i, 14, 0xa6);
		_mt7620_mii_write(gsw, i, 13, 0x401e);
		_mt7620_mii_write(gsw, i, 14, 0x300);

		/* Disable HW auto downshift*/
		_mt7620_mii_write(gsw, i, 31, 0x1);
		val = _mt7620_mii_read(gsw, i, 0x14);
		val &= ~BIT(4);
		_mt7620_mii_write(gsw, i, 0x14, val);
	}

	/* turn on all PHYs */
	for (i = 0; i <= 4; i++) {
		val = _mt7620_mii_read(gsw, i, 0);
		val &= ~BIT(11);
		_mt7620_mii_write(gsw, i, 0, val);
	}

	/* enable irq */
	mt7530_mdio_m32(gsw, 0, TOP_SIG_CTRL_NORMAL, MT7530_TOP_SIG_CTRL);
}

static const struct of_device_id mediatek_gsw_match[] = {
	{ .compatible = "mediatek,mt7623-gsw" },
	{},
};
MODULE_DEVICE_TABLE(of, mediatek_gsw_match);

int mtk_gsw_init(struct mtk_eth *eth)
{
	struct device_node *np = eth->switch_np;
	struct platform_device *pdev = of_find_device_by_node(np);
	struct mt7620_gsw *gsw;

	if (!pdev)
		return -ENODEV;

	if (!of_device_is_compatible(np, mediatek_gsw_match->compatible))
		return -EINVAL;

	gsw = platform_get_drvdata(pdev);
	if (!gsw)
		return -ENODEV;
	eth->sw_priv = gsw;

	mt7623_hw_init(eth, gsw, np);

	request_threaded_irq(gsw->irq, gsw_interrupt_mt7623, NULL, 0,
			     "gsw", eth);
	mt7530_mdio_w32(gsw, MT7530_SYS_INT_EN, 0x1f);

	return 0;
}

static int mt7623_gsw_probe(struct platform_device *pdev)
{
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct device_node *np = pdev->dev.of_node;
	struct device_node *pctl;
	int reset_pin, ret;
	struct mt7620_gsw *gsw;
	struct regulator *supply;

	gsw = devm_kzalloc(&pdev->dev, sizeof(struct mt7620_gsw), GFP_KERNEL);
	if (!gsw)
		return -ENOMEM;

	gsw->dev = &pdev->dev;
	gsw->irq = irq_of_parse_and_map(np, 0);
	if (gsw->irq < 0)
		return -EINVAL;

	gsw->base = devm_ioremap_resource(&pdev->dev, res);
	if (!gsw->base)
		return -EADDRNOTAVAIL;

	gsw->ethsys = syscon_regmap_lookup_by_phandle(np, "mediatek,ethsys");
	if (IS_ERR(gsw->ethsys))
		return PTR_ERR(gsw->ethsys);

	reset_pin = of_get_named_gpio(np, "mediatek,reset-pin", 0);
	if (reset_pin < 0)
		return reset_pin;

	pctl = of_parse_phandle(np, "mediatek,pctl-regmap", 0);
	if (IS_ERR(pctl))
		return PTR_ERR(pctl);

	gsw->pctl = syscon_node_to_regmap(pctl);
	if (IS_ERR(pctl))
		return PTR_ERR(pctl);

	ret = devm_gpio_request(&pdev->dev, reset_pin, "mt7530-reset");
	if (ret)
		return ret;

	gsw->clk_gsw = devm_clk_get(&pdev->dev, "esw");
	gsw->clk_gp1 = devm_clk_get(&pdev->dev, "gp1");
	gsw->clk_gp2 = devm_clk_get(&pdev->dev, "gp2");
	gsw->clk_trgpll = devm_clk_get(&pdev->dev, "trgpll");

	if (IS_ERR(gsw->clk_gsw) || IS_ERR(gsw->clk_gp1) ||
	    IS_ERR(gsw->clk_gp2) || IS_ERR(gsw->clk_trgpll))
		return -ENODEV;

	supply = devm_regulator_get(&pdev->dev, "mt7530");
	if (IS_ERR(supply))
		return PTR_ERR(supply);

	regulator_set_voltage(supply, 1000000, 1000000);
	ret = regulator_enable(supply);
	if (ret) {
		dev_err(&pdev->dev, "Failed to enable reg-7530: %d\n", ret);
		return ret;
	}
	pm_runtime_enable(&pdev->dev);
	pm_runtime_get_sync(&pdev->dev);

	ret = clk_set_rate(gsw->clk_trgpll, 500000000);
	if (ret)
		return ret;

	clk_prepare_enable(gsw->clk_gsw);
	clk_prepare_enable(gsw->clk_gp1);
	clk_prepare_enable(gsw->clk_gp2);
	clk_prepare_enable(gsw->clk_trgpll);

	gpio_direction_output(reset_pin, 0);
	udelay(1000);
	gpio_set_value(reset_pin, 1);
	mdelay(100);

	/* Set GE2 driving and slew rate */
	regmap_write(gsw->pctl, GPIO_DRV_SEL10, 0xa00);

	/* set GE2 TDSEL */
	regmap_write(gsw->pctl, GPIO_OD33_CTRL8, 0x5);

	/* set GE2 TUNE */
	regmap_write(gsw->pctl, GPIO_BIAS_CTRL, 0x0);

	platform_set_drvdata(pdev, gsw);

	return 0;
}

static int mt7623_gsw_remove(struct platform_device *pdev)
{
	struct mt7620_gsw *gsw = platform_get_drvdata(pdev);

	clk_disable_unprepare(gsw->clk_gsw);
	clk_disable_unprepare(gsw->clk_gp1);
	clk_disable_unprepare(gsw->clk_gp2);
	clk_disable_unprepare(gsw->clk_trgpll);

	pm_runtime_put_sync(&pdev->dev);
	pm_runtime_disable(&pdev->dev);

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static struct platform_driver gsw_driver = {
	.probe = mt7623_gsw_probe,
	.remove = mt7623_gsw_remove,
	.driver = {
		.name = "mt7623-gsw",
		.owner = THIS_MODULE,
		.of_match_table = mediatek_gsw_match,
	},
};

module_platform_driver(gsw_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Crispin <blogic@openwrt.org>");
MODULE_DESCRIPTION("GBit switch driver for Mediatek MT7623 SoC");
