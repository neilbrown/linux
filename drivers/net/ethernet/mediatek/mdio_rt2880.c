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
#include <linux/of_net.h>
#include <linux/of_mdio.h>

#include "ra_eth_soc.h"
#include "mdio_rt2880.h"
#include "mdio.h"

#define MTK_MDIO_RETRY	1000

static unsigned char *rt2880_speed_str(struct mtk_eth *eth)
{
	switch (eth->phy->speed[0]) {
	case SPEED_1000:
		return "1000";
	case SPEED_100:
		return "100";
	case SPEED_10:
		return "10";
	}

	return "?";
}

void rt2880_mdio_link_adjust(struct mtk_eth *eth, int port)
{
	u32 mdio_cfg;

	if (!eth->link[0]) {
		netif_carrier_off(*eth->netdev);
		netdev_info(*eth->netdev, "link down\n");
		return;
	}

	mdio_cfg = MTK_MDIO_CFG_TX_CLK_SKEW_200 |
		   MTK_MDIO_CFG_RX_CLK_SKEW_200 |
		   MTK_MDIO_CFG_GP1_FRC_EN;

	if (eth->phy->duplex[0] == DUPLEX_FULL)
		mdio_cfg |= MTK_MDIO_CFG_GP1_DUPLEX;

	if (eth->phy->tx_fc[0])
		mdio_cfg |= MTK_MDIO_CFG_GP1_FC_TX;

	if (eth->phy->rx_fc[0])
		mdio_cfg |= MTK_MDIO_CFG_GP1_FC_RX;

	switch (eth->phy->speed[0]) {
	case SPEED_10:
		mdio_cfg |= MTK_MDIO_CFG_GP1_SPEED_10;
		break;
	case SPEED_100:
		mdio_cfg |= MTK_MDIO_CFG_GP1_SPEED_100;
		break;
	case SPEED_1000:
		mdio_cfg |= MTK_MDIO_CFG_GP1_SPEED_1000;
		break;
	default:
		netdev_err(*eth->netdev, "unknown link speed\n");
		return;
	}

	mtk_w32(eth, mdio_cfg, MTK_MDIO_CFG);

	netif_carrier_on(*eth->netdev);
	netdev_info(*eth->netdev, "link up (%sMbps/%s duplex)\n",
		    rt2880_speed_str(eth),
		    (eth->phy->duplex[0] == DUPLEX_FULL) ? "Full" : "Half");
}

static int rt2880_mdio_wait_ready(struct mtk_eth *eth)
{
	int retries;

	retries = MTK_MDIO_RETRY;
	while (1) {
		u32 t;

		t = mtk_r32(eth, MTK_MDIO_ACCESS);
		if ((t & BIT(31)) == 0)
			return 0;

		if (retries-- == 0)
			break;

		udelay(1);
	}

	dev_err(eth->dev, "MDIO operation timed out\n");
	return -ETIMEDOUT;
}

int rt2880_mdio_read(struct mii_bus *bus, int phy_addr, int phy_reg)
{
	struct mtk_eth *eth = bus->priv;
	int err;
	u32 t;

	err = rt2880_mdio_wait_ready(eth);
	if (err)
		return 0xffff;

	t = (phy_addr << 24) | (phy_reg << 16);
	mtk_w32(eth, t, MTK_MDIO_ACCESS);
	t |= BIT(31);
	mtk_w32(eth, t, MTK_MDIO_ACCESS);

	err = rt2880_mdio_wait_ready(eth);
	if (err)
		return 0xffff;

	pr_debug("%s: addr=%04x, reg=%04x, value=%04x\n", __func__,
		 phy_addr, phy_reg, mtk_r32(eth, MTK_MDIO_ACCESS) & 0xffff);

	return mtk_r32(eth, MTK_MDIO_ACCESS) & 0xffff;
}

int rt2880_mdio_write(struct mii_bus *bus, int phy_addr, int phy_reg, u16 val)
{
	struct mtk_eth *eth = bus->priv;
	int err;
	u32 t;

	pr_debug("%s: addr=%04x, reg=%04x, value=%04x\n", __func__,
		 phy_addr, phy_reg, mtk_r32(eth, MTK_MDIO_ACCESS) & 0xffff);

	err = rt2880_mdio_wait_ready(eth);
	if (err)
		return err;

	t = (1 << 30) | (phy_addr << 24) | (phy_reg << 16) | val;
	mtk_w32(eth, t, MTK_MDIO_ACCESS);
	t |= BIT(31);
	mtk_w32(eth, t, MTK_MDIO_ACCESS);

	return rt2880_mdio_wait_ready(eth);
}

void rt2880_port_init(struct mtk_eth *eth, struct mtk_mac *mac,
		      struct device_node *np)
{
	const __be32 *id = of_get_property(np, "reg", NULL);
	const __be32 *link;
	int size;
	int phy_mode;

	if (!id || (be32_to_cpu(*id) != 0)) {
		pr_err("%s: invalid port id\n", np->name);
		return;
	}

	eth->phy->phy_fixed[0] = of_get_property(np,
						  "mediatek,fixed-link", &size);
	if (eth->phy->phy_fixed[0] &&
	    (size != (4 * sizeof(*eth->phy->phy_fixed[0])))) {
		pr_err("%s: invalid fixed link property\n", np->name);
		eth->phy->phy_fixed[0] = NULL;
		return;
	}

	phy_mode = of_get_phy_mode(np);
	switch (phy_mode) {
	case PHY_INTERFACE_MODE_RGMII:
		break;
	case PHY_INTERFACE_MODE_MII:
		break;
	case PHY_INTERFACE_MODE_RMII:
		break;
	default:
		if (!eth->phy->phy_fixed[0])
			dev_err(eth->dev, "port %d - invalid phy mode\n",
				eth->phy->speed[0]);
		break;
	}

	eth->phy->phy_node[0] = of_parse_phandle(np, "phy-handle", 0);
	if (!eth->phy->phy_node[0] && !eth->phy->phy_fixed[0])
		return;

	if (eth->phy->phy_fixed[0]) {
		link = eth->phy->phy_fixed[0];
		eth->phy->speed[0] = be32_to_cpup(link++);
		eth->phy->duplex[0] = be32_to_cpup(link++);
		eth->phy->tx_fc[0] = be32_to_cpup(link++);
		eth->phy->rx_fc[0] = be32_to_cpup(link++);

		eth->link[0] = 1;
		switch (eth->phy->speed[0]) {
		case SPEED_10:
			break;
		case SPEED_100:
			break;
		case SPEED_1000:
			break;
		default:
			dev_err(eth->dev, "invalid link speed: %d\n",
				eth->phy->speed[0]);
			eth->phy->phy_fixed[0] = 0;
			return;
		}
		dev_info(eth->dev, "using fixed link parameters\n");
		rt2880_mdio_link_adjust(eth, 0);
		return;
	}

	if (eth->phy->phy_node[0] && eth->mii_bus->phy_map[0])
		mtk_connect_phy_node(eth, mac, eth->phy->phy_node[0]);
}
