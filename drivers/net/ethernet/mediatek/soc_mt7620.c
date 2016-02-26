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
#include <linux/platform_device.h>
#include <linux/if_vlan.h>
#include <linux/of_net.h>

#include <asm/mach-ralink/ralink_regs.h>

#include <mt7620.h>
#include "ra_eth_soc.h"
#include "gsw_mt7620.h"
#include "mdio.h"

#define MT7620_CDMA_CSG_CFG	0x400
#define MT7620_DMA_VID		(MT7620_CDMA_CSG_CFG + 0x30)
#define MT7620_RESET_FE		BIT(21)
#define MT7620_RESET_ESW	BIT(23)
#define MT7620_L4_VALID		BIT(23)

#define MT7620_TX_DMA_UDF	BIT(15)
#define TX_DMA_FP_BMAP		((0xff) << 19)

#define CDMA_ICS_EN		BIT(2)
#define CDMA_UCS_EN		BIT(1)
#define CDMA_TCS_EN		BIT(0)

#define GDMA_ICS_EN		BIT(22)
#define GDMA_TCS_EN		BIT(21)
#define GDMA_UCS_EN		BIT(20)
#define	GDMA_FRC_P_MASK		0x07

/* frame engine counters */
#define MT7620_REG_MIB_OFFSET	0x1000
#define MT7620_PPE_AC_BCNT0	(MT7620_REG_MIB_OFFSET + 0x00)
#define MT7620_GDM1_TX_GBCNT	(MT7620_REG_MIB_OFFSET + 0x300)
#define MT7620_GDM2_TX_GBCNT	(MT7620_GDM1_TX_GBCNT + 0x40)

#define GSW_REG_GDMA1_MAC_ADRL	0x508
#define GSW_REG_GDMA1_MAC_ADRH	0x50C

#define MT7620_MTK_RST_GL	0x04
#define MT7620_MTK_INT_STATUS2	0x08

/* MTK_INT_STATUS reg on mt7620 define CNT_GDM1_AF at BIT(29)
 * but after test it should be BIT(13).
 */
#define MT7620_MTK_GDM1_AF	BIT(13)

static const u16 mt7620_reg_table[MTK_REG_COUNT] = {
	[MTK_REG_PDMA_GLO_CFG] = RT5350_PDMA_GLO_CFG,
	[MTK_REG_PDMA_RST_CFG] = RT5350_PDMA_RST_CFG,
	[MTK_REG_DLY_INT_CFG] = RT5350_DLY_INT_CFG,
	[MTK_REG_TX_BASE_PTR0] = RT5350_TX_BASE_PTR0,
	[MTK_REG_TX_MAX_CNT0] = RT5350_TX_MAX_CNT0,
	[MTK_REG_TX_CTX_IDX0] = RT5350_TX_CTX_IDX0,
	[MTK_REG_TX_DTX_IDX0] = RT5350_TX_DTX_IDX0,
	[MTK_REG_RX_BASE_PTR0] = RT5350_RX_BASE_PTR0,
	[MTK_REG_RX_MAX_CNT0] = RT5350_RX_MAX_CNT0,
	[MTK_REG_RX_CALC_IDX0] = RT5350_RX_CALC_IDX0,
	[MTK_REG_RX_DRX_IDX0] = RT5350_RX_DRX_IDX0,
	[MTK_REG_MTK_INT_ENABLE] = RT5350_MTK_INT_ENABLE,
	[MTK_REG_MTK_INT_STATUS] = RT5350_MTK_INT_STATUS,
	[MTK_REG_MTK_DMA_VID_BASE] = MT7620_DMA_VID,
	[MTK_REG_MTK_COUNTER_BASE] = MT7620_GDM1_TX_GBCNT,
	[MTK_REG_MTK_RST_GL] = MT7620_MTK_RST_GL,
	[MTK_REG_MTK_INT_STATUS2] = MT7620_MTK_INT_STATUS2,
};

static void mt7620_set_mac(struct mtk_mac *mac, unsigned char *hwaddr)
{
	struct mt7620_gsw *gsw = (struct mt7620_gsw *)mac->hw->sw_priv;
	unsigned long flags;

	spin_lock_irqsave(&mac->hw->page_lock, flags);
	mtk_switch_w32(gsw, (hwaddr[0] << 8) | hwaddr[1], GSW_REG_SMACCR1);
	mtk_switch_w32(gsw, (hwaddr[2] << 24) | (hwaddr[3] << 16) |
			    (hwaddr[4] << 8) | hwaddr[5],
		       GSW_REG_SMACCR0);
	spin_unlock_irqrestore(&mac->hw->page_lock, flags);
}

/* figure out which is the lowest and highest phy connected and enable
 * autopolling for those phys
 */
static void mt7620_auto_poll(struct mt7620_gsw *gsw)
{
	int phy;
	int lsb = -1, msb = 0;

	for_each_set_bit(phy, &gsw->autopoll, 32) {
		if (lsb < 0)
			lsb = phy;
		msb = phy;
	}

	if (lsb == msb)
		lsb--;

	mtk_switch_w32(gsw, PHY_AN_EN | PHY_PRE_EN | PMY_MDC_CONF(5) |
		(msb << 8) | lsb, MT7620_ESW_PHY_POLLING);
}

static void mt7620_port_init(struct mtk_eth *eth, struct mtk_mac *mac,
			     struct device_node *np)
{
	struct mt7620_gsw *gsw = (struct mt7620_gsw *)eth->sw_priv;
	const __be32 *_id = of_get_property(np, "reg", NULL);
	int phy_mode, size, id;
	int shift = 12;
	u32 val, mask = 0;
	int min = (gsw->port4 == PORT4_EPHY) ? (5) : (4);

	if (!_id || (be32_to_cpu(*_id) < min) || (be32_to_cpu(*_id) > 5)) {
		if (_id)
			pr_err("%s: invalid port id %d\n", np->name,
			       be32_to_cpu(*_id));
		else
			pr_err("%s: invalid port id\n", np->name);
		return;
	}

	id = be32_to_cpu(*_id);

	if (id == 4)
		shift = 14;

	eth->phy->phy_fixed[id] = of_get_property(np, "mediatek,fixed-link",
						   &size);
	if (eth->phy->phy_fixed[id] &&
	    (size != (4 * sizeof(*eth->phy->phy_fixed[id])))) {
		pr_err("%s: invalid fixed link property\n", np->name);
		eth->phy->phy_fixed[id] = NULL;
		return;
	}

	phy_mode = of_get_phy_mode(np);
	switch (phy_mode) {
	case PHY_INTERFACE_MODE_RGMII:
		mask = 0;
		break;
	case PHY_INTERFACE_MODE_MII:
		mask = 1;
		break;
	case PHY_INTERFACE_MODE_RMII:
		mask = 2;
		break;
	default:
		dev_err(eth->dev, "port %d - invalid phy mode\n", id);
		return;
	}

	eth->phy->phy_node[id] = of_parse_phandle(np, "phy-handle", 0);
	if (!eth->phy->phy_node[id] && !eth->phy->phy_fixed[id])
		return;

	val = rt_sysc_r32(SYSC_REG_CFG1);
	val &= ~(3 << shift);
	val |= mask << shift;
	rt_sysc_w32(val, SYSC_REG_CFG1);

	if (eth->phy->phy_fixed[id]) {
		const __be32 *link = eth->phy->phy_fixed[id];
		int tx_fc, rx_fc;
		u32 val = 0;

		eth->phy->speed[id] = be32_to_cpup(link++);
		tx_fc = be32_to_cpup(link++);
		rx_fc = be32_to_cpup(link++);
		eth->phy->duplex[id] = be32_to_cpup(link++);
		eth->link[id] = 1;

		switch (eth->phy->speed[id]) {
		case SPEED_10:
			val = 0;
			break;
		case SPEED_100:
			val = 1;
			break;
		case SPEED_1000:
			val = 2;
			break;
		default:
			dev_err(eth->dev, "invalid link speed: %d\n",
				eth->phy->speed[id]);
			eth->phy->phy_fixed[id] = 0;
			return;
		}
		val = PMCR_SPEED(val);
		val |= PMCR_LINK | PMCR_BACKPRES | PMCR_BACKOFF | PMCR_RX_EN |
			PMCR_TX_EN | PMCR_FORCE | PMCR_MAC_MODE | PMCR_IPG;
		if (tx_fc)
			val |= PMCR_TX_FC;
		if (rx_fc)
			val |= PMCR_RX_FC;
		if (eth->phy->duplex[id])
			val |= PMCR_DUPLEX;
		mtk_switch_w32(gsw, val, GSW_REG_PORT_PMCR(id));
		dev_info(eth->dev, "using fixed link parameters\n");
		return;
	}

	if (eth->phy->phy_node[id] && eth->mii_bus->phy_map[id]) {
		u32 val = PMCR_BACKPRES | PMCR_BACKOFF | PMCR_RX_EN |
			PMCR_TX_EN |  PMCR_MAC_MODE | PMCR_IPG;

		mtk_switch_w32(gsw, val, GSW_REG_PORT_PMCR(id));
		mtk_connect_phy_node(eth, mac, eth->phy->phy_node[id]);
		gsw->autopoll |= BIT(id);
		mt7620_auto_poll(gsw);
		return;
	}
}

static void mt7620_mtk_reset(struct mtk_eth *eth)
{
	mtk_reset(eth, MT7620_RESET_FE | MT7620_RESET_ESW);
}

static int mt7620_fwd_config(struct mtk_eth *eth)
{
	/* Make sure that the CPU port is used as the mac destination port */
	mtk_w32(eth, mtk_r32(eth, MT7620_GDMA1_FWD_CFG) & ~GDMA_FRC_P_MASK,
		MT7620_GDMA1_FWD_CFG);

	/* Enable TX Checksum Offloading */
	mtk_w32(eth,
		mtk_r32(eth, MT7620_GDMA1_FWD_CFG) |
		(GDMA_ICS_EN | GDMA_TCS_EN | GDMA_UCS_EN),
		MT7620_GDMA1_FWD_CFG);

	/* Enable RX Checksum Offloading */
	mtk_w32(eth,
		mtk_r32(eth, MT7620_CDMA_CSG_CFG) |
		(CDMA_ICS_EN | CDMA_UCS_EN | CDMA_TCS_EN),
		MT7620_CDMA_CSG_CFG);

	return 0;
}

static void mt7620_init_data(struct mtk_soc_data *data,
			     struct net_device *netdev)
{
	if (mt7620_get_eco() >= 5)
		netdev->hw_features |= NETIF_F_SG | NETIF_F_TSO | NETIF_F_TSO6 |
			NETIF_F_IPV6_CSUM;
}

static struct mtk_soc_data mt7620_data = {
	.hw_features = NETIF_F_IP_CSUM | NETIF_F_RXCSUM |
		       NETIF_F_HW_VLAN_CTAG_TX,
	.dma_type = MTK_PDMA,
	.dma_ring_size = 256,
	.napi_weight = 64,
	.piac_offset = 0x7000,
	.padding_64b = 1,
	.rx_2b_offset = 1,
	.rx_sg_dma = 1,
	.has_switch = 1,
	.mac_count = 1,
	.init_data = mt7620_init_data,
	.reset_fe = mt7620_mtk_reset,
	.set_mac = mt7620_set_mac,
	.fwd_config = mt7620_fwd_config,
	.switch_init = mtk_gsw_init,
	.port_init = mt7620_port_init,
	.reg_table = mt7620_reg_table,
	.pdma_glo_cfg = MTK_PDMA_SIZE_16DWORDS,
	.rx_int = RT5350_RX_DONE_INT,
	.tx_int = RT5350_TX_DONE_INT,
	.status_int = MT7620_MTK_GDM1_AF,
	.checksum_bit = MT7620_L4_VALID,
	.has_carrier = mt7620_has_carrier,
	.mdio_read = mt7620_mdio_read,
	.mdio_write = mt7620_mdio_write,
	.mdio_adjust_link = mt7620_mdio_link_adjust,
};

const struct of_device_id of_mtk_match[] = {
	{ .compatible = "mediatek,mt7620-eth", .data = &mt7620_data },
	{},
};

MODULE_DEVICE_TABLE(of, of_mtk_match);
