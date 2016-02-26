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

#include <asm/mach-ralink/ralink_regs.h>

#include "ra_eth_soc.h"
#include "mdio_rt2880.h"

#define RT3883_RSTCTRL_FE		BIT(21)

static void rt3883_mtk_reset(struct mtk_eth *eth)
{
	mtk_reset(eth, RT3883_RSTCTRL_FE);
}

static int rt3883_fwd_config(struct mtk_eth *eth)
{
	int ret;

	ret = mtk_set_clock_cycle(eth);
	if (ret)
		return ret;

	mtk_fwd_config(eth);
	mtk_w32(eth, MTK_PSE_FQFC_CFG_256Q, MTK_PSE_FQ_CFG);
	mtk_csum_config(eth);

	return ret;
}

static struct mtk_soc_data rt3883_data = {
	.hw_features = NETIF_F_SG | NETIF_F_IP_CSUM |
		       NETIF_F_RXCSUM | NETIF_F_HW_VLAN_CTAG_TX,
	.dma_type = MTK_PDMA,
	.dma_ring_size = 128,
	.napi_weight = 32,
	.padding_64b = 1,
	.padding_bug = 1,
	.mac_count = 1,
	.txd4 = TX_DMA_DESP4_DEF,
	.reset_fe = rt3883_mtk_reset,
	.fwd_config = rt3883_fwd_config,
	.pdma_glo_cfg = MTK_PDMA_SIZE_8DWORDS,
	.rx_int = MTK_RX_DONE_INT,
	.tx_int = MTK_TX_DONE_INT,
	.status_int = MTK_CNT_GDM_AF,
	.checksum_bit = RX_DMA_L4VALID,
	.mdio_read = rt2880_mdio_read,
	.mdio_write = rt2880_mdio_write,
	.mdio_adjust_link = rt2880_mdio_link_adjust,
	.port_init = rt2880_port_init,
};

const struct of_device_id of_mtk_match[] = {
	{ .compatible = "ralink,rt3883-eth", .data = &rt3883_data },
	{},
};

MODULE_DEVICE_TABLE(of, of_mtk_match);
