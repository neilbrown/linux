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

#ifndef _RALINK_MDIO_RT2880_H__
#define _RALINK_MDIO_RT2880_H__

void rt2880_mdio_link_adjust(struct mtk_eth *eth, int port);
int rt2880_mdio_read(struct mii_bus *bus, int phy_addr, int phy_reg);
int rt2880_mdio_write(struct mii_bus *bus, int phy_addr, int phy_reg, u16 val);
void rt2880_port_init(struct mtk_eth *eth, struct mtk_mac *mac,
		      struct device_node *np);

#endif
