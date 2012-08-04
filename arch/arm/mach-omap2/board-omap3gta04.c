/*
 * linux/arch/arm/mach-omap2/board-omap3gta04.c
 *
 * Copyright (C) 2008 Texas Instruments
 *
 * Modified from mach-omap2/board-omap3gta04.c
 *
 * Initial code: Syed Mohammed Khasim
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/leds.h>
#include <linux/gpio.h>
#include <linux/irq.h>
#include <linux/input.h>
#include <linux/gpio_keys.h>
#include <linux/backlight.h>
#include <linux/pwm_backlight.h>
#include <linux/rfkill-regulator.h>
#include <linux/opp.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/mtd/nand.h>
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio.h>

#include <linux/regulator/machine.h>
#include <linux/regulator/fixed.h>
#include <linux/i2c/twl.h>
#include <linux/i2c/tsc2007.h>

#include <linux/i2c/bmp085.h>
#ifdef CONFIG_LEDS_TCA6507
#include <linux/leds-tca6507.h>
#endif

#include <linux/sysfs.h>

#include <mach/hardware.h>
#include <asm/mach-types.h>
#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/flash.h>

#include <plat/board.h>
#include <plat/common.h>
#include <video/omapdss.h>
#include <video/omap-panel-generic-dpi.h>
#include <plat/gpmc.h>
#include <plat/nand.h>
#include <plat/usb.h>
#include <plat/clock.h>
#include <plat/omap-pm.h>
#include <plat/mcspi.h>
#include <plat/omap-serial.h>
#include <plat/omap_device.h>
#include <plat/pwm.h>

#include "mux.h"
#include "hsmmc.h"
#include "pm.h"
#include "common-board-devices.h"
#include "control.h"

#define GPMC_CS0_BASE  0x60
#define GPMC_CS_SIZE   0x30

#define NAND_BLOCK_SIZE		SZ_128K

#define	AUX_BUTTON_GPIO		7
#define TWL4030_MSECURE_GPIO	22
#define	TS_PENIRQ_GPIO		160
#define	WO3G_GPIO		(gta04_version >= 4 ? 10 : 176)

/* see: https://patchwork.kernel.org/patch/120449/
 * OMAP3 gta04 revision
 * Run time detection of gta04 revision is done by reading GPIO.
 * GPIO ID -
 *	AXBX	= GPIO173, GPIO172, GPIO171: 1 1 1
 *	C1_3	= GPIO173, GPIO172, GPIO171: 1 1 0
 *	C4	= GPIO173, GPIO172, GPIO171: 1 0 1
 *	XM	= GPIO173, GPIO172, GPIO171: 0 0 0
 */
enum {
	gta04_BOARD_UNKN = 0,
	gta04_BOARD_AXBX,
	gta04_BOARD_C1_3,
	gta04_BOARD_C4,
	gta04_BOARD_XM,
};

static u8 gta04_version;	/* counts 2..9 */

static void __init gta04_init_rev(void)
{
	int ret;
	u16 gta04_rev = 0;
	static char revision[8] = {	/* revision table defined by pull-down
					 * R305, R306, R307 */
		9,
		6,
		7,
		3,
		8,
		4,
		5,
		2
	};
	printk("Running gta04_init_rev()\n");

	omap_mux_init_gpio(171, OMAP_PIN_INPUT_PULLUP);
	omap_mux_init_gpio(172, OMAP_PIN_INPUT_PULLUP);
	omap_mux_init_gpio(173, OMAP_PIN_INPUT_PULLUP);

	udelay(100);

	ret = gpio_request(171, "rev_id_0");
	if (ret < 0)
		goto fail0;

	ret = gpio_request(172, "rev_id_1");
	if (ret < 0)
		goto fail1;

	ret = gpio_request(173, "rev_id_2");
	if (ret < 0)
		goto fail2;

	udelay(100);

	gpio_direction_input(171);
	gpio_direction_input(172);
	gpio_direction_input(173);

	udelay(100);

	gta04_rev = gpio_get_value(171)
				| (gpio_get_value(172) << 1)
				| (gpio_get_value(173) << 2);

	printk("gta04_rev %u\n", gta04_rev);

	gta04_version = revision[gta04_rev];

	return;

fail2:
	gpio_free(172);
fail1:
	gpio_free(171);
fail0:
	printk(KERN_ERR "Unable to get revision detection GPIO pins\n");
	gta04_version = 0;

	return;
}


static struct mtd_partition gta04_nand_partitions[] = {
	/* All the partition sizes are listed in terms of NAND block size */
	{
		.name		= "X-Loader",
		.offset		= 0,
		.size		= 4 * NAND_BLOCK_SIZE,
		.mask_flags	= MTD_WRITEABLE,	/* force read-only */
	},
	{
		.name		= "U-Boot",
		.offset		= MTDPART_OFS_APPEND,	/* Offset = 0x80000 */
		.size		= 15 * NAND_BLOCK_SIZE,
	},
	{
		.name		= "U-Boot Env",
		.offset		= MTDPART_OFS_APPEND,	/* Offset = 0x260000 */
		.size		= 1 * NAND_BLOCK_SIZE,
	},
	{
		.name		= "Kernel",
		.offset		= MTDPART_OFS_APPEND,	/* Offset = 0x280000 */
		.size		= 32 * NAND_BLOCK_SIZE,
	},
	{
		.name		= "File System",
		.offset		= MTDPART_OFS_APPEND,	/* Offset = 0x680000 */
		.size		= MTDPART_SIZ_FULL,
	},
};

/* DSS */

static int gta04_enable_dvi(struct omap_dss_device *dssdev)
{
	if (dssdev->reset_gpio != -1)
		gpio_set_value(dssdev->reset_gpio, 1);

	return 0;
}

static void gta04_disable_dvi(struct omap_dss_device *dssdev)
{
	if (dssdev->reset_gpio != -1)
		gpio_set_value(dssdev->reset_gpio, 0);
}

static struct omap_dss_device gta04_dvi_device = {
	.type = OMAP_DISPLAY_TYPE_DPI,
	.name = "dvi",
	.driver_name = "generic_panel",
	.phy.dpi.data_lines = 24,
//	.reset_gpio = 170,
	.reset_gpio = -1,
	.platform_enable = gta04_enable_dvi,
	.platform_disable = gta04_disable_dvi,
};


static struct omap2_pwm_platform_config pwm_config = {
	.timer_id           = 11,   // GPT11_PWM_EVT
	.polarity           = 1     // Active-high
};

static struct platform_device pwm_device = {
	.name               = "omap-pwm",
	.id                 = 0,
	.dev.platform_data  = &pwm_config,
};

static struct platform_pwm_backlight_data pwm_backlight = {
	.pwm_id		= 0,
	.max_brightness = 100,
	.dft_brightness = 100,
	.pwm_period_ns  = 2000000, /* 500 Hz */
	.lth_brightness = 11, /* Below 11% display appears as off */
};
static struct platform_device backlight_device = {
	.name = "pwm-backlight",
	.dev = {
		.platform_data = &pwm_backlight,
	},
	.id = -1,
};

static int gta04_enable_lcd(struct omap_dss_device *dssdev)
{
	static int did_reg = 0;
	printk("gta04_enable_lcd()\n");
	if (!did_reg) {
		/* Cannot do this in gta04_init() as clocks aren't
		 * initialised yet, so do it here.
		 */
		platform_device_register(&pwm_device);
		platform_device_register(&backlight_device);
		did_reg = 1;
	}
	return 0;
}

static void gta04_disable_lcd(struct omap_dss_device *dssdev)
{
	printk("gta04_disable_lcd()\n");
}

static struct omap_dss_device gta04_lcd_device = {
	.type = OMAP_DISPLAY_TYPE_DPI,
	.name = "lcd",
	.driver_name = "td028ttec1_panel",
	.phy.dpi.data_lines = 24,
	.platform_enable = gta04_enable_lcd,
	.platform_disable = gta04_disable_lcd,
};

static int gta04_panel_enable_tv(struct omap_dss_device *dssdev)
{
	u32 reg;

#define ENABLE_VDAC_DEDICATED           0x03
#define ENABLE_VDAC_DEV_GRP             0x20
#define OMAP2_TVACEN				(1 << 11)
#define OMAP2_TVOUTBYPASS			(1 << 18)

	twl_i2c_write_u8(TWL4030_MODULE_PM_RECEIVER,
			ENABLE_VDAC_DEDICATED,
			TWL4030_VDAC_DEDICATED);
	twl_i2c_write_u8(TWL4030_MODULE_PM_RECEIVER,
			ENABLE_VDAC_DEV_GRP, TWL4030_VDAC_DEV_GRP);

	/* taken from https://e2e.ti.com/support/dsp/omap_applications_processors/f/447/p/94072/343691.aspx */
	reg = omap_ctrl_readl(OMAP343X_CONTROL_DEVCONF1);
//	printk(KERN_INFO "Value of DEVCONF1 was: %08x\n", reg);
	reg |= OMAP2_TVOUTBYPASS;	/* enable TV bypass mode for external video driver (for OPA362 driver) */
	reg |= OMAP2_TVACEN;		/* assume AC coupling to remove DC offset */
	omap_ctrl_writel(reg, OMAP343X_CONTROL_DEVCONF1);
	reg = omap_ctrl_readl(OMAP343X_CONTROL_DEVCONF1);
//	printk(KERN_INFO "Value of DEVCONF1 now: %08x\n", reg);

	gpio_set_value(23, 1);	// enable output driver (OPA362)

	return 0;
}

static void gta04_panel_disable_tv(struct omap_dss_device *dssdev)
{
	gpio_set_value(23, 0);	// disable output driver (and re-enable microphone)

	twl_i2c_write_u8(TWL4030_MODULE_PM_RECEIVER, 0x00,
			TWL4030_VDAC_DEDICATED);
	twl_i2c_write_u8(TWL4030_MODULE_PM_RECEIVER, 0x00,
			TWL4030_VDAC_DEV_GRP);
}

static struct omap_dss_device gta04_tv_device = {
	.name = "tv",
	.driver_name = "venc",
	.type = OMAP_DISPLAY_TYPE_VENC,
	/* GTA04 has a single composite output (with external video driver) */
	.phy.venc.type = OMAP_DSS_VENC_TYPE_COMPOSITE, /*OMAP_DSS_VENC_TYPE_SVIDEO, */
	.phy.venc.invert_polarity = true,	/* needed if we use external video driver */
	.platform_enable = gta04_panel_enable_tv,
	.platform_disable = gta04_panel_disable_tv,
};

static struct omap_dss_device *gta04_dss_devices[] = {
// 	&gta04_dvi_device,
// 	&gta04_tv_device,
	&gta04_lcd_device,
};

static struct omap_dss_board_info gta04_dss_data = {
	.num_devices = ARRAY_SIZE(gta04_dss_devices),
	.devices = gta04_dss_devices,
// 	.default_device = &gta04_lcd_device,
};

static struct platform_device gta04_dss_device = {
	.name          = "omapdss",
	.id            = 0,
	.dev            = {
		.platform_data = &gta04_dss_data,
	},
};

static struct regulator_consumer_supply gta04_vdac_supply = {
	.supply		= "vdda_dac",
	.dev		= &gta04_dss_device.dev,
};

static struct regulator_consumer_supply gta04_vdvi_supply = {
	.supply		= "vdds_dsi",
	.dev		= &gta04_dss_device.dev,
};

#include "sdram-micron-mt46h32m32lf-6.h"

static struct omap2_hsmmc_info mmc[] = {
	{
		.mmc		= 1,
		 // only 4 wires are connected, and they cannot be removed...
		.caps		= (MMC_CAP_4_BIT_DATA
				   |MMC_CAP_NONREMOVABLE
				   |MMC_CAP_POWER_OFF_CARD),
		.gpio_cd	= -EINVAL,	// no card detect
		.gpio_wp	= -EINVAL,	// no write protect
	},
	{ // this is the WiFi SDIO interface
		.mmc		= 2,
		.caps		= (MMC_CAP_4_BIT_DATA // only 4 wires are connected
				   |MMC_CAP_NONREMOVABLE
				   |MMC_CAP_POWER_OFF_CARD),
		.gpio_cd	= -EINVAL, // virtual card detect
		.gpio_wp	= -EINVAL,	// no write protect
		.transceiver	= true,	// external transceiver
		.ocr_mask	= MMC_VDD_31_32,	/* 3.15 is what we want */
	},
	{}	/* Terminator */
};

static struct regulator_consumer_supply gta04_vmmc1_supply[] = {
	REGULATOR_SUPPLY("vmmc", "omap_hsmmc.0"),
// 	.supply			= "vmmc",
};

static struct regulator_consumer_supply gta04_vsim_supply[] = {
	REGULATOR_SUPPLY("vrfkill", "rfkill-regulator.0"),
};

static struct twl4030_gpio_platform_data gta04_gpio_data = {
	.gpio_base	= OMAP_MAX_GPIO_LINES,
	.irq_base	= TWL4030_GPIO_IRQ_BASE,
	.irq_end	= TWL4030_GPIO_IRQ_END,
	.use_leds	= true,
	.pullups	= BIT(1),
	.pulldowns	= BIT(2) | BIT(6) | BIT(7) | BIT(8) | BIT(13)
				| BIT(15) | BIT(16) | BIT(17),
};

static struct twl4030_clock_init_data gta04_clock = {
	.ck32k_lowpwr_enable = 1, /* Reduce power when on backup battery */
};

/* VMMC1 for MMC1 pins CMD, CLK, DAT0..DAT3 (20 mA, plus card == max 220 mA) */
static struct regulator_init_data gta04_vmmc1 = {
	.constraints = {
		.name			= "VMMC1",
		.min_uV			= 1850000,
		.max_uV			= 3150000,
		.valid_modes_mask	= REGULATOR_MODE_NORMAL
					| REGULATOR_MODE_STANDBY,
		.valid_ops_mask		= REGULATOR_CHANGE_VOLTAGE
					| REGULATOR_CHANGE_MODE
					| REGULATOR_CHANGE_STATUS,
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= gta04_vmmc1_supply,
};

/* Pseudo Fixed regulator to provide reset toggle to Wifi module */
static struct regulator_consumer_supply gta04_vwlan_supply[] = {
	REGULATOR_SUPPLY("vmmc", "omap_hsmmc.1"), // wlan
};

static struct regulator_init_data gta04_vwlan_data = {
	.supply_regulator = "VAUX4",
	.constraints = {
		.name			= "VWLAN",
		.min_uV			= 2800000,
		.max_uV			= 3150000,
		.valid_modes_mask	= (REGULATOR_MODE_NORMAL
					   | REGULATOR_MODE_STANDBY),
		.valid_ops_mask		= (REGULATOR_CHANGE_VOLTAGE
					   | REGULATOR_CHANGE_MODE
					   | REGULATOR_CHANGE_STATUS),
	},
	.num_consumer_supplies	= ARRAY_SIZE(gta04_vwlan_supply),
	.consumer_supplies	= gta04_vwlan_supply,
};

/* "+2" because TWL4030 adds 2 LED drives as gpio outputs */
#define GPIO_WIFI_RESET (OMAP_MAX_GPIO_LINES + TWL4030_GPIO_MAX + 2)

static struct fixed_voltage_config gta04_vwlan = {
	.supply_name		= "vwlan",
	.microvolts		= 3150000, /* 3.15V */
	.gpio			= GPIO_WIFI_RESET,
	.startup_delay		= 10000, /* 10ms */
	.enable_high		= 1,
	.enabled_at_boot	= 0,
	.init_data		= &gta04_vwlan_data,
};

static struct platform_device gta04_vwlan_device = {
	.name		= "reg-fixed-voltage",
	.id		= 1,
	.dev = {
		.platform_data = &gta04_vwlan,
	},
};

/* VAUX4 powers Bluetooth and WLAN */

static struct regulator_consumer_supply gta04_vaux4_supply[] = {
	REGULATOR_SUPPLY("vrfkill", "rfkill-regulator.1"), // bluetooth
};

static struct regulator_init_data gta04_vaux4 = {
	.constraints = {
		.name			= "VAUX4",
		.min_uV			= 2800000,
		/* FIXME: this is a HW issue - 3.15V or 3.3V isn't supported
		 * officially - set CONFIG_TWL4030_ALLOW_UNSUPPORTED */
		.max_uV			= 3150000,
		.valid_modes_mask	= (REGULATOR_MODE_NORMAL
					   | REGULATOR_MODE_STANDBY),
		.valid_ops_mask		= (REGULATOR_CHANGE_VOLTAGE
					   | REGULATOR_CHANGE_MODE
					   | REGULATOR_CHANGE_STATUS),
	},
	.num_consumer_supplies	= ARRAY_SIZE(gta04_vaux4_supply),
	.consumer_supplies	= gta04_vaux4_supply,
};

/* VAUX3 for Camera */

static struct regulator_consumer_supply gta04_vaux3_supply = {
	.supply			= "vaux3",
};

static struct regulator_init_data gta04_vaux3 = {
	.constraints = {
		.name			= "VAUX3",
		.min_uV			= 2500000,
		.max_uV			= 2500000,
		.valid_modes_mask	= (REGULATOR_MODE_NORMAL
					   | REGULATOR_MODE_STANDBY),
		.valid_ops_mask		= (REGULATOR_CHANGE_VOLTAGE
					   | REGULATOR_CHANGE_MODE
					   | REGULATOR_CHANGE_STATUS),
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &gta04_vaux3_supply,
};

/* VAUX2 for Sensors ITG3200 (and LIS302/LSM303) */

static struct regulator_consumer_supply gta04_vaux2_supply = {
	.supply			= "vaux2",
};

static struct regulator_init_data gta04_vaux2 = {
	.constraints = {
		.name			= "VAUX2",
		.min_uV			= 2800000,
		.max_uV			= 2800000,
		.always_on		= 1,
		.valid_modes_mask	= REGULATOR_MODE_NORMAL,
		.valid_ops_mask		= 0,
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &gta04_vaux2_supply,
};

/* VAUX1 unused */

static struct regulator_consumer_supply gta04_vaux1_supply = {
	.supply			= "vaux1",
};

static struct regulator_init_data gta04_vaux1 = {
	.constraints = {
		.name			= "VAUX1",
		.min_uV			= 2500000,
		.max_uV			= 3000000,
		.valid_modes_mask	= REGULATOR_MODE_NORMAL
		| REGULATOR_MODE_STANDBY,
		.valid_ops_mask		= REGULATOR_CHANGE_VOLTAGE
		| REGULATOR_CHANGE_MODE
		| REGULATOR_CHANGE_STATUS,
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &gta04_vaux1_supply,
};

/* VSIM used for powering the external GPS Antenna */

static struct regulator_init_data gta04_vsim = {
	.constraints = {
		.name			= "VSIM",
		.min_uV			= 2800000,
		.max_uV			= 2800000,
		.valid_modes_mask	= REGULATOR_MODE_NORMAL
					| REGULATOR_MODE_STANDBY,
		.valid_ops_mask		= REGULATOR_CHANGE_VOLTAGE
					| REGULATOR_CHANGE_MODE
					| REGULATOR_CHANGE_STATUS,
	},
	.num_consumer_supplies	= ARRAY_SIZE(gta04_vsim_supply),
	.consumer_supplies	= gta04_vsim_supply,
};

/* VDAC for DSS driving S-Video (8 mA unloaded, max 65 mA) */
static struct regulator_init_data gta04_vdac = {
	.constraints = {
		.name			= "VDAC",
		.min_uV			= 1800000,
		.max_uV			= 1800000,
		.valid_modes_mask	= REGULATOR_MODE_NORMAL
					| REGULATOR_MODE_STANDBY,
		.valid_ops_mask		= REGULATOR_CHANGE_MODE
					| REGULATOR_CHANGE_STATUS,
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &gta04_vdac_supply,
};

/* VPLL2 for digital video outputs */
static struct regulator_init_data gta04_vpll2 = {
	.constraints = {
		.name			= "VDVI",
		.min_uV			= 1800000,
		.max_uV			= 1800000,
		.valid_modes_mask	= REGULATOR_MODE_NORMAL
					| REGULATOR_MODE_STANDBY,
		.valid_ops_mask		= REGULATOR_CHANGE_MODE
					| REGULATOR_CHANGE_STATUS,
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &gta04_vdvi_supply,
};

static struct regulator_init_data *all_reg_data[] = {
	&gta04_vmmc1,
	&gta04_vwlan_data,
	&gta04_vaux4,
	&gta04_vaux3,
	&gta04_vaux2,
	&gta04_vaux1,
	&gta04_vsim,
	&gta04_vdac,
	&gta04_vpll2,
	NULL
};

/* rfkill devices for GPS and Bluetooth to control regulators */

static struct rfkill_regulator_platform_data gps_rfkill_data = {
	.name = "GPS",
	.type = RFKILL_TYPE_GPS,
};

static struct rfkill_regulator_platform_data bt_rfkill_data = {
	.name = "Bluetooth",
	.type = RFKILL_TYPE_BLUETOOTH,
};

static struct platform_device gps_rfkill_device = {
	.name = "rfkill-regulator",
	.id = 0,
	.dev.platform_data = &gps_rfkill_data,
};

static struct platform_device bt_rfkill_device = {
	.name = "rfkill-regulator",
	.id = 1,
	.dev.platform_data = &bt_rfkill_data,
};

static struct twl4030_usb_data gta04_usb_data = {
	.usb_mode	= T2_USB_MODE_ULPI,
};

static struct twl4030_codec_data omap3_codec;

static struct twl4030_vibra_data gta04_vibra_data = {
	.coexist	=	0,
};

static struct twl4030_audio_data omap3_audio_pdata = {
	.audio_mclk = 26000000,
	.codec = &omap3_codec,
	.vibra = &gta04_vibra_data,
};

static struct twl4030_madc_platform_data gta04_madc_data = {
	.irq_line	= 1,
};

// FIXME: we could copy more scripts from board-sdp3430.c if we understand what they do... */


static struct twl4030_ins __initdata sleep_on_seq[] = {
	/* Turn off HFCLKOUT */
//	{MSG_SINGULAR(DEV_GRP_P3, RES_HFCLKOUT, RES_STATE_OFF), 2},
	/* Turn OFF VDD1 */
	{MSG_SINGULAR(DEV_GRP_P1, RES_VDD1, RES_STATE_OFF), 2},
	/* Turn OFF VDD2 */
	{MSG_SINGULAR(DEV_GRP_P1, RES_VDD2, RES_STATE_OFF), 2},
	/* Turn OFF VPLL1 */
	{MSG_SINGULAR(DEV_GRP_P1, RES_VPLL1, RES_STATE_OFF), 2},

	{MSG_SINGULAR(DEV_GRP_P1, RES_VINTANA1, RES_STATE_OFF), 2},
	{MSG_SINGULAR(DEV_GRP_P1, RES_VINTANA2, RES_STATE_OFF), 2},
	{MSG_SINGULAR(DEV_GRP_P1, RES_VINTDIG, RES_STATE_OFF), 2},

};

static struct twl4030_script sleep_on_script __initdata = {
	.script	= sleep_on_seq,
	.size	= ARRAY_SIZE(sleep_on_seq),
	.flags	= TWL4030_SLEEP_SCRIPT,
};

static struct twl4030_ins wakeup_p12_seq[] __initdata = {
	{MSG_SINGULAR(DEV_GRP_P1, RES_VINTANA1, RES_STATE_ACTIVE), 2},
	{MSG_SINGULAR(DEV_GRP_P1, RES_VINTANA2, RES_STATE_ACTIVE), 2},
	{MSG_SINGULAR(DEV_GRP_P1, RES_VINTDIG, RES_STATE_ACTIVE), 2},

	/* Turn on HFCLKOUT */
//	{MSG_SINGULAR(DEV_GRP_P1, RES_HFCLKOUT, RES_STATE_ACTIVE), 2},
	/* Turn ON VDD1 */
	{MSG_SINGULAR(DEV_GRP_P1, RES_VDD1, RES_STATE_ACTIVE), 2},
	/* Turn ON VDD2 */
	{MSG_SINGULAR(DEV_GRP_P1, RES_VDD2, RES_STATE_ACTIVE), 2},
	/* Turn ON VPLL1 */
	{MSG_SINGULAR(DEV_GRP_P1, RES_VPLL1, RES_STATE_ACTIVE), 2},
};

static struct twl4030_script wakeup_p12_script __initdata = {
	.script	= wakeup_p12_seq,
	.size	= ARRAY_SIZE(wakeup_p12_seq),
	.flags	= TWL4030_WAKEUP12_SCRIPT,
};

/* Turn the HFCLK on when CPU asks for it. */
static struct twl4030_ins wakeup_p3_seq[] __initdata = {
	{MSG_SINGULAR(DEV_GRP_P1, RES_HFCLKOUT, RES_STATE_ACTIVE), 2},
};

static struct twl4030_script wakeup_p3_script __initdata = {
	.script = wakeup_p3_seq,
	.size   = ARRAY_SIZE(wakeup_p3_seq),
	.flags  = TWL4030_WAKEUP3_SCRIPT,
};

static struct twl4030_ins wrst_seq[] __initdata = {
/*
 * Reset twl4030.
 * Reset VDD1 regulator.
 * Reset VDD2 regulator.
 * Reset VPLL1 regulator.
 * Enable sysclk output.
 * Reenable twl4030.
 */
	{MSG_SINGULAR(DEV_GRP_NULL, RES_RESET, RES_STATE_OFF), 2},
	{MSG_SINGULAR(DEV_GRP_P1, RES_VDD1, RES_STATE_WRST), 15},
	{MSG_SINGULAR(DEV_GRP_P1, RES_VDD2, RES_STATE_WRST), 15},
	{MSG_SINGULAR(DEV_GRP_P1, RES_VPLL1, RES_STATE_WRST), 0x60},
	{MSG_SINGULAR(DEV_GRP_P1, RES_HFCLKOUT, RES_STATE_ACTIVE), 2},
	{MSG_SINGULAR(DEV_GRP_NULL, RES_RESET, RES_STATE_ACTIVE), 2},
};

static struct twl4030_script wrst_script __initdata = {
	.script = wrst_seq,
	.size   = ARRAY_SIZE(wrst_seq),
	.flags  = TWL4030_WRST_SCRIPT,
};

static struct twl4030_script *twl4030_scripts[] __initdata = {
	&wakeup_p12_script,
	&wakeup_p3_script,
	&sleep_on_script,
	&wrst_script,
};

#define TWL_RES_CFG(_res, _devg) { .resource = _res, .devgroup = _devg, \
	.type = TWL4030_RESCONFIG_UNDEF, .type2 = TWL4030_RESCONFIG_UNDEF,}

#define DEV_GRP_ALL (DEV_GRP_P1|DEV_GRP_P2|DEV_GRP_P3)
static struct twl4030_resconfig twl4030_rconfig[] = {
	TWL_RES_CFG(RES_HFCLKOUT, DEV_GRP_P3),
	TWL_RES_CFG(RES_VINTANA1, DEV_GRP_ALL),
	TWL_RES_CFG(RES_VINTANA1, DEV_GRP_P1),
	TWL_RES_CFG(RES_VINTANA2, DEV_GRP_ALL),
	TWL_RES_CFG(RES_VINTANA2, DEV_GRP_P1),
	TWL_RES_CFG(RES_VINTDIG, DEV_GRP_ALL),
	TWL_RES_CFG(RES_VINTDIG, DEV_GRP_P1),
	{ 0, 0},
};

struct twl4030_power_data gta04_power_scripts = {
//	.scripts	= twl4030_scripts,
//	.num		= ARRAY_SIZE(twl4030_scripts),
	.resource_config = twl4030_rconfig,
	.use_poweroff	= 1,
};

/* override TWL defaults */

static int gta04_batt_table[] = {
	/* 0 C*/
	30800, 29500, 28300, 27100,
	26000, 24900, 23900, 22900, 22000, 21100, 20300, 19400, 18700, 17900,
	17200, 16500, 15900, 15300, 14700, 14100, 13600, 13100, 12600, 12100,
	11600, 11200, 10800, 10400, 10000, 9630,  9280,  8950,  8620,  8310,
	8020,  7730,  7460,  7200,  6950,  6710,  6470,  6250,  6040,  5830,
	5640,  5450,  5260,  5090,  4920,  4760,  4600,  4450,  4310,  4170,
	4040,  3910,  3790,  3670,  3550
};

static struct twl4030_bci_platform_data gta04_bci_data = {
	.battery_tmp_tbl        = gta04_batt_table,
	.tblsize                = ARRAY_SIZE(gta04_batt_table),
	.bb_uvolt		= 3200000,
	.bb_uamp		= 150,
};


static struct twl4030_platform_data gta04_twldata = {
	.irq_base	= TWL4030_IRQ_BASE,
	.irq_end	= TWL4030_IRQ_END,

	/* platform_data for children goes here */
	.bci		= &gta04_bci_data,
	.gpio		= &gta04_gpio_data,
	.madc		= &gta04_madc_data,
	.power		= &gta04_power_scripts,	/* empty but if not present, pm_power_off is not initialized */
	.usb		= &gta04_usb_data,
	.audio		= &omap3_audio_pdata,
	.clock		= &gta04_clock,

	.vaux1		= &gta04_vaux1,
	.vaux2		= &gta04_vaux2,
	.vaux3		= &gta04_vaux3,
	.vaux4		= &gta04_vaux4,
	.vmmc1		= &gta04_vmmc1,
	.vsim		= &gta04_vsim,
	.vdac		= &gta04_vdac,
	.vpll2		= &gta04_vpll2,
};


#if defined(CONFIG_SND_SOC_GTM601)

static struct platform_device gta04_gtm601_codec_audio_device = {
	.name	= "gtm601_codec_audio",
	.id	= -1,
	.dev	= {
		.platform_data	= NULL,
	},
};
#endif

#if defined(CONFIG_SND_SOC_SI47XX)

static struct platform_device gta04_si47xx_codec_audio_device = {
	.name	= "si47xx_codec_audio",
	.id	= -1,
	.dev	= {
		.platform_data	= NULL,
	},
};
#endif

#if defined(CONFIG_SND_SOC_W2CBW003)

static struct platform_device gta04_w2cbw003_codec_audio_device = {
	.name	= "w2cbw003_codec_audio",
	.id	= -1,
	.dev	= {
		.platform_data	= NULL,
	},
};
#endif

#ifdef CONFIG_TOUCHSCREEN_TSC2007

// TODO: see also http://e2e.ti.com/support/arm174_microprocessors/omap_applications_processors/f/42/t/33262.aspx for an example...
// and http://www.embedded-bits.co.uk/?tag=struct-i2c_board_info for a description of how struct i2c_board_info works

/* TouchScreen */

static int ts_get_pendown_state(void)
{
#if 1
	int val = 0;
	//	gpio_free(GPIO_FN_INTC_IRQ0);	// what does this change or not change on the board we have copied the code from?
//	gpio_request(TS_PENIRQ_GPIO, "tsc2007_pen_down");
//	gpio_direction_input(TS_PENIRQ_GPIO);

	val = gpio_get_value(TS_PENIRQ_GPIO);

//	gpio_free(TS_PENIRQ_GPIO);
	//	gpio_request(GPIO_FN_INTC_IRQ0, NULL);
//	printk("ts_get_pendown_state() -> %d\n", val);
	return val ? 0 : 1;
#else
	return 0;
#endif
}

static int __init tsc2007_init(void)
{
	printk("tsc2007_init()\n");
	omap_mux_init_gpio(TS_PENIRQ_GPIO, OMAP_PIN_INPUT_PULLUP);
	if (gpio_request(TS_PENIRQ_GPIO, "tsc2007_pen_down")) {
		printk(KERN_ERR "Failed to request GPIO %d for "
			   "TSC2007 pen down IRQ\n", TS_PENIRQ_GPIO);
		return  -ENODEV;
	}

	if (gpio_direction_input(TS_PENIRQ_GPIO)) {
		printk(KERN_WARNING "GPIO#%d cannot be configured as "
			   "input\n", TS_PENIRQ_GPIO);
		return -ENXIO;
	}
//	debounce isn't handled properly when power-saving and we lose
//	interrupts, so don't bother for now.
//	gpio_set_debounce(TS_PENIRQ_GPIO, (0x0a+1)*31);
	irq_set_irq_type(OMAP_GPIO_IRQ(TS_PENIRQ_GPIO), IRQ_TYPE_EDGE_FALLING);
	return 0;
}

static void tsc2007_exit(void)
{
	gpio_free(TS_PENIRQ_GPIO);
}

struct tsc2007_platform_data tsc2007_info = {
	.model			= 2007,
	.x_plate_ohms		= 600,	// range: 250 .. 900
	.get_pendown_state	= ts_get_pendown_state,
	.init_platform_hw	= tsc2007_init,
	.exit_platform_hw	= tsc2007_exit,
};

#endif


#ifdef CONFIG_BMP085

#define BMP085_EOC_IRQ_GPIO		113	/* BMP085 end of conversion GPIO */

struct bmp085_platform_data bmp085_info = {
	.gpio = BMP085_EOC_IRQ_GPIO,
};

#endif

#ifdef CONFIG_LEDS_TCA6507

static struct led_info tca6507_leds[] = {
	[0] = { .name = "gta04:red:aux" },
	[1] = { .name = "gta04:green:aux" },
	[3] = { .name = "gta04:red:power", .default_trigger = "default-on" },
	[4] = { .name = "gta04:green:power" },

	[6] = { .name = "gta04:wlan:reset", .flags = TCA6507_MAKE_GPIO },
};
static struct tca6507_platform_data tca6507_info = {
	.leds = {
		.num_leds = 7,
		.leds = tca6507_leds,
	},
	.gpio_base = GPIO_WIFI_RESET,
};
#endif

static struct i2c_board_info __initdata gta04_i2c2_boardinfo[] = {
#ifdef CONFIG_TOUCHSCREEN_TSC2007
{
	I2C_BOARD_INFO("tsc2007", 0x48),
	.type		= "tsc2007",
	.platform_data	= &tsc2007_info,
	.irq		=  OMAP_GPIO_IRQ(TS_PENIRQ_GPIO),
},
#endif
#ifdef CONFIG_BMP085
{
	I2C_BOARD_INFO("bmp085", 0x77),
	.type		= "bmp085",
	.platform_data	= &bmp085_info,
	.irq		=  OMAP_GPIO_IRQ(BMP085_EOC_IRQ_GPIO),
},
#endif
#ifdef CONFIG_LIS302
{
	I2C_BOARD_INFO("lis302top", 0x1c),
	.type		= "lis302",
	.platform_data	= &lis302_info,
	.irq		=  -EINVAL,
},
{
	I2C_BOARD_INFO("lis302bottom", 0x1d),
	.type		= "lis302",
	.platform_data	= &lis302_info,
	.irq		=  114,
},
#endif
#if defined(CONFIG_LEDS_TCA6507)
{
	I2C_BOARD_INFO("tca6507", 0x45),
	.type		= "tca6507",
	.platform_data	= &tca6507_info,
},
#endif
#ifdef CONFIG_INPUT_BMA150
{
	I2C_BOARD_INFO("bma150", 0x41),
	.type		= "bma150",
},
#endif
	/* FIXME: add other drivers for HMC5883, BMA180, Si472x, Camera */
};

static int __init gta04_i2c_init(void)
{
	omap_pmic_init(1, 2600, "twl4030", INT_34XX_SYS_NIRQ,
		       &gta04_twldata);
	omap_register_i2c_bus(2, 400,  gta04_i2c2_boardinfo,
				ARRAY_SIZE(gta04_i2c2_boardinfo));
	/* Bus 3 is attached to the DVI port where devices like the pico DLP
	 * projector don't work reliably with 400kHz */
	omap_register_i2c_bus(3, 100, NULL, 0);
	return 0;
}

#if 0
// FIXME: initialize SPIs and McBSPs

static struct spi_board_info gta04fpga_mcspi_board_info[] = {
	// spi 4.0
	{
		.modalias	= "spidev",
		.max_speed_hz	= 48000000, //48 Mbps
		.bus_num	= 4,	// McSPI4
		.chip_select	= 0,
		.mode = SPI_MODE_1,
	},
};

static void __init gta04fpga_init_spi(void)
{
		/* hook the spi ports to the spidev driver */
		spi_register_board_info(gta04fpga_mcspi_board_info,
			ARRAY_SIZE(gta04fpga_mcspi_board_info));
}
#endif

static struct gpio_keys_button gpio_buttons[] = {
	{
		.code			= KEY_PHONE,
		.gpio			= AUX_BUTTON_GPIO,
		.desc			= "AUX",
		.wakeup			= 1,
	},
};

static struct gpio_keys_platform_data gpio_key_info = {
	.buttons	= gpio_buttons,
	.nbuttons	= ARRAY_SIZE(gpio_buttons),
};

static struct platform_device keys_gpio = {
	.name	= "gpio-keys",
	.id	= -1,
	.dev	= {
		.platform_data	= &gpio_key_info,
	},
};

static void __init gta04_init_early(void)
{
// 	printk("Doing gta04_init_early()\n");
	omap3_init_early();
}

#if defined(CONFIG_REGULATOR_VIRTUAL_CONSUMER)

static struct platform_device gta04_vaux1_virtual_regulator_device = {
	.name		= "reg-virt-consumer",
	.id			= 1,
	.dev		= {
		.platform_data	= "vaux1",
	},
};

static struct platform_device gta04_vaux2_virtual_regulator_device = {
	.name		= "reg-virt-consumer",
	.id			= 2,
	.dev		= {
		.platform_data	= "vaux2",
	},
};

static struct platform_device gta04_vaux3_virtual_regulator_device = {
	.name		= "reg-virt-consumer",
	.id			= 3,
	.dev		= {
		.platform_data	= "vaux3",
	},
};
#endif

static struct platform_device *gta04_devices[] __initdata = {
//	&leds_gpio,
	&keys_gpio,
// 	&gta04_dss_device,
	&gta04_vwlan_device,
	&gps_rfkill_device,
	&bt_rfkill_device,
#if defined(CONFIG_REGULATOR_VIRTUAL_CONSUMER)
	&gta04_vaux1_virtual_regulator_device,
	&gta04_vaux2_virtual_regulator_device,
	&gta04_vaux3_virtual_regulator_device,
#endif
#if defined(CONFIG_SND_SOC_GTM601)
	&gta04_gtm601_codec_audio_device,
#endif
#if defined(CONFIG_SND_SOC_SI47XX)
	&gta04_si47xx_codec_audio_device,
#endif
#if defined(CONFIG_SND_SOC_W2CBW003)
	&gta04_w2cbw003_codec_audio_device,
#endif
};

static const struct usbhs_omap_board_data usbhs_bdata __initconst = {

	/* HSUSB0 - is not a EHCI port; TPS65950 configured by twl4030.c and musb driver */
	.port_mode[0] = OMAP_USBHS_PORT_MODE_UNUSED,	/* HSUSB1 - n/a */
	.port_mode[1] = OMAP_EHCI_PORT_MODE_PHY,		/* HSUSB2 - USB3322C <-> WWAN */
	.port_mode[2] = OMAP_USBHS_PORT_MODE_UNUSED,	/* HSUSB3 - n/a */

	.phy_reset  = true,
	.reset_gpio_port[0]  = -EINVAL,
	.reset_gpio_port[1]  = 174,
	.reset_gpio_port[2]  = -EINVAL
};

static struct omap_board_mux board_mux[] __initdata = {
	/* Enable GPT11_PWM_EVT instead of GPIO-57 */
	OMAP3_MUX(GPMC_NCS6, OMAP_MUX_MODE3),

	{ .reg_offset = OMAP_MUX_TERMINATOR },
};

struct wakeup_source *wake_3g;
static irqreturn_t wake_3G_irq(int irq, void *handle)
{
	printk("3G Wakeup\n");
	__pm_wakeup_event(wake_3g, 0);
	return IRQ_HANDLED;
}

static int __init wake_3G_init(void)
{
	int err;

	omap_mux_init_gpio(WO3G_GPIO, OMAP_PIN_INPUT | OMAP_WAKEUP_EN);
	if (gpio_request(WO3G_GPIO, "3G_wakeup"))
		return -ENODEV;

	if (gpio_direction_input(WO3G_GPIO))
		return -ENXIO;

	gpio_export(WO3G_GPIO, 0);
//	gpio_set_debounce(WO3G_GPIO, 350);
	irq_set_irq_wake(OMAP_GPIO_IRQ(WO3G_GPIO), 1);

	wake_3g = wakeup_source_register("3g");

	err = request_irq(OMAP_GPIO_IRQ(WO3G_GPIO),
			  wake_3G_irq, IRQF_SHARED|IRQF_TRIGGER_RISING,
			  "wake_3G", (void*)wake_3G_init);
	return err;
}

static void __init gta04_opp_init(void)
{
	int r = 0;

	/* Initialize the omap3 opp table */
	if (omap3_opp_init()) {
		pr_err("%s: opp default init failed\n", __func__);
		return;
	}

	/* Custom OPP enabled for all xM versions */
	if (cpu_is_omap3630()) {
		struct device *mpu_dev, *iva_dev;

		mpu_dev = omap_device_get_by_hwmod_name("mpu");
		iva_dev = omap_device_get_by_hwmod_name("iva");

		if (!mpu_dev || !iva_dev) {
			pr_err("%s: Aiee.. no mpu/dsp devices? %p %p\n",
				__func__, mpu_dev, iva_dev);
			return;
		}
		/* Enable MPU 1GHz and lower opps */
		r = opp_enable(mpu_dev, 800000000);
		/* TODO: MPU 1GHz needs SR and ABB */

		/* Enable IVA 800MHz and lower opps */
		r |= opp_enable(iva_dev, 660000000);
		/* TODO: DSP 800MHz needs SR and ABB */
		if (r) {
			pr_err("%s: failed to enable higher opp %d\n",
				__func__, r);
			/*
			 * Cleanup - disable the higher freqs - we dont care
			 * about the results
			 */
			opp_disable(mpu_dev, 800000000);
			opp_disable(iva_dev, 660000000);
		}
	}
}

static void __init gta04_init(void)
{
	int err;

	printk("running gta04_init()\n");
	omap3_mux_init(board_mux, OMAP_PACKAGE_CBB);
	gta04_init_rev();
	gta04_i2c_init();

	regulator_has_full_constraints_listed(all_reg_data);
	omap_serial_init();
	omap_sdrc_init(mt46h32m32lf6_sdrc_params,
		       mt46h32m32lf6_sdrc_params);

	omap_display_init(&gta04_dss_data);

	platform_add_devices(gta04_devices,
						ARRAY_SIZE(gta04_devices));
	omap2_hsmmc_init(mmc);

// #ifdef CONFIG_OMAP_MUX

	// for a definition of the mux names see arch/arm/mach-omap2/mux34xx.c
	// the syntax of the first paramter to omap_mux_init_signal() is "muxname" or "m0name.muxname" (for ambiguous modes)
	// note: calling omap_mux_init_signal() overwrites the parameter string...

// 	omap_mux_init_signal("mcbsp3_clkx.uart2_tx", OMAP_PIN_OUTPUT);	// gpio 142 / GPS TX
// 	omap_mux_init_signal("mcbsp3_fsx.uart2_rx", OMAP_PIN_INPUT);	// gpio 143 / GPS RX

// #else
// #error we need CONFIG_OMAP_MUX
// #endif

	printk(KERN_INFO "Revision GTA04A%d\n", gta04_version);
	// gpio_export() allows to access through /sys/devices/virtual/gpio/gpio*/value

#if 0
	//	omap_mux_init_gpio(170, OMAP_PIN_INPUT);
	omap_mux_init_gpio(170, OMAP_PIN_OUTPUT);
	gpio_request(170, "DVI_nPD");
	gpio_direction_output(170, false);	/* leave DVI powered down until it's needed ... */
	gpio_export(170, 0);	// no direction change
#endif

	gpio_request(145, "GPS_ON");
	gpio_direction_output(145, false);
	gpio_export(145, 0);	// no direction change

	// omap_mux_init_signal("gpio138", OMAP_PIN_INPUT);	// gpio 138 - with no pullup/pull-down
	gpio_request(144, "EXT_ANT");
	gpio_direction_input(144);
	gpio_export(144, 0);	// no direction change


	if(gta04_version >= 4) { /* feature of GTA04A4 */
		omap_mux_init_gpio(186, OMAP_PIN_OUTPUT);    // this needs CONFIG_OMAP_MUX!
		gpio_request(186, "WWAN_RESET");
		gpio_direction_output(186, 0); // keep initial value 
		gpio_export(186, 0);    // no direction change
        }

#ifdef GTA04A2
	// has different pins but neither chips are installed

#else

	// enable AUX out/Headset switch
	gpio_request(55, "AUX_OUT");
	gpio_direction_output(55, true);
	gpio_export(55, 0);	// no direction change

	// disable Video out switch
	gpio_request(23, "VIDEO_OUT");
	gpio_direction_output(23, false);
	gpio_export(23, 0);	// no direction change

#endif

	err = wake_3G_init();
	if (err)
		printk("Failed to init 3G wake interrupt: %d\n", err);

	usb_musb_init(NULL);
	usbhs_init(&usbhs_bdata);
	omap_nand_flash_init(NAND_BUSWIDTH_16, gta04_nand_partitions,
		ARRAY_SIZE(gta04_nand_partitions));

	/* Ensure SDRC pins are mux'd for self-refresh */
	omap_mux_init_signal("sdrc_cke0", OMAP_PIN_OUTPUT);
	omap_mux_init_signal("sdrc_cke1", OMAP_PIN_OUTPUT);

	/* TPS65950 mSecure initialization for write access enabling to RTC registers */
	omap_mux_init_gpio(TWL4030_MSECURE_GPIO, OMAP_PIN_OUTPUT);	// this needs CONFIG_OMAP_MUX!
	gpio_request(TWL4030_MSECURE_GPIO, "mSecure");
	gpio_direction_output(TWL4030_MSECURE_GPIO, true);

	gta04_opp_init();

	printk("gta04_init done...\n");
}

MACHINE_START(GTA04, "GTA04")
	/* Maintainer: Nikolaus Schaller - http://www.gta04.org */
// 	.phys_io	= 0x48000000,
// 	.io_pg_offst	= ((0xfa000000) >> 18) & 0xfffc,
//	.boot_params	=	0x80000100,
	.atag_offset	=	0x100,
	.reserve	=	omap_reserve,
	.map_io		=	omap3_map_io,
	.init_irq	=	omap3_init_irq,
	.init_early	=	gta04_init_early,
	.init_machine	=	gta04_init,
	.timer		=	&omap3_secure_timer,
MACHINE_END
