/*
 * TWL4030/TPS65950 BCI (Battery Charger Interface) driver
 *
 * Copyright (C) 2010 Gražvydas Ignotas <notasas@gmail.com>
 *
 * based on twl4030_bci_battery.c by TI
 * Copyright (C) 2008 Texas Instruments, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/i2c/twl.h>
#include <linux/power_supply.h>
#include <linux/notifier.h>
#include <linux/usb/otg.h>
#include <linux/regulator/machine.h>

#define TWL4030_BCIMDEN		0x00
#define TWL4030_BCIMDKEY	0x01
#define TWL4030_BCIMSTATEC	0x02
#define TWL4030_BCIICHG		0x08
#define TWL4030_BCIVAC		0x0a
#define TWL4030_BCIVBUS		0x0c
#define TWL4030_BCIMFSTS3	0x0F
#define TWL4030_BCIMFSTS4	0x10
#define TWL4030_BCICTL1		0x23
#define TWL4030_BB_CFG		0x12
#define TWL4030_BCIIREF1	0x27
#define TWL4030_BCIIREF2	0x28
#define TWL4030_BCIMFKEY	0x11
#define TWL4030_BCIMFEN3	0x14
#define TWL4030_BCIMFTH2	0x17
#define TWL4030_BCIMFTH8	0x1d
#define TWL4030_BCIMFTH9	0x1e
#define TWL4030_BCIWDKEY	0x21

#define TWL4030_BCIMFSTS1	0x01

#define TWL4030_BCIAUTOWEN	BIT(5)
#define TWL4030_CONFIG_DONE	BIT(4)
#define TWL4030_CVENAC		BIT(2)
#define TWL4030_BCIAUTOUSB	BIT(1)
#define TWL4030_BCIAUTOAC	BIT(0)
#define TWL4030_CGAIN		BIT(5)
#define TWL4030_USBFASTMCHG	BIT(2)
#define TWL4030_USBSLOWMCHG     BIT(1)
#define TWL4030_STS_VBUS	BIT(7)
#define TWL4030_STS_USB_ID	BIT(2)
#define TWL4030_BBCHEN		BIT(4)
#define TWL4030_BBSEL_MASK	0x0c
#define TWL4030_BBSEL_2V5	0x00
#define TWL4030_BBSEL_3V0	0x04
#define TWL4030_BBSEL_3V1	0x08
#define TWL4030_BBSEL_3V2	0x0c
#define TWL4030_BBISEL_MASK	0x03
#define TWL4030_BBISEL_25uA	0x00
#define TWL4030_BBISEL_150uA	0x01
#define TWL4030_BBISEL_500uA	0x02
#define TWL4030_BBISEL_1000uA	0x03

#define TWL4030_BATSTSPCHG	BIT(2)
#define TWL4030_BATSTSMCHG	BIT(6)

/* BCI interrupts */
#define TWL4030_WOVF		BIT(0) /* Watchdog overflow */
#define TWL4030_TMOVF		BIT(1) /* Timer overflow */
#define TWL4030_ICHGHIGH	BIT(2) /* Battery charge current high */
#define TWL4030_ICHGLOW		BIT(3) /* Battery cc. low / FSM state change */
#define TWL4030_ICHGEOC		BIT(4) /* Battery current end-of-charge */
#define TWL4030_TBATOR2		BIT(5) /* Battery temperature out of range 2 */
#define TWL4030_TBATOR1		BIT(6) /* Battery temperature out of range 1 */
#define TWL4030_BATSTS		BIT(7) /* Battery status */

#define TWL4030_VBATLVL		BIT(0) /* VBAT level */
#define TWL4030_VBATOV		BIT(1) /* VBAT overvoltage */
#define TWL4030_VBUSOV		BIT(2) /* VBUS overvoltage */
#define TWL4030_ACCHGOV		BIT(3) /* Ac charger overvoltage */

#define TWL4030_MSTATEC_USB		BIT(4)
#define TWL4030_MSTATEC_AC		BIT(5)
#define TWL4030_MSTATEC_MASK		0x0f
#define TWL4030_MSTATEC_QUICK1		0x02
#define TWL4030_MSTATEC_QUICK7		0x07
#define TWL4030_MSTATEC_COMPLETE1	0x0b
#define TWL4030_MSTATEC_COMPLETE4	0x0e

static bool allow_usb;
module_param(allow_usb, bool, 0644);
MODULE_PARM_DESC(allow_usb, "Allow USB charge drawing default current");

static int default_usb_current = 100000;
module_param(default_usb_current, int, 0644);
MODULE_PARM_DESC(default_usb_current, "Default usb current for newly connected devices in uA");
struct twl4030_bci {
	struct device		*dev;
	struct power_supply	ac;
	struct power_supply	usb;
	struct usb_phy		*transceiver;
	struct notifier_block	usb_nb;
	struct work_struct	work;
	int			irq_chg;
	int			irq_bci;
	struct regulator	*usb_reg;
	int			usb_enabled;
	int			min_battery_mvolts_ac;
	int			min_battery_mvolts_usb;
	int			usb_mode, ac_mode; /* charging mode requested */
#define	CHARGE_OFF	0
#define	CHARGE_AUTO	1
#define	CHARGE_LINEAR	2

	/* ichg values in uA. If any are 'large', we set CGAIN to
	 * '1' which doubles the range for half the precision.
	 */
	int			ichg_eoc, ichg_lo, ichg_hi, ichg;

	unsigned long		event;
};

/*
 * clear and set bits on an given register on a given module
 */
static int twl4030_clear_set(u8 mod_no, u8 clear, u8 set, u8 reg)
{
	u8 val = 0;
	int ret;

	ret = twl_i2c_read_u8(mod_no, &val, reg);
	if (ret)
		return ret;

	val &= ~clear;
	val |= set;

	return twl_i2c_write_u8(mod_no, val, reg);
}

static int twl4030_bci_read(u8 reg, u8 *val)
{
	return twl_i2c_read_u8(TWL_MODULE_MAIN_CHARGE, val, reg);
}

static int twl4030_clear_set_boot_bci(u8 clear, u8 set)
{
	return twl4030_clear_set(TWL_MODULE_PM_MASTER, clear,
			TWL4030_CONFIG_DONE | TWL4030_BCIAUTOWEN | set,
			TWL4030_PM_MASTER_BOOT_BCI);
}

static int twl4030bci_read_adc_val(u8 reg)
{
	int ret, temp;
	u8 val;

	/* read MSB */
	ret = twl4030_bci_read(reg + 1, &val);
	if (ret)
		return ret;

	temp = (int)(val & 0x03) << 8;

	/* read LSB */
	ret = twl4030_bci_read(reg, &val);
	if (ret)
		return ret;

	return temp | val;
}

/*
 * Check if Battery Pack was present
 */
static int twl4030_is_battery_present(struct twl4030_bci *bci)
{
	int ret;
	u8 val = 0;

	/* Battery presence in Main charge? */
	ret = twl_i2c_read_u8(TWL_MODULE_MAIN_CHARGE, &val, TWL4030_BCIMFSTS3);
	if (ret)
		return ret;
	if (val & TWL4030_BATSTSMCHG)
		return 0;

	/*
	 * OK, It could be that bootloader did not enable main charger,
	 * pre-charge is h/w auto. So, Battery presence in Pre-charge?
	 */
	ret = twl_i2c_read_u8(TWL4030_MODULE_PRECHARGE, &val,
			      TWL4030_BCIMFSTS1);
	if (ret)
		return ret;
	if (val & TWL4030_BATSTSPCHG)
		return 0;

	return -ENODEV;
}

/*
 * Check if VBUS power is present
 */
static int twl4030_bci_have_vbus(struct twl4030_bci *bci)
{
	int ret;
	u8 hwsts;

	ret = twl_i2c_read_u8(TWL_MODULE_PM_MASTER, &hwsts,
			      TWL4030_PM_MASTER_STS_HW_CONDITIONS);
	if (ret < 0)
		return 0;

	dev_dbg(bci->dev, "check_vbus: HW_CONDITIONS %02x\n", hwsts);

	return (hwsts & TWL4030_STS_VBUS);
}
/*
 * TI provided formulas:
 * CGAIN == 0: ICHG = (BCIICHG * 1.7) / (2^10 - 1) - 0.85
 * CGAIN == 1: ICHG = (BCIICHG * 3.4) / (2^10 - 1) - 1.7
 * Here we use integer approximation of:
 * CGAIN == 0: val * 1.6618 - 0.85 * 1000
 * CGAIN == 1: (val * 1.6618 - 0.85 * 1000) * 2
 */
/*
 * convert twl register value for currents into uA
 */
static int regval2ua(int regval, bool cgain)
{
	if (cgain)
		return (regval * 16618 - 850 * 10000) / 5;
	else
		return (regval * 16618 - 850 * 10000) / 10;
}

/*
 * convert uA currents into twl register value
 */
static int ua2regval(int ua, bool cgain)
{
	int ret;
	if (cgain)
		ua /= 2;
	ret = (ua * 10 + 850 * 10000) / 16618;
	/* rounding problems */
	if (ret < 512)
		ret = 512;
	return ret;
}

static int twl4030_charger_set_max_current(int cur, bool cgain)
{
	int status;
	cur = ua2regval(cur, cgain);
	/* we have only 10 bit */
	if (cur > 0x3ff)
		cur = 0x3ff;
	/* disable write protection for one write access for BCIIREF */
	status = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0xE7,
			TWL4030_BCIMFKEY);
	if (status < 0)
		return status;
	status = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE,
			(cur & 0x100) ? 3 : 2, TWL4030_BCIIREF2);
	if (status < 0)
		return status;
	/* disable write protection for one write access for BCIIREF */
	status = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0xE7,
			TWL4030_BCIMFKEY);
	if (status < 0)
		return status;
	status = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, cur & 0xff,
			TWL4030_BCIIREF1);
	return status;
}

static int twl4030_charger_update_current(struct twl4030_bci *bci)
{
	int status;
	unsigned reg;
	u8 bcictl1, oldreg, fullreg;
	int cgain = 0;

	/* First, check thresholds and see if cgain is needed */
	if (bci->ichg_eoc >= 200000)
		cgain = 1;
	if (bci->ichg_lo >= 400000)
		cgain = 1;
	if (bci->ichg_hi >= 820000)
		cgain = 1;
	if (bci->ichg > 852000)
		cgain = 1;

	if (!cgain) {
		status = twl4030_bci_read(TWL4030_BCICTL1, &bcictl1);
		if (status < 0)
			return status;
		if (bcictl1 & TWL4030_CGAIN) {
			bcictl1 &= ~TWL4030_CGAIN;
			twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE,
					 bcictl1, TWL4030_BCICTL1);
		}
	}

	/* For ichg_eoc, reg value must be 100XXXX000, we only
	 * set the XXXX
	 */
	reg = ua2regval(bci->ichg_eoc, cgain);
	if (reg > 0x278)
		reg = 0x278;
	if (reg < 0x200)
		reg = 0x200;
	reg = (reg >> 3) & 0xf;
	fullreg = reg << 4;

	/* For ichg_lo, reg value must be 10XXXX0000. */
	reg = ua2regval(bci->ichg_lo, cgain);
	if (reg > 0x2F0)
		reg = 0x2F0;
	if (reg < 0x200)
		reg = 0x200;
	reg = (reg >> 4) & 0xf;
	fullreg |= reg;

	/* ichg_eoc and ichg_lo live in same register */
	status = twl4030_bci_read(TWL4030_BCIMFTH8, &oldreg);
	if (status < 0)
		return status;
	if (oldreg != fullreg) {
		status = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0xF4,
					  TWL4030_BCIMFKEY);
		if (status < 0)
			return status;
		twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE,
				 fullreg, TWL4030_BCIMFTH8);
	}

	/* ichg_hi must be 1XXXX01100 (I think) */
	reg = ua2regval(bci->ichg_hi, cgain);
	if (reg > 0x3E0)
		reg = 0x3E0;
	if (reg < 0x200)
		reg = 0x200;
	fullreg = (reg >> 5) & 0xF;
	fullreg <<= 4;
	status = twl4030_bci_read(TWL4030_BCIMFTH9, &oldreg);
	if (status < 0)
		return status;
	if ((oldreg & 0xF0) != fullreg) {
		fullreg |= (oldreg & 0x0F);
		status = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0xE7,
					  TWL4030_BCIMFKEY);
		if (status < 0)
			return status;
		twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE,
				 fullreg, TWL4030_BCIMFTH9);
	}

	/* And finally, set the current */
	twl4030_charger_set_max_current(bci->ichg, cgain);

	if (cgain) {
		status = twl4030_bci_read(TWL4030_BCICTL1, &bcictl1);
		if (status < 0)
			return status;
		if (!(bcictl1 & TWL4030_CGAIN)) {
			bcictl1 |= TWL4030_CGAIN;
			twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE,
					 bcictl1, TWL4030_BCICTL1);
		}
	}
	return 0;
}

/*
 * Set charge-start voltage.
 * When battery voltage drops below BATOV4 the charging cycle
 * will restart.
 * The default is 3.95V which corresponds to about 75% charge on
 * Openmoko battery.
 * 4.0V is close to 90%
 * Full charge is 4.2V. 4.11V is the highest possible setting.
 * value can be from 0 to 15 which corresponds to
 * 3.761V to 4.112V in steps of 0.0234V
 *
 * Set OV3 2 points below OV4.  I'm not sure exactly what this does,
 * but the default is 2 points below....
 *
 */
static int twl4030_charger_OV4(int mV)
{
	u8 TH2;
	int ret = 0;

	TH2 = mV << 4;
	if (mV > 2)
		mV -= 2;
	else
		mV = 0;
	TH2 |= mV;
	/* Enable write */
	ret = ret ?: twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0x7F,
				      TWL4030_BCIMFKEY);
	ret = ret ?: twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, TH2,
				      TWL4030_BCIMFTH2);
	return ret;
}

static int twl4030_set_min_mvolts(struct twl4030_bci *bci)
{
	u8 s;
	twl4030_bci_read(TWL4030_BCIMDEN, &s);
	if (s & 1)
		return twl4030_charger_OV4(bci->min_battery_mvolts_usb);
	else
		return twl4030_charger_OV4(bci->min_battery_mvolts_ac);
}

static ssize_t
twl4030_bci_mvolts_show(struct device *dev, struct device_attribute *attr,
	char *buf)
{
	struct twl4030_bci *bci = dev_get_drvdata(dev->parent);
	int mv;
	if (dev == bci->ac.dev)
		mv = bci->min_battery_mvolts_ac;
	else
		mv = bci->min_battery_mvolts_usb;
	return sprintf(buf, "%d\n", (mv * 234)/10 + 3761);
}

static ssize_t
twl4030_bci_mvolts_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t n)
{
	struct twl4030_bci *bci = dev_get_drvdata(dev->parent);
	int mV;
	int ret = kstrtoint(buf, 10, &mV);
	if (ret)
		return ret;
	if (mV <= 0 || mV > 5000)
		return -EINVAL;

	/* Convert millivolts to setting for TWL4030 */
	mV -= 3761;
	if (mV < 0)
		mV = 0;
	mV = mV*10 / 234;
	if (mV > 15)
		mV = 15;

	if (dev == bci->ac.dev)
		bci->min_battery_mvolts_ac = mV;
	else
		bci->min_battery_mvolts_usb = mV;

	ret = twl4030_set_min_mvolts(bci);
	if (ret)
		return ret;
	return n;
}
static DEVICE_ATTR(min_battery_mvolts, 0644, twl4030_bci_mvolts_show,
		   twl4030_bci_mvolts_store);

/*
 * Enable/Disable USB Charge functionality.
 */
static int twl4030_charger_enable_usb(struct twl4030_bci *bci, bool enable)
{
	int ret;

	if (bci->usb_mode == CHARGE_OFF)
		enable = false;
	if (enable) {
		/* Check for USB charger connected */
		if (bci->usb_mode == CHARGE_AUTO && !twl4030_bci_have_vbus(bci))
			return -ENODEV;

		/* Need to keep regulator on */
		if (!bci->usb_enabled) {
			ret = regulator_enable(bci->usb_reg);
			if (ret) {
				dev_err(bci->dev,
					"Failed to enable regulator\n");
				return ret;
			}
			bci->usb_enabled = 1;
		}

		twl4030_charger_update_current(bci);

		if (bci->usb_mode == CHARGE_AUTO) {
			/* forcing the field BCIAUTOUSB (BOOT_BCI[1]) to 1 */
			ret = twl4030_clear_set_boot_bci(0, TWL4030_BCIAUTOUSB);
			if (ret < 0)
				return ret;
			twl4030_clear_set_boot_bci(0, TWL4030_BCIAUTOAC|TWL4030_CVENAC);
			twl4030_set_min_mvolts(bci);
		}

		/* forcing USBFASTMCHG(BCIMFSTS4[2]) to 1 */
		ret = twl4030_clear_set(TWL_MODULE_MAIN_CHARGE,
			TWL4030_USBSLOWMCHG,
			TWL4030_USBFASTMCHG, TWL4030_BCIMFSTS4);
		if (bci->usb_mode == CHARGE_LINEAR) {
			twl4030_clear_set_boot_bci(TWL4030_BCIAUTOAC|TWL4030_CVENAC, 0);
			/* Watch dog key: WOVF acknowledge */
			ret = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0x33,
					       TWL4030_BCIWDKEY);
			/* 0x24 + EKEY6:  off mode */
			ret = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0x2a,
					       TWL4030_BCIMDKEY);
			/* EKEY2: Linear charge: usb path */
			ret = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0x26,
					       TWL4030_BCIMDKEY);
			/* WDKEY5: stop watchdog count */
			ret = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0xf3,
					       TWL4030_BCIWDKEY);
			/* enable MFEN3 access */
			ret = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0x9c,
					       TWL4030_BCIMFKEY);
			 /* ICHGEOCEN - end-of-charge monitor (current < 80mA)
			  *                      (charging continues)
			  * ICHGLOWEN - current level monitor (charge continues)
			  * don't monitor over-current or heat save
			  */
			ret = twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0xf0,
					       TWL4030_BCIMFEN3);
		}
	} else {
		ret = twl4030_clear_set_boot_bci(TWL4030_BCIAUTOUSB|TWL4030_CVENAC, 0);
		ret |= twl_i2c_write_u8(TWL_MODULE_MAIN_CHARGE, 0x2a,
					TWL4030_BCIMDKEY);
		if (bci->usb_enabled) {
			regulator_disable(bci->usb_reg);
			bci->usb_enabled = 0;
		}
		twl4030_set_min_mvolts(bci);
	}

	return ret;
}

/*
 * Enable/Disable AC Charge funtionality.
 */
static int twl4030_charger_enable_ac(struct twl4030_bci *bci, bool enable)
{
	int ret;

	if (bci->ac_mode == CHARGE_OFF)
		enable = false;

	if (enable)
		ret = twl4030_clear_set_boot_bci(0, TWL4030_BCIAUTOAC);
	else
		ret = twl4030_clear_set_boot_bci(TWL4030_BCIAUTOAC, 0);

	return ret;
}

/*
 * Enable/Disable charging of Backup Battery.
 */
static int twl4030_charger_enable_backup(int uvolt, int uamp)
{
	int ret;
	u8 flags;

	if (uvolt < 2500000 ||
	    uamp < 25) {
		/* disable charging of backup battery */
		ret = twl4030_clear_set(TWL_MODULE_PM_RECEIVER,
					TWL4030_BBCHEN, 0, TWL4030_BB_CFG);
		return ret;
	}

	flags = TWL4030_BBCHEN;
	if (uvolt >= 3200000)
		flags |= TWL4030_BBSEL_3V2;
	else if (uvolt >= 3100000)
		flags |= TWL4030_BBSEL_3V1;
	else if (uvolt >= 3000000)
		flags |= TWL4030_BBSEL_3V0;
	else
		flags |= TWL4030_BBSEL_2V5;

	if (uamp >= 1000)
		flags |= TWL4030_BBISEL_1000uA;
	else if (uamp >= 500)
		flags |= TWL4030_BBISEL_500uA;
	else if (uamp >= 150)
		flags |= TWL4030_BBISEL_150uA;
	else
		flags |= TWL4030_BBISEL_25uA;

	ret = twl4030_clear_set(TWL_MODULE_PM_RECEIVER,
				TWL4030_BBSEL_MASK | TWL4030_BBISEL_MASK,
				flags,
				TWL4030_BB_CFG);

	return ret;
}

/*
 * TWL4030 CHG_PRES (AC charger presence) events
 */
static irqreturn_t twl4030_charger_interrupt(int irq, void *arg)
{
	struct twl4030_bci *bci = arg;

	dev_dbg(bci->dev, "CHG_PRES irq\n");
	power_supply_changed(&bci->ac);
	power_supply_changed(&bci->usb);

	return IRQ_HANDLED;
}

/*
 * TWL4030 BCI monitoring events
 */
static irqreturn_t twl4030_bci_interrupt(int irq, void *arg)
{
	struct twl4030_bci *bci = arg;
	u8 irqs1, irqs2;
	int ret;

	ret = twl_i2c_read_u8(TWL4030_MODULE_INTERRUPTS, &irqs1,
			      TWL4030_INTERRUPTS_BCIISR1A);
	if (ret < 0)
		return IRQ_HANDLED;

	ret = twl_i2c_read_u8(TWL4030_MODULE_INTERRUPTS, &irqs2,
			      TWL4030_INTERRUPTS_BCIISR2A);
	if (ret < 0)
		return IRQ_HANDLED;

	dev_dbg(bci->dev, "BCI irq %02x %02x\n", irqs2, irqs1);

	if (irqs1 & (TWL4030_ICHGLOW | TWL4030_ICHGEOC)) {
		/* charger state change, inform the core */
		power_supply_changed(&bci->ac);
		power_supply_changed(&bci->usb);
	}

	/* various monitoring events, for now we just log them here */
	if (irqs1 & (TWL4030_TBATOR2 | TWL4030_TBATOR1))
		dev_warn(bci->dev, "battery temperature out of range\n");

	if (irqs1 & TWL4030_BATSTS)
		dev_crit(bci->dev, "battery disconnected\n");

	if (irqs2 & TWL4030_VBATOV)
		dev_crit(bci->dev, "VBAT overvoltage\n");

	if (irqs2 & TWL4030_VBUSOV)
		dev_crit(bci->dev, "VBUS overvoltage\n");

	if (irqs2 & TWL4030_ACCHGOV)
		dev_crit(bci->dev, "Ac charger overvoltage\n");

	return IRQ_HANDLED;
}

static void twl4030_bci_usb_work(struct work_struct *data)
{
	struct twl4030_bci *bci = container_of(data, struct twl4030_bci, work);

	/* reset current on each 'plug' event */
	if (allow_usb && default_usb_current < 500000)
		bci->ichg = 500000;
	else
		bci->ichg = default_usb_current;

	switch (bci->event) {
	case USB_EVENT_VBUS:
	case USB_EVENT_CHARGER:
		twl4030_charger_enable_usb(bci, true);
		break;
	case USB_EVENT_NONE:
		twl4030_charger_enable_usb(bci, false);
		break;
	}
}

static int twl4030_bci_usb_ncb(struct notifier_block *nb, unsigned long val,
			       void *priv)
{
	struct twl4030_bci *bci = container_of(nb, struct twl4030_bci, usb_nb);

	dev_dbg(bci->dev, "OTG notify %lu\n", val);

	bci->event = val;
	schedule_work(&bci->work);

	return NOTIFY_OK;
}

/*
 * sysfs max_current store
 */
static ssize_t
twl4030_bci_max_current_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t n)
{
	struct twl4030_bci *bci = dev_get_drvdata(dev);
	int cur = 0;
	int status = 0;
	status = kstrtoint(buf, 10, &cur);
	if (status)
		return status;
	if (cur < 0)
		return -EINVAL;
	if (bci->ichg == cur)
		return n;
	bci->ichg = cur;
	twl4030_charger_enable_usb(bci, false);
	twl4030_charger_enable_ac(bci, false);
	twl4030_charger_update_current(bci);
	twl4030_charger_enable_ac(bci, true);
	twl4030_charger_enable_usb(bci, true);
	return (status == 0) ? n : status;
}

/*
 * sysfs max_current show
 */
static ssize_t twl4030_bci_max_current_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int status = 0;
	int cur;
	u8 bcictl1;
	cur = twl4030bci_read_adc_val(TWL4030_BCIIREF1);
	if (cur < 0)
		return cur;
	status = twl4030_bci_read(TWL4030_BCICTL1, &bcictl1);
	if (status < 0)
		return status;
	cur = regval2ua(cur, bcictl1 & TWL4030_CGAIN);
	return scnprintf(buf, PAGE_SIZE, "%u\n", cur);
}

static DEVICE_ATTR(max_current, 0644, twl4030_bci_max_current_show,
			twl4030_bci_max_current_store);

/*
 * sysfs charger enabled store
 */
static char *modes[] = { "off", "auto", "continuous" };
static ssize_t
twl4030_bci_mode_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t n)
{
	struct twl4030_bci *bci = dev_get_drvdata(dev->parent);
	int mode;
	int status;

	if (sysfs_streq(buf, modes[0]))
		mode = 0;
	else if (sysfs_streq(buf, modes[1]))
		mode = 1;
	else if (sysfs_streq(buf, modes[2]))
		mode = 2;
	else
		return -EINVAL;
	if (dev == bci->ac.dev) {
		if (mode == CHARGE_LINEAR)
			/* Not yet supported */
			return -EINVAL;
		twl4030_charger_enable_ac(bci, false);
		bci->ac_mode = mode;
		status = twl4030_charger_enable_ac(bci, true);
	} else {
		twl4030_charger_enable_usb(bci, false);
		bci->usb_mode = mode;
		status = twl4030_charger_enable_usb(bci, true);
	}
	return (status == 0) ? n : status;
}

/*
 * sysfs charger enabled show
 */
static ssize_t
twl4030_bci_mode_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct twl4030_bci *bci = dev_get_drvdata(dev->parent);
	int len = 0;
	int i;
	int mode = bci->usb_mode;

	if (dev == bci->ac.dev)
		mode = bci->ac_mode;

	for (i = 0; i < ARRAY_SIZE(modes); i++)
		if (mode == i)
			len += snprintf(buf+len, PAGE_SIZE-len,
					"[%s] ", modes[i]);
		else
			len += snprintf(buf+len, PAGE_SIZE-len,
					"%s ", modes[i]);
	buf[len-1] = '\n';
	return len;
}
static DEVICE_ATTR(mode, 0644, twl4030_bci_mode_show,
		   twl4030_bci_mode_store);

static int twl4030_charger_get_current(void)
{
	int curr;
	int ret;
	u8 bcictl1;

	curr = twl4030bci_read_adc_val(TWL4030_BCIICHG);
	if (curr < 0)
		return curr;

	ret = twl4030_bci_read(TWL4030_BCICTL1, &bcictl1);
	if (ret)
		return ret;
	return regval2ua(curr, bcictl1 & TWL4030_CGAIN);
}

/*
 * Returns the main charge FSM state
 * Or < 0 on failure.
 */
static int twl4030bci_state(struct twl4030_bci *bci)
{
	int ret;
	u8 state;

	ret = twl4030_bci_read(TWL4030_BCIMSTATEC, &state);
	if (ret) {
		pr_err("twl4030_bci: error reading BCIMSTATEC\n");
		return ret;
	}

	dev_dbg(bci->dev, "state: %02x\n", state);

	return state;
}

static int twl4030_bci_state_to_status(int state)
{
	state &= TWL4030_MSTATEC_MASK;
	if (TWL4030_MSTATEC_QUICK1 <= state && state <= TWL4030_MSTATEC_QUICK7)
		return POWER_SUPPLY_STATUS_CHARGING;
	else if (TWL4030_MSTATEC_COMPLETE1 <= state &&
					state <= TWL4030_MSTATEC_COMPLETE4)
		return POWER_SUPPLY_STATUS_FULL;
	else
		return POWER_SUPPLY_STATUS_NOT_CHARGING;
}

static int twl4030_bci_get_property(struct power_supply *psy,
				    enum power_supply_property psp,
				    union power_supply_propval *val)
{
	struct twl4030_bci *bci = dev_get_drvdata(psy->dev->parent);
	int is_charging;
	int state;
	int ret;

	state = twl4030bci_state(bci);
	if (state < 0)
		return state;

	if (psy->type == POWER_SUPPLY_TYPE_USB)
		is_charging = state & TWL4030_MSTATEC_USB;
	else
		is_charging = state & TWL4030_MSTATEC_AC;
	if (!is_charging) {
		u8 s;
		twl4030_bci_read(TWL4030_BCIMDEN, &s);
		if (psy->type == POWER_SUPPLY_TYPE_USB)
			is_charging = s & 1;
		else
			is_charging = s & 2;
		if (is_charging)
			/* A little white lie */
			state = TWL4030_MSTATEC_QUICK1;
	}

	switch (psp) {
	case POWER_SUPPLY_PROP_STATUS:
		if (is_charging)
			val->intval = twl4030_bci_state_to_status(state);
		else
			val->intval = POWER_SUPPLY_STATUS_NOT_CHARGING;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		/* charging must be active for meaningful result */
		if (!is_charging)
			return -ENODATA;
		if (psy->type == POWER_SUPPLY_TYPE_USB) {
			ret = twl4030bci_read_adc_val(TWL4030_BCIVBUS);
			if (ret < 0)
				return ret;
			/* BCIVBUS uses ADCIN8, 7/1023 V/step */
			val->intval = ret * 6843;
		} else {
			ret = twl4030bci_read_adc_val(TWL4030_BCIVAC);
			if (ret < 0)
				return ret;
			/* BCIVAC uses ADCIN11, 10/1023 V/step */
			val->intval = ret * 9775;
		}
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		if (!is_charging)
			return -ENODATA;
		/* current measurement is shared between AC and USB */
		ret = twl4030_charger_get_current();
		if (ret < 0)
			return ret;
		val->intval = ret;
		break;
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = is_charging &&
			twl4030_bci_state_to_status(state) !=
				POWER_SUPPLY_STATUS_NOT_CHARGING;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static enum power_supply_property twl4030_charger_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_ONLINE,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CURRENT_NOW,
};

#ifdef CONFIG_OF
static const struct twl4030_bci_platform_data *
twl4030_bci_parse_dt(struct device *dev)
{
	struct device_node *np = dev->of_node;
	struct twl4030_bci_platform_data *pdata;
	u32 num;

	if (!np)
		return NULL;
	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return pdata;

	if (of_property_read_u32(np, "ti,bb-uvolt", &num) == 0)
		pdata->bb_uvolt = num;
	if (of_property_read_u32(np, "ti,bb-uamp", &num) == 0)
		pdata->bb_uamp = num;
	return pdata;
}
#else
static inline const struct twl4030_bci_platform_data *
twl4030_bci_parse_dt(struct device *dev)
{
	return NULL;
}
#endif

static int __init twl4030_bci_probe(struct platform_device *pdev)
{
	struct twl4030_bci *bci;
	const struct twl4030_bci_platform_data *pdata = pdev->dev.platform_data;
	int ret;
	u32 reg;

	bci = kzalloc(sizeof(*bci), GFP_KERNEL);
	if (bci == NULL)
		return -ENOMEM;

	if (!pdata)
		pdata = twl4030_bci_parse_dt(&pdev->dev);

	/* Hardware default is 3950. Max is 4113.
	 * We let's try 4070 - hopefully not too high
	 * For 'ac' it is likely to be plugged in continuously
	 * so a lower minimum is OK.
	 */
	bci->min_battery_mvolts_usb = 0xC;
	bci->min_battery_mvolts_ac = 0x8;
	bci->usb_mode = CHARGE_AUTO;
	bci->ac_mode = CHARGE_AUTO;

	bci->ichg_eoc = 80100; /* Stop charging when current drops to here */
	bci->ichg_lo = 241000; /* low threshold */
	bci->ichg_hi = 500000; /* High threshold */
	bci->ichg = default_usb_current;

	bci->dev = &pdev->dev;
	bci->irq_chg = platform_get_irq(pdev, 0);
	bci->irq_bci = platform_get_irq(pdev, 1);

	/* Only proceed further *IF* battery is physically present */
	ret = twl4030_is_battery_present(bci);
	if  (ret) {
		dev_crit(&pdev->dev, "Battery was not detected:%d\n", ret);
		goto fail_no_battery;
	}

	platform_set_drvdata(pdev, bci);
	bci->ac.name = "twl4030_ac";
	bci->ac.type = POWER_SUPPLY_TYPE_MAINS;
	bci->ac.properties = twl4030_charger_props;
	bci->ac.num_properties = ARRAY_SIZE(twl4030_charger_props);
	bci->ac.get_property = twl4030_bci_get_property;

	ret = power_supply_register(&pdev->dev, &bci->ac);
	if (ret) {
		dev_err(&pdev->dev, "failed to register ac: %d\n", ret);
		goto fail_register_ac;
	}

	bci->usb.name = "twl4030_usb";
	bci->usb.type = POWER_SUPPLY_TYPE_USB;
	bci->usb.properties = twl4030_charger_props;
	bci->usb.num_properties = ARRAY_SIZE(twl4030_charger_props);
	bci->usb.get_property = twl4030_bci_get_property;

	bci->usb_reg = regulator_get(bci->dev, "bci3v1");

	ret = power_supply_register(&pdev->dev, &bci->usb);
	if (ret) {
		dev_err(&pdev->dev, "failed to register usb: %d\n", ret);
		goto fail_register_usb;
	}

	ret = request_threaded_irq(bci->irq_chg, NULL,
			twl4030_charger_interrupt, IRQF_ONESHOT, pdev->name,
			bci);
	if (ret < 0) {
		dev_err(&pdev->dev, "could not request irq %d, status %d\n",
			bci->irq_chg, ret);
		goto fail_chg_irq;
	}

	ret = request_threaded_irq(bci->irq_bci, NULL,
			twl4030_bci_interrupt, IRQF_ONESHOT, pdev->name, bci);
	if (ret < 0) {
		dev_err(&pdev->dev, "could not request irq %d, status %d\n",
			bci->irq_bci, ret);
		goto fail_bci_irq;
	}

	INIT_WORK(&bci->work, twl4030_bci_usb_work);

	bci->transceiver = usb_get_phy(USB_PHY_TYPE_USB2);
	if (!IS_ERR_OR_NULL(bci->transceiver)) {
		bci->usb_nb.notifier_call = twl4030_bci_usb_ncb;
		usb_register_notifier(bci->transceiver, &bci->usb_nb);
	}

	/* Enable interrupts now. */
	reg = ~(u32)(TWL4030_ICHGLOW | TWL4030_ICHGEOC | TWL4030_TBATOR2 |
		TWL4030_TBATOR1 | TWL4030_BATSTS);
	ret = twl_i2c_write_u8(TWL4030_MODULE_INTERRUPTS, reg,
			       TWL4030_INTERRUPTS_BCIIMR1A);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to unmask interrupts: %d\n", ret);
		goto fail_unmask_interrupts;
	}

	reg = ~(u32)(TWL4030_VBATOV | TWL4030_VBUSOV | TWL4030_ACCHGOV);
	ret = twl_i2c_write_u8(TWL4030_MODULE_INTERRUPTS, reg,
			       TWL4030_INTERRUPTS_BCIIMR2A);
	if (ret < 0)
		dev_warn(&pdev->dev, "failed to unmask interrupts: %d\n", ret);

	if (device_create_file(&pdev->dev, &dev_attr_max_current))
		dev_warn(&pdev->dev, "could not create sysfs file\n");
	if (device_create_file(bci->usb.dev, &dev_attr_mode))
		dev_warn(&pdev->dev, "could not create sysfs file\n");
	if (device_create_file(bci->ac.dev, &dev_attr_mode))
		dev_warn(&pdev->dev, "could not create sysfs file\n");
	if (device_create_file(bci->usb.dev, &dev_attr_min_battery_mvolts))
		dev_warn(&pdev->dev, "could not create sysfs file\n");
	if (device_create_file(bci->ac.dev, &dev_attr_min_battery_mvolts))
		dev_warn(&pdev->dev, "could not create sysfs file\n");

	twl4030_charger_enable_ac(bci, true);
	twl4030_charger_enable_usb(bci, true);
	if (pdata)
		twl4030_charger_enable_backup(pdata->bb_uvolt,
					      pdata->bb_uamp);
	else
		twl4030_charger_enable_backup(0, 0);

	return 0;

fail_unmask_interrupts:
	if (!IS_ERR_OR_NULL(bci->transceiver)) {
		usb_unregister_notifier(bci->transceiver, &bci->usb_nb);
		usb_put_phy(bci->transceiver);
	}
	free_irq(bci->irq_bci, bci);
fail_bci_irq:
	free_irq(bci->irq_chg, bci);
fail_chg_irq:
	power_supply_unregister(&bci->usb);
fail_register_usb:
	power_supply_unregister(&bci->ac);
fail_register_ac:
fail_no_battery:
	kfree(bci);

	return ret;
}

static int __exit twl4030_bci_remove(struct platform_device *pdev)
{
	struct twl4030_bci *bci = platform_get_drvdata(pdev);
	device_remove_file(bci->usb.dev, &dev_attr_mode);
	device_remove_file(&pdev->dev, &dev_attr_max_current);
	device_remove_file(&pdev->dev, &dev_attr_min_battery_mvolts);
	twl4030_charger_enable_ac(bci, false);
	twl4030_charger_enable_usb(bci, false);
	twl4030_charger_enable_backup(0, 0);

	/* mask interrupts */
	twl_i2c_write_u8(TWL4030_MODULE_INTERRUPTS, 0xff,
			 TWL4030_INTERRUPTS_BCIIMR1A);
	twl_i2c_write_u8(TWL4030_MODULE_INTERRUPTS, 0xff,
			 TWL4030_INTERRUPTS_BCIIMR2A);

	if (!IS_ERR_OR_NULL(bci->transceiver)) {
		usb_unregister_notifier(bci->transceiver, &bci->usb_nb);
		usb_put_phy(bci->transceiver);
	}
	free_irq(bci->irq_bci, bci);
	free_irq(bci->irq_chg, bci);
	power_supply_unregister(&bci->usb);
	power_supply_unregister(&bci->ac);
	kfree(bci);

	return 0;
}

static const struct of_device_id twl_bci_of_match[] = {
	{.compatible = "ti,twl4030-bci", },
	{ }
};
MODULE_DEVICE_TABLE(of, twl_bci_of_match);

static struct platform_driver twl4030_bci_driver = {
	.driver	= {
		.name	= "twl4030_bci",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(twl_bci_of_match),
	},
	.remove	= __exit_p(twl4030_bci_remove),
};

module_platform_driver_probe(twl4030_bci_driver, twl4030_bci_probe);

MODULE_AUTHOR("Gražvydas Ignotas");
MODULE_DESCRIPTION("TWL4030 Battery Charger Interface driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:twl4030_bci");
