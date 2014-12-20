/*
 *    Copyright (c) 2012 NeilBrown <neilb@suse.de>
 *    Heavily based on earlier code which is:
 *    Copyright (c) 2010 Grant Erickson <marathon96@gmail.com>
 *
 *    Also based on pwm-samsung.c
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License
 *    version 2 as published by the Free Software Foundation.
 *
 *    Description:
 *      This file is the core OMAP support for the generic, Linux
 *      PWM driver / controller, using the OMAP's dual-mode timers.
 *
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/pwm.h>
#include <linux/module.h>
#include <linux/platform_data/omap-pwm.h>

#include <../arch/arm/plat-omap/include/plat/dmtimer.h>

#define DM_TIMER_LOAD_MIN		0xFFFFFFFE

struct omap_chip {
	struct omap_dm_timer	*dm_timer;
	enum pwm_polarity	polarity;
	unsigned int		duty_ns, period_ns;
	struct pwm_chip		chip;
};

#define to_omap_chip(chip)	container_of(chip, struct omap_chip, chip)

/**
 * pwm_calc_value - Determine the counter value for a clock rate and period.
 * @clk_rate: The clock rate, in Hz, of the PWM's clock source to compute the
 *            counter value for.
 * @ns: The period, in nanoseconds, to compute the counter value for.
 *
 * Returns the PWM counter value for the specified clock rate and period.
 */
static inline int pwm_calc_value(unsigned long clk_rate, int ns)
{
	u64 c;

	c = (u64)clk_rate * ns;
	do_div(c, NSEC_PER_SEC);

	return DM_TIMER_LOAD_MIN - c;
}

static int omap_pwm_enable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct omap_chip *omap = to_omap_chip(chip);

	omap_dm_timer_start(omap->dm_timer);
	omap_dm_timer_write_counter(omap->dm_timer, DM_TIMER_LOAD_MIN);

	return 0;
}

static void omap_pwm_disable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct omap_chip *omap = to_omap_chip(chip);

	omap_dm_timer_stop(omap->dm_timer);
}

static int omap_pwm_config(struct pwm_chip *chip, struct pwm_device *pwm,
			   int duty_ns, int period_ns)
{
	struct omap_chip *omap = to_omap_chip(chip);
	int load_value, match_value;
	unsigned long clk_rate;

	dev_dbg(chip->dev, "duty cycle: %d, period %d\n", duty_ns, period_ns);

	if (omap->duty_ns == duty_ns &&
	    omap->period_ns == period_ns)
		/* No change - don't cause any transients. */
		return 0;

	clk_rate = clk_get_rate(omap_dm_timer_get_fclk(omap->dm_timer));

	/*
	 * Calculate the appropriate load and match values based on the
	 * specified period and duty cycle. The load value determines the
	 * cycle time and the match value determines the duty cycle.
	 */

	load_value = pwm_calc_value(clk_rate, period_ns);
	match_value = pwm_calc_value(clk_rate, period_ns - duty_ns);

	/*
	 * We MUST enable yet stop the associated dual-mode timer before
	 * attempting to write its registers.  Hopefully it is already
	 * disabled, but call the (idempotent) pwm_disable just in case.
	 */

	pwm_disable(pwm);

	omap_dm_timer_set_load(omap->dm_timer, true, load_value);
	omap_dm_timer_set_match(omap->dm_timer, true, match_value);

	dev_dbg(chip->dev, "load value: %#08x (%d), match value: %#08x (%d)\n",
		load_value, load_value,	match_value, match_value);

	omap_dm_timer_set_pwm(omap->dm_timer,
			      omap->polarity == PWM_POLARITY_INVERSED,
			      true,
			      OMAP_TIMER_TRIGGER_OVERFLOW_AND_COMPARE);

	omap->duty_ns = duty_ns;
	omap->period_ns = period_ns;

	return 0;
}

static int omap_pwm_set_polarity(struct pwm_chip *chip, struct pwm_device *pwm,
				 enum pwm_polarity polarity)
{
	struct omap_chip *omap = to_omap_chip(chip);

	if (omap->polarity == polarity)
		return 0;

	omap->polarity = polarity;

	omap_dm_timer_set_pwm(omap->dm_timer,
			      omap->polarity == PWM_POLARITY_INVERSED,
			      true,
			      OMAP_TIMER_TRIGGER_OVERFLOW_AND_COMPARE);
	return 0;
}

static struct pwm_ops omap_pwm_ops = {
	.enable		= omap_pwm_enable,
	.disable	= omap_pwm_disable,
	.config		= omap_pwm_config,
	.set_polarity	= omap_pwm_set_polarity,
	.owner		= THIS_MODULE,
};

static int omap_pwm_from_pdata(struct omap_chip *omap,
			       struct omap_pwm_pdata *pdata)
{

	/*
	 * Request the OMAP dual-mode timer that will be bound to and
	 * associated with this generic PWM.
	 */

	omap->dm_timer = omap_dm_timer_request_specific(pdata->timer_id);
	if (omap->dm_timer == NULL)
		return -EPROBE_DEFER;

	/*
	 * Configure the source for the dual-mode timer backing this
	 * generic PWM device. The clock source will ultimately determine
	 * how small or large the PWM frequency can be.
	 *
	 * At some point, it's probably worth revisiting moving this to
	 * the configure method and choosing either the slow- or
	 * system-clock source as appropriate for the desired PWM period.
	 */

	return 0;
}

#ifdef CONFIG_OF
static inline int omap_pwm_from_dt(struct omap_chip *omap,
				  struct device *dev)
{
	struct device_node *np = dev->of_node;
	struct device_node *timer;
	if (!np)
		return -ENODEV;
	timer = of_parse_phandle(np, "timers", 0);
	if (!timer)
		return -ENODEV;

	omap->dm_timer = omap_dm_timer_request_by_node(timer);
	if (!omap->dm_timer)
		return -EPROBE_DEFER;
	return 0;
}
#else
static inline in omap_pwm_from_dt(struct omap_chip *omap,
				  struct device *dev)
{
	return -ENODEV;
}
#endif

static int omap_pwm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct omap_chip *omap;
	int status = 0;
	struct omap_pwm_pdata *pdata = dev->platform_data;

	omap = devm_kzalloc(dev, sizeof(*omap), GFP_KERNEL);
	if (omap == NULL) {
		dev_err(dev, "Could not allocate memory.\n");
		return -ENOMEM;
	}
	if (pdata)
		status = omap_pwm_from_pdata(omap, pdata);
	else
		status = omap_pwm_from_dt(omap, dev);
	if (status)
		return status;

	omap_dm_timer_set_source(omap->dm_timer, OMAP_TIMER_SRC_SYS_CLK);
	/*
	 * Cache away other miscellaneous driver-private data and state
	 * information and add the driver-private data to the platform
	 * device.
	 */

	omap->chip.dev = dev;
	omap->chip.ops = &omap_pwm_ops;
	omap->chip.base = -1;
	omap->chip.npwm = 1;
	omap->polarity = PWM_POLARITY_NORMAL;

	status = pwmchip_add(&omap->chip);
	if (status < 0) {
		dev_err(dev, "failed to register PWM\n");
		omap_dm_timer_free(omap->dm_timer);
		return status;
	}

	platform_set_drvdata(pdev, omap);

	return 0;
}

static int omap_pwm_remove(struct platform_device *pdev)
{
	struct omap_chip *omap = platform_get_drvdata(pdev);
	int status;

	omap_dm_timer_stop(omap->dm_timer);
	status = pwmchip_remove(&omap->chip);
	if (status < 0)
		return status;

	omap_dm_timer_free(omap->dm_timer);

	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id omap_pwm_of_match[] = {
	{.compatible = "ti,omap-pwm"},
	{}
};
MODULE_DEVICE_TABLE(of, omap_pwm_of_match);
#endif

static struct platform_driver omap_pwm_driver = {
	.driver = {
		.name	= "omap-pwm",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(omap_pwm_of_match),
	},
	.probe		= omap_pwm_probe,
	.remove		= omap_pwm_remove,
};
module_platform_driver(omap_pwm_driver);

MODULE_AUTHOR("Grant Erickson <marathon96@gmail.com>");
MODULE_AUTHOR("NeilBrown <neilb@suse.de>");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("2012-12-01");
MODULE_DESCRIPTION("OMAP PWM Driver using Dual-mode Timers");
