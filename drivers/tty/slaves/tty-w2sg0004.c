/*
 * tty-w2sg0004.c - tty-slave for  w2sg0004 GPS device
 *
 * Copyright (C) 2014  NeilBrown <neil@brown.name>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * The w2sg0004 is turned 'on' or 'off' by toggling a line, which
 * is normally connected to a GPIO.  Thus you need to know the current
 * state in order to determine how to achieve some particular state.
 * The only way to detect the state is by detecting transitions on
 * its TX line (our RX line).
 * So this tty slave listens for 'recv' events and deduces the GPS is
 * on if it has received one recently.
 * If suitably configure, and if the hardware is capable, it also
 * enables an interrupt (presumably via a GPIO connected to the RX
 * line via pinctrl) when the tty is inactive and treat and interrupts
 * as an indication that the device is 'on' and should be turned 'off'.
 *
 * Driver also listens for open/close and trys to turn the GPS on if it is
 * off and the tty is open.  On final 'close', the GPS is then turned
 * off.
 *
 * When the device is opened, the GPIO is toggled immediately and then
 * again after 2 seconds of no data.  If there is still no data the
 * toggle happens are 4, 8, 16 seconds etc.
 *
 * When the device is closed, the GPIO is toggled immediately and
 * if interrupts are received after 1 second it is toggled again
 * (and again and again with exponentially increasing delays while
 * interrupts continue).
 *
 * If a regulator is configured (e.g. to power the antenna), that is
 * enabled/disabled on open/close.
 *
 * During system suspend the GPS is turned off even if the tty is
 * open.  No repeat attempts are made.
 * Possibly it should be possible to keep the GPS on with some
 * configuration.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/regulator/consumer.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/tty.h>
#include <linux/delay.h>
#include <linux/pm_runtime.h>

struct w2sg_data {
	int		gpio;
	int		irq;	/* irq line from RX pin when pinctrl
				 * set to 'idle' */
	struct regulator *reg;

	unsigned long	last_toggle;	/* jiffies when last toggle completed. */
	unsigned long	backoff;	/* jiffies since last_toggle when
					 * we try again
					 */
	enum {Idle, Down, Up} state;	/* state-machine state. */
	bool		requested, is_on;
	bool		suspended;
	bool		reg_enabled;

	struct delayed_work	work;
	spinlock_t	lock;
	struct device *dev;
};

/*
 * There seems to restrictions on how quickly we can toggle the
 * on/off line.  Data sheets says "two rtc ticks", whatever that means.
 * If we do it too soon it doesn't work.
 * So we have a state machine which uses the common work queue to ensure
 * clean transitions.
 * When a change is requested we record that request and only act on it
 * once the previous change has completed.
 * A change involves a 10ms low pulse, and a 10ms raised level.
 */

static void toggle_work(struct work_struct *work)
{
	struct w2sg_data *data = container_of(
		work, struct w2sg_data, work.work);

	spin_lock_irq(&data->lock);
	switch (data->state) {
	case Up:
		data->state = Idle;
		if (data->requested == data->is_on)
			break;
		if (!data->requested)
			/* Assume it is off unless activity is detected */
			break;
		/* Try again in a while unless we get some activity */
		dev_dbg(data->dev, "Wait %dusec until retry\n",
		       jiffies_to_msecs(data->backoff));
		schedule_delayed_work(&data->work, data->backoff);
		break;
	case Idle:
		if (data->requested == data->is_on)
			break;

		/* Time to toggle */
		dev_dbg(data->dev, "Starting toggle to turn %s\n",
			data->requested ? "on" : "off");
		data->state = Down;
		spin_unlock_irq(&data->lock);
		gpio_set_value_cansleep(data->gpio, 0);
		schedule_delayed_work(&data->work,
				      msecs_to_jiffies(10));
		return;

	case Down:
		data->state = Up;
		data->last_toggle = jiffies;
		dev_dbg(data->dev, "Toggle completed, should be %s now.\n",
			data->is_on ? "off" : "on");
		data->is_on = ! data->is_on;
		spin_unlock_irq(&data->lock);

		gpio_set_value_cansleep(data->gpio, 1);
		schedule_delayed_work(&data->work,
				      msecs_to_jiffies(10));
		return;
	}
	spin_unlock_irq(&data->lock);
}

static irqreturn_t tty_w2_isr(int irq, void *dev_id)
{
	struct w2sg_data *data = dev_id;
	unsigned long flags;

	spin_lock_irqsave(&data->lock, flags);
	if (!data->requested && !data->is_on && data->state == Idle &&
	    time_after(jiffies, data->last_toggle + data->backoff)) {
		data->is_on = 1;
		data->backoff *= 2;
		dev_dbg(data->dev, "Received data, must be on. Try to turn off\n");
		if (!data->suspended)
			schedule_delayed_work(&data->work, 0);
	}
	spin_unlock_irqrestore(&data->lock, flags);
	return IRQ_HANDLED;
}

static int tty_w2_runtime_resume(struct device *slave)
{
	struct w2sg_data *data = dev_get_drvdata(slave);
	unsigned long flags;

	if (!data->reg_enabled && data->reg)
		if (regulator_enable(data->reg) == 0)
			data->reg_enabled = true;

	spin_lock_irqsave(&data->lock, flags);
	if (!data->requested) {
		dev_dbg(data->dev, "Device open - turn GPS on\n");
		data->requested = true;
		data->backoff = HZ;
		if (data->irq) {
			disable_irq(data->irq);
			pinctrl_pm_select_default_state(slave);
		}
		if (!data->suspended && data->state == Idle)
			schedule_delayed_work(&data->work, 0);
	}
	spin_unlock_irqrestore(&data->lock, flags);
	return 0;
}

static int tty_w2_runtime_suspend(struct device *slave)
{
	struct w2sg_data *data = dev_get_drvdata(slave);
	unsigned long flags;

	dev_dbg(data->dev, "Device closed - turn GPS off\n");
	if (data->reg && data->reg_enabled)
		if (regulator_disable(data->reg) == 0)
			data->reg_enabled = false;

	spin_lock_irqsave(&data->lock, flags);
	if (data->requested) {
		data->requested = false;
		data->backoff = HZ;
		if (data->irq) {
			pinctrl_pm_select_idle_state(slave);
			enable_irq(data->irq);
		}
		if (!data->suspended && data->state == Idle)
			schedule_delayed_work(&data->work, 0);
	}
	spin_unlock_irqrestore(&data->lock, flags);
	return 0;
}

static int tty_w2_suspend(struct device *dev)
{
	/* Ignore incoming data and just turn device off.
	 * we cannot really wait for a separate thread to
	 * do things, so we disable that and do it all
	 * here
	 */
	struct w2sg_data *data = dev_get_drvdata(dev);

	spin_lock_irq(&data->lock);
	data->suspended = true;
	spin_unlock_irq(&data->lock);

	cancel_delayed_work_sync(&data->work);
	if (data->state == Down) {
		dev_dbg(data->dev, "Suspending while GPIO down - raising\n");
		msleep(10);
		gpio_set_value_cansleep(data->gpio, 1);
		data->last_toggle = jiffies;
		data->is_on = !data->is_on;
		data->state = Up;
	}
	if (data->state == Up) {
		msleep(10);
		data->state = Idle;
	}
	if (data->is_on) {
		dev_dbg(data->dev, "Suspending while GPS on: toggling\n");
		gpio_set_value_cansleep(data->gpio, 0);
		msleep(10);
		gpio_set_value_cansleep(data->gpio, 1);
		data->is_on = 0;
	}
	return 0;
}

static int tty_w2_resume(struct device *dev)
{
	struct w2sg_data *data = dev_get_drvdata(dev);

	spin_lock_irq(&data->lock);
	data->suspended = false;
	spin_unlock_irq(&data->lock);
	schedule_delayed_work(&data->work, 0);
	return 0;
}

static const struct dev_pm_ops tty_w2_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(tty_w2_suspend, tty_w2_resume)
	SET_RUNTIME_PM_OPS(tty_w2_runtime_suspend,
			   tty_w2_runtime_resume,
			   NULL)
};

static bool toggle_on_probe = false;

static int tty_w2_probe(struct platform_device *pdev)
{
	struct w2sg_data *data;
	struct regulator *reg;
	int err;

	if (pdev->dev.parent == NULL)
		return -ENODEV;

	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	reg = devm_regulator_get(&pdev->dev, "vdd");
	if (IS_ERR(reg)) {
		err = PTR_ERR(reg);
		if (err != -ENODEV)
			goto out;
	} else
		data->reg = reg;

	data->irq = platform_get_irq(pdev, 0);
	if (data->irq < 0) {
		err = data->irq;
		goto out;
	}
	dev_dbg(&pdev->dev, "IRQ configured: %d\n", data->irq);

	data->last_toggle = jiffies;
	data->backoff = HZ;
	data->state = Idle;
	data->gpio = of_get_named_gpio(pdev->dev.of_node, "gpios", 0);
	if (data->gpio < 0) {
		err = data->gpio;
		goto out;
	}
	dev_dbg(&pdev->dev, "GPIO configured: %d\n", data->gpio);
	spin_lock_init(&data->lock);
	INIT_DELAYED_WORK(&data->work, toggle_work);
	err = devm_gpio_request_one(&pdev->dev, data->gpio,
				    GPIOF_OUT_INIT_HIGH,
				    "tty-w2sg0004-on-off");
	if (err)
		goto out;

	if (data->irq) {
		irq_set_status_flags(data->irq, IRQ_NOAUTOEN);
		err = devm_request_irq(&pdev->dev, data->irq, tty_w2_isr,
				       IRQF_TRIGGER_FALLING,
				       "tty-w2sg0004", data);
	}
	if (err)
		goto out;
	platform_set_drvdata(pdev, data);
	data->dev = &pdev->dev;
	err = tty_set_slave(pdev->dev.parent, &pdev->dev);
	pm_runtime_enable(&pdev->dev);
	if (data->irq) {
		pinctrl_pm_select_idle_state(&pdev->dev);
		enable_irq(data->irq);
	}
	if (toggle_on_probe) {
		dev_dbg(data->dev, "Performing initial toggle\n");
		gpio_set_value_cansleep(data->gpio, 0);
		msleep(10);
		gpio_set_value_cansleep(data->gpio, 1);
		msleep(10);
	}
out:
	dev_dbg(data->dev, "Probed: err=%d\n", err);
	return err;
}
module_param(toggle_on_probe, bool, 0);
MODULE_PARM_DESC(toggle_on_probe, "simulate power-on with GPS active");

static int tty_w2_remove(struct platform_device *pdev)
{
	tty_clear_slave(pdev->dev.parent);
	return 0;
}


static struct of_device_id tty_w2_dt_ids[] = {
	{ .compatible = "tty,w2sg0004", },
	{}
};

static struct platform_driver tty_w2_driver = {
	.driver.name	= "tty-w2sg0004",
	.driver.owner	= THIS_MODULE,
	.driver.pm	= &tty_w2_pm_ops,
	.driver.of_match_table = tty_w2_dt_ids,
	.probe		= tty_w2_probe,
	.remove		= tty_w2_remove,
};

static int __init tty_w2_init(void)
{
	return platform_driver_register(&tty_w2_driver);
}
module_init(tty_w2_init);

static void __exit tty_w2_exit(void)
{
	platform_driver_unregister(&tty_w2_driver);
}
module_exit(tty_w2_exit);

MODULE_AUTHOR("NeilBrown <neilb@suse.de>");
MODULE_DESCRIPTION("Serial port device which turns on W2SG0004 GPS");
MODULE_LICENSE("GPL v2");
