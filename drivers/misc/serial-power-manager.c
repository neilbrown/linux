/*
 * Serial-power-manager
 * Register for  open/close events on a tty, and turn power
 * on/off for the device which is connected.
 *
 * Currently supported devices:
 *  wi2wi,w2sg0004 - GPS with on/off toggle on a GPIO
 *  wi2wi,w2cbw003 - bluetooth port; powered by regulator.
 *
 * When appropriate, an RFKILL will be registered which
 * can power-down the device even when it is open.
 *
 * Device can be turned on either by
 *  - enabling a regulator.  Disable to turn off
 *  - toggling a GPIO.  Toggle again to turn off.  This requires
 *     that we know the current state.  It is assumed to be 'off'
 *     at boot, however if an interrupt can be generated when on,
 *     such as by connecting RX to a GPIO, that can be used to detect
 *     if the device is on when it should be off.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/regulator/consumer.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/tty.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/rfkill.h>


/* This is used for testing. Setting this module parameter
 * will simulate booting with the device "on"
 */
static bool toggle_on_probe = false;
module_param(toggle_on_probe, bool, 0);
MODULE_PARM_DESC(toggle_on_probe, "simulate power-on with devices active");

struct spm_config {
	int	rfkill_type;		/* type of rfkill to register */
	int	toggle_time;		/* msec to pulse GPIO for on/off */
	int	toggle_gap;		/* min msecs between toggles */
	bool	off_in_suspend;
}
	simple_config = {
		.off_in_suspend = true,
	},
	w2sg_config = {
		.rfkill_type = RFKILL_TYPE_GPS,
		.toggle_time = 10,
		.toggle_gap = 500,
		.off_in_suspend = true,
	};

const static struct of_device_id spm_dt_ids[] = {
       { .compatible = "wi2wi,w2sg0004", .data = &w2sg_config},
       { .compatible = "wi2wi,w2cbw003", .data = &simple_config},
       {}
};

struct spm_data {
	const struct spm_config *config;
	struct gpio_desc *gpiod;
	int		irq;	/* irq line from RX pin when pinctrl
				 * set to 'idle' */
	struct regulator *reg;

	unsigned long	toggle_time;
	unsigned long	toggle_gap;
	unsigned long	last_toggle;	/* jiffies when last toggle completed. */
	unsigned long	backoff;	/* jiffies since last_toggle when
					 * we try again
					 */
	enum {Idle, Down, Up} state;	/* state-machine state. */

	bool		is_open;
	bool		requested, is_on;
	bool		suspended;
	bool		reg_enabled;

	struct pinctrl	*pins;
	struct pinctrl_state *pins_off;

	struct delayed_work work;
	spinlock_t	lock;
	struct device	*dev;

	struct rfkill	*rfkill;
};

/* When a device is powered on/off by toggling a GPIO we perform
 * all the toggling via a workqueue to ensure only one toggle happens
 * at a time and to allow easy timing.
 * This is managed as a state machine which transitions
 *  Idle -> Down -> Up -> Idle
 * The GPIO is held down for toggle_time and then up for toggle_time,
 * and then we assume the device has changed state.
 * We never toggle until at least toggle_gap has passed since the
 * last toggle.
 */
static void toggle_work(struct work_struct *work)
{
	struct spm_data *data = container_of(
		work, struct spm_data, work.work);

	if (data->gpiod == NULL)
		return;

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
		gpiod_set_value_cansleep(data->gpiod, 1);
		schedule_delayed_work(&data->work, data->toggle_time);

		return;

	case Down:
		data->state = Up;
		data->last_toggle = jiffies;
		dev_dbg(data->dev, "Toggle completed, should be %s now.\n",
			data->is_on ? "off" : "on");
		data->is_on = ! data->is_on;
		spin_unlock_irq(&data->lock);

		gpiod_set_value_cansleep(data->gpiod, 0);
		schedule_delayed_work(&data->work, data->toggle_time);

		return;
	}
	spin_unlock_irq(&data->lock);
}

static irqreturn_t spm_isr(int irq, void *dev_id)
{
	struct spm_data *data = dev_id;
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

static void spm_open(struct device *slave, struct tty_struct *tty)
{
	struct spm_data *data = dev_get_drvdata(slave);
	unsigned long flags;

	data->is_open = true;

	if (data->rfkill && rfkill_blocked(data->rfkill))
		return;

	if (!data->reg_enabled &&
	    data->reg &&
	    regulator_enable(data->reg) == 0)
		data->reg_enabled = true;

	spin_lock_irqsave(&data->lock, flags);
	if (!data->requested) {
		dev_dbg(data->dev, "TTY open - turn device on\n");
		data->requested = true;
		data->backoff = data->toggle_gap;
		if (data->irq > 0) {
			disable_irq(data->irq);
			pinctrl_pm_select_default_state(slave);
		}
		if (!data->suspended && data->state == Idle)
			schedule_delayed_work(&data->work, 0);
	}
	spin_unlock_irqrestore(&data->lock, flags);
}

static void spm_off(struct spm_data *data)
{
	unsigned long flags;

	if (data->reg && data->reg_enabled)
		if (regulator_disable(data->reg) == 0)
			data->reg_enabled = false;

	spin_lock_irqsave(&data->lock, flags);
	if (data->requested) {
		data->requested = false;
		data->backoff = data->toggle_gap;
		if (data->pins_off) {
			pinctrl_select_state(data->pins,
					     data->pins_off);
			enable_irq(data->irq);
		}
		if (!data->suspended && data->state == Idle)
			schedule_delayed_work(&data->work, 0);
	}
	spin_unlock_irqrestore(&data->lock, flags);
}

static void spm_release(struct device *slave, struct tty_struct *tty)
{
	struct spm_data *data = dev_get_drvdata(slave);

	data->is_open = false;
	dev_dbg(data->dev, "TTY closed - turn device off\n");
	spm_off(data);
}

static int spm_rfkill_set_block(void *vdata, bool blocked)
{
	struct spm_data *data = vdata;

	dev_dbg(data->dev, "rfkill_set_blocked %d\n", blocked);
	if (blocked)
		spm_off(data);

	if (!blocked &&
	    data->is_open)
		spm_open(data->dev, NULL);

	return 0;
}

static struct rfkill_ops spm_rfkill_ops = {
	.set_block = spm_rfkill_set_block,
};

static int spm_suspend(struct device *dev)
{
	/* Ignore incoming data and just turn device off.
	 * we cannot really wait for a separate thread to
	 * do things, so we disable that and do it all
	 * here
	 */
	struct spm_data *data = dev_get_drvdata(dev);

	spin_lock_irq(&data->lock);
	data->suspended = true;
	spin_unlock_irq(&data->lock);
	if (!data->config->off_in_suspend)
		return 0;

	if (data->gpiod) {

		cancel_delayed_work_sync(&data->work);
		if (data->state == Down) {
			dev_dbg(data->dev, "Suspending while GPIO down - raising\n");
			msleep(data->config->toggle_time);
			gpiod_set_value_cansleep(data->gpiod, 0);
			data->last_toggle = jiffies;
			data->is_on = !data->is_on;
			data->state = Up;
		}
		if (data->state == Up) {
			msleep(data->config->toggle_time);
			data->state = Idle;
		}
		if (data->is_on) {
			dev_dbg(data->dev, "Suspending while device on: toggling\n");
			gpiod_set_value_cansleep(data->gpiod, 1);
			msleep(data->config->toggle_time);
			gpiod_set_value_cansleep(data->gpiod, 0);
			data->is_on = 0;
		}
	}

	if (data->reg && data->reg_enabled)
		if (regulator_disable(data->reg) == 0)
			data->reg_enabled = false;

	return 0;
}

static int spm_resume(struct device *dev)
{
	struct spm_data *data = dev_get_drvdata(dev);

	spin_lock_irq(&data->lock);
	data->suspended = false;
	spin_unlock_irq(&data->lock);
	schedule_delayed_work(&data->work, 0);

	if (data->is_open &&
	    (!data->rfkill || !rfkill_blocked(data->rfkill))) {
		if (!data->reg_enabled &&
		    data->reg &&
		    regulator_enable(data->reg) == 0)
			data->reg_enabled = true;
	}
	return 0;
}

static const struct dev_pm_ops spm_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(spm_suspend, spm_resume)
};

static struct tty_slave_operations spm_ops = {
	.open	=	spm_open,
	.release=	spm_release,
};

static int spm_probe(struct platform_device *pdev)
{
	struct spm_data *data;
	struct regulator *reg;
	int err;
	const struct of_device_id *id;
	const char *name;

	if (pdev->dev.parent == NULL)
		return -ENODEV;

	id = of_match_device(spm_dt_ids, &pdev->dev);
	if (!id)
		return -ENODEV;

	if (pdev->dev.of_node && pdev->dev.of_node->name)
		name = pdev->dev.of_node->name;
	else
		name = "serial-power-manager";

	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->config = id->data;
	data->toggle_time = msecs_to_jiffies(data->config->toggle_time) + 1;
	data->toggle_gap = msecs_to_jiffies(data->config->toggle_gap) + 1;
	data->last_toggle = jiffies;
	data->backoff = data->toggle_gap;
	data->state = Idle;
	spin_lock_init(&data->lock);
	INIT_DELAYED_WORK(&data->work, toggle_work);

	/* If a regulator is provided, it is enabled on 'open'
	 * and disabled on 'release'
	 */
	reg = devm_regulator_get(&pdev->dev, "vdd");
	if (IS_ERR(reg)) {
		err = PTR_ERR(reg);
		if (err != -ENODEV)
			goto out;
	} else
		data->reg = reg;

	/* If an irq is provided, any transitions are taken as
	 * indication that the device is currently "on"
	 */
	data->irq = platform_get_irq(pdev, 0);
	if (data->irq < 0) {
		err = data->irq;
		if (err != -ENXIO)
			goto out;
	} else {
		dev_dbg(&pdev->dev, "IRQ configured: %d\n", data->irq);

		irq_set_status_flags(data->irq, IRQ_NOAUTOEN);
		err = devm_request_irq(&pdev->dev, data->irq, spm_isr,
				       IRQF_TRIGGER_FALLING,
				       name, data);

		if (err)
			goto out;

	}

	/* If a gpio is provided, then it is used to turn the device
	 * on/off.
	 * If toggle_time is zero, then the GPIO directly controls
	 * the device.  If non-zero, then the GPIO must be toggled to
	 * change the state of the device.
	 */
	data->gpiod = devm_gpiod_get(&pdev->dev, NULL, GPIOD_OUT_LOW);
	if (IS_ERR(data->gpiod)) {
		err = PTR_ERR(data->gpiod);
		if (err != -ENOENT)
			goto out;
		data->gpiod = NULL;
	} else
		dev_dbg(&pdev->dev, "GPIO configured: %d\n",
			desc_to_gpio(data->gpiod));

	/* If an 'off' pinctrl state is defined, we apply that
	 * when the device is assumed to be off.  This is expected to
	 * route the 'rx' line to the 'irq' interrupt.
	 */
	data->pins = devm_pinctrl_get(&pdev->dev);
	if (data->pins && data->irq > 0) {
		data->pins_off = pinctrl_lookup_state(data->pins, "off");
		if (IS_ERR(data->pins_off))
			data->pins_off = NULL;
	}

	if (data->config->rfkill_type) {
		data->rfkill = rfkill_alloc(name, &pdev->dev,
					    data->config->rfkill_type,
					    &spm_rfkill_ops, data);
		if (!data->rfkill) {
			err = -ENOMEM;
			goto out;
		}
		err = rfkill_register(data->rfkill);
		if (err) {
			dev_err(&pdev->dev, "Cannot register rfkill device");
			rfkill_destroy(data->rfkill);
			goto out;
		}
	}
	platform_set_drvdata(pdev, data);
	data->dev = &pdev->dev;
	tty_set_slave(pdev->dev.parent, &pdev->dev, &spm_ops);

	if (data->pins_off)
		pinctrl_select_state(data->pins, data->pins_off);
	if (data->irq > 0)
		enable_irq(data->irq);

	if (toggle_on_probe && data->gpiod) {
		dev_dbg(data->dev, "Performing initial toggle\n");
		gpiod_set_value_cansleep(data->gpiod, 1);
		msleep(data->config->toggle_time);
		gpiod_set_value_cansleep(data->gpiod, 0);
		msleep(data->config->toggle_time);
	}
	err = 0;
out:
	dev_dbg(data->dev, "Probed: err=%d\n", err);
	return err;
}

static int spm_remove(struct platform_device *pdev)
{
       struct spm_data *data = dev_get_drvdata(&pdev->dev);

       tty_clear_slave(pdev->dev.parent, &pdev->dev);
       if (data->rfkill) {
               rfkill_unregister(data->rfkill);
               rfkill_destroy(data->rfkill);
       }
       return 0;
}

static struct platform_driver spm_driver = {
       .driver.name		= "serial-power-manager",
       .driver.owner		= THIS_MODULE,
       .driver.of_match_table	= spm_dt_ids,
       .probe			= spm_probe,
       .remove			= spm_remove,
};

static int __init spm_init(void)
{
       return platform_driver_register(&spm_driver);
}
module_init(spm_init);

static void __exit spm_exit(void)
{
       platform_driver_unregister(&spm_driver);
}
module_exit(spm_exit);

MODULE_AUTHOR("NeilBrown <neil@brown.name>");
MODULE_DEVICE_TABLE(of, spm_dt_ids);
MODULE_DESCRIPTION("Power management for Serial-attached device.");
MODULE_LICENSE("GPL v2");
