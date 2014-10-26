/*
 * tty-reg:
 *   Support for any device which needs a regulator turned on
 *   when a tty is opened.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/regulator/consumer.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/tty.h>

struct tty_reg_data {
	struct regulator *reg;
	bool	reg_enabled;
};

static int tty_reg_runtime_resume(struct device *slave)
{
	struct tty_reg_data *data = dev_get_drvdata(slave);
	if (!data->reg_enabled &&
	    regulator_enable(data->reg) == 0) {
		dev_dbg(slave, "power on\n");
		data->reg_enabled = true;
	}
	return 0;
}

static int tty_reg_runtime_suspend(struct device *slave)
{
	struct tty_reg_data *data = dev_get_drvdata(slave);

	if (data->reg_enabled &&
	    regulator_disable(data->reg) == 0) {
		dev_dbg(slave, "power off\n");
		data->reg_enabled = false;
	}
	return 0;
}

static int tty_reg_probe(struct platform_device *pdev)
{
	struct tty_reg_data *data;
	struct regulator *reg;
	int err;

	err = -ENODEV;
	if (pdev->dev.parent == NULL)
		goto out;
	reg = devm_regulator_get(&pdev->dev, "vdd");
	err = PTR_ERR(reg);
	if (IS_ERR(reg))
		goto out;

	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	err = -ENOMEM;
	if (!data)
		goto out;
	data->reg = reg;
	data->reg_enabled = false;
	tty_set_slave(pdev->dev.parent, &pdev->dev);
	pm_runtime_enable(&pdev->dev);
	platform_set_drvdata(pdev, data);
	err = 0;
out:
	return err;
}

static int tty_reg_remove(struct platform_device *pdev)
{
	tty_clear_slave(pdev->dev.parent);
	return 0;
}

static struct of_device_id tty_reg_dt_ids[] = {
	{ .compatible = "tty,regulator", },
	{}
};

static const struct dev_pm_ops tty_reg_pm_ops = {
	SET_RUNTIME_PM_OPS(tty_reg_runtime_suspend,
			   tty_reg_runtime_resume, NULL)
};

static struct platform_driver tty_reg_driver = {
	.driver.name	= "tty-regulator",
	.driver.owner	= THIS_MODULE,
	.driver.of_match_table = tty_reg_dt_ids,
	.driver.pm	= &tty_reg_pm_ops,
	.probe		= tty_reg_probe,
	.remove		= tty_reg_remove,
};

static int __init tty_reg_init(void)
{
	return platform_driver_register(&tty_reg_driver);
}
module_init(tty_reg_init);

static void __exit tty_reg_exit(void)
{
	platform_driver_unregister(&tty_reg_driver);
}
module_exit(tty_reg_exit);

MODULE_AUTHOR("NeilBrown <neilb@suse.de>");
MODULE_DESCRIPTION("Serial port device which requires a regulator when open.");
MODULE_LICENSE("GPL v2");
