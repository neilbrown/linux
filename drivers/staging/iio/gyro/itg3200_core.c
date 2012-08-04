/*
 * ITG3200 3-axis gyroscope.
 *
 * Copyright 2012 Neil Brown <neil@brown.name>
 * Defines and bits of code borrowed from
 *    Copyright (c) 2010  Christoph Mair <christoph.mair@gmail.com>
 *
 * Licensed under the GPLv2.
 *
 * The itg3200 3-axis gyroscope simply reports rate of rotation
 * in each axis with sample range from 4Hz to 8KHz, with low pass
 * filtering to remove some of the noise.
 * Running all three gyroscopes at once draws approximately 6.5mA
 * so it is important to turn them off when not in use.
 * We provide an '*_en' file for each axis.  When all 3 are
 * disabled, the device is put to sleep.
 *
 * The internal sample rate is either 8KHz to 1 KHz.  It can then
 * be subdivided by a value from 1 to 256.
 * This driver allows a sample rate to be specified and the nearest
 * possible value not less than that is used, where 8KHz internal is
 * only used for rates above 256Hz.
 * The low-pass filter is set to at least twice the sample frequency.
 * This interrupt should be made into a trigger once I understand those.
 *
 * There are several options for clock source.  If platform data is
 * present and suggests a fixed frequency is available, we use that.
 * Otherwise we use one of the Gyros if any are activated.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/delay.h>
#include "../iio.h"
#include "../sysfs.h"
#include "itg3200_platform_data.h"


#define ITG3200_REG_ID				0x00 /* 110100x */
#define ITG3200_REG_SAMPLE_RATE_DIV		0x15 /* 0x00 */
#define ITG3200_REG_LP_FULL_SCALE		0x16 /* 0x00 */
#define ITG3200_REG_IRQ				0x17 /* 0x00 */
#define ITG3200_REG_IRQ_STATUS			0x1A /* 0x00 */
#define ITG3200_REG_TEMP_OUT_H			0x1B
#define ITG3200_REG_TEMP_OUT_L			0x1C
#define ITG3200_REG_GYRO_XOUT_H			0x1D
#define ITG3200_REG_GYRO_XOUT_L			0x1E
#define ITG3200_REG_GYRO_YOUT_H			0x1F
#define ITG3200_REG_GYRO_YOUT_L			0x20
#define ITG3200_REG_GYRO_ZOUT_H			0x21
#define ITG3200_REG_GYRO_ZOUT_L			0x22
#define ITG3200_REG_POWER_MGMT			0x3E	/* 0x00 */

#define ITG3200_FULL_SCALE_2000			(0x03 << 3)

#define ITG3200_LP_256				0x00
#define ITG3200_LP_188				0x01
#define ITG3200_LP_98				0x02
#define ITG3200_LP_42				0x03
#define ITG3200_LP_20				0x04
#define ITG3200_LP_10				0x05
#define ITG3200_LP_5				0x06

#define ITG3200_IRQ_LOGIC_LEVEL			7
#define ITG3200_IRQ_DRIVE_TYPE			6
#define ITG3200_IRQ_LATCH_MODE			5
#define ITG3200_IRQ_LATCH_CLEAR_MODE		4
#define ITG3200_IRQ_DEVICE_READY		2
#define ITG3200_IRC_DATA_AVAILABLE		0

#define ITG3200_IRQ_ACTIVE_LOW			0x01
#define ITG3200_IRQ_ACTIVE_HIGH			0x00
#define ITG3200_IRQ_OPEN_DRAIN			0x01
#define ITG3200_IRQ_PUSH_PULL			0x00
#define ITG3200_IRQ_LATCH_UNTIL_CLEARED		0x01
#define ITG3200_IRQ_LATCH_PULSE			0x00
#define ITG3200_IRQ_ENABLE_DEVICE_READY		0x01
#define ITG3200_IRQ_ENABLE_DATA_AVAILABLE	0x01


#define ITG3200_OSC_INTERNAL			0x00
#define ITG3200_OSC_GYRO_X			0x01
#define ITG3200_OSC_GYRO_Y			0x02
#define ITG3200_OSC_GYRO_Z			0x03

#ifndef ITG3200_OSC_32K
#define ITG3200_OSC_32K				0x04
#define ITG3200_OSC_19M				0x05
#endif

#define	ITG3200_OSC_MASK			0x07

#define ITG3200_GYRO_X				(0x01 << 3)
#define ITG3200_GYRO_Y				(0x01 << 4)
#define ITG3200_GYRO_Z				(0x01 << 5)

#define ITG3200_STANDBY_Z			(0x01 << 3)
#define ITG3200_STANDBY_Y			(0x01 << 4)
#define ITG3200_STANDBY_X			(0x01 << 5)
#define ITG3200_SLEEP				(0x01 << 6)
#define	ITG3200_STANDBY_MASK			(0x0F << 3)

#define ITG3200_RESET				(0x01 << 7)

struct itg3200_data {
	struct mutex lock;

	unsigned char intr_cfg;
	unsigned char power_management;

	unsigned int sample_freq;

	int enabled; /* Bit map */
	int suspend_enabled;	/* keep 'enabled' safe during suspend */
};

static void itg3200_reset(struct i2c_client *client,
			 struct itg3200_data *data)
{
	s32 result;

	i2c_smbus_write_byte_data(client, ITG3200_REG_POWER_MGMT, ITG3200_RESET);
	result = i2c_smbus_read_byte_data(client, ITG3200_REG_POWER_MGMT);
	data->power_management = result;
	result = i2c_smbus_read_byte_data(client, ITG3200_REG_IRQ);
	data->intr_cfg = result;
}

static s32 itg3200_get_id(struct i2c_client *client)
{
	return i2c_smbus_read_byte_data(client, ITG3200_REG_ID);
}

static int itg3200_read_raw(struct iio_dev *indio_dev,
			    struct iio_chan_spec const *chan,
			    int *val, int *val2,
			    long mask)
{
	struct i2c_client *client = to_i2c_client(indio_dev->dev.parent);
	struct itg3200_data *data = iio_priv(indio_dev);
	s32 result;

	if (mask)
		return -EINVAL;

	mutex_lock(&data->lock);
	result = i2c_smbus_read_word_data(client, chan->address);
	mutex_unlock(&data->lock);
	if (result < 0)
		return -EINVAL;

	*val = (s16)swab16((u16)result);
	return IIO_VAL_INT;
}


static int lp_filter_freq[] = {256, 188, 98, 42, 20, 10, 5, -1};

static void itg3200_update_freq(struct i2c_client *client,
			       struct itg3200_data *data,
			       int freq)
{
	/* choose best frequency near 'freq' and set it */
	int base, div, filter;
	unsigned char dlpf;
	s32 result;

	if (freq <= 0)
		return;
	if (freq > 256)
		base = 8192;
	else
		base = 1024;

	if (freq > base)
		freq = base;

	div = base / freq;
	if (div > 256)
		div = 256;
	if (div < 1)
		div = 1;
	freq = base / div;

	filter = freq/2;

	filter = 0;
	if (base == 1024) {
		filter = 1;
		while (lp_filter_freq[filter+1] >= freq/2)
			filter++;
	}
	dlpf = ITG3200_FULL_SCALE_2000 | filter;
	result = i2c_smbus_write_byte_data(client,
					   ITG3200_REG_LP_FULL_SCALE,
					   dlpf);
	if (result < 0)
		return;
	result = i2c_smbus_write_byte_data(client,
					   ITG3200_REG_SAMPLE_RATE_DIV,
					   div-1);
	if (result < 0)
		return;
	data->sample_freq = freq;
}

static int itg3200_set_clock(struct i2c_client *client,
			      struct itg3200_data *data,
			      int clk)
{
	unsigned char pm;
	s32 result;

	pm = (data->power_management & ~ITG3200_OSC_MASK) | clk;

	result = i2c_smbus_write_byte_data(client,
					   ITG3200_REG_POWER_MGMT,
					   pm);
	if (result < 0)
		return result;
	/* Need to wait .. nice to wait for an interrupt */
	msleep(100);

	data->power_management = pm;
	return 0;
}

static int itg3200_choose_clock(struct i2c_client *client,
				struct itg3200_data *data,
				int enabled)
{
	/* Choose a clock which will work with the give
	 * gyros enabled
	 */
	int bit;
	unsigned char clk;

	switch(data->power_management & ITG3200_OSC_MASK) {
	case ITG3200_OSC_INTERNAL: bit = 0; break;
	case ITG3200_OSC_GYRO_X: bit = 1; break;
	case ITG3200_OSC_GYRO_Y: bit = 2; break;
	case ITG3200_OSC_GYRO_Z: bit = 4; break;

	default: return 0;
	}
	if (enabled & bit)
		/* current clock is fine */
		return 0;
	if (bit == 0 && enabled == 0)
		/* current clock will have to do */
		return 0;

	/* Choose a different clock */
	if (enabled & 1)
		clk = ITG3200_OSC_GYRO_X;
	else if (enabled & 2)
		clk = ITG3200_OSC_GYRO_Y;
	else if (enabled & 4)
		clk = ITG3200_OSC_GYRO_Z;
	else
		clk = ITG3200_OSC_INTERNAL;
	return itg3200_set_clock(client, data, clk);
}


static void itg3200_update_enabled(struct i2c_client *client,
				   struct itg3200_data *data,
				   int enabled)
{
	int rv;
	unsigned char pm;
	s32 result;

	if (data->enabled == enabled)
		return;

	/* First we must ensure that we aren't turning off
	 * the current clock source
	 */
	rv = itg3200_choose_clock(client, data, data->enabled & enabled);
	if (rv)
		return;

	pm = data->power_management &~ ITG3200_STANDBY_MASK;
	if (enabled == 0)
		pm |= ITG3200_SLEEP;
	if (!(enabled & 1))
		pm |= ITG3200_STANDBY_X;
	if (!(enabled & 2))
		pm |= ITG3200_STANDBY_Y;
	if (!(enabled & 4))
		pm |= ITG3200_STANDBY_Z;

	result = i2c_smbus_write_byte_data(client,
					   ITG3200_REG_POWER_MGMT,
					   pm);
	if (result < 0)
		return;
	/* Need to wait .. nice to wait for an interrupt */
	msleep(100);

	data->enabled = enabled;
	data->power_management = pm;
	itg3200_choose_clock(client, data, data->enabled);
}

static ssize_t itg3200_show_axis_enable(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct itg3200_data *data = iio_priv(indio_dev);
	struct iio_dev_attr *dattr = to_iio_dev_attr(attr);
	return sprintf(buf, "%c\n", (data->enabled & (1<<dattr->address))
		       ? 'Y' : 'N');
}

static ssize_t itg3200_set_axis_enable(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct i2c_client *client = to_i2c_client(indio_dev->dev.parent);
	struct itg3200_data *data = iio_priv(indio_dev);
	struct iio_dev_attr *dattr = to_iio_dev_attr(attr);
	int rv;
	bool en;
	int bit = (1 << dattr->address);

	rv = strtobool(buf, &en);
	if (rv)
		return rv;

	if (en == !!(data->enabled & bit))
		return count;

	mutex_lock(&data->lock);

	if (en)
		itg3200_update_enabled(client, data, data->enabled | bit);
	else
		itg3200_update_enabled(client, data, data->enabled & ~bit);

	mutex_unlock(&data->lock);
	return count;
}

static IIO_DEVICE_ATTR(in_anglvel_x_en, S_IWUSR | S_IRUGO,
		       itg3200_show_axis_enable,
		       itg3200_set_axis_enable,
		       0);
static IIO_DEVICE_ATTR(in_anglvel_y_en, S_IWUSR | S_IRUGO,
		       itg3200_show_axis_enable,
		       itg3200_set_axis_enable,
		       1);
static IIO_DEVICE_ATTR(in_anglvel_z_en, S_IWUSR | S_IRUGO,
		       itg3200_show_axis_enable,
		       itg3200_set_axis_enable,
		       2);


static ssize_t itg3200_show_sample_frequency(struct device *dev,
					     struct device_attribute *attr,
					     char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct itg3200_data *data = iio_priv(indio_dev);
	return sprintf(buf, "%d\n", data->sample_freq);
}

static ssize_t itg3200_set_sample_frequency(struct device *dev,
					    struct device_attribute *attr,
					    const char *buf,
					    size_t count)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct i2c_client *client = to_i2c_client(indio_dev->dev.parent);
	struct itg3200_data *data = iio_priv(indio_dev);
	int rv;
	unsigned int freq;

	rv = kstrtouint(buf, 10, &freq);
	if (rv)
		return rv;
	if (data->sample_freq == freq)
		return count;
	if (data->sample_freq > 8192)
		return -EINVAL;

	mutex_lock(&data->lock);
	if (freq == 0) {
		itg3200_update_enabled(client, data, 0);
		data->sample_freq = 0;
	} else
		itg3200_update_freq(client, data, freq);
	mutex_unlock(&data->lock);
	return count;
}
static IIO_DEV_ATTR_SAMP_FREQ(S_IWUSR | S_IRUGO,
			      itg3200_show_sample_frequency,
			      itg3200_set_sample_frequency);

#define _IIO_ATTR(x) &iio_dev_attr_##x.dev_attr.attr
static struct attribute *itg3200_attributes[] = {
	_IIO_ATTR(sampling_frequency),
	_IIO_ATTR(in_anglvel_x_en),
	_IIO_ATTR(in_anglvel_y_en),
	_IIO_ATTR(in_anglvel_z_en),
	NULL
};

static struct attribute_group itg3200_group = {
	.attrs = itg3200_attributes,
};

static void itg3200_init_client(struct i2c_client *client,
				struct itg3200_data *data)
{
	itg3200_reset(client, data);
	itg3200_update_freq(client, data, 10);
	data->enabled = 1;
	itg3200_update_enabled(client, data, 0);
}

static const unsigned  short normal_i2c[] = {
	0x68, 0x69, I2C_CLIENT_END
};

static int itg3200_detect(struct i2c_client *client,
			  struct i2c_board_info *info)
{
	/* The only non-zero register at boot is the 'id'
	 * register which contains the I2C address.
	 * The documentation says
	 *    Contains the I2C address of the device, which can
	 *    also be changed by writing to this register.
	 * And the address is selectable by an input pin.
	 * However when that pin is low and the 0x68 address is in
	 * use, the register still contains 0x69!
	 *
	 * Worse - the register occasionally reads as zero!!
	 */
	unsigned char id = itg3200_get_id(client);
	if (((id & 0xFE) != (client->addr & 0xFE))
	    && id != 0)
		return -ENODEV;
	strlcpy(info->type, "itg3200", I2C_NAME_SIZE);

	return 0;
}

static const struct iio_info itg3200_info = {
	.attrs = &itg3200_group,
	.read_raw = &itg3200_read_raw,
	.driver_module = THIS_MODULE,
};

#define ITG3200_CHANNEL(axis, add)				\
	{							\
		.type		= IIO_ANGL_VEL,			\
		.modified	= 1,				\
		.channel2	= IIO_MOD_##axis,		\
		.address	= add,			 	\
	}

static const struct iio_chan_spec itg3200_channels[] = {
	ITG3200_CHANNEL(X, ITG3200_REG_GYRO_XOUT_H),
	ITG3200_CHANNEL(Y, ITG3200_REG_GYRO_YOUT_H),
	ITG3200_CHANNEL(Z, ITG3200_REG_GYRO_ZOUT_H),
};

static int itg3200_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	struct itg3200_data *data;
	struct iio_dev *indio_dev;
	struct itg3200_platform_data *pdata = client->dev.platform_data;
	int err = 0;

	indio_dev = iio_allocate_device(sizeof(*data));
	if (indio_dev == NULL) {
		err = -ENOMEM;
		goto exit;
	}

	data = iio_priv(indio_dev);

	mutex_init(&data->lock);

	i2c_set_clientdata(client, indio_dev);

	itg3200_init_client(client, data);
	if (pdata && pdata->clock)
		itg3200_set_clock(client, data, pdata->clock);

	indio_dev->info = &itg3200_info;
	indio_dev->name = id->name;
	indio_dev->channels = itg3200_channels;
	indio_dev->num_channels = ARRAY_SIZE(itg3200_channels);
	indio_dev->dev.parent = &client->dev;
	indio_dev->modes = INDIO_DIRECT_MODE;

	err = iio_device_register(indio_dev);
	if (err)
		goto exit_free;
	return 0;

exit_free:
	iio_free_device(indio_dev);
exit:
	return err;
}

static int itg3200_remove(struct i2c_client *client)
{
	struct iio_dev *indio_dev = i2c_get_clientdata(client);
	struct itg3200_data *data = iio_priv(indio_dev);

	iio_device_unregister(indio_dev);
	itg3200_update_enabled(client, data, 0);
	iio_free_device(indio_dev);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int itg3200_suspend(struct device *dev)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct i2c_client *client = to_i2c_client(indio_dev->dev.parent);
	struct itg3200_data *data = iio_priv(indio_dev);

	data->suspend_enabled = data->enabled;
	itg3200_update_enabled(client, data, 0);
	return 0;
}

static int itg3200_resume(struct device *dev)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct i2c_client *client = to_i2c_client(indio_dev->dev.parent);
	struct itg3200_data *data = iio_priv(indio_dev);

	itg3200_update_enabled(client, data, data->suspend_enabled);
	return 0;
}

static SIMPLE_DEV_PM_OPS(itg3200_pm_ops, itg3200_suspend, itg3200_resume);
#define ITG3200_PM_OPS (&itg3200_pm_ops)
#else
#define ITG3200_PM_OPS NULL
#endif

static const struct i2c_device_id itg3200_id[] = {
	{ "itg3200", 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, itg3200_id);

static struct i2c_driver itg3200_driver = {
	.driver.name	= "itg3200",
	.driver.owner	= THIS_MODULE,
	.driver.pm	= ITG3200_PM_OPS,

	.id_table	= itg3200_id,
	.probe		= itg3200_probe,
	.remove		= itg3200_remove,

	.class		= I2C_CLASS_HWMON,
	.detect		= itg3200_detect,
	.address_list	= normal_i2c,
};
static int __init itg3200_driver_init(void)
{
	return i2c_add_driver(&itg3200_driver);
}
module_init(itg3200_driver_init);
static void __exit itg3200_driver_exit(void)
{
	i2c_del_driver(&itg3200_driver);
}

MODULE_AUTHOR("NeilBrown <neil@brown.name>");
MODULE_DESCRIPTION("InvenSense ITG3200 gyroscope");
MODULE_LICENSE("GPLv2");
