#ifndef __LINUX_I2C_BMP085_H
#define __LINUX_I2C_BMP085_H

/* linux/i2c/bmp085.h */

/* If GPIO is set, it is the End Of Conversion line which
 * is High when conversion is finished.
 * if it is <0, and irq > 0, then it is an interrupt with no
 * GPIO.
 */
struct bmp085_platform_data {
	int	gpio;
	int	irq;
};

#endif
