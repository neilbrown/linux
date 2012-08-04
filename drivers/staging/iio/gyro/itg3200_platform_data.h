
/* ITG3200 3-axis gyroscope.
 * Platform can determine clock type
 */

#define ITG3200_OSC_32K				0x04
#define ITG3200_OSC_19M				0x05

struct itg3200_platform_data {
	unsigned char clock;
};
