#include <linux/init.h>

#include <linux/of.h>
#include <linux/clk-provider.h>
#include <asm/time.h>
#include <asm/time.h>

#include "common.h"

void __init plat_time_init(void)
{
	ralink_of_remap();
	ralink_clk_init();
	if (!mips_hpt_frequency)
		mips_hpt_frequency = 880000000 / 2;

	of_clk_init(NULL);
	clocksource_probe();
}
