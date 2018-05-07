#include <linux/init.h>

#include <linux/of.h>
#include <linux/clk-provider.h>
#include <linux/clocksource.h>

#include "common.h"

void __init plat_time_init(void)
{
	ralink_of_remap();

	of_clk_init(NULL);
	clocksource_probe();
}
