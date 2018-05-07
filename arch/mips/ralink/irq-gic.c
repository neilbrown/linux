#include <linux/init.h>

#include <linux/of.h>
#include <linux/irqchip.h>
#include <linux/irqchip/mips-gic.h>

int get_c0_perfcount_int(void)
{
	return gic_get_c0_perfcount_int();
}
EXPORT_SYMBOL_GPL(get_c0_perfcount_int);

void __init
arch_init_irq(void)
{
	irqchip_init();
}

