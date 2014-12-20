/*
 * omap-pwm.h
 *
 *    Copyright (c) 2012 NeilBrown <neilb@suse.de>
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License
 *    version 2 as published by the Free Software Foundation.
 *
 * Set the timer id to use for a PWM
 */

#ifndef _OMAP_PWM_H_
#define _OMAP_PWM_H_

struct omap_pwm_pdata {
	int	timer_id;
};

#endif /* _OMAP_PWM_H_ */
