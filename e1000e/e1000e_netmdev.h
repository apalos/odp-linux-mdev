/* Intel PRO/1000 Linux driver
 * Copyright (c) 2017, Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 */

#ifndef _E1000E_NETMDEV_H_
#define _E1000E_NETMDEV_H_

#include <linux/netdevice.h>

void e1000e_register_netmdev(struct device *dev);
void e1000e_unregister_netmdev(struct device *dev);
#endif
