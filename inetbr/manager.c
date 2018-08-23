/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2018, CESAR. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "udp4.h"
#include "tcp4.h"
#include "udp6.h"
#include "tcp6.h"

#include "manager.h"

int manager_start(int port4, int port6)
{
	int ret;

	ret = udp4_start(port4);
	if (ret < 0)
		return ret;

	ret = tcp4_start(port4);
	if (ret < 0)
		goto tcp4_fail;

	ret = udp6_start(port6);
	if (ret < 0)
		goto udp6_fail;

	ret = tcp6_start(port6);
	if (ret < 0)
		goto tcp6_fail;

	return ret;

tcp6_fail:
	udp6_stop();
udp6_fail:
	tcp4_stop();
tcp4_fail:
	udp4_stop();

	return ret;
}

void manager_stop(void)
{
	udp4_stop();
	tcp4_stop();
	udp6_stop();
	tcp6_stop();
}
