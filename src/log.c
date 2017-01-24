/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2017, CESAR. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the CESAR nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CESAR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <syslog.h>
#include <stdarg.h>

#include "log.h"

void log_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsyslog(LOG_ERR, format, ap);
	va_end(ap);
}

void log_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsyslog(LOG_WARNING, format, ap);
	va_end(ap);
}

void log_info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsyslog(LOG_INFO, format, ap);
	va_end(ap);
}

void log_dbg(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsyslog(LOG_DEBUG, format, ap);
	va_end(ap);
}

void log_init(const char *ident)
{
	int option = LOG_NDELAY | LOG_PID | LOG_PERROR;

	openlog(ident, option, LOG_DAEMON);
}

void log_close(void)
{
	closelog();
}
