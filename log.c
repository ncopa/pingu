/* log.c - Logging via syslog
 * copied from opennhrp
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or later as
 * published by the Free Software Foundation.
 *
 * See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>

#include "pingu.h"
#include "log.h"

static int log_verbose = 0;

void log_init(int verbose)
{
	log_verbose = verbose;
	openlog("pingu", LOG_PERROR | LOG_PID, LOG_DAEMON);
}

void log_debug(const char *format, ...)
{
	va_list va;

	if (log_verbose) {
		va_start(va, format);
		vsyslog(LOG_DEBUG, format, va);
		va_end(va);
	}
}

void log_perror(const char *message)
{
	log_error("%s: %s", message, strerror(errno));
}

void log_error(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	vsyslog(LOG_ERR, format, va);
	va_end(va);
}

void log_info(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	vsyslog(LOG_INFO, format, va);
	va_end(va);
}
