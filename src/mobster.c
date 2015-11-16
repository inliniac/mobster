/* Copyright (C) 2012-2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/* 
 *
 * author Randy Caldejon <randy@packetchaser.org>
 *
 */

#define _GNU_SOURCE

#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <linux/limits.h>

#include "event_publisher.h"
#include "event_handlers.h"

uint64_t g_msgPublished = 0;
uint64_t g_msgSubscribed = 0;
uint64_t g_msgReceived = 0;

#define REDIS_HOSTNAME	"127.0.0.1"
#define REDIS_PORT       6379
#define EVE_SOCKET_PATH "/var/run/suricata/eve.socket"
#define CONFIG_FILE_NAME "mobster-config.lua"

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
 
int main(int argc, char **argv)
{
	char config_path [PATH_MAX];
	const char* mobster_root=getenv("MOBSTER_ROOT");

	signal(SIGPIPE, SIG_IGN);
	openlog ("mobster", LOG_PERROR, LOG_USER);

	if (!mobster_root)
	{
		fprintf(stderr,"Environment variable MOBSTER_ROOT is required\n");
		exit(1);
	}
	snprintf (config_path, PATH_MAX,"%s/etc/%s", mobster_root, CONFIG_FILE_NAME);

	
        pthread_setname_np(pthread_self(), "mobster");

	if (mobster_start (config_path) < 0)
	{
		syslog (LOG_ERR,"foragers_start() failed");
		return (EXIT_FAILURE);
	}

	if (eve_processor_start (EVE_SOCKET_PATH, REDIS_HOSTNAME, REDIS_PORT) < 0)
	{
		syslog (LOG_ERR,"eve_processor_start() failed");
		return (EXIT_FAILURE);
	}
	closelog ();
	
	return (EXIT_SUCCESS);		
}

/*
 * ---------------------------------------------------------------------------------------
 */

