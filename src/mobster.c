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
#include <sys/stat.h>
#include <linux/limits.h>

#include "event_handlers.h"

uint64_t g_msgSubscribed = 0;
uint64_t g_msgReceived = 0;

#define MOBSTER_ROOT    "MOBSTER_ROOT"

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
 
int main(int argc, char **argv)
{
	int running=1;
	struct stat sb;
	const char* mobster_root=getenv(MOBSTER_ROOT);

	if (!mobster_root)
	{
	   fprintf (stderr,"Must define environment variable MOBSTER_ROOT\n");
	   exit (EXIT_FAILURE);
	}
 	if ((lstat (mobster_root,&sb)<0) || !S_ISDIR(sb.st_mode))
	{
	   fprintf (stderr,"MOBSTER_ROOT %s does not exist\n", mobster_root);
	   exit (EXIT_FAILURE);
	}

	signal(SIGPIPE, SIG_IGN);
	openlog ("mobster", LOG_PERROR, LOG_USER);

        pthread_setname_np(pthread_self(), "mobster");

	if (mobster_start (mobster_root) < 0)
	{
		syslog (LOG_ERR,"mobster_start() failed");
		return (EXIT_FAILURE);
	}
	while (running)
	{
		sleep(1);
	}
	closelog ();
	
	return (EXIT_SUCCESS);		
}

/*
 * ---------------------------------------------------------------------------------------
 */

