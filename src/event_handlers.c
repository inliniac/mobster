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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>

#include <lua5.1/lua.h>                               
#include <lua5.1/lauxlib.h>                            
#include <lua5.1/lualib.h>                             

#ifdef ENABLE_JIT
#include <luajit-2.0/luajit.h>
#endif

#define CONFIG_FILE_NAME "config.lua"
static char *g_redis_host = "127.0.0.1";
static int g_redis_port = 6379;

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static void *lua_thread (void *ptr)
{
    char *name = NULL;
    const char* lua_script = strndup((const char *)ptr, PATH_MAX);

    pthread_detach(pthread_self());
    /*
     * Set thread name to the file name of the lua script
     */
    const char *path = strndup (lua_script, PATH_MAX);
    char *period = strrchr (path, (int)'.');
    if (period) *period = '\0';
    char* slash = strrchr (path, (int)'/');
    if (slash) name = (slash+1);
    if (name)
    {
	pthread_setname_np(pthread_self(), name);
    }

    lua_State *L = luaL_newstate();                       
    luaL_openlibs(L);  
  
    syslog (LOG_ERR, "Loading %s", lua_script);
    if (luaL_loadfile(L, lua_script)||lua_pcall(L, 0, 0, 0))
    {
        syslog (LOG_ERR, "luaL_loadfile %s failed - %s",lua_script, lua_tostring(L, -1));
    	pthread_exit(NULL);
    }

    /* globally set redis host and port number in the LUA engine */ 
    lua_pushnumber(L, g_redis_port);
    lua_setglobal(L, "redis_port");
    lua_pushstring(L, g_redis_host);
    lua_setglobal(L, "redis_host");

    syslog (LOG_NOTICE,"Running %s as %s\n", lua_script, name);
    lua_getglobal(L, "run");             
    if (lua_pcall(L, 0, 0, 0))  
    {
        syslog (LOG_ERR,"lua_pcall run(%s) failed; %s",lua_script, lua_tostring(L, -1));
    	pthread_exit(NULL);
    }          
    lua_close(L);         
    syslog (LOG_NOTICE,"%s exiting", (name?name:"thread"));
    pthread_exit(NULL);
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */

static void run_mobster (const char* mobster_root)
{

    lua_State *L = luaL_newstate();                       
    luaL_openlibs(L);                           
    char config_file [PATH_MAX];

    snprintf (config_file, PATH_MAX, "%s/scripts/%s", mobster_root, CONFIG_FILE_NAME);
    if (luaL_loadfile(L, config_file)) 
    {
        syslog (LOG_ERR,"luaL_loadfile failed; %s",lua_tostring(L, -1));
    	pthread_exit(NULL);
    }

    if (lua_pcall(L, 0, 0, 0))                  
    {
        syslog (LOG_ERR,"lua_pcall failed; %s",lua_tostring(L, -1));
    	pthread_exit(NULL);
    }

    lua_getglobal(L, "redis_host");
    if (lua_isstring(L, -1))
    {
	g_redis_host = strdup(lua_tostring(L, -1));
    }

    lua_getglobal(L, "redis_port");
    if (lua_isnumber(L, -1))
    {
	g_redis_port = (int) lua_tonumber(L, -1);
    }

    lua_getglobal(L, "mobster_scripts");             

    lua_pushnil(L);  

    if (!lua_istable(L, -2))
    {
        syslog (LOG_ERR,"Configuration item mobster_scripts must be a table");
    	pthread_exit(NULL);
    }

    while (lua_next(L, -2)) 
    {                   
	struct stat sb;
	pthread_t thread;
        const char *lua_script = lua_tostring(L, -1);                 
	char tmp [PATH_MAX];
	snprintf (tmp, PATH_MAX, "%s/scripts/%s", mobster_root, lua_script);

	/*
         * check that file exists with execute permissions 
         */
	if ((lstat (tmp,&sb)>=0) && S_ISREG(sb.st_mode))
	{
		char *mobster_script = strndup((const char *)tmp, PATH_MAX);
		if(pthread_create(&thread, NULL, lua_thread, (void *) mobster_script)!=0)
		{
			syslog (LOG_ERR,"pthread_create() %s", strerror (errno));
    			pthread_exit(NULL);
		}
	}
	else
	{
		syslog (LOG_ERR,"Mobster script %s does not exist.", lua_script);
	}
        lua_pop(L,1);                           
    }
    lua_close(L);                               
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */

void mobster_start(const char* mobster_root)
{
    run_mobster (mobster_root);
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */

#ifdef UNIT_TEST
int main(void)
{
    openlog ("mobster", LOG_PERROR, LOG_USER);
    mobster_start("mobster-config.lua");
    closelog();
}
#endif

/*
 * ---------------------------------------------------------------------------------------
 */

