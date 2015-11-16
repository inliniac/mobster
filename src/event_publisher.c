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

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <hiredis/hiredis.h>

#include "jsmn.h"

extern uint64_t g_msgReceived;
extern uint64_t g_msgPublished;
extern uint64_t g_msgSubscribed;
static char *g_host = NULL;
static int g_port = 0;
static redisContext *g_redis = NULL;

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
#define MAX_JSON_TOKENS	64
 
static int json_token_streq(char *js, jsmntok_t *t, char *s)
{
    return (strncmp(js + t->start, s, t->end - t->start) == 0
            && strlen(s) == (size_t) (t->end - t->start));
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static char * json_token_tostr(char *js, jsmntok_t *t)
{
    js[t->end] = '\0';
    return js + t->start;
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static void eve_json_handler (struct bufferevent *bev, void *ctx)
{
	char *event_type = NULL;
	char *json_object = NULL;
        char *json_record = NULL;
        size_t len = 0; 
        struct evbuffer *input = bufferevent_get_input(bev);
    
	if ((json_record = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF))==NULL)
	{
		/* not a full JSON record yet */
    		return;
	}
	if ((json_object=strndup (json_record, len+1))==NULL)
	{
		syslog (LOG_ERR,"strndup() failed; %s", strerror (errno));
		free(json_record);
		return;
	}
	g_msgReceived++;

	/*
	 * parse JSON
	 */
	int status;
	jsmntok_t tokens[MAX_JSON_TOKENS];
	jsmn_parser parser;
	jsmn_init(&parser);
	
	memset (tokens, 0, sizeof (tokens));
	if ((status=jsmn_parse(&parser, json_object, len, tokens, MAX_JSON_TOKENS)) < 0)
	{
		/* error or not a valid json string */
		syslog (LOG_ERR,"jsmn_parse() failed to parse %s", json_object);
		free(json_record);
		free(json_object);
		return;
	}
	
	/* walk through the tokens */
	int i=0;
	for (i=0; i < MAX_JSON_TOKENS; i++)
	{	 
		jsmntok_t *t = &tokens[i];
		if ((t!=NULL) && (t->type == JSMN_STRING) && (json_token_streq(json_object, t,"event_type")))
		{
			/*
                         * Get the even_type value 
                         */
			t = &tokens[i+1];
			event_type = json_token_tostr(json_object, t);
			break;
		}
	}
	if (!event_type)
	{
		free(json_object);
		free(json_record);
		return;
	}

	/* 
         * Check if conneciton to redis is established
         */
	if (!g_redis)
	{
		g_redis=redisConnect(g_host, g_port);
		if (!g_redis) 
		{
			syslog (LOG_ERR,"redisConnect() failed; %s", g_redis->errstr);
			abort ();
		}
		if (g_redis->err)
		{
			syslog (LOG_ERR,"redisConnect() failed; %s", g_redis->errstr);
			redisFree(g_redis);
			g_redis=NULL;
			return;
		}
	}
	/*
	 * publish JSON record
	 */
	redisReply *reply = redisCommand(g_redis, "PUBLISH EVE:%s %s", event_type, json_record);
	if (!reply)
	{
		syslog (LOG_ERR,"redisCommand() failed; %s", g_redis->errstr);
		abort ();
	}
	else if (reply->type==REDIS_REPLY_ERROR)
	{
		syslog (LOG_ERR,"redisCommand() failed; %s", reply->str);
	}
	else
	{
		g_msgPublished++;
	}
	freeReplyObject (reply);
	free(json_object);
	free(json_record);
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static void *notice_subscriber_thread (void *v)
{
    (void) v;
    FILE * fp = NULL;
    redisContext *redis = NULL;
    pthread_setname_np(pthread_self(), "notice");

    syslog (LOG_INFO,"%s running", __FUNCTION__);
    do
    {
	if (!fp)
        {
		fp = fopen ("/var/log/notice.log", "a");
		if (!fp)
		{
			syslog (LOG_ERR,"fopen() failed; %s", strerror (errno));
			/* retry in 10 seconds */
			sleep (10);
			continue;
		}
        }
	if (!redis)
        {
                redis=redisConnect(g_host, g_port);
	        if (!redis)
		{
                        syslog (LOG_ERR,"redisConnect() failed; %s", redis->errstr);
			abort ();
		}
                if (redis->err)
                {
                        syslog (LOG_ERR,"redisConnect() failed; %s", redis->errstr);
			redisFree(redis);
                        redis=NULL;
			/* retry in 10 seconds */
			sleep (10);
			continue;
                }
        }
	redisReply *reply  = redisCommand(redis,"SUBSCRIBE notice");
	if (!reply)
        {
                syslog (LOG_ERR,"redisCommand() failed; %s", redis->errstr);
		abort ();
        }
        else if (reply->type==REDIS_REPLY_ERROR)
        {
                syslog (LOG_ERR,"redisCommand() failed; %s", reply->str);
    		freeReplyObject(reply);
        }
        else
        {
    	    freeReplyObject(reply);
	    reply = NULL;

	    while(redisGetReply(redis, (void **) &reply) == REDIS_OK)
	    {
		    if (reply && reply->type==REDIS_REPLY_ARRAY && (reply->elements>=3))
		    {
			time_t gmt;
			struct tm result;
			time(&gmt);
			
			gmtime_r(&gmt, &result);
		        fprintf(fp, "{ \"timestamp\":\"%u-%u-%uT%02u:%02u:%02u.000000\", \"event_type\":\"%s\", \"%s\": { \"%s\":\"%s\" }}\n", 
					    (1900+result.tm_year),
					    (result.tm_mon+1),
					    (result.tm_mday),
					    (result.tm_hour),
					    (result.tm_min),
					    (result.tm_sec),
					    reply->element[1]->str,
					    reply->element[1]->str,
					    reply->element[0]->str,
					    reply->element[2]->str);
		        freeReplyObject(reply);
			reply = NULL;
			//fflush (fp);
			if (ferror (fp))
			{
			    syslog (LOG_ERR,"fprintf() failed; %s", strerror (errno));
			    fclose (fp);
			    fp = NULL;
			    break;
			}	
		     }
		     else
		     {
		        freeReplyObject(reply);
                     }
	    }
	    if (redis)
	    {
	 	redisFree (redis);
	    	redis=NULL;
	    }
	}
    } while (1);

    pthread_exit(NULL);
}
/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static void eve_event_handler (struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_ERROR)
    {
    	syslog (LOG_ERR,"bufferevent() error");
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) 
    {
	redisContext *redis = *((redisContext **) ctx);
	redisFree (redis);
        bufferevent_free(bev);
    }
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static void eve_accept_handler (struct evconnlistener *listener, evutil_socket_t fd, 
			   	            struct sockaddr *address, int socklen, void *ctx)
{
    fprintf (stderr,"%s\n", __FUNCTION__);

    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    //
    // setup redis connection
    //
    bufferevent_setcb(bev, eve_json_handler, NULL, eve_event_handler, (void *)ctx);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
static void eve_error_handler (struct evconnlistener *listener, void *ctx)
{
    fprintf (stderr,"DEBUG(%s:%u)\n", __FUNCTION__, __LINE__);
    struct event_base *base = evconnlistener_get_base(listener);
    syslog (LOG_ERR,"evconnlistener() %s ", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    event_base_loopexit(base, NULL);
}

/*
 * ---------------------------------------------------------------------------------------
 *
 * ---------------------------------------------------------------------------------------
 */
int eve_processor_start (char *socket_path, const char* ip, int port)
{
    struct event_base *base;
    struct evconnlistener *listener;
    struct sockaddr_un sin;

    unlink (socket_path);
    g_host = strndup (ip, 128);
    g_port = port;

    pthread_t thread;
    if(pthread_create(&thread, NULL, notice_subscriber_thread, (void *) NULL)!=0)
    {
    	syslog (LOG_ERR,"pthread_create() %s", strerror (errno));
        return -1;
    }

    /*
     * setup libevent connection
    */
    base = event_base_new();
    if (!base) 
    {
        syslog (LOG_ERR,"event_base_new() failed");
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sun_family = AF_LOCAL;
    strcpy(sin.sun_path, socket_path);

    listener = evconnlistener_new_bind(base, eve_accept_handler, NULL,
                                       LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                       (struct sockaddr *) &sin, sizeof(sin));
    if (!listener) 
    {
        syslog (LOG_ERR,"evconnlistener_new_bind() failed");
        return -1;
    }
    evconnlistener_set_error_cb(listener, eve_error_handler);
    event_base_dispatch(base);

    return 0;
}

/*
 * ---------------------------------------------------------------------------------------
 */

