-- ----------------------------------------------
-- Global LUA variables
-- ----------------------------------------------

redis_host="127.0.0.1"
redis_port=6379

-- changed the following to ${MOBSTER}/lua directory
event_threads =
{
	"/home/github/mobster/lua/file-events.lua",
	"/home/github/mobster/lua/dns-events.lua",
	"/home/github/mobster/lua/ssh-events.lua",
	"/home/github/mobster/lua/tls-events.lua",
	"/home/github/mobster/lua//http-events.lua",
	"/home/github/mobster/lua/flow-events.lua",
	"/home/github/mobster/lua/sumstats-events.lua"
}


