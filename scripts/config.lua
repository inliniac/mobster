-- ----------------------------------------------
-- Global LUA variables
-- ----------------------------------------------

redis_host="127.0.0.1"
redis_port=6379
notice_key="EVE:notice"
log_dir="/var/log/mobster"
log_file="mobster.log"
script_dir="/opt/mobster/scripts"

mobster_scripts= 
{
	"file-events.lua",
	"dns-events.lua",
	"ssh-events.lua",
	"tls-events.lua",
	"http-events.lua",
	"flow-events.lua",
	"sumstats-events.lua"
}

