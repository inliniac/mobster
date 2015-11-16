#!/usr/local/bin/luajit
-- ----------------------------------------------
--
-- ----------------------------------------------

local mobster_root = os.getenv("MOBSTER_ROOT") 
local script_root = mobster_root.."/lua"
package.path = script_root.."/?.lua;" .. package.path
package.cpath = mobster_root.."/lib/?.so;" .. package.path

pcall(require, "luarocks.require")

local redis = require('redis')
local json = require('cjson')

-- ----------------------------------------------
--
-- ----------------------------------------------
function process()
	local channels = { 'EVE:flow' }
	local params = { host = redis_host, port = redis_port }

	local listen = redis.connect(params)
	local client = redis.connect(params)

	for msg, abort in listen:pubsub({ subscribe = channels }) do
	    if msg.kind == 'message' then
		local eve = json.decode(msg.payload)
		local key = "unique:"..eve.src_ip
		client:pfadd(key,eve.dest_ip)
	    end
	end
end

-- ----------------------------------------------
--
-- ----------------------------------------------
function run()
    while true do
        print ("sumstats event handler listening to "..redis_host..":"..redis_port)
   	local success, result = pcall(process)
        if not success then
                print(result)
        end
    end
end

