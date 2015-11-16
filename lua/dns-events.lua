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
	local channel = { 'EVE:dns' }
	local params = { host = redis_host, port = redis_port }

	local listener = redis.connect(params)
	local client = redis.connect(params)
	for msg, abort in listener:pubsub({ subscribe = channel }) do
	    if msg.kind == 'subscribe' then
        	print('subscribed to channel '..msg.channel)
	    elseif msg.kind == 'message' and msg.channel == 'EVE:dns' then
			local eve = json.decode(msg.payload)
			if eve.dns.type == 'answer' and eve.dns.rdata then
				local value = nil
				local rrdata = eve.dns.rdata 
				local key = "dns:"..eve.flow_id..":"..eve.dns.id
				if string.find (eve.dns.rrname,"notary.icsi.berkeley.edu") then
				-- skip notary
				elseif not client:exists(key) then
					client:zincrby("dns",1,eve.dns.rrname)
					--print(">> "..key .." : " ..eve.dns.rrtype .." : "..eve.dns.rrname)
				else
					value = client:hget(key,eve.dns.rrtype)
					if value then
						rrdata = value .." "..eve.dns.rdata	
					end	
				end
				if not client:hmset(key, eve.dns.rrtype,rrdata,"ttl",eve.dns.ttl) then
					print ("hmset ERROR!")
				end
				client:expire(key,"60")
				-- DNS repuation lookup
				if client:sismember("black_list:dns",eve.dns.rrname) then
					client:publish("notice","matched bad dns: "..eve.dns.rrname)	
				end
			end
	    end
	end
end

-- ----------------------------------------------
--
-- ----------------------------------------------
function run()
    while true do
        print ("dns event handler listening to "..redis_host..":"..redis_port)
        local success, result = pcall(process)
	if not success then
        	print(result)
	end
    end
end

