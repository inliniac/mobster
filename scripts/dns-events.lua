-- ----------------------------------------------
--
-- ----------------------------------------------

local mobster_root = os.getenv("MOBSTER_ROOT")
package.path = mobster_root.."/scripts/?.lua;" .. package.path
package.cpath = mobster_root.."/lib/?.so;" .. package.cpath

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
	    elseif msg.kind == 'message' then
			local eve = json.decode(msg.payload)
			if eve.dns.type == 'answer' and eve.dns.rdata then
				local value = nil
				local rrdata = eve.dns.rdata 
				local key = "dns:"..eve.flow_id..":"..eve.dns.id
				if not client:exists(key) then
					client:zincrby("dns",1,eve.dns.rrname)
				else
					value = client:hget(key,eve.dns.rrtype)
					if value then
						rrdata = value .." "..eve.dns.rdata	
					end	
				end
				if not client:hmset(key, eve.dns.rrtype,rrdata,"ttl",eve.dns.ttl) then
					print ("EVE:dns - hmset ERROR!")
				end
				client:expire(key,"60")
				-- DNS reputation lookup
				if client:sismember("dns:negative",eve.dns.rrname) then
					message = "matched negative dns: "..eve.dns.rrname
					mobster_notify (eve.timestamp, "dns", "notice", message)
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

