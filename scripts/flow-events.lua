-- ----------------------------------------------
--
-- ----------------------------------------------

local mobster_root = os.getenv("MOBSTER_ROOT")
package.path = mobster_root.."/scripts/?.lua;" .. package.path
package.cpath = mobster_root.."/lib/?.so;" .. package.cpath

local redis = require('redis')
local json = require('cjson')

local mm = require 'maxminddb'
local db = mm.open('/var/lib/libmaxminddb/GeoLite2-Country.mmdb')

-- ----------------------------------------------
--
-- ----------------------------------------------
function process()
	local channel = { 'EVE:flow' }
        local params = { host = redis_host, port = redis_port }

	local listen = redis.connect(params)
	local client = redis.connect(params)

	-- ----------------------------------------------
	--
	-- ----------------------------------------------
	for msg, abort in listen:pubsub({ subscribe = channel }) do
            if msg.kind == 'subscribe' then
                print('subscribed to channel '..msg.channel)
	    elseif msg.kind == 'message' then
		local res = nil
		local eve = json.decode(msg.payload)

		local key = "flow:"..eve.src_ip
		client:hincrby(key, "bytes_in",eve.flow.bytes_toclient)
		client:hincrby(key, "pkts_in",eve.flow.pkts_toclient)
		client:expire(key,'60')

		key = "flow:"..eve.dest_ip
		client:hincrby(key, "bytes_in",eve.flow.bytes_toserver)
		client:hincrby(key, "pkts_in",eve.flow.pkts_toserver)
		client:expire(key,'60')

		-- bytes out > bytes in ?
		if  tonumber(eve.flow.bytes_toserver) > tonumber (eve.flow.bytes_toclient) and  tonumber(eve.flow.bytes_toserver) > 65536 then
			local message = "flow - out:"..eve.dest_ip.."("..eve.flow.bytes_toserver..") > in:"..eve.src_ip.."("..eve.flow.bytes_toclient..")"
			mobster_notify (eve.timestamp, "flow", "notice", message)
		end


		-- ----------------------------------------------
		-- GEO IP lookup 
		-- ----------------------------------------------
                local src_country = "unknown"
                if not eve.src_ip == "0.0.0.0" then
                        res = db:lookup(eve.src_ip)
                        if res then
                                src_country = res:get("country", "names", "en")
				if not string.match (src_country,"United States") then
					local message = "Foreign connection "..eve.src_ip.." : "..src_country 
					mobster_notify (eve.timestamp, "flow", "notice", message)
 				end 
                        end
                end

                local dst_country = "unknown"
                if not eve.dest_ip == "0.0.0.0" then
                        res = db:lookup(eve.dest_ip)
                        if res then
                                dst_country = res:get("country", "names", "en")
				if not string.match (dst_country,"United States") then
					local message = "Foreign connection "..eve.dest_ip.." : "..dst_country 
					mobster_notify (eve.timestamp, "flow", "notice", message)
 				end 
                        end
                end

		-- ----------------------------------------------
		-- IP reputation lookup
		-- ----------------------------------------------
		if client:sismember("ip:negative",eve.src_ip) then
			local message = "Matched negative src ip address: "..eve.src_ip..":"..eve.src_port.." ("..src_country..") -> "..eve.dest_ip..":"..dest_port.." ("..dst_country..")"
			mobster_notify (eve.timestamp, "flow", "notice", message)
		end

		if client:sismember("ip:negative",eve.dest_ip) then
			local message = "Matched negative dst ip address: "..eve.dest_ip..":"..dest_port.." ("..dst_country..") <- "..src_ip..":"..eve.src_port.." ("..src_country..")
	 		mobster_notify (eve.timestamp, "flow", "notice", message)
		end	
	    end
	end
end

-- ----------------------------------------------
--
-- ----------------------------------------------
function run()
    while true do
        print ("flow event handler listening to "..redis_host..":"..redis_port)
   	local success, result = pcall(process)
        if not success then
                print(result)
        end
    end
end
