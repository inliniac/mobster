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
	local params = { host = redis_host, port = redis_port }
	local channels = { 'EVE:ssh' }

	local listen = redis.connect(params)
	local client = redis.connect(params)
	for msg, abort in listen:pubsub({ subscribe = channels }) do
	    if msg.kind == 'message' then
			local eve = json.decode(msg.payload)
			local src_country = "unknown"
			local dst_country = "unknown"
			local key = "ssh:"..eve.src_ip
			if eve.src_ip and not eve.src_ip == "0.0.0.0" then
				--print(">> country lookup: "..eve.src_ip)
				res = db:lookup(eve.src_ip)
				if res then
					src_country = res:get("country", "names", "en")
					client:hmset(key, "country", country)
				end
				res = db:lookup(eve.dest_ip)
				if res then
					dst_country = res:get("country", "names", "en")
				end
				client.publish("EVE:notice","SSH "..eve.src_ip.."("..src_country..") => "..eve.dest_ip.."("..dst_country..")")
			end
	    end	
    	end
end

-- ----------------------------------------------
--
-- ----------------------------------------------
function run()
    while true do
        print ("ssh event handler listening to "..redis_host..":"..redis_port)
   	local success, result = pcall(process)
        if not success then
                print(result)
        end
    end
end

