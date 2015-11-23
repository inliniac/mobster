-- ----------------------------------------------
--
-- ----------------------------------------------

local mobster_root = os.getenv("MOBSTER_ROOT")
package.path = mobster_root.."/scripts/?.lua;" .. package.path
package.cpath = mobster_root.."/lib/?.so;" .. package.cpath

-- pcall(require, "luarocks.require")

local redis = require('redis')
local json = require('cjson')

-- ----------------------------------------------
--
-- ----------------------------------------------
function process()
	local channel = { 'EVE:flow' }
        local params = { host = redis_host, port = redis_port }

	local listen = redis.connect(params)
	local client = redis.connect(params)

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
		if  tonumber(eve.flow.bytes_toserver) > tonumber (eve.flow.bytes_toclient) then
			client:publish("notice"," out:"..eve.dest_ip.."("..eve.flow.bytes_toserver..") > in:"..eve.src_ip.."("..eve.flow.bytes_toclient..")")
		end

		-- IP repuation lookup
		if client:sismember("black_list:ip",eve.src_ip) then
			client:publish("notice","matched bad ip address: "..eve.src_ip)	
		end

		if client:sismember("black_list:ip",eve.dest_ip) then
			client:publish("notice","matched bad ip address: "..eve.dest_ip)	
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
