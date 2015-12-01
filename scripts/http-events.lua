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
        local params = { host = redis_host, port = redis_port }
	local channels = { 'EVE:http' }

	local listen = redis.connect(params)
	local client = redis.connect(params)
	for msg, abort in listen:pubsub({ subscribe = channels }) do
	    if msg.kind == 'message' then
		local eve = json.decode(msg.payload)
		if eve.http.http_user_agent then
			client:zincrby("http_user_agent",1,eve.http.http_user_agent)
			--print(">> http_user_agent: "..eve.http.http_user_agent)
		end
	    end
	end
end

-- ----------------------------------------------
--
-- ----------------------------------------------
function run()
    while true do
        print ("http event handler listening to "..redis_host..":"..redis_port)
   	local success, result = pcall(process)
        if not success then
                print(result)
        end
    end
end

