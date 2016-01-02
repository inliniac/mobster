-- ----------------------------------------------
--
-- ----------------------------------------------

local mobster_root = os.getenv("MOBSTER_ROOT")
package.path = script_dir.."/?.lua;" .. package.path
package.cpath = script_dir.."/lib/?.so;" .. package.cpath

local redis = require('redis')
local json = require('cjson')
local notice_log_path = log_dir.."/notice.log"

-- ----------------------------------------------
--
-- ----------------------------------------------
function process()
        print(notice_log_path)
	local channels = { notice_key }
	local params = { host = redis_host, port = redis_port }

	local listen = redis.connect(params)
	local client = redis.connect(params)
	local notice_log = io.open(notice_log_path, "a+")

	for msg, abort in listen:pubsub({ subscribe = channels }) do
	    if msg.kind == 'subscribe' then
                print('subscribed to channel '..msg.channel)
            elseif msg.kind == 'message' then
		notice_log:write(msg.payload,"\n")
                notice_log:flush()
	    end
	end

	notice_log:close()
end

-- ----------------------------------------------
--
-- ----------------------------------------------
function run()
    while true do
        print ("notice event handler listening to "..redis_host..":"..redis_port)
   	local success, result = pcall(process)
        if not success then
                print(result)
        end
    end
end

