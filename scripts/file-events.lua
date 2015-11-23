-- ----------------------------------------------
--
-- ----------------------------------------------

local mobster_root = os.getenv("MOBSTER_ROOT")
package.path = mobster_root.."/scripts/?.lua;" .. package.path
package.cpath = mobster_root.."/lib/?.so;" .. package.cpath

--pcall(require, "luarocks.require")

local redis = require('redis')
local json = require('cjson')

-- ----------------------------------------------
--
-- ----------------------------------------------
function process()
	local channel = { 'EVE:fileinfo' }
        local params = { host = redis_host, port = redis_port }

	local listen = redis.connect(params)
	local client = redis.connect(params)
	for msg, abort in listen:pubsub({ subscribe = channel }) do
            if msg.kind == 'subscribe' then
                print('subscribed to channel '..msg.channel)
	    elseif msg.kind == 'message' then
			local eve = json.decode(msg.payload)
			key = "fileinfo:"..eve.flow_id
			local filename = eve.fileinfo.filename
			local index = eve.fileinfo.filename:match('^.*()/')
			if index then
				filename = string.sub (eve.fileinfo.filename, index+1)
			end
			client:hmset(key, "filename",filename,"magic",eve.fileinfo.magic)
			client:expire(key,'300')
			--client:zincrby("fileinfo",1,eve.fileinfo.md5)
			--print (key.." : " .. filename)
	    end
	end
end

-- ----------------------------------------------
--
-- ----------------------------------------------
function run()
    while true do
        print ("file event handler listening to "..redis_host..":"..redis_port)
   	local success, result = pcall(process)
        if not success then
                print(result)
        end
    end
end

