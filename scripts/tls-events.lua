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
	local channels = { 'EVE:tls' }
	local params = { host = redis_host, port = redis_port }

	local listen = redis.connect(params)
	local client = redis.connect(params)

	for msg, abort in listen:pubsub({ subscribe = channels }) do
            if msg.kind == 'subscribe' then
                print('subscribed to channel '..msg.channel)
	    elseif msg.kind == 'message' then
		local eve = json.decode(msg.payload)
		local sha1 = string.gsub(eve.tls.fingerprint, ":", "")
		if sha1 then
			key = "tls:"..sha1
			client:hmset(key, "issuerdn",eve.tls.issuerdn,"subject",eve.tls.subject,"version", eve.tls.version)
			client:expire(key,'300')
			client:zincrby("tls",1,eve.tls.fingerprint)
			if not client:sismember("tls:valid",sha1) then
				local a_record = sha1..".notary.icsi.berkeley.edu"
				local ip = socket.dns.toip(a_record) 
				if ip == nil then
					client.publish("EVE:notice", "QUESTIONABLE cert: "..sha1.."\n\tissuer: "..eve.tls.issuerdn.."\n\tsubject: "..eve.tls.subject)
				else
					--print(">> TLS notary resp: "..ip)
					if ip == "127.0.0.2" or ip == "127.0.0.1" then
						--print(">> VALIDATED certificate "..sha1.." subject: "..eve.tls.subject)
						client:sadd("tls:valid",sha1) 
						client:expire(key,'300')
					else
						client.publish("EVE:notice","INVALID cert: "..sha1.."\n\tissuer: "..eve.tls.issuerdn.."\n\tsubject: "..eve.tls.subject)
					end
				end
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
        print ("tls event handler listening to "..redis_host..":"..redis_port)
   	local success, result = pcall(process)
        if not success then
                print(result)
        end
    end
end

