
module(..., package.seeall)


local function status(self)
	self.handle:write("status\n")
	self.handle:flush()

	local t = {}
	local line = self.handle:read("*line")
	while line ~= "" do
		local host, status = string.match(line, "^(.*): (.*)$")
		t[host] = status
		line = self.handle:read("*line")
	end
	return t
end

local function close(self)
	return self.handle:close()
end

function connect(socket_path)
	local socket = require("pingu.client")
	local fh, err
	if socket ~= nil then
		fh, err = socket.open(socket_path)
	end
	if fh == nil then
		return fh, err
	end
	return {
		["handle"] = fh,
		["status"] = status,
		["close"] = close
	}
end


