
module(..., package.seeall)


local function run_command(self, cmd)
	self.handle:write(cmd.."\n")
	self.handle:flush()

	local t = {}
	local line = self.handle:read("*line")
	while line ~= "" do
		local key, value = string.match(line, "^(.*): (.*)$")
		t[key] = value
		line = self.handle:read("*line")
	end
	return t
end

local function host_status(self)
	return self:run_command("host-status")
end

local function gateway_status(self)
	return self:run_command("gateway-status")
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
		["run_command"] = run_command,
		["host_status"] = host_status,
		["gateway_status"] = gateway_status,
		["close"] = close
	}
end


