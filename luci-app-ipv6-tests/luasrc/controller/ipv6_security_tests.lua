-- IPv6 security tests luci backend
--
-- Copyright (c) 2015 Brno University of Technology
--
-- Author(s): Jan Dražil <xdrazi00@stud.fit.vutbr.cz>
--

module("luci.controller.ipv6_security_tests", package.seeall)

function index()
	entry({"admin", "ipv6_security_tests"},
	alias("admin", "ipv6_security_tests", "RRA"),
		_("IPv6 Security Tests"), 60)

	entry({"admin", "ipv6_security_tests", "RRA"},
	call("RRA"),
		_("RRA"), 60)

	entry({"admin", "ipv6_security_tests", "NCP"},
	call("NCP"),
		_("NCP"), 60)
end

function interfaces()

	ifcs = {}
	for n,v in pairs(luci.sys.net.deviceinfo()) do
		if(n ~= "lo") then	
			table.insert(ifcs, n)
		end
	end

	return ifcs

end

function RRA()

	local values = {form={}, ifcs=interfaces()}
	values.form.output = ""
	values.form.test = ""
	values.form.timeout = ""
	values.form.dest_mac = ""
	values.form.dest_ip = ""
	values.form.source_mac = ""
	values.form.source_ip = ""
	values.form.cur_hop_limit = ""
	values.form.router_pref = ""
	values.form.router_lifetime = ""
	values.form.reachable_time = ""
	values.form.retrans_timer = ""
	values.form.ext_num = ""
	values.form.max_mtu = ""
	values.form.sll_address = ""
	values.form.adv_mtu = ""
	values.form.adv_prefix = false
	values.form.prefix = ""
	values.form.length = ""
	values.form.l_flag = false
	values.form.a_flag = false
	values.form.r_flag = false
	values.form.valid_lifetime = ""
	values.form.pref_lifetime = ""
	values.attack = "Rough Router Advertisement"
		
	local file = nil


	local x = luci.http.formvaluetable("form");
	for n,v in pairs(x) do values.form[n] = v end

	if luci.http.formvalue("getresult") then
		luci.http.prepare_content("text/plain")
		local result_file = io.open("/tmp/ipv6-tests-result", "r")
		if result_file then
			luci.http.write(tostring(result_file:read("*n")))
		else
			luci.http.write("99")
		end
		luci.http.close()
		
	elseif values.form.run then
		path = (luci.sys.getenv("PATH") or "/usr/bin:/usr/sbin") .. ":/opt/usr/bin:/opt/usr/sbin"
		library_path = (luci.sys.getenv("LD_LIBRARY_PATH") or "/lib:/usr/lib") .. ":/opt/usr/lib:/opt/lib"
		
		local function build_prefix() 
			if values.form.adv_prefix == "1" then
				local str = "\"".. values.form.prefix .."\""
				str = str .. " \"" .. values.form.length .."\""
				str = str .. " ".. (values.form.l_flag == "1" and "1" or "0")
				str = str .. " ".. (values.form.a_flag == "1" and "1" or "0")
				str = str .. " ".. (values.form.r_flag == "1" and "1" or "0")
				str = str .. " \"" .. values.form.valid_lifetime .."\""
				str = str .. " \"" .. values.form.pref_lifetime .."\""
				return str
			else
				return nil
			end
		end
		
		local wrapper_params = {
			{"-o", values.form.output},
			{"-t", values.form.test},
			{"-w", values.form.timeout}
		}
		
		local rra_params = {
		{"-d", values.form.dest_mac},
		{"-D", values.form.dest_ip},
		{"-s", values.form.source_mac},
		{"-S", values.form.source_ip},
		{"-c", values.form.cur_hop_limit},
		{"-p", values.form.router_pref},
		{"-l", values.form.router_lifetime},
		{"-r", values.form.reachable_time},
		{"-R", values.form.retrans_timer},
		{"-e", values.form.ext_num},
		{"-f", values.form.max_mtu},
		{"-a", values.form.sll_address},
		{"-m", values.form.adv_mtu},
		}
		
		local command="wrapper.py"
		
		for index, param in ipairs(wrapper_params) do
			if param[2] ~= "" then
				command = command .." ".. param[1] .." \"".. param[2] .."\""
			end
		end
		
		command = command .." RRA"
		
		for index, param in ipairs(rra_params) do
			if param[2] ~= "" then
				command = command .." ".. param[1] .." \"".. param[2] .."\""
			end
		end
		
		local prefix_param = build_prefix()
		if prefix_param ~= nil then
			command = command .." -P ".. prefix_param
		end
		
		cmd_out = io.popen("PATH=".. path .." LD_LIBRARY_PATH=".. library_path .." ".. command  .." 2>&1")
		values.cmd_out = cmd_out
		values.command = command
		
		values.result_file = io.open("/tmp/ipv6-tests-result", "w")
		luci.template.render("ipv6_security_tests/result", values)
	else
		luci.template.render("ipv6_security_tests/rra", values)
	end

end

function NCP()
	local values = {form={}, ifcs=interfaces()}
	values.form.output = ""
	values.form.test = ""
	values.form.timeout = ""
	values.form.dest_mac = ""
	values.form.dest_ip = ""
	values.form.source_mac = ""
	values.form.source_ip = ""
	values.form.neigh_adv = false
	values.form.ext_num = ""
	values.form.max_mtu = ""
	values.form.sll_address = ""
	values.form.target_ip = ""
	values.form.r_flag = false
	values.form.s_flag = false
	values.form.o_flag = false
	values.attack = "Neighbor Cache Poison"
		
	local file = nil


	local x = luci.http.formvaluetable("form");
	for n,v in pairs(x) do values.form[n] = v end

	if luci.http.formvalue("getresult") then
		luci.http.prepare_content("text/plain")
		local result_file = io.open("/tmp/ipv6-tests-result", "r")
		if result_file then
			luci.http.write(tostring(result_file:read("*n")))
		else
			luci.http.write("99")
		end
		luci.http.close()
		
	elseif values.form.run then
		path = (luci.sys.getenv("PATH") or "/usr/bin:/usr/sbin") .. ":/opt/usr/bin:/opt/usr/sbin"
		library_path = (luci.sys.getenv("LD_LIBRARY_PATH") or "/lib:/usr/lib") .. ":/opt/usr/lib:/opt/lib"
		
		local function build_neigh_adv() 
			local str = "\"".. values.form.target_ip .."\""
			str = str .. " ".. (values.form.r_flag == "1" and "1" or "0")
			str = str .. " ".. (values.form.s_flag == "1" and "1" or "0")
			str = str .. " ".. (values.form.o_flag == "1" and "1" or "0")
			return str
		end
		
		local wrapper_params = {
			{"-o", values.form.output},
			{"-t", values.form.test},
			{"-w", values.form.timeout}
		}
		
		local ncp_params = {
		{"-d", values.form.dest_mac},
		{"-D", values.form.dest_ip},
		{"-s", values.form.source_mac},
		{"-S", values.form.source_ip},
		{"-e", values.form.ext_num},
		{"-f", values.form.max_mtu},
		{"-a", values.form.sll_address},
		}
		
		local command="wrapper.py"
		
		for index, param in ipairs(wrapper_params) do
			if param[2] ~= "" then
				command = command .." ".. param[1] .." \"".. param[2] .."\""
			end
		end
		
		command = command .." NCP"
		
		for index, param in ipairs(ncp_params) do
			if param[2] ~= "" then
				command = command .." ".. param[1] .." \"".. param[2] .."\""
			end
		end
		
		command = command .." -n ".. build_neigh_adv()
		
		cmd_out = io.popen("PATH=".. path .." LD_LIBRARY_PATH=".. library_path .." ".. command  .." 2>&1")
		values.cmd_out = cmd_out
		values.command = command
		
		values.result_file = io.open("/tmp/ipv6-tests-result", "w")
		luci.template.render("ipv6_security_tests/result", values)
	else
		luci.template.render("ipv6_security_tests/ncp", values)
	end
end
