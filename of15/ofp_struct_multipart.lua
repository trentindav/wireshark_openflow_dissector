-- Author: Davide Trentin (trentindav@gmail.com)
-- Licensed under the Apache License, Version 2.0, see LICENSE for details

local ofp = require "ofp_const"
local ofp_struct = require "of15.ofp_struct"

local M = {}

fields = _G.of_proto.fields
M.parsers_ofpmp_request = {}
M.parsers_ofpmp_reply = {}

-- Flow Stats
fields.flow_desc = ProtoField.new("Flow Desc", "of.flow_desc", ftypes.STRING)
fields.flow_desc_table_id = ProtoField.new("Table Id", "of.flow_desc.table_id", ftypes.UINT8, nil, base.DEC)
fields.flow_desc_priority = ProtoField.new("Priority", "of.flow_desc.priority", ftypes.UINT16, nil, base.DEC)
fields.flow_desc_idle_timeout = ProtoField.new("Idle Timeout", "of.flow_desc.idle_timeout", ftypes.UINT16, nil, base.DEC)
fields.flow_desc_hard_timeout = ProtoField.new("Hard Timeout", "of.flow_desc.hard_timeout", ftypes.UINT16, nil, base.DEC)
fields.flow_desc_flags = ProtoField.new("Flags", "of.flow_desc.flags", ftypes.UINT16, nil, base.HEX, 0xffffffff)
-- fields.flow_desc_flags = ProtoField.new("OFPMPF_REQUEST_MORE", "of.multipart.flags.request_more", ftypes.BOOLEAN, nil, 16, 0x00000001)
fields.flow_desc_importance = ProtoField.new("Importance", "of.flow_desc.importance", ftypes.UINT16, nil, base.DEC)
fields.flow_desc_cookie = ProtoField.new("Cookie", "of.flow_desc.cookie", ftypes.UINT64, nil, base.HEX)
function ofp_flow_desc(tvb, pinfo, tree)
    local subtree = tree:add(fields.flow_desc, tvb(), "", "Flow Desc")
    subtree:add(fields.length, tvb(0,2))
    -- subtree:add(fields.pad2, tvb(2,2))
    subtree:add(fields.flow_desc_table_id, tvb(4,1))
    -- subtree:add(fields.pad, tvb(5,1))
    subtree:add(fields.flow_desc_priority, tvb(6,2))
    subtree:add(fields.flow_desc_idle_timeout, tvb(8,2))
    subtree:add(fields.flow_desc_hard_timeout, tvb(10,2))
    subtree:add(fields.flow_desc_flags, tvb(12,2))  -- TODO: OFPFF_ flags
    subtree:add(fields.flow_desc_importance, tvb(14,2))
    subtree:add(fields.flow_desc_cookie, tvb(16,8))
    local match_len = ofp_struct.ofp_match(tvb(24, ofp.roundup(tvb(26,2):uint())), pinfo, subtree)
    local stats_len = ofp_struct.ofp_stats(tvb(24+match_len, tvb(26+match_len,2):uint()), pinfo, subtree)
    -- ofp_instruction
    ofp_struct.instruction_list(tvb(24+match_len+stats_len), pinfo, subtree)
    return tvb(0, 2):uint()
end
M.ofp_flow_desc = ofp_flow_desc

fields.flow_stats = ProtoField.new("Flow Stats", "of.flow_stats", ftypes.STRING)
fields.flow_stats_table_id = ProtoField.new("Table Id", "of.flow_stats.table_id", ftypes.UINT8, nil, base.DEC)
fields.flow_stats_reason = ProtoField.new("Reason", "of.flow_stats.reason", ftypes.UINT8, ofp.ofp_flow_stats_reason, base.DEC)
fields.flow_stats_priority = ProtoField.new("Priority", "of.flow_stats.priority", ftypes.UINT16, nil, base.DEC)
function ofp_flow_stats(tvb, pinfo, tree)
    local subtree = tree:add(fields.flow_stats, tvb(), "", "Flow Stats")
    subtree:add(fields.length, tvb(0,2))
    -- subtree:add(fields.pad2, tvb(2,2))
    subtree:add(fields.flow_stats_table_id, tvb(4,1))
    subtree:add(fields.flow_stats_reason, tvb(5,1))
    subtree:add(fields.flow_stats_priority, tvb(6,2))
    -- match
    local match_len = ofp_struct.ofp_match(tvb(8, ofp.roundup(tvb(10,2):uint())), pinfo, subtree)
    -- stats
    local stats_len = ofp_struct.ofp_stats(tvb(8+match_len), pinfo, subtree)
    return tvb(0, 2):uint()
end
M.ofp_flow_stats = ofp_flow_stats

fields.flow_desc_request = ProtoField.new("Flow Desc Request", "of.flow_desc_request", ftypes.STRING)
function ofp_flow_desc_request(tvb, pinfo, tree)
    tree:add(fields.flow_desc_request, tvb())
end
M.ofp_flow_desc_request = ofp_flow_desc_request
M.parsers_ofpmp_request[ofp.OFPMP_FLOW_DESC] = ofp_flow_desc_request

fields.ofp_flow_desc_request = ProtoField.new("Flow Desc Request", "of.flow_desc_request", ftypes.STRING)
fields.flow_desc_request_table_id = ProtoField.new("Table Id", "of.flow_desc_request.table_id", ftypes.UINT8, nil, base.DEC)
fields.flow_desc_request_out_port = ProtoField.new("Out Port", "of.flow_desc_request.out_port", ftypes.UINT32, nil, base.DEC)
fields.flow_desc_request_out_group = ProtoField.new("Out Group", "of.flow_desc_request.out_group", ftypes.UINT32, nil, base.DEC)
fields.flow_desc_request_cookie = ProtoField.new("Cookie", "of.flow_desc_request.cookie", ftypes.UINT64, nil, base.HEX)
fields.flow_desc_request_cookie_mask = ProtoField.new("Cookie Mask", "of.flow_desc_request.cookie_mask", ftypes.UINT64, nil, base.HEX)
function ofp_flow_desc_request(tvb, pinfo, tree)
    local subtree = tree:add(fields.flow_stats_request, tvb(), "", "Flow Desc Request")
    subtree:add(fields.flow_desc_request_table_id, tvb(0,1))
    -- subtree:add(fields.pad3, tvb(1,3))
    local out_port = tvb(4,4):uint()
    local out_group = tvb(8,4):uint()
    if (ofp.ofp_port_no[out_port] ~= nil) then
        subtree:add(fields.flow_desc_request_out_port, tvb(4,4), out_port, "Out Port: "..ofp.ofp_port_no[out_port])
    else
        subtree:add(fields.flow_desc_request_out_port, tvb(4,4))
    end
    if (ofp.ofp_group[out_group] ~= nil) then
        subtree:add(fields.flow_desc_request_out_group, tvb(8,4), out_group, "Out Group: "..ofp.ofp_group[out_group])
    else
        subtree:add(fields.flow_desc_request_out_group, tvb(8,4))
    end
    -- subtree:add(fields.pad4, tvb(12,4))
    subtree:add(fields.flow_desc_request_cookie, tvb(16,8))
    subtree:add(fields.flow_desc_request_cookie_mask, tvb(24,8))
    ofp_struct.ofp_match(tvb(32), pinfo, subtree)
end
M.ofp_flow_desc_request = ofp_flow_desc_request
M.parsers_ofpmp_request[ofp.OFPMP_FLOW_DESC] = ofp_flow_desc_request

fields.flow_desc_reply = ProtoField.new("Flow Desc Reply", "of.flow_desc_reply", ftypes.STRING)
function ofp_flow_desc_reply(tvb, pinfo, tree)
    offset = 0
    while (offset < tvb:len()) do
        offset = offset + ofp_flow_desc(tvb(offset, tvb(offset,2):uint()), pinfo, tree)
    end
end
M.ofp_flow_desc_reply = ofp_flow_desc_reply
M.parsers_ofpmp_reply[ofp.OFPMP_FLOW_DESC] = ofp_flow_desc_reply

fields.flow_stats_request = ProtoField.new("Flow Stats Request", "of.flow_stats_request", ftypes.STRING)
fields.flow_stats_request_out_port = ProtoField.new("Out Port", "of.flow_stats_request.out_port", ftypes.UINT32, nil, base.DEC)
fields.flow_stats_request_out_group = ProtoField.new("Out Group", "of.flow_stats_request.out_group", ftypes.UINT32, nil, base.DEC)
fields.flow_stats_request_cookie = ProtoField.new("Cookie", "of.flow_stats_request.cookie", ftypes.UINT64, nil, base.HEX)
fields.flow_stats_request_cookie_mask = ProtoField.new("Cookie Mask", "of.flow_stats_request.cookie_mask", ftypes.UINT64, nil, base.HEX)
function ofp_flow_stats_request(tvb, pinfo, tree)
    local subtree = tree:add(fields.flow_stats_request, tvb(), "", "Flow Stats Request")
    subtree:add(fields.flow_stats_table_id, tvb(0,1))
    -- subtree:add(fields.pad3, tvb(1,3))
    local out_port = tvb(4,4):uint()
    local out_group = tvb(8,4):uint()
    if (ofp.ofp_port_no[out_port] ~= nil) then
        subtree:add(fields.flow_stats_request_out_port, tvb(4,4), out_port, "Out Port: "..ofp.ofp_port_no[out_port])
    else
        subtree:add(fields.flow_stats_request_out_port, tvb(4,4))
    end
    if (ofp.ofp_group[out_group] ~= nil) then
        subtree:add(fields.flow_stats_request_out_group, tvb(8,4), out_group, "Out Group: "..ofp.ofp_group[out_group])
    else
        subtree:add(fields.flow_stats_request_out_group, tvb(8,4))
    end
    -- subtree:add(fields.pad4, tvb(12,4))
    subtree:add(fields.flow_stats_request_cookie, tvb(16,8))
    subtree:add(fields.flow_stats_request_cookie_mask, tvb(24,8))
    ofp_struct.ofp_match(tvb(32), pinfo, subtree)
end
M.ofp_flow_stats_request = ofp_flow_stats_request
M.parsers_ofpmp_request[ofp.OFPMP_FLOW_STATS] = ofp_flow_stats_request

fields.flow_stats_reply = ProtoField.new("Flow Stats Reply", "of.flow_stats_reply", ftypes.STRING)
function ofp_flow_stats_reply(tvb, pinfo, tree)
    -- tree:add(fields.flow_stats_reply, tvb())
    offset = 0
    while (offset < tvb:len()) do
        offset = offset + ofp_flow_stats(tvb(offset, tvb(offset,2):uint()), pinfo, tree)
    end
end
M.ofp_flow_stats_reply = ofp_flow_stats_reply
M.parsers_ofpmp_reply[ofp.OFPMP_FLOW_STATS] = ofp_flow_stats_reply

fields.aggregate_flow_stats_request = ProtoField.new("Aggregate Flow Stats Request", "of.aggregate_flow_stats_request", ftypes.STRING)
fields.aggregate_flow_stats_request_table_id = ProtoField.new("Table Id", "of.aggregate_flow_stats_request.table_id", ftypes.UINT8, nil, base.DEC)
fields.aggregate_flow_stats_request_out_port = ProtoField.new("Out Port", "of.aggregate_flow_stats_request.out_port", ftypes.UINT32, nil, base.DEC)
fields.aggregate_flow_stats_request_out_group = ProtoField.new("Out Group", "of.aggregate_flow_stats_request.out_group", ftypes.UINT32, nil, base.DEC)
fields.aggregate_flow_stats_request_cookie = ProtoField.new("Cookie", "of.aggregate_flow_stats_request.cookie", ftypes.UINT64, nil, base.HEX)
fields.aggregate_flow_stats_request_cookie_mask = ProtoField.new("Cookie Mask", "of.aggregate_flow_stats_request.cookie_mask", ftypes.UINT64, nil, base.HEX)
function ofp_aggregate_flow_stats_request(tvb, pinfo, tree)
    local subtree = tree:add(fields.flow_stats_request, tvb(), "", "Aggregate Flow Stats Request")
    subtree:add(fields.aggregate_flow_stats_request_table_id, tvb(0,1))
    -- subtree:add(fields.pad3, tvb(1,3))
    local out_port = tvb(4,4):uint()
    local out_group = tvb(8,4):uint()
    if (ofp.ofp_port_no[out_port] ~= nil) then
        subtree:add(fields.aggregate_flow_stats_request_out_port, tvb(4,4), out_port, "Out Port: "..ofp.ofp_port_no[out_port])
    else
        subtree:add(fields.aggregate_flow_stats_request_out_port, tvb(4,4))
    end
    if (ofp.ofp_group[out_group] ~= nil) then
        subtree:add(fields.aggregate_flow_stats_request_out_group, tvb(8,4), out_group, "Out Group: "..ofp.ofp_group[out_group])
    else
        subtree:add(fields.aggregate_flow_stats_request_out_group, tvb(8,4))
    end
    -- subtree:add(fields.pad4, tvb(12,4))
    subtree:add(fields.aggregate_flow_stats_request_cookie, tvb(16,8))
    subtree:add(fields.aggregate_flow_stats_request_cookie_mask, tvb(24,8))
    ofp_struct.ofp_match(tvb(32), pinfo, subtree)
end
M.ofp_aggregate_flow_stats_request = ofp_aggregate_flow_stats_request
M.parsers_ofpmp_request[ofp.OFPMP_AGGREGATE_STATS] = ofp_aggregate_flow_stats_request

fields.aggregate_flow_stats_reply = ProtoField.new("Aggregate Flow Stats Reply", "of.aggregate_flow_stats_reply", ftypes.STRING)
function ofp_aggregate_flow_stats_reply(tvb, pinfo, tree)
    offset = 0
    while (offset < tvb:len()) do
        offset = offset + ofp_struct.ofp_stats(tvb(offset), pinfo, tree)
    end
end
M.ofp_aggregate_flow_stats_reply = ofp_aggregate_flow_stats_reply
M.parsers_ofpmp_reply[ofp.OFPMP_AGGREGATE_STATS] = ofp_aggregate_flow_stats_reply

-- Group Desc
fields.ofp_group_desc_request = ProtoField.new("Group Desc Request", "of.group_desc_request", ftypes.STRING)
fields.ofp_group_desc_request_group_id = ProtoField.new("Group Id", "of.group_desc_request.group_id", ftypes.UINT32, ofp.ofp_group, base.DEC)
function ofp_group_desc_request(tvb, pinfo, tree)
    local subtree = tree:add(fields.ofp_group_desc_request, tvb(0,8), "", "Group Desc Request")
    subtree:add(fields.ofp_group_desc_request_group_id, tvb(0,4))
    subtree:add(fields.pad4, tvb(4,4))
end
M.ofp_group_desc_request = ofp_group_desc_request
M.parsers_ofpmp_request[ofp.OFPMP_GROUP_DESC] = ofp_group_desc_request

-- fields.ofp_group_desc_reply = ProtoField.new("Group Desc reply", "of.group_desc_reply", ftypes.STRING)
function ofp_group_desc_reply(tvb, pinfo, tree)
    -- local subtree = tree:add(fields.ofp_group_desc_reply, tvb(0, len), "", "Group Desc Reply")
    local offset = 0
    while (offset < tvb():len()) do
        offset = offset + ofp_group_desc(tvb(offset), pinfo, tree)
    end

    local len = tvb(0,2):uint()
end
M.ofp_group_desc_request = ofp_group_desc_request
M.parsers_ofpmp_reply[ofp.OFPMP_GROUP_DESC] = ofp_group_desc_reply

fields.ofp_group_desc = ProtoField.new("Group Desc", "of.ofp_group_desc", ftypes.STRING)
fields.ofp_group_desc_length = ProtoField.new("Length", "of.ofp_group_desc.length", ftypes.UINT16, nil, base.DEC)
fields.ofp_group_desc_type = ProtoField.new("Type", "of.ofp_group_desc.type", ftypes.UINT8, ofp.ofp_group_type, base.DEC)
fields.ofp_group_desc_group_id = ProtoField.new("Group Id", "of.ofp_group_desc.group_id", ftypes.UINT32, nil, base.DEC)
fields.ofp_group_desc_bucket_array_len = ProtoField.new("Bucket Array Length", "of.ofp_group_desc.bucket_array_len", ftypes.UINT16, nil, base.DEC)
function ofp_group_desc(tvb, pinfo, tree)
    local len = tvb(0,2):uint()
    local subtree = tree:add(fields.ofp_group_desc, tvb(0, len), "", "Group Desc")
    subtree:add(fields.ofp_group_desc_length, tvb(0,2))
    subtree:add(fields.ofp_group_desc_type, tvb(2,1))
    ofp.add_padding(subtree, tvb, 3, 1)
    subtree:add(fields.ofp_group_desc_group_id, tvb(4,4))
    local bucket_array_len = tvb(8,2):uint()
    subtree:add(fields.ofp_group_desc_bucket_array_len, tvb(8,2))
    ofp.add_padding(subtree, tvb, 10, 3)
    ofp.add_padding(subtree, tvb, 13, 3)
    local offset = 16
    while (offset < 16+bucket_array_len) do
        offset = offset + ofp_struct.ofp_bucket(tvb(offset), pinfo, subtree)
    end
    return len
end
M.ofp_group_desc = ofp_group_desc

-- Port Desc & Stats
fields.ofp_port_desc_request = ProtoField.new("Port Desc Request", "of.port_desc_request", ftypes.STRING)
fields.ofp_port_desc_port_no = ProtoField.new("Port No", "of.port_desc_request.port_no", ftypes.UINT32, nil, base.DEC)
function ofp_port_desc_request(tvb, pinfo, tree)
    local port_no = tvb(0,4):uint()
    local str_port = tostring(port_no)
    if ofp.ofp_port_no[port_no]~=nil then
        str_port  = ofp.ofp_port_no[port_no]
    end
    local subtree = tree:add(fields.ofp_port_desc_request, tvb(0,8), "", "Port Desc Request")
    subtree:add(fields.ofp_port_desc_port_no, tvb(0,4), port_no, "Port No: "..str_port)
    subtree:add(fields.pad4, tvb(4,4))
end
M.ofp_port_desc_request = ofp_port_desc_request
M.parsers_ofpmp_request[ofp.OFPMP_PORT_DESC] = ofp_port_desc_request

fields.ofp_port_stats_request = ProtoField.new("Port Stats Request", "of.port_stats_request", ftypes.STRING)
fields.ofp_port_stats_port_no = ProtoField.new("Port No", "of.port_stats_request.port_no", ftypes.UINT32, nil, base.DEC)
function ofp_port_stats_request(tvb, pinfo, tree)
    local port_no = tvb(0,4):uint()
    local str_port = tostring(port_no)
    if ofp.ofp_port_no[port_no]~=nil then
        str_port  = ofp.ofp_port_no[port_no]
    end
    local subtree = tree:add(fields.ofp_port_stats_request, tvb(0,8), "", "Port Stats Request")
    subtree:add(fields.ofp_port_stats_port_no, tvb(0,4), port_no, "Port No: "..str_port)
    subtree:add(fields.pad4, tvb(4,4))
end
M.ofp_port_stats_request = ofp_port_stats_request
M.parsers_ofpmp_request[ofp.OFPMP_PORT_STATS] = ofp_port_stats_request



function ofp_port_desc_reply(tvb, pinfo, tree)
    local offset = 0
    while (offset < tvb():len()) do
        offset = offset + ofp_struct.ofp_port(tvb(offset), pinfo, tree)
    end
end
M.ofp_port_desc_reply = ofp_port_desc_reply
M.parsers_ofpmp_reply[ofp.OFPMP_PORT_DESC] = ofp_port_desc_reply

return M