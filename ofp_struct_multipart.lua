local ofp = require "ofp_const"
local ofp_struct = require "ofp_struct"

M = {}

fields = _G.of_proto.fields

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
    local subtree = tree:add(fields.flow_desc, tvb())
    subtree:add(fields.length, tvb(0,2))
    subtree:add(fields.pad2, tvb(2,2))
    subtree:add(fields.flow_desc_table_id, tvb(4,1))
    subtree:add(fields.pad, tvb(5,1))
    subtree:add(fields.flow_desc_priority, tvb(6,2))
    subtree:add(fields.flow_desc_idle_timeout, tvb(8,2))
    subtree:add(fields.flow_desc_hard_timeout, tvb(10,2))
    subtree:add(fields.flow_desc_flags, tvb(12,2))
    subtree:add(fields.flow_desc_importance, tvb(14,2))
    subtree:add(fields.flow_desc_cookie, tvb(16,8))
    return tvb(0, 2):uint()
    -- ofp_match
    -- ofp_stats
    -- ofp_instruction
end
M.ofp_flow_desc = ofp_flow_desc


fields.flow_desc_request = ProtoField.new("Flow Desc Request", "of.flow_desc_request", ftypes.STRING)
function ofp_flow_desc_request(tvb, pinfo, tree)
    tree:add(fields.flow_desc_request, tvb())
end
M.ofp_flow_desc_request = ofp_flow_desc_request

fields.flow_desc_reply = ProtoField.new("Flow Desc Reply", "of.flow_desc_reply", ftypes.STRING)
function ofp_flow_desc_reply(tvb, pinfo, tree)
    -- tree:add(fields.flow_desc_reply, tvb())
    offset = 0
    while (offset < tvb:len()) do
        offset = offset + ofp_flow_desc(tvb(offset), pinfo, tree)
    end
end
M.ofp_flow_desc_reply = ofp_flow_desc_reply

fields.flow_stats_request = ProtoField.new("Flow Stats Request", "of.flow_stats_request", ftypes.STRING)
fields.flow_stats_request_out_port = ProtoField.new("Out Port", "of.flow_stats_request.out_port", ftypes.UINT32, nil, base.DEC)
fields.flow_stats_request_out_group = ProtoField.new("Out Group", "of.flow_stats_request.out_group", ftypes.UINT32, nil, base.DEC)
fields.flow_stats_request_cookie = ProtoField.new("Cookie", "of.flow_stats_request.cookie", ftypes.UINT64, nil, base.HEX)
fields.flow_stats_request_cookie_mask = ProtoField.new("Cookie Mask", "of.flow_stats_request.cookie_mask", ftypes.UINT64, nil, base.HEX)
function ofp_flow_stats_request(tvb, pinfo, tree)
    local subtree = tree:add(fields.flow_stats_request, tvb(), "", "Flow Stats Request")
    subtree:add(fields.flow_stats_table_id, tvb(0,1))
    subtree:add(fields.pad3, tvb(1,3))
    subtree:add(fields.flow_stats_request_out_port, tvb(4,4)) -- TODO: parse special OFPG values string
    subtree:add(fields.flow_stats_request_out_group, tvb(8,4))
    subtree:add(fields.pad4, tvb(12,4))
    subtree:add(fields.flow_stats_request_cookie, tvb(16,8))
    subtree:add(fields.flow_stats_request_cookie_mask, tvb(24,8))
    ofp_struct.ofp_match(tvb(32), pinfo, subtree)
end
M.ofp_flow_stats_request = ofp_flow_stats_request

fields.flow_stats = ProtoField.new("Flow Stats", "of.flow_stats", ftypes.STRING)
fields.flow_stats_table_id = ProtoField.new("Table Id", "of.flow_stats.table_id", ftypes.UINT8, nil, base.DEC)
fields.flow_stats_reason = ProtoField.new("Reason", "of.flow_stats.reason", ftypes.UINT8, ofp.ofp_flow_stats_reason, base.DEC)
fields.flow_stats_priority = ProtoField.new("Priority", "of.flow_stats.priority", ftypes.UINT16, nil, base.DEC)
function ofp_flow_stats(tvb, pinfo, tree)
    local subtree = tree:add(fields.flow_stats, tvb())
    subtree:add(fields.length, tvb(0,2))
    subtree:add(fields.pad2, tvb(2,2))
    subtree:add(fields.flow_stats_table_id, tvb(4,1))
    subtree:add(fields.flow_stats_reason, tvb(5,1))
    subtree:add(fields.flow_stats_priority, tvb(6,2))
    -- match
    local match_len = ofp_struct.ofp_match(tvb(8, ofp.roundup(tvb(10,2):uint())), pinfo, subtree)
    -- stats
    local stats_len = ofp_struct.ofp_stats(tvb(8+match_len), pinfo, subtree)
    return tvb(0, 2):uint()
end

fields.flow_stats_reply = ProtoField.new("Flow Stats Reply", "of.flow_stats_reply", ftypes.STRING)
function ofp_flow_stats_reply(tvb, pinfo, tree)
    -- tree:add(fields.flow_stats_reply, tvb())
    offset = 0
    while (offset < tvb:len()) do
        offset = offset + ofp_flow_stats(tvb(offset), pinfo, tree)
    end
end
M.ofp_flow_stats_reply = ofp_flow_stats_reply

return M