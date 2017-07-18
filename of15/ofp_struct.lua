-- Author: Davide Trentin (trentindav@gmail.com)
-- Licensed under the Apache License, Version 2.0, see LICENSE for details

local ofp = require "ofp_const"

local M = {}

fields = _G.of_proto.fields

-- Match
fields.match = ProtoField.new("Match", "of15.match", ftypes.STRING)
fields.match_type = ProtoField.new("Type", "of15.match.type", ftypes.UINT16, ofp.ofp_match_type, base.DEC)
function ofp_match(tvb, pinfo, tree)
    local subtree = tree:add(fields.match, tvb(), "", "Match")
    subtree:add(fields.match_type, tvb(0,2))
    subtree:add(fields.length, tvb(2,2))
    offset = 4
    local unpadded_len = tvb(2,2):uint()
    while (offset < unpadded_len) do
        offset = offset + oxm_field(tvb(offset), pinfo, subtree)
    end
    local pad_len = math.floor((unpadded_len+7)/8)*8 - unpadded_len
    -- while (offset < unpadded_len+pad_len) do
        -- subtree:add(fields.pad, tvb(offset,1))
    --     offset = offset + 1
    -- end
    return unpadded_len+pad_len
end
M.ofp_match = ofp_match

function oxm_value_port_no(tvb)
    local str_in_port
    if ofp.ofp_port_no[tvb():uint()] ~= nil then
        str_in_port = ofp.ofp_port_no[tvb():uint()]
    else
        str_in_port = string.format("%d", tvb():uint())
    end
    return str_in_port
end
M.oxm_value_port_no = oxm_value_port_no
function oxm_value_int(tvb)
    return string.format("%d", tvb():uint())
end
M.oxm_value_int = oxm_value_int
function oxm_value_eth(tvb)
    return string.format("%02x:%02x:%02x:%02x:%02x:%02x", tvb(0,1):uint(), tvb(1,1):uint(), tvb(2,1):uint(), tvb(3,1):uint(), tvb(4,1):uint(), tvb(5,1):uint())
end
M.oxm_value_eth = oxm_value_eth
function oxm_value_ipv4(tvb)
    return string.format("%d.%d.%d.%d", tvb(0,1):uint(), tvb(1,1):uint(), tvb(2,1):uint(), tvb(3,1):uint())
end
M.oxm_value_ipv4 = oxm_value_ipv4
function oxm_value_ipv6(tvb)
    return string.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", 
                         tvb(0,1):uint(), tvb(1,1):uint(), tvb(2,1):uint(), tvb(3,1):uint(), 
                         tvb(4,1):uint(), tvb(5,1):uint(), tvb(6,1):uint(), tvb(7,1):uint(), 
                         tvb(8,1):uint(), tvb(9,1):uint(), tvb(10,1):uint(), tvb(11,1):uint(), 
                         tvb(12,1):uint(), tvb(13,1):uint(), tvb(14,1):uint(), tvb(15,1):uint()
                         )
end
M.oxm_value_ipv6 = oxm_value_ipv6

parsers_oxm_value = {
    [ofp.OFPXMT_OFB_IN_PORT] = oxm_value_port_no,
    [ofp.OFPXMT_OFB_ETH_DST] = oxm_value_eth, [ofp.OFPXMT_OFB_ETH_SRC] = oxm_value_eth,
    [ofp.OFPXMT_OFB_ARP_SHA] = oxm_value_eth, [ofp.OFPXMT_OFB_ARP_THA] = oxm_value_eth,
    [ofp.OFPXMT_OFB_IPV6_ND_SLL] = oxm_value_eth, [ofp.OFPXMT_OFB_IPV6_ND_TLL] = oxm_value_eth,
    [ofp.OFPXMT_OFB_IPV4_DST] = oxm_value_ipv4, [ofp.OFPXMT_OFB_IPV4_SRC] = oxm_value_ipv4,
    [ofp.OFPXMT_OFB_ARP_SPA] = oxm_value_ipv4, [ofp.OFPXMT_OFB_ARP_TPA] = oxm_value_ipv4,
    [ofp.OFPXMT_OFB_IPV6_DST] = oxm_value_ipv6, [ofp.OFPXMT_OFB_IPV6_SRC] = oxm_value_ipv6,
    [ofp.OFPXMT_OFB_IPV6_ND_TARGET] = oxm_value_ipv6
}

fields.oxm_field = ProtoField.new("OXM Field", "of15.oxm_field", ftypes.STRING)
fields.oxm_field_class = ProtoField.new("Class", "of15.oxm_field.class", ftypes.UINT16, ofp.ofp_oxm_class, base.HEX)
fields.oxm_field_field = ProtoField.new("Field", "of15.oxm_field.field", ftypes.UINT16, ofp.oxm_ofb_match_fields, base.DEC, 0xfe)
fields.oxm_field_hasmask = ProtoField.new("Hasmask", "of15.oxm_field.hasmask", ftypes.BOOLEAN, nil, base.DEC, 0x01)
fields.oxm_field_length = ProtoField.new("Length", "of15.oxm_field.length", ftypes.UINT8, nil, base.DEC)
fields.oxm_field_value = ProtoField.bytes("Value", "of15.oxm_field.value")
fields.oxm_field_mask = ProtoField.bytes("Mask", "of15.oxm_field.mask")
function oxm_field(tvb, pinfo, tree)
    assert(tvb:len() >= 4, "OXM field: not enough bytes")
    local oxm_len = tvb(3,1):uint()
    local str_value = ""
    local str_mask = ""
    local value_parser
    if parsers_oxm_value[tvb(2,1):uint()/2] ~= nil then
        value_parser = parsers_oxm_value[tvb(2,1):uint()/2]
    else 
        value_parser = oxm_value_int
    end
    if (bit32.band(tvb(2,1):uint(), 0x01) == 1) then
        str_value = value_parser(tvb(4, oxm_len/2))
        str_mask = value_parser(tvb(4+oxm_len/2, oxm_len/2))
    else
        str_value = value_parser(tvb(4, oxm_len))
    end
    local subtree = tree:add(fields.oxm_field, tvb(0), "", 
                             string.gsub(string.lower(ofp.oxm_ofb_match_fields[tvb(2,1):uint()/2]), "ofpxmt_ofb_", "").." = "..str_value..str_mask, "")
    subtree:add(fields.oxm_field_class, tvb(0,2))
    subtree:add(fields.oxm_field_field, tvb(2,1))
    subtree:add(fields.oxm_field_hasmask, tvb(2,1))
    subtree:add(fields.oxm_field_length, tvb(3,1))
    if (bit32.band(tvb(2,1):uint(), 0x01) == 1) then
        subtree:add(fields.oxm_field_value, tvb(4, oxm_len/2))
        subtree:add(fields.oxm_field_mask, tvb(4+oxm_len/2, oxm_len/2))
    else
        subtree:add(fields.oxm_field_value, tvb(4, oxm_len), "", "Value: "..str_value)
    end
    return oxm_len + 4
end
M.oxm_field = oxm_field


-- Stats
fields.ofp_stats = ProtoField.new("Stats", "of15.ofp_stats", ftypes.STRING)
fields.ofp_stats_reserved = ProtoField.new("reserved", "of15.ofp_stats.reserved", ftypes.UINT16, nil, base.HEX)
function ofp_stats(tvb, pinfo, tree)
    local subtree = tree:add(fields.ofp_stats, tvb(0, tvb(2,2):uint()), "", "Stats")
    subtree:add(fields.ofp_stats_reserved, tvb(0,2))
    subtree:add(fields.length, tvb(2,2))
    offset = 4
    local unpadded_len = tvb(2,2):uint()
    assert(unpadded_len >= 8, "ofp_stats.length must be at least 8 bytes")
    while (offset < unpadded_len) do
        offset = offset + oxs_field(tvb(offset), pinfo, subtree)
    end
    local pad_len = math.floor((unpadded_len+7)/8)*8 - unpadded_len
    while (offset < unpadded_len+pad_len) do
        -- subtree:add(fields.pad, tvb(offset,1))
        offset = offset + 1
    end
    return unpadded_len + pad_len
end
M.ofp_stats = ofp_stats

fields.oxs_field = ProtoField.new("OXS Field", "of15.oxs_field", ftypes.STRING)
fields.oxs_field_class = ProtoField.new("Class", "of15.oxs_field.class", ftypes.UINT16, ofp.ofp_oxs_class, base.HEX)
fields.oxs_field_field = ProtoField.new("Field", "of15.oxs_field.type", ftypes.UINT8, ofp.oxs_ofb_stat_fields, base.DEC, 0xfe)
fields.oxs_field_reserved = ProtoField.new("reserved", "of15.oxs_field.reserved", ftypes.UINT8, nil, base.HEX, 0x01)
fields.oxs_field_length = ProtoField.new("Length", "of15.oxs_field.length", ftypes.UINT8, nil, base.DEC)
fields.oxs_field_value = ProtoField.bytes("Value", "of15.oxs_field.value")
function oxs_field(tvb, pinfo, tree)
    assert(tvb:len() >= 4, "OXM field: not enough bytes")
    local oxs_len = tvb(3,1):uint()
    local oxs_field_int = tvb(2,1):uint()/2
    local subtree = tree:add(fields.oxs_field, tvb(0), "", 
                             string.gsub(string.lower(ofp.oxs_ofb_stat_fields[oxs_field_int]), "ofpxst_ofb_", ""), "")
    subtree:add(fields.oxs_field_class, tvb(0,2))
    subtree:add(fields.oxs_field_field, tvb(2,1))
    subtree:add(fields.oxs_field_reserved, tvb(2,1))
    subtree:add(fields.oxs_field_length, tvb(3,1))
    oxs_field_value_parsers[oxs_field_int](tvb(4), pinfo, subtree)

    return oxs_len + 4
end
M.oxs_field = oxs_field

oxs_field_value_parsers = {}

fields.oxs_field_value_duration_sec = ProtoField.new("Seconds", "of15.oxs_field.value.duration_sec", ftypes.UINT64, nil, base.DEC)
fields.oxs_field_value_duration_nsec = ProtoField.new("Nanoseconds", "of15.oxs_field.value.duration_nsec", ftypes.UINT64, nil, base.DEC)
function oxs_field_duration(tvb, pinfo, tree)
    assert(tvb:len() >= 8, "At least 8 Bytes required for duration OXS field")
    tree:add(fields.oxs_field_value_duration_sec, tvb(0,4))
    tree:add(fields.oxs_field_value_duration_nsec, tvb(4,4))
end
oxs_field_value_parsers[ofp.OFPXST_OFB_DURATION] = oxs_field_duration
oxs_field_value_parsers[ofp.OFPXST_OFB_IDLE_TIME] = oxs_field_duration

fields.oxs_field_value_32bit = ProtoField.new("Count", "of15.oxs_field.value.count32", ftypes.UINT32, nil, base.DEC)
function oxs_field_value_32bit(tvb, pinfo, tree)
    assert(tvb:len() >= 4, "OXS Field: at least 4 Bytes required")
    tree:add(fields.oxs_field_value_32bit, tvb(0,4))
end
oxs_field_value_parsers[ofp.OFPXST_OFB_FLOW_COUNT] = oxs_field_value_32bit

fields.oxs_field_value_64bit = ProtoField.new("Count", "of15.oxs_field.value.count64", ftypes.UINT64, nil, base.DEC)
function oxs_field_value_64bit(tvb, pinfo, tree)
    assert(tvb:len() >= 8, "OXS Field: at least 8 Bytes required")
    tree:add(fields.oxs_field_value_64bit, tvb(0,4))
end
oxs_field_value_parsers[ofp.OFPXST_OFB_PACKET_COUNT] = oxs_field_value_64bit
oxs_field_value_parsers[ofp.OFPXST_OFB_BYTE_COUNT] = oxs_field_value_64bit


fields.ofp_bucket = ProtoField.new("Bucket", "of15.ofp_bucket", ftypes.STRING)
fields.ofp_bucket_len = ProtoField.new("Length", "of15.ofp_bucket.len", ftypes.UINT16, nil, base.DEC)
fields.ofp_bucket_action_array_len = ProtoField.new("Action Array Length", "of15.ofp_bucket.action_array_len", ftypes.UINT16, nil, base.DEC)
fields.ofp_bucket_bucket_id = ProtoField.new("Bucket Id", "of15.ofp_bucket.bucket_id", ftypes.UINT32, nil, base.DEC)
function ofp_bucket(tvb, pinfo, tree)
    local len = tvb(0,2):uint()
    local subtree = tree:add(fields.ofp_bucket, tvb(0, len), "", "Bucket")
    subtree:add(fields.ofp_bucket_len, tvb(0,2))
    local action_array_len = tvb(2,2):uint()
    subtree:add(fields.ofp_bucket_action_array_len, tvb(2,2))
    subtree:add(fields.ofp_bucket_bucket_id, tvb(4,4))
    local offset = 8
    while (offset < action_array_len+8) do
        offset = offset + ofp_action_header(tvb(offset), pinfo, subtree)
    end
    -- TODO: Properties ofp_group_buck_prop_header
    return len
end
M.ofp_bucket = ofp_bucket

-- Actions
action_parsers = {}
fields.ofp_action_port = ProtoField.new("Port No", "of15.ofp_action.port", ftypes.UINT32, nil, base.DEC)
fields.ofp_action_max_len = ProtoField.new("Max Len", "of15.ofp_action.max_len", ftypes.UINT16, nil, base.DEC)
function ofp_action_output(tvb, pinfo, tree)
    local int_port = tvb(4,4):uint()
    local str_port
    if ofp.ofp_port_no[int_port]~=nil then
        str_port = ofp.ofp_port_no[int_port]
    else
        str_port = int_port
    end
    local subtree = tree:add(fields.ofp_action_header, tvb(0), "", "Output port="..str_port)
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    if ofp.ofp_port_no[int_port]~=nil then
        subtree:add(fields.ofp_action_port, tvb(4,4), int_port, "Port No: "..ofp.ofp_port_no[int_port])
    else
        subtree:add(fields.ofp_action_port, tvb(4,4))
    end
    local int_max_len = tvb(8,2):uint()
    if ofp.ofp_controller_max_len[int_max_len]~=nil then
        subtree:add(fields.ofp_action_max_len, tvb(8,2), int_max_len, "Max Len: "..ofp.ofp_controller_max_len[int_max_len])
    else
        subtree:add(fields.ofp_action_max_len, tvb(8,2))
    end
    -- subtree:add(fields.pad2, tvb(10,2))
    -- subtree:add(fields.pad4, tvb(12,4))
end
M.ofp_action_output = ofp_action_output
action_parsers[ofp.OFPAT_OUTPUT] = ofp_action_output

fields.ofp_action_group_id = ProtoField.new("Group Id", "of15.ofp_action.group_id", ftypes.UINT32, nil, base.DEC)
function ofp_action_group(tvb, pinfo, tree)
    local group_id = tvb(4,4):uint()
    local subtree = tree:add(fields.ofp_action_header, tvb(0), "", "Group id="..tostring(group_id))
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_group_id, group_id)
end
M.ofp_action_group = ofp_action_group
action_parsers[ofp.OFPAT_GROUP] = ofp_action_group

fields.ofp_action_queue_id = ProtoField.new("Queue Id", "of15.ofp_action.queue_id", ftypes.UINT32, nil, base.DEC)
function ofp_action_set_queue(tvb, pinfo, tree)
    local queue_id = tvb(4,4):uint()
    local subtree = tree:add(fields.ofp_action_header, tvb(0), "", "Queue id="..tostring(queue_id))
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_queue_id, queue_id)
end
M.ofp_action_set_queue = ofp_action_set_queue
action_parsers[ofp.OFPAT_SET_QUEUE] = ofp_action_set_queue

fields.ofp_action_meter_id = ProtoField.new("Meter Id", "of15.ofp_action.meter_id", ftypes.UINT32, nil, base.DEC)
function ofp_action_meter(tvb, pinfo, tree)
    local meter_id = tvb(4,4):uint()
    local subtree = tree:add(fields.ofp_action_header, tvb(0), "", "Meter id="..tostring(meter_id))
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_meter_id, meter_id)
end
M.ofp_action_meter = ofp_action_meter
action_parsers[ofp.OFPAT_METER] = ofp_action_meter

fields.ofp_action_mpls_ttl = ProtoField.new("MPLS TTL", "of15.ofp_action.mpls_ttl", ftypes.UINT8, nil, base.DEC)
function ofp_action_mpls_ttl(tvb, pinfo, tree)
    local mpls_ttl = tvb(4,1):uint()
    local subtree = tree:add(fields.ofp_action_header, tvb(), "", "MPLS TTL="..tostring(mpls_ttl))
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_mpls_ttl, mpls_ttl)
    subtree:add(fields.pad3, tvb(5,3))
end
M.ofp_action_mpls_ttl = ofp_action_mpls_ttl
action_parsers[ofp.OFPAT_SET_MPLS_TTL] = ofp_action_mpls_ttl

function ofp_action_generic(tvb, pinfo, tree)
    local act_type_int = tvb(0,2):uint()
    subtree = tree:add(fields.ofp_action_header, tvb(), "", 
                       string.gsub(string.lower(ofp.ofp_action_type[act_type_int]), "ofpat_", ""), "")
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.pad4, tvb(5,4))
end
M.ofp_action_generic = ofp_action_generic
action_parsers[ofp.OFPAT_DEC_MPLS_TTL] = ofp_actioofp_action_genericn_mpls_ttl
action_parsers[ofp.OFPAT_COPY_TTL_OUT] = ofp_actioofp_action_genericn_mpls_ttl
action_parsers[ofp.OFPAT_COPY_TTL_IN] = ofp_actioofp_action_genericn_mpls_ttl
action_parsers[ofp.OFPAT_DEC_NW_TTL] = ofp_actioofp_action_genericn_mpls_ttl
action_parsers[ofp.OFPAT_POP_VLAN] = ofp_actioofp_action_genericn_mpls_ttl
action_parsers[ofp.OFPAT_POP_PBB] = ofp_actioofp_action_genericn_mpls_ttl

fields.ofp_action_nw_ttl = ProtoField.new("Nw TTL", "of15.ofp_action.nw_ttl", ftypes.UINT8, nil, base.DEC)
function ofp_action_nw_ttl(tvb, pinfo, tree)
    local nw_ttl = tvb(4,1):uint()
    local subtree = tree:add(fields.ofp_action_header, tvb(), "", "Nw TTL="..tostring(mpls_ttl))
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_nw_ttl, nw_ttl)
    subtree:add(fields.pad3, tvb(5,3))
end
M.ofp_action_nw_ttl = ofp_action_nw_ttl
action_parsers[ofp.OFPAT_SET_NW_TTL] = ofp_action_nw_ttl

fields.ofp_action_ethertype = ProtoField.new("Ethertype", "of15.ofp_action.ethertype", ftypes.UINT16, nil, base.DEC)
function ofp_action_push(tvb, pinfo, tree)
    local ethertype = tvb(4,2):uint()
    local subtree = tree:add(fields.ofp_action_header, tvb(), "",
        string.format("%s ethertype=0x%x", string.gsub(string.lower(ofp.ofp_action_type[act_type_int]), "ofpat_", ""), ethertype))
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_ethertype, ethertype)
    subtree:add(fields.pad2, tvb(6,2))
end
M.ofp_action_push = ofp_action_push
action_parsers[ofp.OFPAT_PUSH_VLAN] = ofp_action_push
action_parsers[ofp.OFPAT_PUSH_MPLS] = ofp_action_push
action_parsers[ofp.OFPAT_PUSH_PBB] = ofp_action_push

function ofp_action_pop_mpls(tvb, pinfo, tree)
    local ethertype = tvb(4,2):uint()
    local subtree = tree:add(fields.ofp_action_header, tvb(), "",
        string.format("%s ethertype=0x%x", string.gsub(string.lower(ofp.ofp_action_type[act_type_int]), "ofpat_", ""), ethertype))
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_ethertype, ethertype)
    subtree:add(fields.pad2, tvb(6,2))
end
M.ofp_action_pop_mpls = ofp_action_pop_mpls
action_parsers[ofp.OFPAT_POP_MPLS] = ofp_action_pop_mpls

function ofp_action_set_field(tvb, pinfo, tree)
    local int_field = tvb(6,1):uint() / 2
    local oxm_len = tvb(7,1):uint()
    local value_parser
    local str_value = ""
    local str_mask = ""
    if ofp.oxm_ofb_match_fields[int_field]~=nil then
        if parsers_oxm_value[int_field] ~= nil then
            value_parser = parsers_oxm_value[int_field]
        else 
            value_parser = oxm_value_int
        end
        if (bit32.band(tvb(6,1):uint(), 0x01) == 1) then
            str_value = value_parser(tvb(8, oxm_len/2))
            str_mask = "/"..value_parser(tvb(8+oxm_len/2, oxm_len/2))
        else
            str_value = value_parser(tvb(8, oxm_len))
        end
        local subtree = tree:add(fields.ofp_action_header, tvb(), "", 
            string.format("Set Field: %s=%s%s", ofp.oxm_ofb_match_fields[int_field], str_value, str_mask))
    else
        local subtree = tree:add(fields.ofp_action_header, tvb(), "", "Set Field")
    end
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    oxm_field(tvb(4), pinfo, subtree)
    -- Not required to loop through padding, unless we want to show them in the tree
end
M.ofp_action_set_field = ofp_action_set_field
action_parsers[ofp.OFPAT_SET_FIELD] = ofp_action_set_field

fields.ofp_action_n_bits = ProtoField.new("N bits", "of15.ofp_action.n_bits", ftypes.UINT16, nil, base.DEC)
fields.ofp_action_src_offset = ProtoField.new("Src Offset", "of15.ofp_action.src_offset", ftypes.UINT16, nil, base.DEC)
fields.ofp_action_dst_offset = ProtoField.new("Dst Offset", "of15.ofp_action.dst_offset", ftypes.UINT16, nil, base.DEC)
function ofp_action_copy_field(tvb, pinfo, tree)
    local int_field_src = tvb(14,1):uint() / 2
    local oxm_src_len = tvb(15,1):uint()
    local int_field_dst = tvb(14+oxm_src_len,1):uint() / 2
    local src_field = "unknown"
    local dst_field = "unknown"
    if ofp.oxm_ofb_match_fields[int_field_src]~=nil then
        src_field = ofp.oxm_ofb_match_fields[int_field_src]
    end
    if ofp.oxm_ofb_match_fields[int_field_dst]~=nil then
        dst_field = ofp.oxm_ofb_match_fields[int_field_dst]
    end
    local subtree = tree:add(fields.ofp_action_header, tvb(), "", 
        string.format("Set Field: src=%s dst=%s", src_field, dst_field))
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_n_bits, tvb(4,2))
    subtree:add(fields.ofp_action_src_offset, tvb(6,2))
    subtree:add(fields.ofp_action_dst_offset, tvb(8,2))
    subtree:add(fields.pad2, tvb(10,2))
    oxm_field(tvb(12), pinfo, subtree)
    oxm_field(tvb(12+oxm_src_len), pinfo, subtree)
    -- Not required to loop through padding, unless we want to show them in the tree
end
M.ofp_action_copy_field = ofp_action_copy_field
action_parsers[ofp.OFPAT_COPY_FIELD] = ofp_action_copy_field

fields.ofp_action_experimenter = ProtoField.new("Experimenter", "of15.ofp_action.experimenter", ftypes.UINT32, nil, base.DEC)
function ofp_action_experimenter(tvb, pinfo, tree)
    local subtree = tree:add(fields.ofp_action_header, tvb(), "", "Experimenter")
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    subtree:add(fields.ofp_action_experimenter, tvb(4,4))
    -- TODO: Add Vendor specific experimenters
end
M.ofp_action_experimenter = ofp_action_experimenter
action_parsers[ofp.OFPAT_EXPERIMENTER] = ofp_action_experimenter

fields.ofp_action_header = ProtoField.new("Action", "of15.ofp_action", ftypes.STRING)
fields.ofp_action_header_type = ProtoField.new("Type", "of15.ofp_action.type", ftypes.UINT16, ofp.ofp_action_type, base.DEC)
fields.ofp_action_header_len = ProtoField.new("Length", "of15.ofp_action.len", ftypes.UINT16, nil, base.DEC)
function ofp_action_header(tvb, pinfo, tree)
    local len = tvb(2,2):uint()
    local act_type_int = tvb(0,2):uint()
    if action_parsers[act_type_int]~=nil then
        action_parsers[act_type_int](tvb(0,len), pinfo, tree)
    else
        local subtree
        if ofp.ofp_action_type[act_type_int] ~= nil then
            subtree = tree:add(fields.ofp_action_header, tvb(0, len), "", 
                string.gsub(string.lower(ofp.ofp_action_type[act_type_int]), "ofpat_", ""), "")
        else
            subtree = tree:add(fields.ofp_action_header, tvb(0, len), "", "Action")
        end
        subtree:add(fields.ofp_action_header_type, tvb(0,2))
        subtree:add(fields.ofp_action_header_len, tvb(2,2))
    end
    -- TODO: Values for different actions
    assert(len > 0, "Invalid action len=0")
    return len
end
M.ofp_action_header = ofp_action_header

function action_list(tvb, pinfo, tree)
    local offset = 0
    while (offset < tvb():len()) do
        local act_len = tvb(offset+2,2):uint()
        offset = offset + ofp_action_header(tvb(offset, act_len), pinfo, tree)
    end
end
M.action_list = action_list

-- Instructions
instruction_parsers = {}
fields.ofp_instruction_table_id = ProtoField.new("Table Id", "of15.ofp_instruction.table_id", ftypes.UINT8, nil, base.DEC)
function ofp_instruction_goto_table(tvb, pinfo, tree)
    tree:add(fields.ofp_instruction_header_type, tvb(0,2))
    tree:add(fields.ofp_instruction_header_len, tvb(2,2))
    tree:add(fields.ofp_instruction_table_id, tvb(4,1))
    -- tree:add(fields.pad3, tvb(5,3))
end
M.ofp_instruction_goto_table = ofp_instruction_goto_table
instruction_parsers[ofp.OFPIT_GOTO_TABLE] = ofp_instruction_goto_table

fields.ofp_instruction_metadata = ProtoField.new("Metadata", "of15.ofp_instruction.metadata", ftypes.UINT64, nil, base.DEC)
fields.ofp_instruction_metadata_mask = ProtoField.new("Metadata Maks", "of15.ofp_instruction.metadata_mask", ftypes.UINT64, nil, base.DEC)
function ofp_instruction_write_metadata(tvb, pinfo, tree)
    tree:add(fields.ofp_instruction_header_type, tvb(0,2))
    tree:add(fields.ofp_instruction_header_len, tvb(2,2))
    -- tree:add(fields.pad4, tvb(4,4))
    tree:add(fields.ofp_instruction_metadata, tvb(8,8))
    tree:add(fields.ofp_instruction_metadata_mask, tvb(16,8))
end
M.ofp_instruction_write_metadata = ofp_instruction_write_metadata
instruction_parsers[ofp.OFPIT_WRITE_METADATA] = ofp_instruction_write_metadata

function ofp_instruction_actions(tvb, pinfo, tree)
    tree:add(fields.ofp_instruction_header_type, tvb(0,2))
    tree:add(fields.ofp_instruction_header_len, tvb(2,2))
    -- tree:add(fields.pad4, tvb(4,4))
    offset = 8
    while (offset < tvb():len()) do
        offset = offset + ofp_action_header(tvb(offset), pinfo, tree)
    end
end
M.ofp_instruction_actions = ofp_instruction_actions
instruction_parsers[ofp.OFPIT_WRITE_ACTIONS] = ofp_instruction_actions
instruction_parsers[ofp.OFPIT_APPLY_ACTIONS] = ofp_instruction_actions
instruction_parsers[ofp.OFPIT_CLEAR_ACTIONS] = ofp_instruction_actions

fields.ofp_instruction_flags = ProtoField.new("Flags", "of15.ofp_instruction.stat_trigger.flags", ftypes.UINT32, nil, base.HEX, 0x00000003)
fields.ofp_instruction_flags_periodic = ProtoField.new("OFPSTF_PERIODIC", "of15.ofp_instruction.stat_trigger.flags.periodic", ftypes.BOOLEAN, nil, 32, 0x00000001)
fields.ofp_instruction_flags_only_first = ProtoField.new("OFPSTF_ONLY_FIRST", "of15.ofp_instruction.stat_trigger.flags.only_first", ftypes.BOOLEAN, nil, 32, 0x00000002)
function ofp_instruction_stat_trigger(tvb, pinfo, tree)
    tree:add(fields.ofp_instruction_header_type, tvb(0,2))
    tree:add(fields.ofp_instruction_header_len, tvb(2,2))
    tree:add(fields.pad4, tvb(4,4))
    local flags_tree = subtree:add(fields.ofp_instruction_flags_periodic, tvb(4,4))
    flags_tree:add(fields.ofp_instruction_flags_only_first, tvb(4,4))
    -- TODO: missing ofp_stats thresholds
    assert(False, "ofp_stats thresholds not implemented")
end
M.ofp_instruction_stat_trigger = ofp_instruction_stat_trigger
instruction_parsers[ofp.OFPIT_STAT_TRIGGER] = ofp_instruction_stat_trigger

fields.ofp_instruction_experimenter_id = ProtoField.new("Experimenter Id", "of15.ofp_instruction.experimenter_id", ftypes.UINT32, nil, base.DEC)
function ofp_instruction_experimenter(tvb, pinfo, tree)
    tree:add(fields.ofp_instruction_header_type, tvb(0,2))
    tree:add(fields.ofp_instruction_header_len, tvb(2,2))
    tree:add(fields.ofp_instruction_stat_trigger, tvb(4,4))
end
M.ofp_instruction_experimenter = ofp_instruction_experimenter
instruction_parsers[ofp.OFPIT_EXPERIMENTER] = ofp_instruction_experimenter

fields.ofp_instruction_header = ProtoField.new("Instruction", "of15.ofp_instruction", ftypes.STRING)
fields.ofp_instruction_header_type = ProtoField.new("Type", "of15.ofp_instruction.type", ftypes.UINT16, ofp.ofp_instruction_type, base.DEC)
fields.ofp_instruction_header_len = ProtoField.new("Length", "of15.ofp_instruction.len", ftypes.UINT16, nil, base.DEC)
function ofp_instruction_header(tvb, pinfo, tree)
    local len = tvb(2,2):uint()
    local inst_type_int = tvb(0,2):uint()
    local subtree
    if ofp.ofp_instruction_type[inst_type_int] ~= nil then
        subtree = tree:add(fields.ofp_instruction_header, tvb(0, len), "", 
            string.gsub("Instruction: "..string.lower(ofp.ofp_instruction_type[inst_type_int]), "ofpit_", ""), "")
    else
        subtree = tree:add(fields.ofp_instruction_header, tvb(0, len), "", "Instruction")
    end
    if instruction_parsers[inst_type_int] ~= nil then
        instruction_parsers[inst_type_int](tvb, pinfo, subtree)
    else
        subtree:add(fields.ofp_instruction_header_type, tvb(0,2))
        subtree:add(fields.ofp_instruction_header_len, tvb(2,2))
    end
    assert(len > 0, "Invalid instruction len=0")
    return len
end
M.ofp_instruction_header = ofp_instruction_header

function instruction_list(tvb, pinfo, tree)
    local offset = 0
    while (offset < tvb():len()) do
        local inst_len = tvb(offset+2,2):uint()
        offset = offset + ofp_instruction_header(tvb(offset, inst_len), pinfo, tree)
    end
end
M.instruction_list = instruction_list

-- Port 
fields.ofp_port_header = ProtoField.new("Port", "of15.ofp_port", ftypes.STRING)
fields.ofp_port_port_no = ProtoField.new("Port No", "of15.ofp_port.port_no", ftypes.UINT32, nil, base.DEC)
fields.ofp_port_length = ProtoField.new("Length", "of15.ofp_port.length", ftypes.UINT16, nil, base.DEC)
fields.ofp_port_hw_addr = ProtoField.bytes("HwAddr", "of15.ofp_port.hw_addr")
fields.ofp_port_name = ProtoField.new("Name", "of15.ofp_port.name", ftypes.STRING)
fields.ofp_port_config = ProtoField.new("Config", "of15.ofp_port.config", ftypes.UINT32, nil, base.HEX, 0x00000065)
fields.ofp_port_config_port_down = ProtoField.new("OFPPC_PORT_DOWN", "of15.ofp_port.config.port_down", ftypes.BOOLEAN, nil, 32, 0x00000001)
fields.ofp_port_config_no_recv = ProtoField.new("OFPPC_NO_RECV", "of15.ofp_port.config.no_recv", ftypes.BOOLEAN, nil, 32, 0x00000004)
fields.ofp_port_config_no_fwd = ProtoField.new("OFPPC_NO_FWD", "of15.ofp_port.config.no_fwd", ftypes.BOOLEAN, nil, 32, 0x00000020)
fields.ofp_port_config_no_packet_in = ProtoField.new("OFPPC_NO_PACKET_IN", "of15.ofp_port.config.no_packet_in", ftypes.BOOLEAN, nil, 32, 0x00000040)
fields.ofp_port_state = ProtoField.new("State", "of15.ofp_port.state", ftypes.UINT32, nil, base.HEX, 0x00000007)
fields.ofp_port_state_link_down = ProtoField.new("OFPPS_LINK_DOWN", "of15.ofp_port.state.link_down", ftypes.BOOLEAN, nil, 32, 0x00000001)
fields.ofp_port_state_blocked = ProtoField.new("OFPPS_BLOCKED", "of15.ofp_port.state.blocked", ftypes.BOOLEAN, nil, 32, 0x00000002)
fields.ofp_port_state_live = ProtoField.new("OFPPS_LIVE", "of15.ofp_port.state.live", ftypes.BOOLEAN, nil, 32, 0x00000004)
function ofp_port(tvb, pinfo, tree)
    local len = tvb(4,2):uint()
    local port_no = tvb(0,4):uint()
    local subtree = tree:add(fields.ofp_port_header, tvb(0,len), "", "Port "..ofp.get_str_value(ofp.ofp_port_no, port_no))
    subtree:add(fields.ofp_port_port_no, tvb(0,4), port_no, "Port: "..ofp.get_str_value(ofp.ofp_port_no, port_no))
    subtree:add(fields.ofp_port_length, tvb(4,2))
    ofp.add_padding(subtree, tvb, 6, 2)
    subtree:add(fields.ofp_port_hw_addr, tvb(8,6),  "", "Hw Address: "..oxm_value_eth(tvb(8,6)))
    ofp.add_padding(subtree, tvb, 14, 2)
    subtree:add(fields.ofp_port_name, tvb(16,16))
    local config_tree = subtree:add(fields.ofp_port_config, tvb(32,4))
    config_tree:add(fields.ofp_port_config_port_down, tvb(32,4))
    config_tree:add(fields.ofp_port_config_no_recv, tvb(32,4))
    config_tree:add(fields.ofp_port_config_no_fwd, tvb(32,4))
    config_tree:add(fields.ofp_port_config_no_packet_in, tvb(32,4))
    local state_tree = subtree:add(fields.ofp_port_state, tvb(36,4))
    state_tree:add(fields.ofp_port_state_link_down, tvb(36,4))
    state_tree:add(fields.ofp_port_state_blocked, tvb(36,4))
    state_tree:add(fields.ofp_port_state_live, tvb(36,4))
    local offset = 40
    -- while offset < len do
    --     offset = offset + ofp_port_desc_prop_header(tvb(offset), pinfo, tree)  -- TODO: parse properties
    -- end
    return len
end
M.ofp_port = ofp_port



return M