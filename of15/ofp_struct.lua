-- Author: Davide Trentin (trentindav@gmail.com)
-- Licensed under the Apache License, Version 2.0, see LICENSE for details

local ofp = require "ofp_const"

M = {}

fields = _G.of_proto.fields

-- Match
fields.match = ProtoField.new("Match", "of.match", ftypes.STRING)
fields.match_type = ProtoField.new("Type", "of.match.type", ftypes.UINT16, ofp.ofp_match_type, base.DEC)
-- fields.match_length = ProtoField.new("Length", "of.match.length", ftypes.UINT16, nil, base.DEC)
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
    while (offset < unpadded_len+pad_len) do
        subtree:add(fields.pad, tvb(offset,1))
        offset = offset + 1
    end
    return unpadded_len+pad_len
    -- return unpadded_len
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

fields.oxm_field = ProtoField.new("OXM Field", "of.oxm_field", ftypes.STRING)
fields.oxm_field_class = ProtoField.new("Class", "of.oxm_field.class", ftypes.UINT16, ofp.ofp_oxm_class, base.HEX)
fields.oxm_field_field = ProtoField.new("Field", "of.oxm_field.field", ftypes.UINT16, ofp.oxm_ofb_match_fields, base.DEC, 0xfe)
fields.oxm_field_hasmask = ProtoField.new("Hasmask", "of.oxm_field.hasmask", ftypes.BOOLEAN, nil, base.DEC, 0x01)
fields.oxm_field_length = ProtoField.new("Length", "of.oxm_field.length", ftypes.UINT8, nil, base.DEC)
fields.oxm_field_value = ProtoField.bytes("Value", "of.oxm_field.value")
fields.oxm_field_mask = ProtoField.bytes("Mask", "of.oxm_field.mask")
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
fields.ofp_stats = ProtoField.new("Stats", "of.ofp_stats", ftypes.STRING)
fields.ofp_stats_reserved = ProtoField.new("reserved", "of.ofp_stats.reserved", ftypes.UINT16, nil, base.HEX)
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
        subtree:add(fields.pad, tvb(offset,1))
        offset = offset + 1
    end
    return unpadded_len + pad_len
end
M.ofp_stats = ofp_stats

fields.oxs_field = ProtoField.new("OXS Field", "of.oxs_field", ftypes.STRING)
fields.oxs_field_class = ProtoField.new("Class", "of.oxs_field.class", ftypes.UINT16, ofp.ofp_oxs_class, base.HEX)
fields.oxs_field_field = ProtoField.new("Field", "of.oxs_field.type", ftypes.UINT8, ofp.oxs_ofb_stat_fields, base.DEC, 0xfe)
fields.oxs_field_reserved = ProtoField.new("reserved", "of.oxs_field.reserved", ftypes.UINT8, nil, base.HEX, 0x01)
fields.oxs_field_length = ProtoField.new("Length", "of.oxs_field.length", ftypes.UINT8, nil, base.DEC)
fields.oxs_field_value = ProtoField.bytes("Value", "of.oxs_field.value")
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

fields.oxs_field_value_duration_sec = ProtoField.new("Seconds", "of.oxs_field.value.duration_sec", ftypes.UINT64, nil, base.DEC)
fields.oxs_field_value_duration_nsec = ProtoField.new("Nanoseconds", "of.oxs_field.value.duration_nsec", ftypes.UINT64, nil, base.DEC)
function oxs_field_duration(tvb, pinfo, tree)
    assert(tvb:len() >= 8, "At least 8 Bytes required for duration OXS field")
    tree:add(fields.oxs_field_value_duration_sec, tvb(0,4))
    tree:add(fields.oxs_field_value_duration_nsec, tvb(4,4))
end
oxs_field_value_parsers[ofp.OFPXST_OFB_DURATION] = oxs_field_duration
oxs_field_value_parsers[ofp.OFPXST_OFB_IDLE_TIME] = oxs_field_duration

fields.oxs_field_value_32bit = ProtoField.new("Count", "of.oxs_field.value.count32", ftypes.UINT32, nil, base.DEC)
function oxs_field_value_32bit(tvb, pinfo, tree)
    assert(tvb:len() >= 4, "OXS Field: at least 4 Bytes required")
    tree:add(fields.oxs_field_value_32bit, tvb(0,4))
end
oxs_field_value_parsers[ofp.OFPXST_OFB_FLOW_COUNT] = oxs_field_value_32bit

fields.oxs_field_value_64bit = ProtoField.new("Count", "of.oxs_field.value.count64", ftypes.UINT64, nil, base.DEC)
function oxs_field_value_64bit(tvb, pinfo, tree)
    assert(tvb:len() >= 8, "OXS Field: at least 8 Bytes required")
    tree:add(fields.oxs_field_value_64bit, tvb(0,4))
end
oxs_field_value_parsers[ofp.OFPXST_OFB_PACKET_COUNT] = oxs_field_value_64bit
oxs_field_value_parsers[ofp.OFPXST_OFB_BYTE_COUNT] = oxs_field_value_64bit


fields.ofp_bucket = ProtoField.new("Bucket", "of.ofp_bucket", ftypes.STRING)
fields.ofp_bucket_len = ProtoField.new("Length", "of.ofp_bucket.len", ftypes.UINT16, nil, base.DEC)
fields.ofp_bucket_action_array_len = ProtoField.new("Action Array Length", "of.ofp_bucket.action_array_len", ftypes.UINT16, nil, base.DEC)
fields.ofp_bucket_bucket_id = ProtoField.new("Bucket Id", "of.ofp_bucket.bucket_id", ftypes.UINT32, nil, base.DEC)
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


fields.ofp_action_header = ProtoField.new("Action", "of.ofp_action_header", ftypes.STRING)
fields.ofp_action_header_type = ProtoField.new("Type", "of.ofp_bucket.type", ftypes.UINT16, ofp.ofp_action_tyoe, base.DEC)
fields.ofp_action_header_len = ProtoField.new("Length", "of.ofp_bucket.len", ftypes.UINT16, nil, base.DEC)
function ofp_action_header(tvb, pinfo, tree)
    local len = tvb(2,2):uint()
    local act_type_int = tvb(0,2):uint()
    local subtree
    if ofp.ofp_action_type[act_type_int] ~= nil then
        subtree = tree:add(fields.ofp_action_header, tvb(0, len), "", 
            string.gsub(string.lower(ofp.ofp_action_type[act_type_int]), "ofpat_", ""), "")
    else
        subtree = tree:add(fields.ofp_action_header, tvb(0, len), "", "Action")
    end
    subtree:add(fields.ofp_action_header_type, tvb(0,2))
    subtree:add(fields.ofp_action_header_len, tvb(2,2))
    -- TODO: Values for different actions
    assert(len > 0, "Invalid action len=0")
    return len
end
M.ofp_action_header = ofp_action_header



return M