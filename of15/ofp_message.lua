-- Author: Davide Trentin (trentindav@gmail.com)
-- Licensed under the Apache License, Version 2.0, see LICENSE for details

local ofp = require "ofp_const"
local ofp_struct = require "of15.ofp_struct"
local struct_multipart = require "of15.ofp_struct_multipart"
local M = {}

fields = _G.of_proto.fields

M.parsers_ofpt = {}

-- Hello
fields.hello = ProtoField.new("Hello", "of15.hello", ftypes.STRING)
fields.hello_elem = ProtoField.new("Hello Element", "of15.hello.element", ftypes.STRING)
fields.hello_elem_type = ProtoField.new("Type", "of15.hello.element.type", ftypes.UINT16, ofp.ofp_hello_elem_type, base.HEX)
fields.hello_elem_length = ProtoField.new("Length", "of15.hello.element.type", ftypes.UINT16, nil, base.DEC)
fields.hello_elem_bitmap = ProtoField.new("Bitmap", "of15.hello.element.bitmap", ftypes.UINT32, nil, base.HEX, 0xffffffff)
fields.hello_elem_bitmap_of10 = ProtoField.new("OF1.0", "of15.hello.element.bitmap.of10", ftypes.BOOLEAN, nil, 32, 0x00000002)
fields.hello_elem_bitmap_of11 = ProtoField.new("OF1.1", "of15.hello.element.bitmap.of11", ftypes.BOOLEAN, nil, 32, 0x00000004)
fields.hello_elem_bitmap_of12 = ProtoField.new("OF1.2", "of15.hello.element.bitmap.of12", ftypes.BOOLEAN, nil, 32, 0x00000008)
fields.hello_elem_bitmap_of13 = ProtoField.new("OF1.3", "of15.hello.element.bitmap.of13", ftypes.BOOLEAN, nil, 32, 0x00000010)
fields.hello_elem_bitmap_of14 = ProtoField.new("OF1.4", "of15.hello.element.bitmap.of14", ftypes.BOOLEAN, nil, 32, 0x00000020)
fields.hello_elem_bitmap_of15 = ProtoField.new("OF1.5", "of15.hello.element.bitmap.of15", ftypes.BOOLEAN, nil, 32, 0x00000040)
function ofp_hello(tvb, pinfo, tree)
    if (tvb:len() == 0) then return end
    local subtree = tree:add(fields.hello, tvb(), "", "Hello")
    assert(tvb:len() >= 4, "If Hello has body, it must have at least 4 bytes")
    offset = 0
    while (offset < tvb:len()) do
        local hello_elem_header_size = 4
        local tvb_el = tvb:range(offset)
        local elem_len = tvb_el(2,2):uint()
        assert(elem_len <= tvb_el:len(), "Not enough bytes remaining to parse Hello element")
        local helloelem_tree = subtree:add(fields.hello_elem, tvb_el(), "Hello Element")
        -- TODO: parser table based on the element type (only bitmap for now)
        helloelem_tree:add(fields.hello_elem_type, tvb_el(0,2))
        helloelem_tree:add(fields.hello_elem_length, tvb_el(2,2))
        local elem_offset = 0
        while (elem_offset < elem_len-hello_elem_header_size) do
            local tvb_bitmaps = tvb_el:range(offset+hello_elem_header_size)
            helloelem_tree:add(fields.hello_elem_bitmap, tvb_bitmaps(offset))
            helloelem_tree:add(fields.hello_elem_bitmap_of10, tvb_bitmaps(offset))
            helloelem_tree:add(fields.hello_elem_bitmap_of11, tvb_bitmaps(offset))
            helloelem_tree:add(fields.hello_elem_bitmap_of12, tvb_bitmaps(offset))
            helloelem_tree:add(fields.hello_elem_bitmap_of13, tvb_bitmaps(offset))
            helloelem_tree:add(fields.hello_elem_bitmap_of14, tvb_bitmaps(offset))
            helloelem_tree:add(fields.hello_elem_bitmap_of15, tvb_bitmaps(offset))
            elem_offset = elem_offset + 4
        end
        offset = offset + elem_len
    end
end
M.parsers_ofpt[0] = ofp_hello

function ofp_error(tvb, pinfo, tree)
end
M.parsers_ofpt[1] = ofp_error

fields.echo_data = ProtoField.new("Echo Data", "of15.echo.data", ftypes.STRING)
function ofp_echo_request(tvb, pinfo, tree)
    if (tvb:len() == 0) then return end
    tree:add(fields.echo_data, tvb())
end
M.parsers_ofpt[2] = ofp_echo_request

function ofp_echo_reply(tvb, pinfo, tree)
    if (tvb:len() == 0) then return end
    tree:add(fields.echo_data, tvb())
end
M.parsers_ofpt[3] = ofp_echo_reply

function ofp_experimenter(tvb, pinfo, tree)
end
M.parsers_ofpt[4] = ofp_experimenter

function ofp_features_request(tvb, pinfo, tree)
end
M.parsers_ofpt[5] = ofp_features_request

function ofp_features_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[6] = ofp_features_reply

function ofp_get_config_request(tvb, pinfo, tree)
end
M.parsers_ofpt[7] = ofp_get_config_request

function ofp_get_config_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[8] = ofp_get_config_reply

function ofp_set_config(tvb, pinfo, tree)
end
M.parsers_ofpt[9] = ofp_set_config

function ofp_packet_in(tvb, pinfo, tree)
end
M.parsers_ofpt[10] = ofp_packet_in

function ofp_flow_removed(tvb, pinfo, tree)
end
M.parsers_ofpt[11] = ofp_flow_removed

function ofp_port_status(tvb, pinfo, tree)
end
M.parsers_ofpt[12] = ofp_port_status

function ofp_packet_out(tvb, pinfo, tree)
end
M.parsers_ofpt[13] = ofp_packet_out

function ofp_flow_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[14] = ofp_flow_mod

-- Group Mod
fields.group_mod = ProtoField.new("Group Mod", "of15.group_mod", ftypes.STRING)
fields.group_mod_command = ProtoField.new("Command", "of15.group_mod.command", ftypes.UINT16, ofp.ofp_group_mod_command, base.DEC)
fields.group_mod_type = ProtoField.new("Type", "of15.group_mod.type", ftypes.UINT8, ofp.ofp_group_type, base.DEC)
fields.group_mod_group_id = ProtoField.new("Group Id", "of15.group_mod.group_id", ftypes.UINT32, nil, base.DEC)
fields.group_mod_bucket_array_len = ProtoField.new("Bucket Array Len", "of15.group_mod.bucket_array_len", ftypes.UINT16, nil, base.DEC)
fields.group_mod_command_bucket_id = ProtoField.new("Command Bucket Id", "of15.group_mod.command_bucket_id", ftypes.UINT32, nil, base.DEC)
function ofp_group_mod(tvb, pinfo, tree)
    local group_id = tvb(4,4):uint()
    local subtree = tree:add(fields.multipart_request, tvb(), "", "Group Mod: Id="..tostring(group_id))
    subtree:add(fields.group_mod_command, tvb(0,2))
    subtree:add(fields.group_mod_type, tvb(2,1))
    subtree:add(fields.pad, tvb(3,1))
    subtree:add(fields.group_mod_group_id, tvb(4,4))
    local bucket_array_len = tvb(8,2):uint()
    subtree:add(fields.group_mod_bucket_array_len, tvb(8,2))
    subtree:add(fields.pad2, tvb(10,2))
    local command_bucket_id = tvb(12,4):uint()
    if (ofp.ofp_group_bucket[command_bucket_id] ~= nil) then
        subtree:add(fields.group_mod_command_bucket_id, tvb(12,4), command_bucket_id, "Command Bucket Id: "..ofp.ofp_group_bucket[command_bucket_id])
    else
        subtree:add(fields.group_mod_command_bucket_id, tvb(12,4))
    end
    local offset = 16
    while (offset < 16+bucket_array_len) do
        offset = offset + ofp_struct.ofp_bucket(tvb(offset), pinfo, subtree)
    end
    -- TODO: properties
end
M.parsers_ofpt[15] = ofp_group_mod

function ofp_port_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[16] = ofp_port_mod

function ofp_table_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[17] = ofp_table_mod

-- Multipart
fields.multipart_request = ProtoField.new("Multipart Request", "of15.multipart_reply", ftypes.STRING)
fields.multipart_reply = ProtoField.new("Multipart Reply", "of15.multipart_reply", ftypes.STRING)
fields.multipart_type = ProtoField.new("Type", "of15.multipart.type", ftypes.UINT16, ofp.ofp_multipart_type, base.DEC)
fields.multipart_flags = ProtoField.new("Flags", "of15.multipart.flags", ftypes.UINT16, nil, base.HEX, 0x00000001)
fields.multipart_flags_request_more = ProtoField.new("OFPMPF_REQUEST_MORE", "of15.multipart.flags.request_more", ftypes.BOOLEAN, nil, 16, 0x00000001)
fields.multipart_flags_reply_more = ProtoField.new("OFPMPF_REPLY_MORE", "of15.multipart.flags.reply_more", ftypes.BOOLEAN, nil, 16, 0x00000001)

function ofp_multipart_request(tvb, pinfo, tree)
    assert(tvb:len() >= 8, "At least 8 Bytes required")
    local subtree = tree:add(fields.multipart_request, tvb(), "", "Multipart Request: "..ofp.ofp_multipart_type[tvb(0,2):uint()])
    pinfo.cols.info:append(": "..ofp.ofp_multipart_type[tvb(0,2):uint()])
    local i_mult_type = tvb(0,2):uint()
    subtree:add(fields.multipart_type, tvb(0,2))
    subtree:add(fields.multipart_flags, tvb(2,2))
    subtree:add(fields.multipart_flags_request_more, tvb(2,2))
    subtree:add(fields.pad4, tvb(4,4))
    if (struct_multipart.parsers_ofpmp_request[i_mult_type] ~= nil) then
        struct_multipart.parsers_ofpmp_request[i_mult_type](tvb(8), pinfo, subtree)
    else
        pinfo.cols.info:append(" not implemented")
    end
end
M.parsers_ofpt[18] = ofp_multipart_request

function ofp_multipart_reply(tvb, pinfo, tree)
    assert(tvb:len() >= 8, "At least 8 Bytes required")
    local subtree = tree:add(fields.multipart_reply, tvb(), "", "Multipart Reply: "..ofp.ofp_multipart_type[tvb(0,2):uint()])
    pinfo.cols.info:append(": "..ofp.ofp_multipart_type[tvb(0,2):uint()])
    local i_mult_type = tvb(0,2):uint()
    subtree:add(fields.multipart_type, tvb(0,2))
    subtree:add(fields.multipart_flags, tvb(2,2))
    subtree:add(fields.multipart_flags_reply_more, tvb(2,2))
    subtree:add(fields.pad4, tvb(4,4))
    if (tvb():len() > 8) then
        if (struct_multipart.parsers_ofpmp_reply[i_mult_type] ~= nil) then
            struct_multipart.parsers_ofpmp_reply[i_mult_type](tvb(8), pinfo, subtree)
        else
            pinfo.cols.info:append(" not implemented")
        end
    end
end
M.parsers_ofpt[19] = ofp_multipart_reply

function ofp_barrier_request(tvb, pinfo, tree)
end
M.parsers_ofpt[20] = ofp_barrier_request

function ofp_barrier_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[21] = ofp_barrier_reply

function ofp_role_request(tvb, pinfo, tree)
end
M.parsers_ofpt[24] = ofp_role_request

function ofp_role_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[25] = ofp_role_reply

function ofp_get_async_request(tvb, pinfo, tree)
end
M.parsers_ofpt[26] = ofp_get_async_request

function ofp_get_async_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[27] = ofp_get_async_reply

function ofp_set_async(tvb, pinfo, tree)
end
M.parsers_ofpt[28] = ofp_set_async

function ofp_meter_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[29] = ofp_meter_mod

function ofp_role_status(tvb, pinfo, tree)
end
M.parsers_ofpt[30] = ofp_role_status

function ofp_table_status(tvb, pinfo, tree)
end
M.parsers_ofpt[31] = ofp_table_status

function ofp_requestforward(tvb, pinfo, tree)
end
M.parsers_ofpt[32] = ofp_requestforward

function ofp_bundle_control(tvb, pinfo, tree)
end
M.parsers_ofpt[33] = ofp_bundle_control

function ofp_bundle_add_message(tvb, pinfo, tree)
end
M.parsers_ofpt[34] = ofp_bundle_add_message

function ofp_controller_status(tvb, pinfo, tree)
end
M.parsers_ofpt[35] = ofp_controller_status

return M