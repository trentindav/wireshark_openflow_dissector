-- local d = require "debug"
local ofp = require "ofp_const"
local struct_multipart = require "ofp_struct_multipart"
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
function parse_hello(tvb, pinfo, tree)
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
M.parsers_ofpt[0] = parse_hello

function parse_error(tvb, pinfo, tree)
end
M.parsers_ofpt[1] = parse_error

fields.echo_data = ProtoField.new("Echo Data", "of15.echo.data", ftypes.STRING)
function parse_echo_request(tvb, pinfo, tree)
    if (tvb:len() == 0) then return end
    tree:add(fields.echo_data, tvb())
end
M.parsers_ofpt[2] = parse_echo_request

function parse_echo_reply(tvb, pinfo, tree)
    if (tvb:len() == 0) then return end
    tree:add(fields.echo_data, tvb())
end
M.parsers_ofpt[3] = parse_echo_reply

function parse_experimenter(tvb, pinfo, tree)
end
M.parsers_ofpt[4] = parse_experimenter

function parse_features_request(tvb, pinfo, tree)
end
M.parsers_ofpt[5] = parse_features_request

function parse_features_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[6] = parse_features_reply

function parse_get_config_request(tvb, pinfo, tree)
end
M.parsers_ofpt[7] = parse_get_config_request

function parse_get_config_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[8] = parse_get_config_reply

function parse_set_config(tvb, pinfo, tree)
end
M.parsers_ofpt[9] = parse_set_config

function parse_packet_in(tvb, pinfo, tree)
end
M.parsers_ofpt[10] = parse_packet_in

function parse_flow_removed(tvb, pinfo, tree)
end
M.parsers_ofpt[11] = parse_flow_removed

function parse_port_status(tvb, pinfo, tree)
end
M.parsers_ofpt[12] = parse_port_status

function parse_packet_out(tvb, pinfo, tree)
end
M.parsers_ofpt[13] = parse_packet_out

function parse_flow_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[14] = parse_flow_mod

function parse_group_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[15] = parse_group_mod

function parse_port_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[16] = parse_port_mod

function parse_table_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[17] = parse_table_mod

-- Multipart
fields.multipart_request = ProtoField.new("Multipart Request", "of.multipart_reply", ftypes.STRING)
fields.multipart_reply = ProtoField.new("Multipart Reply", "of.multipart_reply", ftypes.STRING)
fields.multipart_type = ProtoField.new("Type", "of.multipart.type", ftypes.UINT16, ofp.ofp_multipart_type, base.DEC)
fields.multipart_flags = ProtoField.new("Flags", "of.multipart.flags", ftypes.UINT16, nil, base.HEX, 0x00000001)
fields.multipart_flags_request_more = ProtoField.new("OFPMPF_REQUEST_MORE", "of.multipart.flags.request_more", ftypes.BOOLEAN, nil, 16, 0x00000001)
fields.multipart_flags_reply_more = ProtoField.new("OFPMPF_REPLY_MORE", "of.multipart.flags.reply_more", ftypes.BOOLEAN, nil, 16, 0x00000001)

function parse_multipart_request(tvb, pinfo, tree)
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
M.parsers_ofpt[18] = parse_multipart_request

function parse_multipart_reply(tvb, pinfo, tree)
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
M.parsers_ofpt[19] = parse_multipart_reply

function parse_barrier_request(tvb, pinfo, tree)
end
M.parsers_ofpt[20] = parse_barrier_request

function parse_barrier_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[21] = parse_barrier_reply

function parse_role_request(tvb, pinfo, tree)
end
M.parsers_ofpt[24] = parse_role_request

function parse_role_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[25] = parse_role_reply

function parse_get_async_request(tvb, pinfo, tree)
end
M.parsers_ofpt[26] = parse_get_async_request

function parse_get_async_reply(tvb, pinfo, tree)
end
M.parsers_ofpt[27] = parse_get_async_reply

function parse_set_async(tvb, pinfo, tree)
end
M.parsers_ofpt[28] = parse_set_async

function parse_meter_mod(tvb, pinfo, tree)
end
M.parsers_ofpt[29] = parse_meter_mod

function parse_role_status(tvb, pinfo, tree)
end
M.parsers_ofpt[30] = parse_role_status

function parse_table_status(tvb, pinfo, tree)
end
M.parsers_ofpt[31] = parse_table_status

function parse_requestforward(tvb, pinfo, tree)
end
M.parsers_ofpt[32] = parse_requestforward

function parse_bundle_control(tvb, pinfo, tree)
end
M.parsers_ofpt[33] = parse_bundle_control

function parse_bundle_add_message(tvb, pinfo, tree)
end
M.parsers_ofpt[34] = parse_bundle_add_message

function parse_controller_status(tvb, pinfo, tree)
end
M.parsers_ofpt[35] = parse_controller_status

return M