-- local d = require "debug"
local ofp = require "ofp_const"

-- for k, v in pairs(Dissector.list()) do
--   print(k, v)
-- end
local builtin_of_dissector = Dissector.get("openflow")
local of_proto = Proto("openflow_lua","OpenFlow (LUA)")
local of = of_proto.fields

_G.of_proto = of_proto

-- OF versions
local of15 = require "openflow_15"

local parsers_version = {
    [6] = of15
}


-- Header
of.header = ProtoField.new("OF Header", "of.header", ftypes.STRING)
of.header_version = ProtoField.new("Version", "of.header.version", ftypes.UINT8, ofp.ofp_versions, base.HEX)
of.header_type = ProtoField.new("Type", "of.header.type", ftypes.UINT8, ofp.ofp_type, base.DEC)
of.header_length = ProtoField.new("Length", "of.header.length", ftypes.UINT16, nil, base.DEC)
of.header_xid = ProtoField.new("Xid", "of.header.xid", ftypes.UINT32, nil, base.HEX)
-- General
of.pad = ProtoField.new("pad", "of.pad", ftypes.UINT8, nil, base.HEX)
of.pad2 = ProtoField.new("pad2", "of.pad2", ftypes.UINT16, nil, base.HEX)
of.pad3 = ProtoField.new("pad2", "of.pad2", ftypes.UINT24, nil, base.HEX)
of.pad4 = ProtoField.new("pad4", "of.pad4", ftypes.UINT32, nil, base.HEX)
of.length = ProtoField.new("Length", "of.length", ftypes.UINT16, nil, base.DEC)


function of_proto.dissector(tvb, pinfo, tree)
    local i_version = tvb(0,1):uint()
    if (i_version < 6) then
        builtin_of_dissector:call(tvb, pinfo, tree)
    else
        pinfo.cols.protocol = "OpenFlow"
        local subtree = tree:add(of_proto, tvb(), "OpenFlow")
        local header = subtree:add(of.header, tvb(), "", "OF Header")

        -- Parse Header
        local i_type = tvb(1,1):uint()
        local i_length = tvb(2,2):uint()
        local i_xid = tvb(4,4):uint()
        pinfo.cols.info = "Type "..ofp.ofp_type[i_type]
        header:add(of.header_version, tvb(0,1))
        header:add(of.header_type, tvb(1,1))
        header:add(of.header_length, tvb(2,2))
        header:add(of.header_xid, tvb(4,4))
        if (tvb:len() > 8) then
            parsers_version[i_version].parsers_ofpt[i_type](tvb:range(8, tvb(2,2):uint()-8), pinfo, subtree)
        end
    end
end

local wtap_diss = DissectorTable.get("tcp.port")
wtap_diss:add(6633, of_proto)

