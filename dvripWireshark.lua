-- -*- coding: utf-8 -*-
-- DVRIP Wireshark Dissector for Port 37777
-- Copyright (C) 2020  Thomas Vogt
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.



-- Definition of the overall protocol name
dahua_proto = Proto("dvrip","Dahua DVRIP Protocol")

-- Protocol tree fields shown in Wireshark
DVRIP_b1_message_type =          ProtoField.uint16("dvrip.type",         "b1 - Message Type        ",          base.HEX)
DVRIP_b2_payload_length =        ProtoField.uint16("dvrip.length1",      "b2 - Payload Length      ",        base.HEX)
DVRIP_b3_sequence_id =           ProtoField.uint16("dvrip.sequence",     "b3 - Sequence ID         ",           base.HEX)
DVRIP_b4_unknown_1 =             ProtoField.uint16("dvrip.unknown1",     "b4 - Unknown             ",               base.HEX)
DVRIP_b5_payload_length_sid =    ProtoField.uint16("dvrip.length2",      "b5 - Payload Length / SID",  base.HEX)
DVRIP_b6_unknown_2 =             ProtoField.uint16("dvrip.unknown2",     "b6 - Unknwon             ",               base.HEX)
DVRIP_b7_sessionID =             ProtoField.uint16("dvrip.sessionID",    "b7 - SessionID           ",             base.HEX)
DVRIP_b8_zero_type =             ProtoField.uint16("dvrip.zero_type",    "b8 - Zero / LoginType    ",      base.HEX)
DVRIP_b9_payload =               ProtoField.uint16("dvrip.payload",      "b9 - Payload Body        ",          base.json_string_f)
DVRIP_b9_payload_JSON_RAW =      ProtoField.string("dvrip.data",         "Raw Message")

-- Adding the previous diefined protocol fields to the protocol
dahua_proto.fields = { 
    DVRIP_b1_message_type,
    DVRIP_b2_payload_length,
    DVRIP_b3_sequence_id,
    DVRIP_b4_unknown_1,
    DVRIP_b5_payload_length_sid,
    DVRIP_b6_unknown_2,
    DVRIP_b7_sessionID,
    DVRIP_b8_zero_type,
    DVRIP_b9_payload,
    DVRIP_b9_payload_JSON_RAW,
}

-- Loading JSON API 
local json = Dissector.get("json")

-- Main definition of the protocl dissector
function dahua_proto.dissector(buffer,pinfo,tree)
    -- checking for zero length
    length = buffer:len()
	if length == 0 then return end

	pinfo.cols.protocol = dahua_proto.name

    -- naming the protocol in menue
    local subtree = tree:add(dahua_proto, buffer(), "Dahua DVRIP Protocol")

    -- adding the protocol fields
    local b1_tree = subtree:add(DVRIP_b1_message_type, buffer(0,4))
    local b2_tree = subtree:add(DVRIP_b2_payload_length, buffer(4,4))
    local b3_tree = subtree:add(DVRIP_b3_sequence_id, buffer(8,4))
    local b4_tree = subtree:add(DVRIP_b4_unknown_1, buffer(12,4))
    local b5_tree = subtree:add(DVRIP_b5_payload_length_sid, buffer(16,4))
    local b6_tree = subtree:add(DVRIP_b6_unknown_2, buffer(20,4))
    local b7_tree = subtree:add(DVRIP_b7_sessionID, buffer(24,4))
    local b8_tree = subtree:add(DVRIP_b8_zero_type, buffer(28,4))
    
    -- search for JSON in the payload field
    if buffer:len() >32 then
        -- detect and load JSON values
        payload_tvbrange = buffer.range

        if buffer(32,1):string() == "{" then
            -- loading buffer
            local tvb_uncompress = buffer(32,buffer:len()-32)
            
            -- raw text
            local b9_tmp = subtree:add(DVRIP_b9_payload_JSON_RAW, tvb_uncompress)

            -- as JSON structure
            local test = json:call(tvb_uncompress:tvb(), pinfo, subtree)

        end
    
    end

end

-- assigning protocol to port
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(37777,dahua_proto)