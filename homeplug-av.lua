--  SPDX-License-Identifier: GPL-2.0-or-later
------------------------------------------------------------------------
--  homeplug-av-dissector - A HomePlug AV protocol dissector for
--                          Wireshark
--  Copyright (C) 2023 John Serock
--
--  This file is part of homeplug-av-dissector.
--
--  homeplug-av-dissector is free software: you can redistribute it
--  and/or modify it under the terms of the GNU General Public License
--  as published by the Free Software Foundation, either version 2 of
--  the License, or (at your option) any later version.
--
--  homeplug-av-dissector is distributed in the hope that it will be
--  useful, but WITHOUT ANY WARRANTY; without even the implied warranty
--  of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program. If not, write to the Free Software
--  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
--  02110-1301, USA.
------------------------------------------------------------------------
local p_homeplug_av = Proto("HomePlugAV",  "HomePlug AV Protocol")

local my_info = {
    description = "A HomePlug AV protocol dissector",
    version = "0.1.0",
    author = "John Serock",
    repository = "https://github.com/serock/homeplug-av-dissector"
}

--  print("Lua version = ", _VERSION)

local ETHERTYPE_HOMEPLUGAV = 0x88e1

local MMTYPE_STA_CAP_REQ      = 0x6034
local MMTYPE_STA_CAP_CNF      = 0x6035
local MMTYPE_STA_IDENTIFY_REQ = 0x6060
local MMTYPE_STA_IDENTIFY_CNF = 0x6061
local MMTYPE_ERROR_IND        = 0x6046

local bidir_bursting_values = {
    [0] = "no",
    [1] = "Selective ACK only",
    [2] = "Selective ACK or reverse start of frame"
}

local eebtm_values = {
    [0] = "Pseudo noise sequence",
    [1] = "Frame control and robust OFDM information for diversity"
}

local guard_intervals = {
    [0x00] = "5.56",
    [0x01] = "7.56",
    [0x02] = "47.12",
    [0x03] = "1.6",
    [0x04] = "2.08",
    [0x05] = "2.56",
    [0x06] = "3.92",
    [0x07] = "9.56",
    [0x08] = "11.56",
    [0x09] = "15.56",
    [0x0a] = "19.56",
    [0x0b] = "0.00",
    [0x0c] = "0.92"
}

local hpav_station_types = {
    [0x00] = "HomePlug AV 1.1 station",
    [0x01] = "HomePlug AV 2.0 station",
    [0xff] = "Not a HomePlug AV station"
}

local hpav_versions = {
    [0] = "1.1",
    [1] = "2.0"
}

local mimo_capabilities = {
    [0] = "no",
    [1] = "Selection diversity",
    [2] = "Beam forming"
}

local mmtype_info = {
    [MMTYPE_STA_CAP_REQ]      = "Get Station Capabilities request",
    [MMTYPE_STA_CAP_CNF]      = "Get Station Capabilities confirmation",
    [MMTYPE_STA_IDENTIFY_REQ] = "Get Station Identification Information request",
    [MMTYPE_STA_IDENTIFY_CNF] = "Get Station Identification Information confirmation",
    [MMTYPE_ERROR_IND]        = "Error indication"
}

local mmtype_lsbs = {
    [0] = "request",
    [1] = "confirmation",
    [2] = "indication",
    [3] = "response"
}

local mmtype_msbs = {
    [0] = "Station -- Central Coordinator",
    [1] = "Proxy Coordinator",
    [2] = "Central Coordinator -- Central Coordinator",
    [3] = "Station -- Station",
    [4] = "Manufacturer specific",
    [5] = "Vendor specific",
    [6] = "Reserved",
    [7] = "Reserved"
}

local mmvs = {
    [0] = "1.0",
    [1] = "1.1",
    [2] = "2.0"
}

local pb_values = {
    [0] = "The maximum number based on physical parameters",
    [1] = "Reserved"
}

local no_yes = {
    [0] = "no",
    [1] = "yes"
}

local ouis = {
   ["00:1f:84"] = "Gigle Semiconductor"
}

local power_levels = {
   [0] = "0.0 dB",
   [1] = "0.5 dB",
   [2] = "1.0 dB",
   [3] = "1.5 dB",
   [4] = "2.0 dB",
   [5] = "2.5 dB",
   [6] = "3.0 dB",
   [7] = "3.5 dB"
}

local regulatory_domains = {
   [0] = "North America only"
}

local pf = {
    mmv             = ProtoField.uint8("homeplugav.mmv", "Management Message Version", base.DEC, mmvs),
    mmtype          = ProtoField.uint16("homeplugav.mmtype", "Management Message Type", base.HEX, mmtype_info),
    mmtype_msbs     = ProtoField.uint16("homeplugav.mmtype.msbs", "Three MSBs", base.DEC, mmtype_msbs, 0xe000),
    mmtype_lsbs     = ProtoField.uint16("homeplugav.mmtype.lsbs", "Two LSBs", base.DEC, mmtype_lsbs, 0x0003),
    fmi             = ProtoField.bytes("homeplugav.fmi", "Fragmentation Management Information", base.COLON),
    fmi_nf_mi       = ProtoField.uint8("homeplugav.fmi.nfMi", "Number of Fragments", base.DEC, nil, 0xf0),
    fmi_fn_mi       = ProtoField.uint8("homeplugav.fmi.fnMi", "Fragment Number", base.DEC, nil, 0x0f),
    fmi_fmsn        = ProtoField.uint8("homeplugav.fmi.fmsn", "Fragmentation Message Sequence Number", base.DEC),
    hpav_version    = ProtoField.uint8("homeplugav.mme.hpavVersion", "HomePlug AV Version", base.DEC, hpav_versions),
    mac_addr        = ProtoField.ether("homeplugav.mme.macAddr", "MAC Address"),
    oui             = ProtoField.bytes("homeplugav.mme.oui", "Organizationally Unique Identifier", base.COLON),
    auto_conn       = ProtoField.uint8("homeplugav.mme.autoConnect", "Auto Connect Capability", base.DEC, no_yes),
    smoothing       = ProtoField.uint8("homeplugav.mme.smoothing", "Smoothing Capability", base.DEC, no_yes),
    cco             = ProtoField.uint8("homeplugav.mme.cco", "CCo Capability", base.DEC, no_yes),
    proxy           = ProtoField.uint8("homeplugav.mme.proxy", "Proxy Capability", base.DEC, no_yes),
    backup_cco      = ProtoField.uint8("homeplugav.mme.backupCCo", "Backup CCo Capability", base.DEC, no_yes),
    soft_handover   = ProtoField.uint8("homeplugav.mme.softHandover", "Soft Handover Capability", base.DEC, no_yes),
    two_sym_fc      = ProtoField.uint8("homeplugav.mme.twoSymFC", "Two-Symbol Frame Control Capability", base.DEC, no_yes),
    max_frame_len   = ProtoField.string("homeplugav.mme.maxFrameLen", "Maximum Frame Length"),
    homeplug_1_1    = ProtoField.uint8("homeplugav.mme.homeplug11", "HomePlug 1.1 Capability", base.DEC, no_yes),
    homeplug_1_0    = ProtoField.uint8("homeplugav.mme.homeplug10", "HomePlug 1.0 Interoperability", base.DEC, no_yes),
    regulatory      = ProtoField.uint8("homeplugav.mme.regulatory", "Regulatory Capability", base.DEC, regulatory_domains),
    bidir_bursting  = ProtoField.uint8("homeplugav.mme.bidirBursting", "Bidirectional Bursting Capability", base.DEC, bidir_bursting_values),
    impl_version    = ProtoField.uint16("homeplugav.mme.implVersion", "Implementation Version", base.DEC),
    green_phy       = ProtoField.uint8("homeplugav.mme.greenPhy", "Green PHY Capability", base.DEC, no_yes),
    power_save      = ProtoField.uint8("homeplugav.mme.powerSave", "Power Save Capability", base.DEC, no_yes),
    gp_pref_alloc   = ProtoField.uint8("homeplugav.mme.gpPrefAlloc", "Green PHY Preferred Allocation Capability", base.DEC, no_yes),
    repeat_route    = ProtoField.uint8("homeplugav.mme.repeatRoute", "Repeating and Routing Capability", base.DEC, no_yes),
    hpav_station    = ProtoField.uint8("homeplugav.mme.hpavStation", "HomePlug AV Station Type", base.DEC, hpav_station_types),
    ext_field_len   = ProtoField.uint8("homeplugav.mme.extFieldLen", "Extended Fields Length", base.DEC),
    mimo            = ProtoField.uint8("homeplugav.mme.mimo", "MIMO Capability", base.DEC, mimo_capabilities),
    ext_freq_band   = ProtoField.uint8("homeplugav.mme.extFreqBand", "Extended Frequency Band Capability", base.DEC, no_yes),
    immed_repeat    = ProtoField.uint8("homeplugav.mme.immedRepeat", "Immediate Repeating Capability", base.DEC, no_yes),
    short_delimiter = ProtoField.uint8("homeplugav.mme.shortDelimiter", "Short Delimiter Capability", base.DEC, no_yes),
    min_tx_gil      = ProtoField.uint8("homeplugav.mme.minTxGil", "Minimum Transmit Guard Interval", base.DEC, guard_intervals),
    min_rx_gil      = ProtoField.uint8("homeplugav.mme.minRxGil", "Minimum Receive Guard Interval", base.DEC, guard_intervals),
    min_carr_freq   = ProtoField.string("homeplugav.mme.minCarrFreq", "Minimum Carrier Frequency"),
    max_carr_freq   = ProtoField.string("homeplugav.mme.maxCarrFreq", "Maximum Carrier Frequency"),
    eebtm           = ProtoField.uint8("homeplugav.mme.eebtm", "Encoding of Extended Broadcast Tone Mask", base.DEC, eebtm_values),
    max_pb_sym      = ProtoField.uint8("homeplugav.mme.maxPbSym", "Maximum PHY Blocks per Symbol", base.DEC),
    max_pb_sym_enum = ProtoField.uint8("homeplugav.mme.maxPbSym", "Maximum PHY Blocks per Symbol", base.DEC, pb_values),
    mimo_power      = ProtoField.uint8("homeplugav.mme.mimoPower", "MIMO Power Allocation", base.DEC, power_levels),
    frame_256       = ProtoField.uint8("homeplugav.mme.frame256", "256-bit Frame Control Capability", base.DEC, no_yes),
    vsinfo_len      = ProtoField.uint16("homeplugav.mme.vsinfoLen", "Vendor-Specific Information Length", base.DEC),
    vendor_oui      = ProtoField.bytes("homeplugav.mme.vendorOui", "Organizationally Unique Identifier", base.COLON),
    vendor_defined  = ProtoField.bytes("homeplugav.mme.vendorDefined", "Vendor Defined", base.COLON)
}

p_homeplug_av.fields = pf

local f = {
    mmtype       = Field.new("homeplugav.mmtype"),
    oui          = Field.new("homeplugav.mme.oui"),
    hpav_station = Field.new("homeplugav.mme.hpavStation"),
    vsinfo_len   = Field.new("homeplugav.mme.vsinfoLen"),
    vendor_oui   = Field.new("homeplugav.mme.vendorOui")
}

local function to_frame_length_string(range)
    return range:le_uint() * 1.28 .. " microseconds"
end

local function to_frequency_string(range)
    local value = range:le_uint() * 24.414
    local result
    if value < 1000.0 then
        result = value .. " kHz"
    else
        result = value / 1000.0 .. " MHz"
    end
    return result
end

local function update_packet_info(pinfo)
    pinfo.cols.protocol = p_homeplug_av.name

    if mmtype_info[mmtype] ~= nil then
        pinfo.cols.info:set(mmtype_info[mmtype])
    end
end

function p_homeplug_av.dissector(buffer, pinfo, tree)
    buffer_len = buffer:len()
    if buffer_len < 46 then return end

    local hpav_tree = tree:add(p_homeplug_av, buffer(), "HomePlug AV Protocol")

    hpav_tree:add_le(pf.mmv, buffer(0, 1))
    local mmtype_tree = hpav_tree:add_le(pf.mmtype, buffer(1, 2))
    mmtype_tree:add_le(pf.mmtype_msbs, buffer(1, 2))
    mmtype_tree:add_le(pf.mmtype_lsbs, buffer(1, 2))

    mmtype = f.mmtype()()

    do
        local fmi_tree = hpav_tree:add(pf.fmi, buffer(3, 2))
        fmi_tree:add(pf.fmi_nf_mi, buffer(3, 1))
        fmi_tree:add(pf.fmi_fn_mi, buffer(3, 1))
        fmi_tree:add(pf.fmi_fmsn,  buffer(4, 1))
    end

    update_packet_info(pinfo)

    if mmtype == MMTYPE_STA_CAP_REQ or mmtype == MMTYPE_STA_IDENTIFY_REQ then return end

    local mme_tree = hpav_tree:add(buffer(5), "Management Message Entry")

    if mmtype == MMTYPE_STA_CAP_CNF then
        mme_tree:add_le(pf.hpav_version, buffer(5, 1))
        mme_tree:add(pf.mac_addr, buffer(6, 6))
        mme_tree:add(pf.oui, buffer(12, 3)):append_text(" (" .. ouis[f.oui().label] .. ")")
        mme_tree:add_le(pf.auto_conn, buffer(15, 1))
        mme_tree:add_le(pf.smoothing, buffer(16, 1))
        mme_tree:add_le(pf.cco, buffer(17, 1))
        mme_tree:add_le(pf.proxy, buffer(18, 1))
        mme_tree:add_le(pf.backup_cco, buffer(19, 1))
        mme_tree:add_le(pf.soft_handover, buffer(20, 1))
        mme_tree:add_le(pf.two_sym_fc, buffer(21, 1))
        do
            local range = buffer(22, 2)
            mme_tree:add_le(pf.max_frame_len, range, to_frame_length_string(range))
        end
        mme_tree:add_le(pf.homeplug_1_1, buffer(24, 1))
        mme_tree:add_le(pf.homeplug_1_0, buffer(25, 1))
        mme_tree:add_le(pf.regulatory, buffer(26, 1))
        mme_tree:add_le(pf.bidir_bursting, buffer(27, 1))
        mme_tree:add_le(pf.impl_version, buffer(28, 2))
        mme_tree:set_len(25)  -- 25=28+2-5
    elseif mmtype == MMTYPE_STA_IDENTIFY_CNF then
        mme_tree:add_le(pf.green_phy, buffer(5, 1))
        mme_tree:add_le(pf.power_save, buffer(6, 1))
        mme_tree:add_le(pf.gp_pref_alloc, buffer(7, 1))
        mme_tree:add_le(pf.repeat_route, buffer(8, 1))
        mme_tree:add_le(pf.hpav_station, buffer(9, 1))
        mme_tree:add_le(pf.ext_field_len, buffer(10, 1))
        local hpav_station = f.hpav_station()()
        if hpav_station == 0x01 then
            local extended_tree = mme_tree:add(buffer(11), "Extended Fields")
            extended_tree:add_le(pf.mimo, buffer(11, 1))
            extended_tree:add_le(pf.ext_freq_band, buffer(12, 1))
            extended_tree:add_le(pf.immed_repeat, buffer(13, 1))
            extended_tree:add_le(pf.short_delimiter, buffer(14, 1))
            extended_tree:add_le(pf.min_tx_gil, buffer(15, 1))
            extended_tree:add_le(pf.min_rx_gil, buffer(16, 1))
            do
                local range = buffer(17, 2)
                extended_tree:add(pf.min_carr_freq, range, to_frequency_string(range))
            end
            do
                local range = buffer(19, 2)
                extended_tree:add(pf.max_carr_freq, range, to_frequency_string(range))
            end
            extended_tree:add_le(pf.eebtm, buffer(21, 1))
            do
                local range = buffer(22, 1)
                local value = range:le_uint()
                if value < 2 then
                    extended_tree:add_le(pf.max_pb_sym_enum, range)
                else
                    extended_tree:add_le(pf.max_pb_sym, range)
                end
            end
            extended_tree:add_le(pf.mimo_power, buffer(23, 1))
            extended_tree:add_le(pf.frame_256, buffer(24, 1))
            extended_tree:add_le(pf.vsinfo_len, buffer(25, 2))
            local vsinfo_len = f.vsinfo_len()()
            if vsinfo_len ~= 0 then
                local vsinfo_tree = extended_tree:add(buffer(27), "Vendor-Specific Information")
                vsinfo_tree:add(pf.vendor_oui, buffer(27, 3)):append_text(" (" .. ouis[f.vendor_oui().label] .. ")")
                vsinfo_tree:add(pf.vendor_defined, buffer(30))
            end
        end
    elseif mmtype == MMTYPE_ERROR_IND then
        -- TODO implement
    end
end

local dt_ethertype = DissectorTable.get("ethertype")
dt_ethertype:add(ETHERTYPE_HOMEPLUGAV, p_homeplug_av)
