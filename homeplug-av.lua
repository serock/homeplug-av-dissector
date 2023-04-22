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
    version = "0.7.0",
    author = "John Serock",
    repository = "https://github.com/serock/homeplug-av-dissector"
}

--  print("Lua version = ", _VERSION)

local ETHERTYPE_HOMEPLUGAV = 0x88e1

local MMTYPE_DISCOVER_LIST_REQ = 0x0014
local MMTYPE_DISCOVER_LIST_CNF = 0x0015
local MMTYPE_STA_CAP_REQ       = 0x6034
local MMTYPE_STA_CAP_CNF       = 0x6035
local MMTYPE_STA_IDENTIFY_REQ  = 0x6060
local MMTYPE_STA_IDENTIFY_CNF  = 0x6061
local MMTYPE_ERROR_IND         = 0x6046

local bidir_bursting_values = {
    [0] = "no",
    [1] = "Selective ACK only",
    [2] = "Selective ACK or reverse start of frame"
}
local cco_capabilities = {
    [0] = "QoS and TDMA not supported",
    [1] = "QoS and TDMA in uncoordinated mode only",
    [2] = "QoS and TDMA in coordinated mode",
    [3] = "future"
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

local homeplug_av_station_types = {
    [0x00] = "HomePlug AV 1.1 station",
    [0x01] = "HomePlug AV 2.0 station",
    [0xff] = "Not a HomePlug AV station"
}

local homeplug_av_versions = {
    [0] = "1.1",
    [1] = "2.0"
}

local mimo_capabilities = {
    [0] = "no",
    [1] = "Selection diversity",
    [2] = "Beam forming"
}

local mmtype_info = {
    [MMTYPE_DISCOVER_LIST_REQ] = "Get Discover List request",
    [MMTYPE_DISCOVER_LIST_CNF] = "Get Discover List confirmation",
    [MMTYPE_STA_CAP_REQ]       = "Get Station Capabilities request",
    [MMTYPE_STA_CAP_CNF]       = "Get Station Capabilities confirmation",
    [MMTYPE_STA_IDENTIFY_REQ]  = "Get Station Identification Information request",
    [MMTYPE_STA_IDENTIFY_CNF]  = "Get Station Identification Information confirmation",
    [MMTYPE_ERROR_IND]         = "Error indication"
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

local network_kinds = {
    [0] = "In-home",
    [1] = "Access"
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

local signal_levels = {
   [0x00] = "Unavailable",
   [0x01] = "> -10 dB, but <= 0 dB",
   [0x02] = "> -15 dB, but <= -10 dB",
   [0x03] = "> -20 dB, but <= -15 dB",
   [0x04] = "> -25 dB, but <= -20 dB",
   [0x05] = "> -30 dB, but <= -25 dB",
   [0x06] = "> -35 dB, but <= -30 dB",
   [0x07] = "> -40 dB, but <= -35 dB",
   [0x08] = "> -45 dB, but <= -40 dB",
   [0x09] = "> -50 dB, but <= -45 dB",
   [0x0a] = "> -55 dB, but <= -50 dB",
   [0x0b] = "> -60 dB, but <= -55 dB",
   [0x0c] = "> -65 dB, but <= -60 dB",
   [0x0d] = "> -70 dB, but <= -65 dB",
   [0x0e] = "> -75 dB, but <= -70 dB",
   [0x0f] = "<= -75 dB",
}

local regulatory_domains = {
   [0] = "North America only"
}

local pf = {
    mmv                      = ProtoField.uint8("homeplugav.mmv", "Management Message Version", base.DEC, mmvs),
    mmtype                   = ProtoField.uint16("homeplugav.mmtype", "Management Message Type", base.HEX, mmtype_info),
    mmtype_msbs              = ProtoField.uint16("homeplugav.mmtype.msbs", "Three MSBs", base.DEC, mmtype_msbs, 0xe000),
    mmtype_lsbs              = ProtoField.uint16("homeplugav.mmtype.lsbs", "Two LSBs", base.DEC, mmtype_lsbs, 0x0003),
    fmi                      = ProtoField.bytes("homeplugav.fmi", "Fragmentation Management Information", base.COLON),
    fmi_nf_mi                = ProtoField.uint8("homeplugav.fmi.nfMi", "Number of Fragments", base.DEC, nil, 0xf0),
    fmi_fn_mi                = ProtoField.uint8("homeplugav.fmi.fnMi", "Fragment Number", base.DEC, nil, 0x0f),
    fmi_fmsn                 = ProtoField.uint8("homeplugav.fmi.fmsn", "Fragmentation Message Sequence Number", base.DEC),
    num_stas                 = ProtoField.uint8("homeplugav.numStas", "Number of Stations Discovered", base.DEC),
    num_networks             = ProtoField.uint8("homeplugav.numNetworks", "Number of Networks Discovered", base.DEC),
    sta_mac_addr             = ProtoField.ether("homeplugav.sta.macAddr", "MAC Address"),
    sta_tei                  = ProtoField.uint8("homeplugav.sta.tei", "Terminal Equipment Identifier", base.DEC),
    sta_same_network         = ProtoField.uint8("homeplugav.sta.sameNetwork", "Same Network", base.DEC, no_yes),
    sta_network_kind         = ProtoField.uint8("homeplugav.sta.networkKind", "Network Type", base.DEC, network_kinds, 0xf0),
    sta_snid                 = ProtoField.uint8("homeplugav.sta.snid", "Short Network Identifier", base.DEC, nil, 0x0f),
    sta_status_bcco          = ProtoField.uint8("homeplugav.sta.statusBcco", "Backup Central Coordinator", base.DEC, no_yes, 0x80),
    sta_status_pco           = ProtoField.uint8("homeplugav.sta.statusPco", "Proxy Coordinator", base.DEC, no_yes, 0x40),
    sta_status_cco           = ProtoField.uint8("homeplugav.sta.statusCco", "Central Coordinator", base.DEC, no_yes, 0x20),
    sta_capability_bcco      = ProtoField.uint8("homeplugav.sta.capabilityBcco", "Backup Central Coordinator Capability", base.DEC, no_yes, 0x10),
    sta_capability_pco       = ProtoField.uint8("homeplugav.sta.capabilityPco", "Proxy Coordinator Capability", base.DEC, no_yes, 0x08),
    sta_capability_cco       = ProtoField.uint8("homeplugav.sta.capabilityCco", "Central Coordinator Capability", base.DEC, cco_capabilities, 0x06),
    sta_reserved             = ProtoField.uint8("homeplugav.sta.reserved", "Reserved", base.DEC, nil, 0x01),
    sta_signal_level         = ProtoField.uint8("homeplugav.sta.signalLevel", "Signal Level", base.DEC, signal_levels),
    sta_ble                  = ProtoField.string("homeplugav.sta.ble", "Average Bit Loading Estimate"),
    sta_ble_mantissa         = ProtoField.uint8("homeplugav.sta.ble.mantissa", "Mantissa", base.DEC, nil, 0xf8),
    sta_ble_exponent         = ProtoField.uint8("homeplugav.sta.ble.exponent", "Exponent", base.DEC, nil, 0x07),
    mac_addr                 = ProtoField.ether("homeplugav.macAddr", "MAC Address"),
    homeplug_av_version      = ProtoField.uint8("homeplugav.hpavVersion", "HomePlug AV Version", base.DEC, homeplug_av_versions),
    oui                      = ProtoField.bytes("homeplugav.oui", "Organizationally Unique Identifier", base.COLON),
    capability_auto_connect  = ProtoField.uint8("homeplugav.capabilityAutoConnect", "Auto Connect Capability", base.DEC, no_yes),
    capability_smoothing     = ProtoField.uint8("homeplugav.capabilitySmoothing", "Smoothing Capability", base.DEC, no_yes),
    capability_cco           = ProtoField.uint8("homeplugav.capabilityCco", "Central Coordinator Capability", base.DEC, no_yes),
    capability_pco           = ProtoField.uint8("homeplugav.capabilityPco", "Proxy Coordinator Capability", base.DEC, no_yes),
    capability_bcco          = ProtoField.uint8("homeplugav.capabilityBcco", "Backup Central Coordinator Capability", base.DEC, no_yes),
    capability_soft_handover = ProtoField.uint8("homeplugav.capabilitySoftHandover", "Soft Handover Capability", base.DEC, no_yes),
    capability_two_symbol_fc = ProtoField.uint8("homeplugav.capabilityTwoSymbolFC", "Two-Symbol Frame Control Capability", base.DEC, no_yes),
    max_frame_len            = ProtoField.string("homeplugav.maxFrameLen", "Maximum Frame Length"),
    capability_homeplug_1_1  = ProtoField.uint8("homeplugav.capabilityHomeplug11", "HomePlug 1.1 Capability", base.DEC, no_yes),
    interop_homeplug_1_0     = ProtoField.uint8("homeplugav.interopHomeplug10", "HomePlug 1.0 Interoperability", base.DEC, no_yes),
    capability_regulatory    = ProtoField.uint8("homeplugav.capabilityRegulatory", "Regulatory Capability", base.DEC, regulatory_domains),
    capability_bidir_burst   = ProtoField.uint8("homeplugav.capabilityBidirBurst", "Bidirectional Bursting Capability", base.DEC, bidir_bursting_values),
    implementation_version   = ProtoField.uint16("homeplugav.implVersion", "Implementation Version", base.DEC),
    capability_green_phy     = ProtoField.uint8("homeplugav.capabilityGreenPhy", "Green PHY Capability", base.DEC, no_yes),
    capability_power_save    = ProtoField.uint8("homeplugav.capabilityPowerSave", "Power Save Capability", base.DEC, no_yes),
    capability_gp_pref_alloc = ProtoField.uint8("homeplugav.capabilityGpPrefAlloc", "Green PHY Preferred Allocation Capability", base.DEC, no_yes),
    capability_repeat_route  = ProtoField.uint8("homeplugav.capabilityRepeatRoute", "Repeating and Routing Capability", base.DEC, no_yes),
    homeplug_av_station      = ProtoField.uint8("homeplugav.hpavStation", "HomePlug AV Station Type", base.DEC, homeplug_av_station_types),
    extended_fields_len      = ProtoField.uint8("homeplugav.extendedFieldsLen", "Extended Fields Length", base.DEC),
    ef_capability_mimo       = ProtoField.uint8("homeplugav.ef.capabilityMimo", "MIMO Capability", base.DEC, mimo_capabilities),
    ef_ext_freq_band         = ProtoField.uint8("homeplugav.ef.extFreqBand", "Extended Frequency Band Capability", base.DEC, no_yes),
    ef_immed_repeat          = ProtoField.uint8("homeplugav.ef.immedRepeat", "Immediate Repeating Capability", base.DEC, no_yes),
    ef_short_delimiter       = ProtoField.uint8("homeplugav.ef.shortDelimiter", "Short Delimiter Capability", base.DEC, no_yes),
    ef_min_tx_gil            = ProtoField.uint8("homeplugav.ef.minTxGil", "Minimum Transmit Guard Interval", base.DEC, guard_intervals),
    ef_min_rx_gil            = ProtoField.uint8("homeplugav.ef.minRxGil", "Minimum Receive Guard Interval", base.DEC, guard_intervals),
    ef_min_carr_freq         = ProtoField.string("homeplugav.ef.minCarrFreq", "Minimum Carrier Frequency"),
    ef_max_carr_freq         = ProtoField.string("homeplugav.ef.maxCarrFreq", "Maximum Carrier Frequency"),
    ef_eebtm                 = ProtoField.uint8("homeplugav.ef.eebtm", "Encoding of Extended Broadcast Tone Mask", base.DEC, eebtm_values),
    ef_max_pb_sym            = ProtoField.uint8("homeplugav.ef.maxPbSym", "Maximum PHY Blocks per Symbol", base.DEC),
    ef_max_pb_sym_enum       = ProtoField.uint8("homeplugav.ef.maxPbSym", "Maximum PHY Blocks per Symbol", base.DEC, pb_values),
    ef_mimo_power            = ProtoField.uint8("homeplugav.ef.mimoPower", "MIMO Power Allocation", base.DEC, power_levels),
    ef_frame_256             = ProtoField.uint8("homeplugav.ef.frame256", "256-bit Frame Control Capability", base.DEC, no_yes),
    ef_vsinfo_len            = ProtoField.uint16("homeplugav.ef.vsinfoLen", "Vendor-Specific Information Length", base.DEC),
    ef_vs_oui                = ProtoField.bytes("homeplugav.ef.vs.oui", "Organizationally Unique Identifier", base.COLON),
    ef_vs_vendor_defined     = ProtoField.bytes("homeplugav.ef.vs.vendorDefined", "Vendor Defined", base.COLON)
}

p_homeplug_av.fields = pf

local f = {
    mmtype              = Field.new("homeplugav.mmtype"),
    num_stas            = Field.new("homeplugav.numStas"),
    num_networks        = Field.new("homeplugav.numNetworks"),
    sta_ble_mantissa    = Field.new("homeplugav.sta.ble.mantissa"),
    sta_ble_exponent    = Field.new("homeplugav.sta.ble.exponent"),
    oui                 = Field.new("homeplugav.oui"),
    homeplug_av_station = Field.new("homeplugav.hpavStation"),
    ef_vsinfo_len       = Field.new("homeplugav.ef.vsinfoLen"),
    ef_vs_oui           = Field.new("homeplugav.ef.vs.oui")
}
local function to_ble(range)
    local mantissa = f.sta_ble_mantissa()()
    local exponent = f.sta_ble_exponent()()
    local ble = (mantissa + 32.0) * 2.0 ^ (exponent - 4.0) + 2.0 ^ (exponent - 5.0)
    return ble .. " bits per microsecond"
end

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

    if mmtype == MMTYPE_DISCOVER_LIST_REQ or mmtype == MMTYPE_STA_CAP_REQ or mmtype == MMTYPE_STA_IDENTIFY_REQ then return end

    local mme_tree = hpav_tree:add(buffer(5), "Management Message Entry")

    if mmtype == MMTYPE_DISCOVER_LIST_CNF then
        mme_tree:add_le(pf.num_stas, buffer(5, 1))
        local num_stas = f.num_stas()()
        local i = 6
        for j = 1, num_stas do
            local sta_tree = mme_tree:add(buffer(i, 12), "Station " .. j)
            sta_tree:add(pf.sta_mac_addr, buffer(i, 6))
            sta_tree:add_le(pf.sta_tei, buffer(i + 6, 1))
            sta_tree:add_le(pf.sta_same_network, buffer(i + 7, 1))
            do
                local range = buffer(i + 8, 1)
                sta_tree:add_le(pf.sta_network_kind, range)
                sta_tree:add_le(pf.sta_snid, range)
            end
            do
                local range = buffer(i + 9, 1)
                sta_tree:add_le(pf.sta_status_bcco, range)
                sta_tree:add_le(pf.sta_status_pco, range)
                sta_tree:add_le(pf.sta_status_cco, range)
                sta_tree:add_le(pf.sta_capability_bcco, range)
                sta_tree:add_le(pf.sta_capability_pco, range)
                sta_tree:add_le(pf.sta_capability_cco, range)
                sta_tree:add_le(pf.sta_reserved, range)
            end
            sta_tree:add_le(pf.sta_signal_level, buffer(i + 10, 1))
            do
                local range = buffer(i + 11, 1)
                local ble_tree = sta_tree:add(range, "Average Bit Loading Estimate")
                ble_tree:add_le(pf.sta_ble_mantissa, range)
                ble_tree:add_le(pf.sta_ble_exponent, range)
                ble_tree:append_text(": " .. to_ble(range))
            end
            i = i + 12
        end
        mme_tree:add_le(pf.num_networks, buffer(i, 1))
        i = i + 1
        local num_networks = f.num_networks()()
        for j = 1, num_networks do
            local network_tree = mme_tree:add(buffer(i, 13), "Network " .. j)
            --  TODO dissect discovered network
            i = i + 13
        end
        mme_tree:set_len(i - 5)
    elseif mmtype == MMTYPE_STA_CAP_CNF then
        mme_tree:add_le(pf.homeplug_av_version, buffer(5, 1))
        mme_tree:add(pf.mac_addr, buffer(6, 6))
        mme_tree:add(pf.oui, buffer(12, 3)):append_text(" (" .. ouis[f.oui().label] .. ")")
        mme_tree:add_le(pf.capability_auto_connect, buffer(15, 1))
        mme_tree:add_le(pf.capability_smoothing, buffer(16, 1))
        mme_tree:add_le(pf.capability_cco, buffer(17, 1))
        mme_tree:add_le(pf.capability_pco, buffer(18, 1))
        mme_tree:add_le(pf.capability_bcco, buffer(19, 1))
        mme_tree:add_le(pf.capability_soft_handover, buffer(20, 1))
        mme_tree:add_le(pf.capability_two_symbol_fc, buffer(21, 1))
        do
            local range = buffer(22, 2)
            mme_tree:add_le(pf.max_frame_len, range, to_frame_length_string(range))
        end
        mme_tree:add_le(pf.capability_homeplug_1_1, buffer(24, 1))
        mme_tree:add_le(pf.interop_homeplug_1_0, buffer(25, 1))
        mme_tree:add_le(pf.capability_regulatory, buffer(26, 1))
        mme_tree:add_le(pf.capability_bidir_burst, buffer(27, 1))
        mme_tree:add_le(pf.implementation_version, buffer(28, 2))
        mme_tree:set_len(25)  -- 25=28+2-5
    elseif mmtype == MMTYPE_STA_IDENTIFY_CNF then
        mme_tree:add_le(pf.capability_green_phy, buffer(5, 1))
        mme_tree:add_le(pf.capability_power_save, buffer(6, 1))
        mme_tree:add_le(pf.capability_gp_pref_alloc, buffer(7, 1))
        mme_tree:add_le(pf.capability_repeat_route, buffer(8, 1))
        mme_tree:add_le(pf.homeplug_av_station, buffer(9, 1))
        mme_tree:add_le(pf.extended_fields_len, buffer(10, 1))
        local homeplug_av_station = f.homeplug_av_station()()
        if homeplug_av_station == 0x01 then
            local extended_tree = mme_tree:add(buffer(11), "Extended Fields")
            extended_tree:add_le(pf.ef_capability_mimo, buffer(11, 1))
            extended_tree:add_le(pf.ef_ext_freq_band, buffer(12, 1))
            extended_tree:add_le(pf.ef_immed_repeat, buffer(13, 1))
            extended_tree:add_le(pf.ef_short_delimiter, buffer(14, 1))
            extended_tree:add_le(pf.ef_min_tx_gil, buffer(15, 1))
            extended_tree:add_le(pf.ef_min_rx_gil, buffer(16, 1))
            do
                local range = buffer(17, 2)
                extended_tree:add(pf.ef_min_carr_freq, range, to_frequency_string(range))
            end
            do
                local range = buffer(19, 2)
                extended_tree:add(pf.ef_max_carr_freq, range, to_frequency_string(range))
            end
            extended_tree:add_le(pf.ef_eebtm, buffer(21, 1))
            do
                local range = buffer(22, 1)
                local value = range:le_uint()
                if value < 2 then
                    extended_tree:add_le(pf.ef_max_pb_sym_enum, range)
                else
                    extended_tree:add_le(pf.ef_max_pb_sym, range)
                end
            end
            extended_tree:add_le(pf.ef_mimo_power, buffer(23, 1))
            extended_tree:add_le(pf.ef_frame_256, buffer(24, 1))
            extended_tree:add_le(pf.ef_vsinfo_len, buffer(25, 2))
            local vsinfo_len = f.ef_vsinfo_len()()
            if vsinfo_len ~= 0 then
                local vsinfo_tree = extended_tree:add(buffer(27), "Vendor-Specific Information")
                vsinfo_tree:add(pf.ef_vs_oui, buffer(27, 3)):append_text(" (" .. ouis[f.ef_vs_oui().label] .. ")")
                vsinfo_tree:add(pf.ef_vs_vendor_defined, buffer(30))
            end
        end
    elseif mmtype == MMTYPE_ERROR_IND then
        -- TODO implement
    end
end

local dt_ethertype = DissectorTable.get("ethertype")
dt_ethertype:add(ETHERTYPE_HOMEPLUGAV, p_homeplug_av)
