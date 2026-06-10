#!/usr/bin/env python

"""
MPEG2 Transport Stream parser for extracting audio and video streams
"""

# Copyright (c) 2024, Bart Rozworski
# All rights reserved.

from functools import partial

class PESPacket:
    stream_id = None
    packet_length = None

    scrambling_control = None
    priority = None
    data_alignment_idicator = None
    copyright = None
    original_or_copy = None
    PTS_DTS_indicator = None
    ESCR_flag = None
    ES_rate_flag = None
    DSM_trick_mode_flag = None
    additional_copy_info_flag = None
    CRC_flag = None
    extension_flag = None
    PES_header_length = None

    PTS = None
    DTS = None
    ESCR = None
    ES_rate = None
    additional_copy_info = None
    previous_PES_CRC = None

    data = None

class TSAdaptationField:
    adaptation_field_length = None
    discontinuity_indicator = None
    random_access_indicator = None
    stream_priority_indicator = None
    PCR_flag = None
    OPCR_flag = None
    splicing_point_flag = None
    transport_private_data_flag = None
    adaptation_field_extension_flag = None

    transport_private_data = None

    stuffing_bytes = None

class TSPacket:
    sync_byte = None
    transport_error_indicator = None
    PUSI = None
    transport_priority = None
    PID = None
    TSC = None
    adaptation_field_control = None
    continuity_counter = None

    adaptation_field = None

    payload = None

def parse_TS(input_filepath, log=True):
    PACKET_SIZE = 188

    TS_packets = []

    packet_num = 0
    with open(input_filepath, mode='rb') as video:
        for packet in iter(partial(video.read, PACKET_SIZE), b''):
            TS_packet = TSPacket()
            
            TS_packet.sync_byte = packet[0]
            if TS_packet.sync_byte != 0x47:
                raise ValueError("Invalid TS packet sync byte")

            TS_packet.transport_error_indicator = (packet[1] & 0b10000000) >> 7
            TS_packet.PUSI = (packet[1] & 0b1000000) >> 6
            TS_packet.transport_priority = (packet[1] & 0b100000) >> 5
            TS_packet.PID = (packet[1] << 8 | packet[2]) & 0x01FFF
            TS_packet.TSC = (packet[3] & 0b11000000) >> 5
            TS_packet.adaptation_field_control  = (packet[3] & 0b110000) >> 4
            TS_packet.continuity_counter = (packet[3] & 0b1111)

            if log: print(f'{packet_num:010d} TS : SB={TS_packet.sync_byte} E={TS_packet.transport_error_indicator} S={TS_packet.PUSI} P={TS_packet.transport_priority} PID={TS_packet.PID:4d} TSC={TS_packet.TSC} AFC={TS_packet.adaptation_field_control} CC={TS_packet.continuity_counter:02d}')

            AFC = TS_packet.adaptation_field_control
            AFL = 0
            stuffing_bytes = 0
            if AFC == 0b10 or AFC == 0b11:
                TS_packet.adaptation_field = TSAdaptationField()

                TS_packet.adaptation_field.adaptation_field_length = packet[4]
                AFL = TS_packet.adaptation_field.adaptation_field_length 
                
                adaptation_field_flags = packet[5]
                optional_field_length = TS_packet.adaptation_field.adaptation_field_length - 1  # for the adaptation_field_flags byte
                stuffing_bytes = optional_field_length

                TS_packet.adaptation_field.discontinuity_indicator = adaptation_field_flags & 0x80
                TS_packet.adaptation_field.random_access_indicator = adaptation_field_flags & 0x40
                TS_packet.adaptation_field.stream_priority_indicator = adaptation_field_flags & 0x20

                TS_packet.adaptation_field.PCR_flag = 0
                if adaptation_field_flags & 0x10:
                    TS_packet.adaptation_field.PCR_flag = 1
                    optional_field_length -= 6
                
                TS_packet.adaptation_field.OPCR_flag = 0
                if adaptation_field_flags & 0x08:
                    TS_packet.adaptation_field.OPCR_flag = 1
                    optional_field_length -= 6
                
                TS_packet.adaptation_field.splicing_point_flag = 0
                if adaptation_field_flags & 0x04:
                    TS_packet.adaptation_field.splicing_point_flag = 1
                    optional_field_length -= 1

                TS_packet.adaptation_field.transport_private_data_flag = 0
                if adaptation_field_flags & 0x02:
                    TS_packet.adaptation_field.transport_private_data_flag = 1
                    transport_private_data_length = packet[6]
                    optional_field_length -= (1 + transport_private_data_length)

                TS_packet.adaptation_field.adaptation_field_extension_flag = 0
                if adaptation_field_flags & 0x01:
                    TS_packet.adaptation_field.adaptation_field_extension_flag = 1
                    adaptation_field_extension_length = packet[6 + optional_field_length]
                    optional_field_length -= (1 + adaptation_field_extension_length)
   
                
                TS_packet.adaptation_field.stuffing_bytes = stuffing_bytes = max(0, optional_field_length)

                if log: print(' '*10 + f' AF : L={TS_packet.adaptation_field.adaptation_field_length:3d} DC={TS_packet.adaptation_field.discontinuity_indicator} RA={TS_packet.adaptation_field.random_access_indicator} SP={TS_packet.adaptation_field.stream_priority_indicator} PR={TS_packet.adaptation_field.PCR_flag} OR={TS_packet.adaptation_field.OPCR_flag} SF={TS_packet.adaptation_field.splicing_point_flag} TP={TS_packet.adaptation_field.transport_private_data_flag} EX={TS_packet.adaptation_field.adaptation_field_extension_flag} Stuffing={TS_packet.adaptation_field.stuffing_bytes}')
            
            if AFC == 0b01:
                TS_packet.payload = parse_PES(packet[4:], log)
            elif AFC == 0b11:
                TS_packet.payload = parse_PES(packet[5 + AFL:], log)

            TS_packets.append(TS_packet)

            packet_num += 1
    
    return TS_packets

def parse_PES(payload, log=True):
    PES_packet = PESPacket()

    if payload[:3] == b'\x00\x00\x01':
        PES_packet.stream_id = payload[3]
        PES_packet.packet_length = (payload[4] << 8) | payload[5]

        if PES_packet.stream_id not in [0xBE, 0xBF]:
            PES_data_length = payload[8]

            PES_packet.data = payload[9+PES_data_length:]

            PES_packet.PTS, PES_packet.DTS = parse_PTS_DTS(payload)

            if log:
                print(' '*10 + f' PES: PSCP=1 SID={PES_packet.stream_id:3d} L={PES_packet.packet_length} PTS={PES_packet.PTS} DTS={PES_packet.DTS}')
        else:
            PES_packet.data  = b''
    
    else:
        PES_packet.data = payload
    
    return PES_packet

def parse_PTS_DTS(payload):
    PTS = DTS = None
    pts_dts_flags = (payload[7] & 0xC0) >> 6

    if pts_dts_flags == 0x2 or pts_dts_flags == 0x3:  # PTS only or PTS and DTS
        PTS = (((payload[9] >> 1) & 0x07) << 30) | (payload[10] << 22) | (((payload[11] >> 1) & 0x7F) << 15) | (payload[12] << 7) | ((payload[13] >> 1) & 0x7F)
    if pts_dts_flags == 0x3:  # PTS and DTS
        DTS = (((payload[14] >> 1) & 0x07) << 30) | (payload[15] << 22) | (((payload[16] >> 1) & 0x7F) << 15) | (payload[17] << 7) | ((payload[18] >> 1) & 0x7F)
    
    return PTS, DTS

def reassemble_stream(TS_packets, target_pid):
    stream = bytearray()
    
    for packet in TS_packets:
        if packet.PID == target_pid and packet.payload != None:
            stream.extend(packet.payload.data)
    
    return stream

def extract_stream(TS_packets, target_pid, output_filepath):
    with open(output_filepath, 'wb') as file:
        file.write(reassemble_stream(TS_packets, target_pid))
    
def reassemble_PES(TS_packets, target_pid, log=True):
    PES_packets = []
    buffer = bytes()
    packet_length = 0

    for packet_num, packet in enumerate(TS_packets):
        if packet.PID == target_pid and packet.payload != None:
            if log:
                print(f'{packet_num:010d} TS : SB={packet.sync_byte} E={packet.transport_error_indicator} S={packet.PUSI} P={packet.transport_priority} PID={packet.PID:4d} TSC={packet.TSC} AFC={packet.adaptation_field_control} CC={packet.continuity_counter:02d} Assembling Continued')
                
                if packet.adaptation_field != None:
                    print(' '*10 + f' AF : L={packet.adaptation_field.adaptation_field_length:3d} DC={packet.adaptation_field.discontinuity_indicator} RA={packet.adaptation_field.random_access_indicator} SP={packet.adaptation_field.stream_priority_indicator} PR={packet.adaptation_field.PCR_flag} OR={packet.adaptation_field.OPCR_flag} SF={packet.adaptation_field.splicing_point_flag} TP={packet.adaptation_field.transport_private_data_flag} EX={packet.adaptation_field.adaptation_field_extension_flag} Stuffing={packet.adaptation_field.stuffing_bytes}')

            if packet.PUSI:
                if log:
                    print(' '*10 + f' PES: PSCP=1 SID={packet.payload.stream_id:3d} L={packet.payload.packet_length} PTS={packet.payload.PTS} (Time={packet.payload.PTS/90000}s)')
                    print(' '*10 + f' Assembling Started')

                PES_packets.append(packet.payload)
                packet_length = packet.payload.packet_length

            else:
                buffer += packet.payload.data

                if TS_packets[packet_num+1].PUSI or packet_num + 1 > len(TS_packets):
                    print(' '*10 + f' Assembling Finished')

                    PES_packets[-1].data += buffer
                    buffer = bytes()

                    print(' '*10 + f' PES: PcktLen={PES_packets[-1].packet_length} HeadLen={PES_packets[-1].packet_length-len(PES_packets[-1].data)} DataLen={len(PES_packets[-1].data)}')

    return PES_packets
