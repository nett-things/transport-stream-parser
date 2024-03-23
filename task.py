from functools import partial

PACKET_SIZE = 188

packet_num = 0
with open('example_new.ts', mode='rb') as video:
    for packet in iter(partial(video.read, PACKET_SIZE), b''):
        SB = packet[0]
        E = (packet[1] & 0b10000000) >> 7
        S = (packet[1] & 0b1000000) >> 6
        P = (packet[1] & 0b100000) >> 5
        PID = (packet[1] << 8 | packet[2]) & 0x01FFF
        TSC = (packet[3] & 0b11000000) >> 5
        AFC = (packet[3] & 0b110000) >> 4
        CC = (packet[3] & 0b1111)

        print(f'{packet_num:010d} TS: SB={SB} E={E} S={S} P={P} PID={PID:4d} TSC={TSC} AFC={AFC} CC={CC:02d}')
        print(len(packet))
        packet_num += 1
        