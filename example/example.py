import ts_parser as tsp

if __name__ == '__main__':
    TS_packets = tsp.parse_TS('data/sample.ts', log=False)

    tsp.extract_stream(TS_packets, 257, 'data/PID257.mp2') # audio
    tsp.extract_stream(TS_packets, 256, 'data/PID256.264') # video

    # ffmpeg -i PID256.264 -c copy PID256.mp4
