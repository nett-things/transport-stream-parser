import ts_parser as tsp

if __name__ == '__main__':
    TS_packets = tsp.parse_TS('data/example_new.ts', log=False)

    tsp.extract_stream(TS_packets, 136, 'data/PID136.mp2') # audio
    tsp.extract_stream(TS_packets, 174, 'data/PID174.264') # video

    # ffmpeg -i PID174.264 -c copy PID174.mp4
