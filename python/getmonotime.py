import getopt, sys

if __name__ == '__main__':
    sippy_path = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:S:i:o:b')
    except getopt.GetoptError:
        usage()

    for o, a in opts:
        if o == '-S':
            sippy_path = a.strip()
            continue

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    from sippy.Time.clock_dtime import clock_getdtime, CLOCK_MONOTONIC
    print clock_getdtime(CLOCK_MONOTONIC)

