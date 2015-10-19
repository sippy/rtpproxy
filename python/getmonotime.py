import getopt, sys

if __name__ == '__main__':
    sippy_path = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'rS:')
    except getopt.GetoptError:
        usage()

    out_realtime = False
    for o, a in opts:
        if o == '-S':
            sippy_path = a.strip()
            continue
        if o == '-r':
            out_realtime = True

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    from sippy.Time.clock_dtime import clock_getdtime, CLOCK_MONOTONIC
    if not out_realtime:
        print(clock_getdtime(CLOCK_MONOTONIC))
    else:
        from sippy.Time.clock_dtime import CLOCK_REALTIME
        print("%f %f" % (clock_getdtime(CLOCK_MONOTONIC), clock_getdtime(CLOCK_REALTIME)))
