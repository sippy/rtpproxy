import getopt, sys

if __name__ == '__main__':
    sippy_path = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'rS:C:')
    except getopt.GetoptError:
        usage()

    out_realtime = False
    clock_name = 'CLOCK_MONOTONIC'
    for o, a in opts:
        if o == '-S':
            sippy_path = a.strip()
            continue
        if o == '-r':
            out_realtime = True
            continue
        if o == '-C':
            clock_name = a.strip()
            continue

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    exec('from sippy.Time.clock_dtime import clock_getdtime, %s' % clock_name)
    if not out_realtime:
        print(clock_getdtime(eval(clock_name)))
    else:
        from sippy.Time.clock_dtime import CLOCK_REALTIME
        print("%f %f" % (clock_getdtime(eval(clock_name)), clock_getdtime(CLOCK_REALTIME)))
