#!/usr/bin/env python3
# Claim one line from an immutable job queue. Each worker opens its own
# cursor descriptor; flock serializes cursor updates across processes.

import fcntl
import os
import sys


def take(queue):
    fd = os.open(queue + '.pos', os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'r+') as cursor:
        fcntl.flock(cursor, fcntl.LOCK_EX)
        offset = int(cursor.read() or '0')
        with open(queue, 'rb') as jobs:
            jobs.seek(offset)
            job = jobs.readline()
            if not job:
                return b''
            cursor.seek(0)
            cursor.write(str(jobs.tell()))
            cursor.truncate()
            # Publish the offset before releasing the lock on close.
            cursor.flush()
        return job


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: glitch_queue.py QUEUE')
    sys.stdout.buffer.write(take(sys.argv[1]))
