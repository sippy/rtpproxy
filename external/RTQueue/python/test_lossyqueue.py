import sys
import unittest
#from LossyQueue_debug import LossyQueue
#from LossyQueue import LossyQueue

class Dcount():
    count: int = 0

class foo():
    def __init__(self, i, dc):
        self.i = i
        self.dc = dc

    def __del__(self):
        sys.stderr.write(f'foo.__del__({self.i})\n')
        sys.stderr.flush()
        self.dc.count += 1

class TestLossyQueue(unittest.TestCase):
    from LossyQueue import LossyQueue
    lq_class = LossyQueue

    def test_queue(self):
        try:
            queue = self.lq_class(42)
        except ValueError:
            pass
        else:
            self.fail('The ValueError exception is not generated')
        queue = self.lq_class(64)
        queue.put('test')
        value = queue.get()
        self.assertEqual(value, 'test')
        dc = Dcount()
        for i in range(0, 10000):
            sys.stderr.write(f'queue.put(foo({i}))\n')
            sys.stderr.flush()
            queue.put(foo(i, dc))
        self.assertEqual(queue.get().i, 9936)
        self.assertEqual(dc.count, 9937)
        del queue
        self.assertEqual(dc.count, 10000)

class TestLossyQueueDebug(TestLossyQueue):
    from LossyQueue_debug import LossyQueue_debug
    lq_class = LossyQueue_debug

if __name__ == '__main__':
    unittest.main()
