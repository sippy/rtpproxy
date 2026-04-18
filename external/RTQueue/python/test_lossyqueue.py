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

    def test_put_many(self):
        queue = self.lq_class(4)

        queue.put_many([1, 2, 3])
        self.assertEqual(queue.get(), 1)
        self.assertEqual(queue.get(), 2)
        self.assertEqual(queue.get(), 3)
        self.assertIsNone(queue.get())

        queue.put_many([4, 5, 6, 7])
        self.assertEqual(queue.get(), 4)
        self.assertEqual(queue.get(), 5)
        self.assertEqual(queue.get(), 6)
        self.assertEqual(queue.get(), 7)
        self.assertIsNone(queue.get())

        queue.put_many(iter([10, 11, 12]))
        self.assertEqual(queue.get(), 10)
        self.assertEqual(queue.get(), 11)
        self.assertEqual(queue.get(), 12)
        self.assertIsNone(queue.get())

        with self.assertRaises(ValueError):
            queue.put_many([13, 14, 15, 16, 17])

class TestLossyQueueDebug(TestLossyQueue):
    from LossyQueue_debug import LossyQueue_debug
    lq_class = LossyQueue_debug

if __name__ == '__main__':
    unittest.main()
