import unittest

from scanner.pipeline import execute_bounded_phase


class PipelineTests(unittest.TestCase):
    def test_exact_limit_order_and_isolated_failure(self):
        def work(value):
            if value == 2:
                raise RuntimeError("isolated")
            return value * 2
        values, omitted = execute_bounded_phase(work, [(3,), (2,), (1,)], workers=2, max_records=2)
        self.assertEqual(values[0], 6)
        self.assertIsInstance(values[1], RuntimeError)
        self.assertEqual(omitted, 1)

    def test_zero_eligible_and_invalid_limits(self):
        self.assertEqual(execute_bounded_phase(lambda: None, [], workers=1, max_records=0), ([], 0))
        with self.assertRaises(ValueError):
            execute_bounded_phase(lambda: None, [], workers=0, max_records=0)
