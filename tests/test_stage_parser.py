import unittest

from kad_stage_parser import parse_case_state, parse_instance_name


def set_eq(a, b):
    return set(a) == set(b)


class StageParserTests(unittest.TestCase):
    def test_case_state_first(self):
        r = parse_case_state("Рассматривается в первой инстанции")
        self.assertEqual(r["lifecycle"], "ACTIVE")
        self.assertTrue(set_eq(r["activeStages"], ["FIRST"]))

    def test_case_state_appeal(self):
        r = parse_case_state("Рассматривается в апелляционной инстанции")
        self.assertTrue(set_eq(r["activeStages"], ["APPEAL"]))

    def test_case_state_cassation(self):
        r = parse_case_state("Рассматривается в кассационной инстанции")
        self.assertTrue(set_eq(r["activeStages"], ["CASSATION"]))

    def test_case_state_multi(self):
        r = parse_case_state("Рассматривается в первой и апелляционной инстанциях")
        self.assertTrue(set_eq(r["activeStages"], ["FIRST", "APPEAL"]))

    def test_case_state_finished(self):
        r = parse_case_state("Рассмотрение дела завершено")
        self.assertEqual(r["lifecycle"], "FINISHED")
        self.assertEqual(r["activeStages"], [])

    def test_instance_first(self):
        r = parse_instance_name("Первая инстанция")
        self.assertEqual(r["stage"], "FIRST")
        self.assertEqual(r["confidence"], "HIGH")

    def test_instance_appeal(self):
        r = parse_instance_name("Апелляционная инстанция")
        self.assertEqual(r["stage"], "APPEAL")
        self.assertEqual(r["confidence"], "HIGH")

    def test_instance_cassation(self):
        r = parse_instance_name("Кассационная инстанция")
        self.assertEqual(r["stage"], "CASSATION")
        self.assertEqual(r["confidence"], "HIGH")


if __name__ == "__main__":
    unittest.main()

