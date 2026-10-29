from dataclasses import replace
import unittest

from portable_fleet.core import Refusal
from portable_fleet.supervision import Observation, Supervisor, expired


class SupervisionTests(unittest.TestCase):
    def supervisor(self):
        obj = Supervisor("fixture-account")
        obj.observe(Observation("fixture-account", 1, 1000, 80, "window-1"), 1000)
        return obj

    def test_loss_supervisor_and_jitter_stop_target(self):
        permit = self.supervisor().permit(1000, 50, "boot-seat")
        self.assertFalse(expired(permit, 1089, 139, "boot-seat"))
        self.assertTrue(expired(permit, 1090.2, 140.2, "boot-seat"))
        self.assertLessEqual(90 + .2 + 5, 100)

    def test_fractional_wall_clock_roundoff_does_not_stop_fresh_permit(self):
        # Catches early stop at a renewal when epoch subtraction rounds above 90.
        wall, mono = 1793161057.051254, 108879.312
        obj = Supervisor("fixture-account")
        obj.observe(Observation("fixture-account", 1, wall, 80, "window"), wall)
        self.assertFalse(expired(obj.permit(wall, mono, "scope"), wall + .01, mono + .01, "scope"))

    def test_renewals_never_refresh_old_observation(self):
        obj = self.supervisor()
        for delta in range(0, 300, 30):
            obj.observe(obj.observation, 1000 + delta)
            permit = obj.permit(1000 + delta, 50 + delta, "scope")
            self.assertLessEqual(permit["expires_wall"], 1300)
        self.assertTrue(expired(permit, 1300.2, 350.2, "scope"))
        with self.assertRaises(Refusal):
            obj.permit(1300, 350, "scope")
        self.assertLessEqual(300 + .2 + 5, 310)

    def test_zero_reset_parse_bad_account_and_restart_hold(self):
        for observation in (None, Observation("other", 2, 1001, 50, "window-1"),
                            Observation("fixture-account", 2, 1001, 0, "window-1"),
                            Observation("fixture-account", 2, 1001, 90, "window-1"),
                            Observation("fixture-account", 2, 1001, 50, "window-2"),
                            Observation("fixture-account", 1, 1001, 50, "window-1"),
                            Observation("fixture-account", 2, float("nan"), 50, "window-1")):
            obj = self.supervisor()
            with self.subTest(observation=observation), self.assertRaises(Refusal):
                obj.observe(observation, 1001)
            with self.assertRaises(Refusal):
                obj.permit(1001, 51, "scope")

    def test_clocks_suspend_resume_boot_and_invalid_permit(self):
        permit = self.supervisor().permit(1000, 50, "scope")
        for wall, mono, scope in ((999, 51, "scope"), (1010, 51, "scope"), (1400, 51, "scope"),
                                   (1400, 450, "scope"), (1001, 51, "new-boot")):
            with self.subTest(wall=wall, mono=mono):
                self.assertTrue(expired(permit, wall, mono, scope))
        self.assertTrue(expired({}, 1000, 50, "scope"))

    def test_threshold_warning_and_fresh_observation(self):
        obj = self.supervisor()
        obj.observe(Observation("fixture-account", 2, 1240, 14, "window-1"), 1240)
        permit = obj.permit(1240, 290, "scope")
        self.assertTrue(permit["warning"])
        self.assertEqual(permit["expires_wall"], 1330)
