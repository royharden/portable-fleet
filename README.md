# Portable Fleet

Experimental Python 3.11+ standard-library building blocks for explicit profiles,
immutable source packages, journaled operations, Windows owned process families,
bounded supervision, provider-usage admission and sequential project transfer.

This snapshot contains generic product code and tests. It installs no scheduler,
network listener, credentials, agent login or automatic production admission.
Native process/console integrations require Windows and separately supplied,
verified public console adapters. Account identity is operator-attested; unmanaged
seats, hostile same-user behavior, suspended kernels and provider work already
issued remain outside the local enforcement guarantees.

Run a small platform-independent check from this directory:

```sh
python -B -m unittest discover -s tests -p test_core.py -v
python -B -m portable_fleet --help
```

Windows family/guard/provider tests require fresh retained fixture directories
through PF_FAMILY_TEST_ROOT, PF_GUARD_TEST_ROOT and PF_PROVIDER_TEST_ROOT.
The full observation-window fixture waits for an actual five-minute window.
Several other tests create and clean their own temporary fixtures.

PROJECTION.json records the exact exported file hashes and source revision.
Host-specific operations, private plans, credentials and execution receipts are
excluded. No external skill or console implementation is bundled. No license
grant for external dependencies is implied by this source snapshot.
