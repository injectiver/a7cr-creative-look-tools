"""Run host tests; all device protocols are mocked and private fixtures skip."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/"device"), str(ROOT/"offline")]


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([loader.discover(str(ROOT/"device"), pattern="test_*.py"),
                               loader.discover(str(ROOT/"tests"), pattern="test_*.py", top_level_dir=str(ROOT))])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {"schema":"a7cr-public-host-tests/1", "run":result.testsRun,
        "skipped":len(result.skipped), "failures":len(result.failures), "errors":len(result.errors),
        "successful":result.wasSuccessful(), "camera_opened":False,
        "note":"Private per-body integration fixtures are deliberately excluded. Skipped tests are not passes."}
    from tools.project_paths import runtime_root
    path = runtime_root(ROOT)/"private/validation/public-host-tests.private.json"
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(summary,indent=2)+"\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
