import sys
import time

sys.path.insert(0, "C:/Users/ItzP/omnisectester-core/tests")
from fixture_server import FixtureServer  # noqa: E402

with FixtureServer() as fix:
    print(fix.url, flush=True)
    time.sleep(120)
