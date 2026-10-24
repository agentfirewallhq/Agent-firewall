import os
import sys
import tempfile

# The app reads its API key and DB path at import time, so both are
# set here before any test module imports main or the stores.
os.environ.setdefault("AGENT_FIREWALL_API_KEY", "test-key-change-me")
os.environ["AGENT_FIREWALL_DB"] = os.path.join(tempfile.gettempdir(), "af_pytest_main.db")
if os.path.exists(os.environ["AGENT_FIREWALL_DB"]):
    os.remove(os.environ["AGENT_FIREWALL_DB"])

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
