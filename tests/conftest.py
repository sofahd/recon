import os
import sys

# Make the recon source tree importable (iot_tools, utils) without installing it.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
# In the multi-repo dev checkout sofahutils is a sibling repo; in CI it is pip-installed.
_sibling_sofahutils = os.path.join(os.path.dirname(__file__), "..", "..", "sofahutils")
if os.path.isdir(_sibling_sofahutils):
    sys.path.insert(0, _sibling_sofahutils)
