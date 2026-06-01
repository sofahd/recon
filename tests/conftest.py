import os
import sys

# Make the recon source tree importable (iot_tools, utils) without installing it.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
