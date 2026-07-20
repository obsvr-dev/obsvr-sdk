"""Single source of truth for the SDK version.

Consumed by obsvr/__init__.py (``__version__``), obsvr/remote.py (the
X-Obsvr-Sdk wire header + signed-event sdk_version stamp), and
pyproject.toml (setuptools dynamic version). Kept as a leaf module with
no imports so neither consumer can create a cycle.
"""

__version__ = "0.10.0"
