import os
import pytest
from pathlib import Path

# Always run tests from the project root so relative paths in config.py resolve correctly
@pytest.fixture(autouse=True, scope="session")
def set_project_root():
    root = Path(__file__).parent.parent
    os.chdir(root)
