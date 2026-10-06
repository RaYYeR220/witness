import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

VECTOR_DIR = Path(__file__).parent / "vectors"


@pytest.fixture(scope="session")
def vectors() -> Callable[[str], Any]:
    def load(name: str) -> Any:
        return json.loads((VECTOR_DIR / f"{name}.json").read_text(encoding="utf-8"))

    return load
