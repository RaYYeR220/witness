import json
import os
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


@pytest.fixture(scope="session")
def regen() -> Callable[[str], bool]:
    """Whether to rewrite vectors/<name>.json: WITNESS_REGEN_VECTORS is "1" (or "all") for
    every file, or a comma list of names, e.g. "bundles,envelopes". Files that do not exist
    yet are always written."""
    raw = os.environ.get("WITNESS_REGEN_VECTORS", "")
    wanted = {part.strip().removesuffix(".json") for part in raw.split(",") if part.strip()}

    def asked(name: str) -> bool:
        return not (VECTOR_DIR / f"{name}.json").exists() or bool(wanted & {"1", "all", name})

    return asked
