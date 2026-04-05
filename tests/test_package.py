from __future__ import annotations

import secagents


def test_version_defined() -> None:
    assert secagents.__version__
    parts = secagents.__version__.split(".")
    assert len(parts) >= 2
