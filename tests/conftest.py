from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from helpers import make_link  # noqa: E402

from turbobond.config import AppConfig, LinkConfig  # noqa: E402
from turbobond.links.model import Link  # noqa: E402
from turbobond.util.cmd import clear_audit, set_dry_run  # noqa: E402


@pytest.fixture(autouse=True)
def dry_run():
    """Every test runs with the host untouched."""

    set_dry_run(True)
    clear_audit()
    yield
    set_dry_run(False)


@pytest.fixture
def cfg(tmp_path: Path) -> AppConfig:
    config = AppConfig(
        dry_run=True,
        config_dir=tmp_path / "etc",
        state_dir=tmp_path / "state",
        run_dir=tmp_path / "run",
    )
    config.links = [
        LinkConfig(name="wan1", interface="eth0", gateway="192.168.1.1", weight=3.0, uplink_mbps=100),
        LinkConfig(name="wan2", interface="eth1", gateway="192.168.2.1", weight=1.0, uplink_mbps=50),
    ]
    config.assign_table_ids()
    return config


@pytest.fixture
def links() -> list[Link]:
    return [
        make_link("wan1", link_id=1, weight=3.0, rtt_ms=20.0, uplink_mbps=100),
        make_link("wan2", link_id=2, weight=1.0, rtt_ms=30.0, uplink_mbps=50),
    ]
