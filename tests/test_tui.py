from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.widgets import DataTable  # noqa: E402

from dfirassist import parsers  # noqa: E402
from dfirassist.assistant import Investigation  # noqa: E402
from dfirassist.llm import LLMClient, MockBackend, Settings  # noqa: E402
from dfirassist.tui import DfirApp  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


async def test_tui_loads_and_summarizes():
    inv = Investigation(
        parsers.load([SAMPLES / "win-rdp-intrusion"]),
        LLMClient(Settings(backend="mock"), backend=MockBackend()),
    )
    app = DfirApp(inv)
    async with app.run_test(size=(160, 48)) as pilot:
        assert app.query_one("#findings", DataTable).row_count == len(inv.findings)
        await pilot.press("f")
        await pilot.pause()
        assert app.query_one("#events", DataTable).row_count > 0
        await pilot.press("s")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "malicious" in app.last_answer
