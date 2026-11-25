import sys
from pathlib import Path
from datetime import date
import state

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fetcher

def test_safe_url_blocks_ftp():
    assert fetcher.safe_url("ftp://example.com/file") == ""

def test_ransomware_headline_is_cyber():
    assert fetcher.classify_title("Ransomware gang hits hospital chain") == "cyber"

def test_ai_headline():
    assert fetcher.classify_title("machine learning") == "ai"

class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def raise_for_status(self):
        pass  # pretend the request succeeded

    def json(self):
        return self._payload

def test_fetch_ctf_events_with_fake_cftime(monkeypatch):
    events = [
        {"title": "Later CTF", "start": "2026-12-05T00:00:00+00:00","url": "https://b.example"},
        {"title": "Sooner CTF", "start": "2026-12-01T00:00:00+00:00",
         "url": "javascript:alert(1)", "ctftime_url": "https://ctftime.org/event/1"}
         ]
    monkeypatch.setattr(fetcher.SESSION, "get", lambda *a, **k: FakeResponse(events))
    out = fetcher.fetch_ctf_events()

    assert [e["title"] for e in out] == ["Sooner CTF", "Later CTF"]
    assert out[0]["url"] == "https://ctftime.org/event/1"

def test_fetch_ctf_events_network_down(monkeypatch):
    def boom(*args, **kwargs):
        raise ConnectionError("network down")
    
    monkeypatch.setattr(fetcher.SESSION, "get", boom)

    assert fetcher.fetch_ctf_events() == []
    assert fetcher.source_status["CTFtime"]["state"] == "failed"

def test_sent_log_round_trip(tmp_path):
    path = str(tmp_path / "sent.json")
    today = date.today().isoformat()

    state.save_sent({"Story:abc": today}, path=path)

    assert state.load_sent(path) == {"Story:abc": today}