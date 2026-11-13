import hmac
from app.auth import authenticate_key, create_client_key
from app.database import Database

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"

def test_dummy_hmac_called_for_non_existent_client(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "timing.sqlite3"))
    db.init()
    
    calls = []
    original_compare = hmac.compare_digest
    def spy_compare(a, b):
        calls.append((a, b))
        return original_compare(a, b)
    
    monkeypatch.setattr(hmac, "compare_digest", spy_compare)
    
    # Non-existent client_id
    res = authenticate_key(db, PEPPER, "gw_0000000000000000.random-token-value-here-1234567890123")
    assert res is None
    assert len(calls) == 1, "hmac.compare_digest must be called even when client does not exist to equalize timing"
