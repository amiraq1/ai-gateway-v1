from app.auth import authenticate_key, create_client_key
from app.database import Database

def test_forged_key_for_existing_client_fails(tmp_path):
    db = Database(str(tmp_path / "forged.sqlite3"))
    db.init()
    pepper = "test-pepper-that-is-at-least-32-bytes-long"
    client_id, valid_key = create_client_key(db, pepper, "test-client")
    
    forged_key = f"gw_{client_id}.forged-secret-not-matching-digest-123456"
    assert authenticate_key(db, pepper, forged_key) is None
