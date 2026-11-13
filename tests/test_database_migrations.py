from app.database import Database
from app.auth import create_client_key

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"

def test_database_has_schema_version_1(tmp_path):
    db_path = str(tmp_path / "versioned.sqlite3")
    db = Database(db_path)
    db.init()
    assert hasattr(db, "get_version"), "Database must have get_version method"
    assert db.get_version() == 1, "Initial schema version must be 1"

def test_migration_preserves_existing_data(tmp_path):
    db_path = str(tmp_path / "preserve.sqlite3")
    db = Database(db_path)
    db.init()
    client_id, _ = create_client_key(db, PEPPER, "existing-client", 60)
    
    # Re-init / re-migrate should preserve client
    db.init()
    assert db.get_version() == 1
    clients = db.list_clients()
    assert len(clients) == 1
    assert clients[0]["client_id"] == client_id
