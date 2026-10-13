import os
import sys
import importlib
import logging
from datetime import datetime
from sqlalchemy import text
from db.database import engine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("db.migrations")

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "versions")

def init_migration_table():
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(64) PRIMARY KEY,
                applied_at DATETIME NOT NULL,
                description VARCHAR(255)
            );
        """))

def get_applied_migrations():
    init_migration_table()
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version FROM schema_migrations ORDER BY version ASC"))
        return [row[0] for row in result.fetchall()]

def get_available_migrations():
    if not os.path.exists(MIGRATIONS_DIR):
        return []
    files = [f for f in os.listdir(MIGRATIONS_DIR) if f.startswith("v") and f.endswith(".py")]
    files.sort()
    migrations = []
    for f in files:
        mod_name = f[:-3]
        version_id = mod_name
        migrations.append((version_id, f))
    return migrations

def run_migrations():
    """
    Applies any pending migrations in sequential order inside transactions.
    """
    init_migration_table()
    applied = set(get_applied_migrations())
    available = get_available_migrations()

    applied_count = 0
    for version_id, filename in available:
        if version_id not in applied:
            logger.info(f"Applying migration: {version_id} ({filename})...")
            
            # Dynamically import migration module
            mod = importlib.import_module(f"db.migrations.versions.{version_id}")
            if not hasattr(mod, "upgrade"):
                raise RuntimeError(f"Migration {version_id} is missing 'upgrade(engine)' function.")

            # Execute migration in transaction
            with engine.begin() as conn:
                mod.upgrade(conn)
                desc = getattr(mod, "DESCRIPTION", "Schema migration")
                conn.execute(
                    text("INSERT INTO schema_migrations (version, applied_at, description) VALUES (:v, :t, :d)"),
                    {"v": version_id, "t": datetime.utcnow(), "d": desc}
                )

            logger.info(f"Successfully applied migration: {version_id}")
            applied_count += 1

    return applied_count

if __name__ == "__main__":
    count = run_migrations()
    print(f"Migrations run completed. {count} new migrations applied.")
