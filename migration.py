"""
migration.py – database-agnostische schema-migraties.

Werkt met zowel SQLite als PostgreSQL.
• SQLite  → try/except per statement (rollback bij fout)
• PostgreSQL → controleert information_schema vóór ALTER TABLE

Voeg nieuwe kolommen toe als dicts in COLUMN_MIGRATIONS:
    {"table": "items", "column": "category", "type": "VARCHAR"}

Gebruik altijd "TIMESTAMP" (niet DATETIME) en "BOOLEAN DEFAULT false"
(niet BOOLEAN DEFAULT 0) — deze werken op beide engines.
"""

import random
import string
from sqlalchemy import text


# ─── Schema-uitbreidingen ──────────────────────────────────────────────────
# Volgorde is belangrijk: later toegevoegde kolommen staan onderaan.
COLUMN_MIGRATIONS = [
    # Feature 1 – terugbrengdatum
    {"table": "borrow_requests", "column": "return_by",       "type": "TIMESTAMP"},
    # Feature 3 – groepsuitnodigingscode
    {"table": "groups",          "column": "invite_code",     "type": "VARCHAR(8)"},
    # Feature 5 – categorie & toestand
    {"table": "items",           "column": "category",        "type": "VARCHAR"},
    {"table": "items",           "column": "condition",       "type": "VARCHAR"},
    # Feature 5 – max uitleentermijn
    {"table": "items",           "column": "max_borrow_days", "type": "INTEGER"},
    # Feature 6 – schademelding
    {"table": "borrow_requests", "column": "has_damage",      "type": "BOOLEAN DEFAULT false"},
    {"table": "borrow_requests", "column": "damage_note",     "type": "VARCHAR"},
    # Feature 6 – overdue-tracker
    {"table": "borrow_requests", "column": "overdue_notif_days", "type": "INTEGER DEFAULT 0"},
    # Feature 7 – vergeten PIN
    {"table": "users",           "column": "reset_token",         "type": "VARCHAR"},
    {"table": "users",           "column": "reset_token_expires",  "type": "TIMESTAMP"},
    # Gratis-item expiry
    {"table": "items",           "column": "listed_at",       "type": "TIMESTAMP"},
    # Borrow blocking – persoonlijk overdue-limiet
    {"table": "users",           "column": "max_overdue_allowed", "type": "INTEGER"},
]


def run_migrations(engine):
    """Voer alle column-migraties uit op de opgegeven engine."""
    url = str(engine.url)
    is_pg = "postgresql" in url or "postgres" in url

    with engine.connect() as conn:
        for m in COLUMN_MIGRATIONS:
            _add_column(conn, m["table"], m["column"], m["type"], is_pg)

    _seed_group_invite_codes(engine)


# ─── Intern ───────────────────────────────────────────────────────────────

def _add_column(conn, table: str, column: str, col_type: str, is_pg: bool):
    if is_pg:
        _add_column_pg(conn, table, column, col_type)
    else:
        _add_column_sqlite(conn, table, column, col_type)


def _add_column_pg(conn, table: str, column: str, col_type: str):
    """PostgreSQL: controleer information_schema vóór toevoegen."""
    try:
        result = conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column})
        if result.fetchone():
            return  # kolom bestaat al
        conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {col_type}'))
        conn.commit()
    except Exception as exc:
        print(f"[MIGRATION PG] Fout bij {table}.{column}: {exc}")
        try:
            conn.rollback()
        except Exception:
            pass


def _add_column_sqlite(conn, table: str, column: str, col_type: str):
    """SQLite: try/except (geen IF NOT EXISTS vóór 3.37)."""
    # SQLite accepteert geen BOOLEAN DEFAULT false — zet om naar INTEGER DEFAULT 0
    sqlite_type = col_type.replace("BOOLEAN DEFAULT false", "INTEGER DEFAULT 0") \
                          .replace("TIMESTAMP", "DATETIME")
    try:
        conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {sqlite_type}'))
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass


def _seed_group_invite_codes(engine):
    """Genereer invite codes voor groepen die er nog geen hebben."""
    def _gen():
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    with engine.connect() as conn:
        try:
            result = conn.execute(text("SELECT id, invite_code FROM groups"))
            rows = result.fetchall()
            for row in rows:
                gid, code = row[0], row[1]
                if not code:
                    conn.execute(
                        text("UPDATE groups SET invite_code = :code WHERE id = :id"),
                        {"code": _gen(), "id": gid}
                    )
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
