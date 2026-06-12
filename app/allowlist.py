from datetime import datetime, timedelta, timezone


def utc_now():
    return datetime.now(timezone.utc)


def is_allowlisted(conn, ip_address):
    if not ip_address:
        return False

    now = utc_now().isoformat()
    row = conn.execute(
        """
        SELECT id FROM allowlist
        WHERE ip_address = ?
          AND status = 'active'
          AND (start_time IS NULL OR start_time <= ?)
          AND (expiry_time IS NULL OR expiry_time >= ?)
        LIMIT 1
        """,
        (ip_address, now, now),
    ).fetchone()
    return row is not None


def add_allowlist_entry(conn, ip_address, duration_minutes, reason=None, added_by="dashboard"):
    now = utc_now()
    expiry = now + timedelta(minutes=duration_minutes)
    cur = conn.execute(
        """
        INSERT INTO allowlist (
          ip_address, reason, added_by, start_time, expiry_time, status, notes
        )
        VALUES (?, ?, ?, ?, ?, 'active', ?)
        """,
        (
            ip_address,
            reason,
            added_by,
            now.isoformat(),
            expiry.isoformat(),
            f"Dashboard allowlist for {duration_minutes} minutes",
        ),
    )
    conn.commit()
    return cur.lastrowid


def deactivate_allowlist_entry(conn, entry_id):
    cur = conn.execute(
        "UPDATE allowlist SET status = 'inactive' WHERE id = ?",
        (entry_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def list_allowlist_entries(conn, limit=50):
    now = utc_now()
    rows = conn.execute(
        """
        SELECT id, ip_address, reason, added_by, start_time, expiry_time, status, notes, created_at
        FROM allowlist
        WHERE status = 'active'
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    entries = []
    for row in rows:
        entry = dict(row)
        expiry_time = entry.get("expiry_time")
        if expiry_time:
            expiry = datetime.fromisoformat(expiry_time)
            if expiry < now:
                entry["effective_status"] = "expired"
                entry["remaining_seconds"] = 0
            else:
                entry["effective_status"] = "active"
                entry["remaining_seconds"] = int((expiry - now).total_seconds())
        else:
            entry["effective_status"] = "active"
            entry["remaining_seconds"] = None
        entries.append(entry)

    return entries
