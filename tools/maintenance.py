"""Maintenance CLI for Ananta.

Goals (safe by default):
- Clean up old log files on disk (retention by age).
- Archive finished scan_jobs into scan_jobs_archive (move rows).
- Clean unused/empty DB tables (optional, allowlist, dry-run default).

Usage examples (dry-run):
    python -m tools.maintenance logs-clean --days 30
    python -m tools.maintenance jobs-archive --days 14
    python -m tools.maintenance db-clean --list

Apply changes:
    python -m tools.maintenance logs-clean --days 30 --apply
    python -m tools.maintenance jobs-archive --days 14 --apply
    python -m tools.maintenance db-clean --drop-empty --apply --yes

Notes:
- Requires DATABASE_URL env var (falls back to sqlite:///./ananta.db via database.py).
- The jobs archive requires the Alembic migration that creates scan_jobs_archive.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

from sqlalchemy import MetaData, Table, func, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


DEFAULT_LOG_DIR = Path("logs")


@dataclass
class Action:
    kind: str
    description: str


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _cutoff(days: int) -> datetime:
    return _utcnow() - timedelta(days=days)


def _fmt_dt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _human_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _load_engine() -> Engine:
    # Reuse project's database engine configuration.
    from database import engine  # pylint: disable=import-error

    return engine


# -----------------------------------------------------------------------------
# LOG CLEANUP
# -----------------------------------------------------------------------------


def logs_clean(log_dir: Path, days: int, apply: bool) -> list[Action]:
    cutoff = _cutoff(days)
    actions: list[Action] = []

    if not log_dir.exists():
        actions.append(Action("noop", f"Log dir not found: {log_dir}"))
        return actions

    # Target: rotated logs, json logs, and misc large logs.
    candidates: list[Path] = []
    for pattern in ["*.log", "*.log.*", "*.json", "*.json.*", "*.txt", "*.txt.*"]:
        candidates.extend(log_dir.glob(pattern))

    for p in sorted(set(candidates)):
        try:
            st = p.stat()
        except FileNotFoundError:
            continue

        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        if mtime >= cutoff:
            continue

        actions.append(
            Action(
                "delete",
                f"Delete {p} (mtime={_fmt_dt(mtime)}, size={_human_bytes(st.st_size)})",
            )
        )
        if apply:
            try:
                p.unlink()
            except Exception as e:  # noqa: BLE001
                actions.append(Action("error", f"Failed to delete {p}: {e}"))

    if not actions:
        actions.append(Action("noop", f"No log files older than {days} days in {log_dir}"))

    return actions


# -----------------------------------------------------------------------------
# JOB ARCHIVE
# -----------------------------------------------------------------------------


def _table_exists(engine: Engine, table_name: str) -> bool:
    insp = inspect(engine)
    return table_name in insp.get_table_names()


def jobs_archive(engine: Engine, days: int, apply: bool, batch_size: int = 500) -> list[Action]:
    """Move finished scan jobs into scan_jobs_archive.

    We only archive statuses that are terminal.

    Implementation is SQL-first to support both Postgres and SQLite.
    """

    actions: list[Action] = []

    if not _table_exists(engine, "scan_jobs"):
        actions.append(Action("noop", "scan_jobs table not found; nothing to archive"))
        return actions

    if not _table_exists(engine, "scan_jobs_archive"):
        actions.append(
            Action(
                "error",
                "scan_jobs_archive table not found. Run Alembic migration first.",
            )
        )
        return actions

    cutoff = _cutoff(days)

    # Use ORM for portability (SQLite/Postgres) and safety.
    from database import ScanJob, ScanJobArchive, SessionLocal  # pylint: disable=import-error

    session: Session = SessionLocal()
    try:
        q = (
            session.query(ScanJob)
            .filter(ScanJob.status.in_(["COMPLETED", "FAILED"]))
            .filter(func.coalesce(ScanJob.updated_at, ScanJob.created_at) < cutoff)
            .order_by(ScanJob.id.asc())
        )
        count = q.count()

        actions.append(Action("info", f"Found {count} scan_jobs to archive (cutoff={_fmt_dt(cutoff)})"))
        if count == 0:
            return actions

        if not apply:
            actions.append(Action("dry-run", "No changes applied (use --apply to move rows)"))
            return actions

        moved_total = 0
        archived_at = _utcnow()

        while True:
            batch = q.limit(batch_size).all()
            if not batch:
                break

            for job in batch:
                session.add(
                    ScanJobArchive(
                        original_scan_job_id=job.id,
                        job_id=job.job_id,
                        query=job.query,
                        report_type=job.report_type,
                        status=job.status,
                        progress=job.progress,
                        result=job.result,
                        error_message=job.error_message,
                        created_at=job.created_at,
                        updated_at=job.updated_at,
                        archived_at=archived_at,
                    )
                )
                session.delete(job)

            session.commit()
            moved_total += len(batch)

        actions.append(Action("apply", f"Archived {moved_total} scan_jobs rows"))
        return actions
    finally:
        session.close()


# -----------------------------------------------------------------------------
# DB CLEAN (DROP EMPTY TABLES)
# -----------------------------------------------------------------------------


ALLOWLIST_DROP_IF_EMPTY = {
    # The TODO list in TODOS.md (only if empty).
    "sources",
    "tool_execution_logs",
    "scan_sessions",
    "pending_approvals",
    "findings",
    "entity_reports",
    "entities",
    "api_keys",
}


def _count_rows(engine: Engine, table_name: str) -> Optional[int]:
    if table_name not in ALLOWLIST_DROP_IF_EMPTY or not _table_exists(engine, table_name):
        return None
    with engine.begin() as conn:
        try:
            table = Table(table_name, MetaData(), autoload_with=conn)
            statement = select(func.count()).select_from(table)
            return int(conn.execute(statement).scalar_one())
        except Exception:
            return None


def db_clean(
    engine: Engine,
    list_only: bool,
    drop_empty: bool,
    apply: bool,
    assume_yes: bool,
    tables: Optional[list[str]] = None,
) -> list[Action]:
    actions: list[Action] = []

    selected = set(tables or [])

    if not selected:
        selected = set(ALLOWLIST_DROP_IF_EMPTY)

    # Ensure allowlist only
    selected = {t for t in selected if t in ALLOWLIST_DROP_IF_EMPTY}

    if not selected:
        actions.append(Action("error", "No valid tables selected (allowlist enforced)"))
        return actions

    # Report counts
    counts: dict[str, Optional[int]] = {t: _count_rows(engine, t) for t in sorted(selected)}
    for t, c in counts.items():
        if c is None:
            actions.append(Action("info", f"{t}: not found"))
        else:
            actions.append(Action("info", f"{t}: {c} rows"))

    if list_only:
        return actions

    if not drop_empty:
        actions.append(Action("noop", "Nothing to do (pass --drop-empty to drop empty tables)"))
        return actions

    to_drop = [t for t, c in counts.items() if c == 0]

    # Respect basic FK dependencies (e.g., findings -> entities)
    drop_priority = ["findings", "entities"]
    to_drop.sort(key=lambda t: drop_priority.index(t) if t in drop_priority else 999)
    if not to_drop:
        actions.append(Action("noop", "No empty tables eligible for drop"))
        return actions

    if not apply:
        for t in to_drop:
            actions.append(Action("dry-run", f"Would DROP TABLE {t} (empty)"))
        actions.append(Action("dry-run", "No changes applied (use --apply)"))
        return actions

    if not assume_yes:
        actions.append(
            Action(
                "error",
                "Refusing to drop tables without --yes (safety).",
            )
        )
        return actions

    with engine.begin() as conn:
        for t in to_drop:
            actions.append(Action("apply", f"DROP TABLE {t}"))
            table = Table(t, MetaData(), autoload_with=conn)
            table.drop(bind=conn, checkfirst=True)

    return actions


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def _print_actions(actions: Iterable[Action]) -> None:
    for a in actions:
        print(f"[{a.kind}] {a.description}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ananta-maintenance")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_logs = sub.add_parser("logs-clean", help="Delete log files older than N days")
    p_logs.add_argument("--days", type=int, default=30)
    p_logs.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR))
    p_logs.add_argument("--apply", action="store_true", help="Actually delete files")

    p_jobs = sub.add_parser("jobs-archive", help="Move completed/failed scan_jobs to archive table")
    p_jobs.add_argument("--days", type=int, default=14)
    p_jobs.add_argument("--batch-size", type=int, default=500)
    p_jobs.add_argument("--apply", action="store_true")

    p_db = sub.add_parser("db-clean", help="Inspect and optionally drop empty unused tables")
    p_db.add_argument("--list", action="store_true", help="Only list row counts")
    p_db.add_argument("--drop-empty", action="store_true")
    p_db.add_argument("--apply", action="store_true")
    p_db.add_argument("--yes", action="store_true", help="Assume yes (required to actually drop)")
    p_db.add_argument(
        "--tables",
        nargs="+",
        default=None,
        help=f"Subset of tables (allowlist): {', '.join(sorted(ALLOWLIST_DROP_IF_EMPTY))}",
    )

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "logs-clean":
        actions = logs_clean(Path(args.log_dir), days=args.days, apply=args.apply)
        _print_actions(actions)
        return 0

    engine = _load_engine()

    if args.cmd == "jobs-archive":
        actions = jobs_archive(engine, days=args.days, apply=args.apply, batch_size=args.batch_size)
        _print_actions(actions)
        return 0

    if args.cmd == "db-clean":
        actions = db_clean(
            engine,
            list_only=args.list,
            drop_empty=args.drop_empty,
            apply=args.apply,
            assume_yes=args.yes,
            tables=args.tables,
        )
        _print_actions(actions)
        return 0

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
