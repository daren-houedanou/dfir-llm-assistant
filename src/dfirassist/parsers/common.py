from __future__ import annotations

from datetime import UTC, datetime


def parse_ts(value: str | float | int | None, default_year: int | None = None) -> datetime | None:
    """Parse the timestamp formats emitted by common forensic tools into aware UTC datetimes."""
    if value in (None, "", "-"):
        return None
    if isinstance(value, int | float) or (isinstance(value, str) and _is_number(value)):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # evtx_dump emits up to 7 fractional digits; Python accepts at most 6.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(ch for ch in tail if ch.isdigit())
        rest = tail[len(digits) :]
        text = f"{head}.{digits[:6]}{rest}"
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    for fmt in ("%m/%d/%Y %H:%M:%S", "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            if fmt == "%b %d %H:%M:%S":  # classic syslog has no year: prepend one before parsing
                year = default_year or datetime.now(UTC).year
                return datetime.strptime(f"{year} {text}", f"%Y {fmt}").replace(tzinfo=UTC)
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def _is_number(text: str) -> bool:
    try:
        float(text)
        return True
    except ValueError:
        return False
