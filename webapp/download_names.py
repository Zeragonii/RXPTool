"""Windows-safe names for RXP editable documents and encrypted imports.

The source name is informational and never affects encryption or account checks.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from urllib.parse import quote

INVALID = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')
RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
            *(f'LPT{i}' for i in range(1, 10))}


def safe_component(value: str | None, fallback: str, max_bytes: int) -> str:
    name = INVALID.sub('_', value or '')
    name = re.sub(r'\s+', ' ', name).strip(' .')
    if not name:
        name = fallback
    if name.split('.', 1)[0].upper() in RESERVED:
        name = '_' + name
    while len(name.encode('utf-8')) > max_bytes:
        name = name[:-1]
    return name.rstrip(' .') or fallback


def source_stem(filename: str | None) -> str:
    """Take the part before the FIRST !; remove an ordinary .txt extension."""
    if not isinstance(filename, str) or not filename.strip():
        return 'editable_guides'
    last_path_segment = re.split(r'[/\\]', filename)[-1]
    first = last_path_segment.split('!', 1)[0]
    if first.lower().endswith('.txt'):
        first = first[:-4]
    return safe_component(first, 'editable_guides', 120)


def editable_filename(stem: str) -> str:
    return safe_component(stem, 'editable_guides', 120) + '.txt'


def safe_timestamp(value: str | None = None) -> str:
    """Prefer a validated browser-local timestamp, otherwise use server UTC."""
    if isinstance(value, str) and re.fullmatch(r'20\d{2}-\d{2}-\d{2}_\d{2}-\d{2}', value):
        try:
            parsed = datetime.strptime(value, '%Y-%m-%d_%H-%M')
            if parsed.strftime('%Y-%m-%d_%H-%M') == value:
                return value
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M')


def encrypted_filename(stem: str, account_id: str, timestamp: str | None = None) -> str:
    # Keep normal BattleTags (including #) unchanged. Bound very long input so
    # the entire filename stays below Windows' per-component limits.
    base = safe_component(stem, 'editable_guides', 120)
    account = safe_component(account_id, 'account', 64)
    return f'{base}!{account}_{safe_timestamp(timestamp)}.txt'


def content_disposition(filename: str) -> str:
    """ASCII header for common names; RFC 5987 for Unicode filenames."""
    try:
        filename.encode('ascii')
    except UnicodeEncodeError:
        fallback = filename.encode('ascii', 'ignore').decode('ascii') or 'download.txt'
        return f'attachment; filename="{fallback}"; filename*=UTF-8\'\'{quote(filename, safe="")}'
    return f'attachment; filename="{filename}"'
