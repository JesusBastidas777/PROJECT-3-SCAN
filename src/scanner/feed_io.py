"""Atomic JSON and record-oriented NDJSON feed output."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from collections.abc import Iterator, Mapping
from typing import Any

from scanner.contract import canonical_json
from scanner.feed import validate_feed


def iter_feed_ndjson(feed: Mapping[str, Any]) -> Iterator[str]:
    envelope={key:value for key,value in feed.items() if key not in {"asset_summaries","endpoint_observations"}}
    yield canonical_json({"record_type":"feed","value":envelope})+"\n"
    for item in feed["asset_summaries"]: yield canonical_json({"record_type":"asset","value":item})+"\n"
    for item in feed["endpoint_observations"]: yield canonical_json({"record_type":"endpoint","value":item})+"\n"


def write_feed(feed: Mapping[str,Any],destination: str|Path,*,format_name: str) -> None:
    validate_feed(feed)
    if format_name not in {"json","ndjson"}: raise ValueError("invalid feed format")
    chunks=(iter([canonical_json(feed)+"\n"]) if format_name=="json" else iter_feed_ndjson(feed))
    if str(destination)=="-":
        for chunk in chunks: sys.stdout.write(chunk)
        return
    path=Path(destination); path.parent.mkdir(parents=True,exist_ok=True); temporary=None
    try:
        with tempfile.NamedTemporaryFile("w",encoding="utf-8",newline="\n",dir=path.parent,prefix=f".{path.name}.",suffix=".tmp",delete=False) as handle:
            temporary=Path(handle.name)
            for chunk in chunks: handle.write(chunk)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary,path); temporary=None
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)
