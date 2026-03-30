from __future__ import annotations

import argparse
import json

from common import (
    IMPROVEMENT_HOTSPOTS_FILE,
    IMPROVEMENT_SUMMARY_FILE,
    resolve_hotspot,
    reopen_hotspot,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve or reopen a tracked Cerberus hotspot.")
    parser.add_argument("--fingerprint", required=True, help="Hotspot fingerprint from improvement_hotspots.json.")
    parser.add_argument("--action", choices=("resolve", "reopen"), required=True, help="Update action.")
    parser.add_argument("--resolved-by", default="skill_maintainer", help="Actor resolving the hotspot.")
    parser.add_argument("--run-id", default="", help="Optional run id associated with the resolution.")
    parser.add_argument("--summary", default="", help="Optional hotspot summary.")
    parser.add_argument("--resolution-note", default="", help="Required when action=resolve.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.action == "resolve":
        if not args.resolution_note.strip():
            raise SystemExit("--resolution-note is required when action=resolve")
        resolve_hotspot(
            fingerprint=args.fingerprint,
            resolution_note=args.resolution_note,
            resolved_by=args.resolved_by,
            resolved_in_run_id=args.run_id or None,
            summary=args.summary or None,
        )
    else:
        reopen_hotspot(fingerprint=args.fingerprint)

    print(
        json.dumps(
            {
                "ok": True,
                "action": args.action,
                "fingerprint": args.fingerprint,
                "summary_file": str(IMPROVEMENT_SUMMARY_FILE),
                "hotspots_file": str(IMPROVEMENT_HOTSPOTS_FILE),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
