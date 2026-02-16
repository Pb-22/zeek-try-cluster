import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional


def _read_zeek_log(path: Path) -> Tuple[List[str], List[str], List[List[str]]]:
    header_lines: List[str] = []
    fields: List[str] = []
    rows: List[List[str]] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#"):
                header_lines.append(line)
                if line.startswith("#fields"):
                    parts = line.split("\t")
                    fields = parts[1:]
                continue
            if not line:
                continue
            rows.append(line.split("\t"))

    return header_lines, fields, rows


def _ts_index(fields: List[str]) -> Optional[int]:
    try:
        return fields.index("ts")
    except ValueError:
        return None


def merge_worker_logs(workers_dir: Path, merged_dir: Path) -> None:
    merged_dir.mkdir(parents=True, exist_ok=True)

    per_log: Dict[str, List[Path]] = {}
    for w in sorted(workers_dir.glob("worker*")):
        logs_dir = w / "logs"
        if not logs_dir.exists():
            continue
        for lp in sorted(logs_dir.glob("*.log")):
            per_log.setdefault(lp.name, []).append(lp)

    for log_name, paths in per_log.items():
        first_header, first_fields, _ = _read_zeek_log(paths[0])
        ts_i = _ts_index(first_fields)

        all_rows: List[List[str]] = []
        for p in paths:
            _, fields, rows = _read_zeek_log(p)
            # Best-effort merge even if field sets differ.
            if fields != first_fields:
                all_rows.extend(rows)
            else:
                all_rows.extend(rows)

        if ts_i is not None:
            def _ts_val(r: List[str]) -> float:
                if ts_i >= len(r):
                    return 0.0
                try:
                    return float(r[ts_i])
                except Exception:
                    return 0.0
            all_rows.sort(key=_ts_val)

        out_path = merged_dir / log_name
        with out_path.open("w", encoding="utf-8") as out:
            for h in first_header:
                out.write(h + "\n")
            for r in all_rows:
                out.write("\t".join(r) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers-dir", required=True)
    ap.add_argument("--merged-dir", required=True)
    args = ap.parse_args()

    merge_worker_logs(Path(args.workers_dir), Path(args.merged_dir))


if __name__ == "__main__":
    main()
