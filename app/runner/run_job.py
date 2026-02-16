import argparse
import shutil
import subprocess
from pathlib import Path

from app.runner.split_pcap import split_pcap_flowhash
from app.runner.merge_logs import merge_worker_logs


def run_zeek_on_slice(worker_dir: Path, slice_pcap: Path, script_path: Path) -> None:
    logs_dir = worker_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["zeek", "-r", str(slice_pcap), str(script_path)]
    proc = subprocess.run(cmd, cwd=str(worker_dir), capture_output=True, text=True)

    (worker_dir / "zeek.stdout").write_text(proc.stdout or "", encoding="utf-8")
    (worker_dir / "zeek.stderr").write_text(proc.stderr or "", encoding="utf-8")

    if proc.returncode != 0:
        raise RuntimeError(f"zeek failed for {worker_dir.name}: {proc.stderr}")

    for lp in worker_dir.glob("*.log"):
        shutil.move(str(lp), str(logs_dir / lp.name))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-dir", required=True)
    ap.add_argument("--workers", type=int, default=7)
    args = ap.parse_args()

    job_dir = Path(args.job_dir)
    workers = args.workers

    script_path = job_dir / "user.zeek"
    pcap_path = job_dir / "input.pcap"
    if not script_path.exists() or not pcap_path.exists():
        raise SystemExit("job-dir missing user.zeek or input.pcap")

    slices_dir = job_dir / "slices"
    workers_dir = job_dir / "workers"
    merged_dir = job_dir / "merged"

    slices_dir.mkdir(parents=True, exist_ok=True)
    workers_dir.mkdir(parents=True, exist_ok=True)
    merged_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Splitting PCAP into {workers} flow-hash slices...")
    map_path = split_pcap_flowhash(pcap_path, slices_dir, workers)
    print(f"[+] Wrote worker map: {map_path}")

    print("[+] Running Zeek on each slice...")
    for i in range(workers):
        worker_dir = workers_dir / f"worker{i+1}"
        if worker_dir.exists():
            shutil.rmtree(worker_dir)
        worker_dir.mkdir(parents=True, exist_ok=True)

        slice_pcap = slices_dir / f"worker{i+1}.pcap"
        run_zeek_on_slice(worker_dir, slice_pcap, script_path)

    print("[+] Merging worker logs...")
    merge_worker_logs(workers_dir, merged_dir)

    merged_map = merged_dir / "worker_map.log"
    shutil.copyfile(str(map_path), str(merged_map))
    print(f"[+] Added worker map tab: {merged_map}")

    print("[+] Done. Merged logs at:", merged_dir)


if __name__ == "__main__":
    main()
