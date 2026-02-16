import os
import uuid
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

JOB_ROOT = Path(os.environ.get("JOB_ROOT", "/data/jobs"))
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "200"))

app = FastAPI(title="Zeek Try Cluster")

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (static_dir / "index.html").read_text(encoding="utf-8")


def _safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _limit_upload(size_bytes: int) -> None:
    if size_bytes > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"Upload too large (> {MAX_UPLOAD_MB} MB).")


# -------------------------
# Query parser (simple)
# -------------------------

_TOKEN_RE = re.compile(
    r"""
    \s*(
        \(|\) |
        (?i:AND|OR|NOT) |
        [^\s()]+ |
        "(?:\\.|[^"])*"
    )
    """,
    re.VERBOSE,
)


def _tokenize(q: str) -> List[str]:
    toks = []
    for m in _TOKEN_RE.finditer(q):
        t = m.group(1)
        if not t:
            continue
        toks.append(t)
    return toks


def _strip_quotes(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
        inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return s


def _wildcard_to_regex(pat: str) -> str:
    # convert * and ? to regex
    out = []
    for ch in pat:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "^" + "".join(out) + "$"


def _match_value(val: str, pat: str) -> bool:
    try:
        rx = re.compile(_wildcard_to_regex(pat), re.IGNORECASE)
        return rx.search(val) is not None
    except Exception:
        return pat.lower() in val.lower()


def _term_predicate(term: str):
    term = _strip_quotes(term)

    # field:value or field=value
    m = re.match(r"^([^:=]+)\s*[:=]\s*(.+)$", term)
    if m:
        field = m.group(1).strip()
        pat = _strip_quotes(m.group(2).strip())

        def _pred(row: Dict[str, str]) -> bool:
            v = row.get(field, "")
            return _match_value(v, pat)

        return _pred

    # bare term -> search across all fields
    pat = term

    def _pred_any(row: Dict[str, str]) -> bool:
        for v in row.values():
            if _match_value(v, pat):
                return True
        return False

    return _pred_any


def _to_rpn(tokens: List[str]) -> List[str]:
    # Shunting-yard: NOT > AND > OR
    prec = {"NOT": 3, "AND": 2, "OR": 1}
    out: List[str] = []
    opstack: List[str] = []

    def norm(t: str) -> str:
        u = t.upper()
        return u if u in ("AND", "OR", "NOT") else t

    for raw in tokens:
        t = norm(raw)
        if t == "(":
            opstack.append(t)
        elif t == ")":
            while opstack and opstack[-1] != "(":
                out.append(opstack.pop())
            if opstack and opstack[-1] == "(":
                opstack.pop()
        elif t in ("AND", "OR", "NOT"):
            while opstack and opstack[-1] in prec and prec[opstack[-1]] >= prec[t]:
                out.append(opstack.pop())
            opstack.append(t)
        else:
            out.append(raw)

    while opstack:
        out.append(opstack.pop())
    return out


def _compile_query(q: str):
    q = (q or "").strip()
    if not q:
        return None

    toks = _tokenize(q)
    if not toks:
        return None

    rpn = _to_rpn(toks)
    preds = []

    for tok in rpn:
        u = tok.upper()
        if u == "NOT":
            if not preds:
                # NOT with nothing: treat as always true (no-op)
                preds.append(lambda row: True)
                continue
            a = preds.pop()
            preds.append(lambda row, a=a: not a(row))
        elif u in ("AND", "OR"):
            if len(preds) < 2:
                preds.append(lambda row: True)
                continue
            b = preds.pop()
            a = preds.pop()
            if u == "AND":
                preds.append(lambda row, a=a, b=b: a(row) and b(row))
            else:
                preds.append(lambda row, a=a, b=b: a(row) or b(row))
        else:
            preds.append(_term_predicate(tok))

    if not preds:
        return None
    return preds[-1]


# -------------------------
# API
# -------------------------

@app.post("/api/run")
async def run_job(
    script_text: str = Form(...),
    workers: int = Form(7),
    pcap: UploadFile = File(...),
) -> JSONResponse:
    if workers < 1 or workers > 16:
        raise HTTPException(status_code=400, detail="workers must be between 1 and 16.")

    job_id = uuid.uuid4().hex[:12]
    job_dir = JOB_ROOT / job_id
    _safe_mkdir(job_dir)

    script_path = job_dir / "user.zeek"
    script_path.write_text(script_text, encoding="utf-8")

    pcap_path = job_dir / "input.pcap"
    data = await pcap.read()
    _limit_upload(len(data))
    pcap_path.write_bytes(data)

    runner = ["/opt/venv/bin/python", "-m", "app.runner.run_job", "--job-dir", str(job_dir), "--workers", str(workers)]
    proc = subprocess.run(runner, capture_output=True, text=True)

    (job_dir / "runner.stdout").write_text(proc.stdout or "", encoding="utf-8")
    (job_dir / "runner.stderr").write_text(proc.stderr or "", encoding="utf-8")

    if proc.returncode != 0:
        return JSONResponse(
            status_code=500,
            content={
                "job_id": job_id,
                "ok": False,
                "error": "runner_failed",
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            },
        )

    merged_dir = job_dir / "merged"
    logs = []
    if merged_dir.exists():
        for p in sorted(merged_dir.glob("*.log")):
            logs.append(p.name)

    return JSONResponse(
        content={
            "job_id": job_id,
            "ok": True,
            "logs": logs,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    )


@app.get("/api/jobs/{job_id}/log/{log_name}")
def get_log(
    job_id: str,
    log_name: str,
    offset: int = 0,
    limit: int = 200,
    q: str = "",
) -> JSONResponse:
    job_dir = JOB_ROOT / job_id
    merged_path = job_dir / "merged" / log_name
    if not merged_path.exists():
        raise HTTPException(status_code=404, detail="log not found")

    pred = _compile_query(q)

    fields: Optional[List[str]] = None
    header_meta: List[str] = []
    all_rows: List[Dict[str, str]] = []

    with merged_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#"):
                header_meta.append(line)
                if line.startswith("#fields"):
                    parts = line.split("\t")
                    fields = parts[1:]
                continue

            if fields is None:
                fields = ["_raw"]
                row = {"_raw": line}
            else:
                parts = line.split("\t")
                if len(parts) < len(fields):
                    parts += [""] * (len(fields) - len(parts))
                parts = parts[: len(fields)]
                row = {fields[i]: parts[i] for i in range(len(fields))}

            if pred is None or pred(row):
                all_rows.append(row)

    total = len(all_rows)
    if offset < 0:
        offset = 0
    if limit < 1:
        limit = 1
    if limit > 5000:
        limit = 5000

    page = all_rows[offset: offset + limit]
    return JSONResponse(
        content={
            "job_id": job_id,
            "log": log_name,
            "fields": fields or [],
            "offset": offset,
            "limit": limit,
            "total": total,
            "rows": page,
            "header": header_meta,
            "q": q or "",
        }
    )


@app.get("/api/jobs/{job_id}/runner/stdout", response_class=PlainTextResponse)
def runner_stdout(job_id: str) -> str:
    p = JOB_ROOT / job_id / "runner.stdout"
    if not p.exists():
        raise HTTPException(status_code=404, detail="not found")
    return p.read_text(encoding="utf-8", errors="replace")


@app.get("/api/jobs/{job_id}/runner/stderr", response_class=PlainTextResponse)
def runner_stderr(job_id: str) -> str:
    p = JOB_ROOT / job_id / "runner.stderr"
    if not p.exists():
        raise HTTPException(status_code=404, detail="not found")
    return p.read_text(encoding="utf-8", errors="replace")
