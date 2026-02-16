````markdown
# Zeek Try Cluster

A “try.zeek.org-style” local web UI that lets you **paste a Zeek script**, **upload a PCAP**, and run analysis in a **multi-worker (cluster-like) environment** — with a built-in **worker→5-tuple mapping log** so you can prove that different parts of a detection landed on different workers.

This project is built for validating **sequence-based detections** that can fail in real clustered deployments when different stages are processed by different workers.

---

## What you get

- Paste a Zeek script in the browser (syntax-highlighted editor)
- Upload a PCAP and run Zeek
- Choose worker count (1–16; default 7)
- Clickable log tabs for all generated Zeek logs (`conn`, `dns`, `ssl`, `notice`, `x509`, etc.)
- Search box with simple boolean + wildcard syntax
- A special **`worker_map.log`** tab showing exactly which **5-tuples** were assigned to which worker (proof of distribution)
- Paginated table view with hover tooltips for long fields

---

## Why this exists

Some detections rely on a **sequence of events** (stage 1 → stage 2 → stage 3). In clustered Zeek deployments, those events may be processed by **different workers**, and if correlation state is not shared correctly (publish/subscribe, manager aggregation, etc.), the final notice may never be raised.

This tool helps you:
1. Force multi-worker processing (by flow-hash slicing across workers)
2. Verify distribution using **`worker_map.log`**
3. Confirm your detection by:
   - Seeing the NOTICE in `notice.log`
   - Clicking into supporting evidence in `conn.log`, `dns.log`, `ssl.log`, etc.

---

## Requirements

- Docker Engine / Docker Desktop
- Docker Compose (v2)

No other local dependencies.

---

## Quickstart

From the repo directory:

```bash
docker compose up --build
````

Open:

* [http://localhost:8880](http://localhost:8880)

Stop:

```bash
docker compose down
```

Reset all run artifacts (deletes the named volume):

```bash
docker compose down -v
```

---

## Using the UI

1. Paste your Zeek script in the editor
2. Choose a PCAP file (`.pcap` / `.pcapng`)
3. Select worker count (default 7)
4. Click **Run**
5. After completion:

   * Click **`notice`** and verify your notice(s)
   * Click **`conn` / `dns` / `ssl` / etc.** to validate evidence
   * Click **`worker_map`** to prove that relevant flows landed on different workers

---

## Search syntax

The search box filters the **current log tab**.

* Field search:

  * `field:value` or `field=value`
* Wildcards:

  * `*` = any length
  * `?` = single character
* Boolean:

  * `AND OR NOT` (case-insensitive)
  * Parentheses allowed: `( ... )`
* No field:

  * Searches across **all values** in the current log

Examples:

* `id.resp_h:192.168.* AND service:dns`
* `query:*evil* OR answers:*evil*`
* `ts:170* AND (service:ssl OR service:http)`
* `evil.com` (no field → search all columns)

---

## The `worker_map.log` tab (distribution proof)

`worker_map.log` is generated during splitting and shows:

* `worker` — the worker index (1..N)
* `src_ip, src_port, dst_ip, dst_port, proto` — normalized 5-tuple info
* `pkt_count` — number of packets from that tuple written into that worker’s slice

Use it to prove that the specific flows/stages your detection depends on were processed on different workers.

---

## Project layout

```text
zeek-try-cluster/
  docker-compose.yml
  Dockerfile
  apt-packages.txt
  requirements.txt
  app/
    main.py
    runner/
      split_pcap.py
      merge_logs.py
      run_job.py
    static/
      index.html
      styles.css
      app.js
      ace.js
      theme-twilight.js
      mode-c_cpp.js
      worker-base.js
```

---

## Notes / limitations

* PCAP slicing uses a deterministic flow-hash based on the observed packet tuple.
* IPv6 extension headers are not fully parsed in the splitter (MVP behavior).
* Logs are merged post-run and sorted by `ts` when available; true global ordering across workers can differ slightly.
* This is a single-node “cluster-like” runner: multiple workers are simulated by slicing and running Zeek separately per slice.

---

## Roadmap ideas

* “Tuple → Worker” planner tool (predict worker assignment before running)
* Better Zeek syntax mode (custom Ace grammar for `.zeek`)
* Async job queue + job history UI
* Improved merge handling for logs with mismatched schemas

---

