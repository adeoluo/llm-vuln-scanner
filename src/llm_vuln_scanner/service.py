"""HTTP service: run scans over HTTP and expose health, readiness and Prometheus metrics.

Routes: ``GET /health``, ``GET /ready``, ``GET /metrics``, ``GET /v1/probes`` and
``POST /v1/scans`` (synchronous; body ``{"target": ..., "probes": [...], "sample": n,
"seed": n, "format": "json"|"sarif"|"junit"|"markdown"|"html"}``).

A scanner that fetches arbitrary URLs on request is a server-side request forgery
primitive, so the service only scans targets whose specification starts with one of the
configured allowed prefixes (by default only the offline simulated models). Scans are
capped in size and run one at a time.
"""

from __future__ import annotations

import json
import threading
import time
from collections import Counter
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from llm_vuln_scanner import __version__, _backend
from llm_vuln_scanner import probes as pr
from llm_vuln_scanner.engine import ScanConfig, Scanner
from llm_vuln_scanner.report import RENDERERS
from llm_vuln_scanner.targets import open_target
from llm_vuln_scanner.taxonomy import OWASP

MAX_BODY = 64 * 1024
MAX_ATTEMPTS = 2000
_BUCKETS = (0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 120.0, 600.0)
_CTYPES = {"json": "application/json", "sarif": "application/sarif+json",
           "junit": "application/xml", "markdown": "text/markdown", "html": "text/html"}  # fmt: skip


class ServiceState:
    def __init__(self, allowed_prefixes: tuple[str, ...]) -> None:
        self.allowed = allowed_prefixes
        self.lock = threading.Lock()
        self.scan_lock = threading.Lock()
        self.requests: Counter[tuple[str, int]] = Counter()
        self.buckets: Counter[float] = Counter()
        self.latency_sum = 0.0
        self.latency_count = 0
        self.attempts_total = 0
        self.successes_total = 0

    def observe(self, route: str, status: int, seconds: float) -> None:
        with self.lock:
            self.requests[(route, status)] += 1
            self.latency_sum += seconds
            self.latency_count += 1
            for b in _BUCKETS:
                if seconds <= b:
                    self.buckets[b] += 1

    def metrics(self) -> str:
        out = ["# HELP lvs_requests_total HTTP requests by route and status.",
               "# TYPE lvs_requests_total counter"]  # fmt: skip
        with self.lock:
            for (route, status), n in sorted(self.requests.items()):
                out.append(f'lvs_requests_total{{route="{route}",status="{status}"}} {n}')
            out += ["# HELP lvs_request_seconds Request latency.", "# TYPE lvs_request_seconds histogram"]
            for b in _BUCKETS:
                out.append(f'lvs_request_seconds_bucket{{le="{b}"}} {self.buckets[b]}')
            out.append(f'lvs_request_seconds_bucket{{le="+Inf"}} {self.latency_count}')
            out.append(f"lvs_request_seconds_sum {self.latency_sum:.6f}")
            out.append(f"lvs_request_seconds_count {self.latency_count}")
            out += ["# HELP lvs_attempts_total Attack attempts run.", "# TYPE lvs_attempts_total counter",
                    f"lvs_attempts_total {self.attempts_total}",
                    "# HELP lvs_successful_attacks_total Attempts where the attack succeeded.",
                    "# TYPE lvs_successful_attacks_total counter",
                    f"lvs_successful_attacks_total {self.successes_total}"]  # fmt: skip
        return "\n".join(out) + "\n"


def run_scan(state: ServiceState, body: dict[str, Any]) -> tuple[int, str, str]:
    target = body.get("target")
    if not isinstance(target, str) or not target:
        raise ValueError("'target' must be a non-empty string")
    if not any(target == p or target.startswith(p) for p in state.allowed):
        return 403, json.dumps({"error": "target not allowed by this service"}), "application/json"
    probes = body.get("probes", ["default"])
    if not isinstance(probes, list) or not all(isinstance(p, str) for p in probes):
        raise ValueError("'probes' must be a list of strings")
    fmt = body.get("format", "json")
    if fmt not in RENDERERS:
        raise ValueError(f"'format' must be one of {', '.join(RENDERERS)}")
    sample = body.get("sample")
    if sample is not None and (not isinstance(sample, int) or sample < 1):
        raise ValueError("'sample' must be a positive integer")
    seed = body.get("seed", 0)
    if not isinstance(seed, int):
        raise ValueError("'seed' must be an integer")
    cfg = ScanConfig(probes=probes, sample=sample, seed=seed)
    with state.scan_lock, ExitStack() as stack:
        scanner = Scanner(open_target(target, stack), cfg)
        if len(scanner.plan()) > MAX_ATTEMPTS:
            raise ValueError(f"scan too large (more than {MAX_ATTEMPTS} attempts); use 'sample'")
        report = scanner.run().to_dict()
    with state.lock:
        state.attempts_total += report["summary"]["attempts"]
        state.successes_total += report["summary"]["successes"]
    return 200, RENDERERS[fmt](report), _CTYPES[fmt]


def make_handler(state: ServiceState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "llm-vuln-scanner/" + __version__

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, status: int, body: str, ctype: str = "application/json") -> None:
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            t0 = time.perf_counter()
            route = self.path.split("?")[0]
            status = 200
            if route == "/health":
                self._send(200, json.dumps({"status": "ok", "version": __version__}))
            elif route == "/ready":
                self._send(200, json.dumps({"ready": True, "rust_core": _backend.rust_available(),
                                            "probes": len(pr.names())}))  # fmt: skip
            elif route == "/metrics":
                self._send(200, state.metrics(), "text/plain; version=0.0.4")
            elif route == "/v1/probes":
                infos = [pr.get(n).info for n in pr.names()]
                self._send(200, json.dumps([{"name": i.name, "title": i.title, "owasp": OWASP[i.owasp].ref,
                                             "asi": list(i.asi), "atlas": list(i.atlas),
                                             "severity": i.severity.name.lower()}
                                            for i in infos]))  # fmt: skip
            else:
                status = 404
                self._send(404, json.dumps({"error": "not found"}))
            state.observe(route if status != 404 else "other", status, time.perf_counter() - t0)

        def do_POST(self) -> None:
            t0 = time.perf_counter()
            route = self.path.split("?")[0]
            if route != "/v1/scans":
                self._send(404, json.dumps({"error": "not found"}))
                state.observe("other", 404, time.perf_counter() - t0)
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0 or length > MAX_BODY:
                    raise ValueError("body must be between 1 byte and 64 KiB")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("body must be a JSON object")
                status, payload, ctype = run_scan(state, body)
            except (ValueError, json.JSONDecodeError) as exc:
                status, payload, ctype = 400, json.dumps({"error": str(exc)}), "application/json"
            self._send(status, payload, ctype)
            state.observe(route, status, time.perf_counter() - t0)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8000,
          allowed_prefixes: tuple[str, ...] = ("naive", "refusing")) -> ThreadingHTTPServer:  # fmt: skip
    """Create (but do not start) the service; call ``serve_forever`` on it."""
    return ThreadingHTTPServer((host, port), make_handler(ServiceState(allowed_prefixes)))
