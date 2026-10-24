import asyncio
import json
from typing import List, Dict, Any
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from vetaal.utils.report_generator import generate_report

app = FastAPI(title="Vetaal Local Security Auditing Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8888", "http://localhost:8888"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

db_manager = None
cve_db = None

def set_database_manager(manager: Any) -> None:
    global db_manager
    db_manager = manager

def set_cve_db(manager: Any) -> None:
    global cve_db
    cve_db = manager

@app.get("/api/report", response_class=PlainTextResponse)
async def api_report() -> str:
    if not db_manager:
        return "# Vetaal Security Scan Report\n\nNo database available yet."
    return generate_report(db_manager, cve_db)

@app.get("/api/health", response_model=Dict[str, str])
async def api_health() -> Dict[str, str]:
    if not db_manager or not hasattr(db_manager, "get_state"):
        return {"status": "unknown", "phase": "UNKNOWN"}
    state = db_manager.get_state()
    phase = state.get("phase", "UNKNOWN")
    error = state.get("error", "")
    # "error" here is whatever the last exception message was, if any —
    # it gets cleared (set to "") on the next successful phase, so a
    # non-empty value means the agent's most recent cycle actually failed,
    # not just that it failed at some point in the past.
    status = "degraded" if error else "ok"
    return {"status": status, "phase": phase, "last_error": error}

@app.get("/api/summary", response_model=Dict[str, int])
async def api_summary() -> Dict[str, int]:
    if not db_manager:
        return {"total_hosts": 0, "total_services": 0, "total_commands": 0}
    return db_manager.get_summary()

@app.get("/api/hosts", response_model=List[Dict[str, Any]])
async def api_hosts(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)) -> List[Dict[str, Any]]:
    if not db_manager:
        return []
    return db_manager.get_hosts(limit=limit, offset=offset)

@app.get("/api/logs", response_model=List[Dict[str, Any]])
async def api_logs(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)) -> List[Dict[str, Any]]:
    if not db_manager:
        return []
    return db_manager.get_logs(limit=limit, offset=offset)

@app.get("/api/logs/stream")
async def api_logs_stream() -> StreamingResponse:
    async def event_generator():
        last_id = 0
        while True:
            if db_manager:
                try:
                    with db_manager._get_connection() as conn:
                        cursor = conn.execute("SELECT id, timestamp, command, status, target FROM audit_logs WHERE id > ? ORDER BY id ASC", (last_id,))
                        for row in cursor.fetchall():
                            last_id = row["id"]
                            yield f"data: {json.dumps(dict(row))}\n\n"
                except Exception:
                    pass
            await asyncio.sleep(1.0)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
<title>Vetaal Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white p-6 font-mono">
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold">VETAAL SECURITY DASHBOARD</h1>
    <div class="flex items-center gap-3">
      <a href="/api/report" download="vetaal-report.md" class="px-3 py-1 rounded text-sm bg-blue-700 hover:bg-blue-600">Download Report</a>
      <span id="status-badge" class="px-3 py-1 rounded text-sm bg-gray-700">checking...</span>
    </div>
  </div>

  <div class="grid grid-cols-3 gap-4 mb-6">
    <div class="bg-gray-800 rounded p-4">
      <div class="text-gray-400 text-sm">Hosts</div>
      <div id="stat-hosts" class="text-3xl font-bold">-</div>
    </div>
    <div class="bg-gray-800 rounded p-4">
      <div class="text-gray-400 text-sm">Services</div>
      <div id="stat-services" class="text-3xl font-bold">-</div>
    </div>
    <div class="bg-gray-800 rounded p-4">
      <div class="text-gray-400 text-sm">Commands</div>
      <div id="stat-commands" class="text-3xl font-bold">-</div>
    </div>
  </div>

  <div class="grid grid-cols-2 gap-4">
    <div class="bg-gray-800 rounded p-4">
      <h2 class="font-bold mb-2">Hosts</h2>
      <table class="w-full text-sm">
        <thead><tr class="text-left text-gray-400">
          <th class="pb-1">IP</th><th class="pb-1">OS Guess</th><th class="pb-1">Status</th><th class="pb-1">Services</th>
        </tr></thead>
        <tbody id="hosts-body"></tbody>
      </table>
    </div>
    <div class="bg-gray-800 rounded p-4">
      <h2 class="font-bold mb-2">Live Audit Log</h2>
      <div id="log-stream" class="text-sm h-64 overflow-y-auto space-y-1"></div>
    </div>
  </div>

<script>
async function refreshSummary() {
  try {
    const s = await (await fetch('/api/summary')).json();
    document.getElementById('stat-hosts').textContent = s.total_hosts;
    document.getElementById('stat-services').textContent = s.total_services;
    document.getElementById('stat-commands').textContent = s.total_commands;
  } catch (e) { console.error(e); }
}

async function refreshHealth() {
  const badge = document.getElementById('status-badge');
  try {
    const h = await (await fetch('/api/health')).json();
    badge.textContent = h.status + ' / ' + h.phase;
    badge.title = h.last_error ? ('Last error: ' + h.last_error) : '';
    badge.className = h.status === 'degraded'
      ? 'px-3 py-1 rounded text-sm bg-yellow-700'
      : 'px-3 py-1 rounded text-sm bg-green-700';
  } catch (e) {
    badge.textContent = 'unreachable';
    badge.title = '';
    badge.className = 'px-3 py-1 rounded text-sm bg-red-700';
  }
}

async function refreshHosts() {
  try {
    const hosts = await (await fetch('/api/hosts')).json();
    const body = document.getElementById('hosts-body');
    body.innerHTML = hosts.map(h => {
      const svcText = (h.services && h.services.length)
        ? h.services.map(s => `${s.port}/${s.protocol} ${s.service_name}${s.banner ? ' (' + s.banner + ')' : ''}`).join(', ')
        : '—';
      return `<tr class="border-t border-gray-700">
        <td class="py-1">${h.ip_address}</td>
        <td class="py-1">${h.os_guess}</td>
        <td class="py-1">${h.status}</td>
        <td class="py-1 text-gray-300">${svcText}</td>
      </tr>`;
    }).join('');
  } catch (e) { console.error(e); }
}

function startLogStream() {
  const box = document.getElementById('log-stream');
  const es = new EventSource('/api/logs/stream');
  es.onmessage = (evt) => {
    const row = JSON.parse(evt.data);
    const line = document.createElement('div');
    line.textContent = `[${row.status}] ${row.command} -> ${row.target}`;
    box.prepend(line);
  };
  es.onerror = () => { /* browser auto-reconnects SSE */ };
}

refreshHealth();
refreshSummary();
refreshHosts();
startLogStream();
setInterval(refreshHealth, 5000);
setInterval(refreshSummary, 5000);
setInterval(refreshHosts, 5000);
</script>
</body>
</html>"""

@app.get("/favicon.ico")
async def favicon():
    # No favicon asset shipped yet — return 204 instead of a noisy 404
    # every time a browser tab requests it.
    from fastapi.responses import Response
    return Response(status_code=204)

@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    return HTMLResponse(content=DASHBOARD_HTML)
