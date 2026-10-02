import hashlib
import json
import os
import shlex
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel, Field


INCIDENTS_DIR = Path(os.getenv("INCIDENT_DATA_DIR", "data/incidents"))
LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100").rstrip("/")
TEMPO_URL = os.getenv("TEMPO_URL", "http://localhost:3200").rstrip("/")
SERVICE_NAME = os.getenv("INCIDENT_SERVICE_NAME", "order-tracker")
LOOKBACK_SECONDS = int(os.getenv("INCIDENT_LOOKBACK_SECONDS", "300"))


class GrafanaWebhook(BaseModel):
    status: str = "unknown"
    receiver: str | None = None
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    group_labels: dict[str, Any] = Field(default_factory=dict, alias="groupLabels")
    common_labels: dict[str, Any] = Field(default_factory=dict, alias="commonLabels")
    common_annotations: dict[str, Any] = Field(
        default_factory=dict, alias="commonAnnotations"
    )
    external_url: str | None = Field(default=None, alias="externalURL")


app = FastAPI(title="Incident Response")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def annotation(alert: dict[str, Any], key: str, default: str = "") -> str:
    annotations = alert.get("annotations") or {}
    return str(annotations.get(key) or default)


def endpoint_for(alert: dict[str, Any]) -> str:
    labels = alert.get("labels") or {}
    return (
        annotation(alert, "endpoint")
        or str(labels.get("http_route") or labels.get("route") or "unknown")
    )


def incident_id_for(alert: dict[str, Any]) -> str:
    fingerprint = str(alert.get("fingerprint") or "")
    if not fingerprint:
        fingerprint = hashlib.sha256(
            json.dumps(
                {"labels": alert.get("labels"), "annotations": alert.get("annotations")},
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:20]
    return "incident-" + "".join(char for char in fingerprint if char.isalnum() or char in "-_")


def backend_json(url: str) -> dict[str, Any]:
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=5) as response:
            body = response.read().decode("utf-8")
            return {"status": "ok", "http_status": response.status, "data": json.loads(body)}
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")[:2000]
        return {"status": "error", "http_status": error.code, "error": body}
    except (URLError, TimeoutError, ValueError, OSError) as error:
        return {"status": "error", "error": str(error)}


def incident_window() -> tuple[datetime, datetime]:
    end = utc_now()
    return end - timedelta(seconds=LOOKBACK_SECONDS), end


def collect_logs(endpoint: str) -> dict[str, Any]:
    start, end = incident_window()
    query = os.getenv("LOKI_LABEL_SELECTOR", f'{{service_name="{SERVICE_NAME}"}}')
    if endpoint != "unknown":
        query += f" |= {json.dumps(endpoint)}"
    params = {
        "query": query,
        "start": str(int(start.timestamp() * 1_000_000_000)),
        "end": str(int(end.timestamp() * 1_000_000_000)),
        "limit": "1000",
        "direction": "backward",
    }
    url = f"{LOKI_URL}/loki/api/v1/query_range?{urlencode(params)}"
    return {"query": query, "window": {"start": start.isoformat(), "end": end.isoformat()}, "result": backend_json(url)}


def collect_traces() -> dict[str, Any]:
    start, end = incident_window()
    params = {
        "tags": f"service.name={SERVICE_NAME}",
        "start": str(int(start.timestamp())),
        "end": str(int(end.timestamp())),
        "limit": "100",
    }
    url = f"{TEMPO_URL}/api/search?{urlencode(params)}"
    return {
        "query": params,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "result": backend_json(url),
    }


def assistant_prompt(record_path: Path, record: dict[str, Any]) -> str:
    return f"""You are investigating an active production-style incident.

Read the saved incident context at {record_path} and inspect the repository in your working directory.
The alert endpoint is {record['endpoint']}. Review the saved alert, Loki logs, and Tempo traces.
Work read-only: do not edit files, commit changes, deploy, or delete data.
Return a concise incident summary with likely root cause, evidence, and a proposed next step.
"""


def start_assistant(record_path: Path, record: dict[str, Any]) -> dict[str, Any]:
    command = os.getenv(
        "CODING_ASSISTANT_COMMAND",
        "codex exec --sandbox read-only --skip-git-repo-check -",
    ).strip()
    if not command:
        return {"status": "disabled", "reason": "CODING_ASSISTANT_COMMAND is empty"}

    try:
        args = shlex.split(command, posix=os.name != "nt")
        if not args:
            return {"status": "disabled", "reason": "assistant command is empty"}
        workdir = Path(os.getenv("ASSISTANT_WORKDIR", str(Path.cwd())))
        if not workdir.exists():
            workdir = Path.cwd()
        output_path = record_path.with_suffix(".assistant.log")
        with output_path.open("a", encoding="utf-8") as output:
            process = subprocess.Popen(
                args,
                cwd=workdir,
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            assert process.stdin is not None
            process.stdin.write(assistant_prompt(record_path, record))
            process.stdin.close()
        return {
            "status": "started",
            "pid": process.pid,
            "command": args,
            "output": str(output_path),
            "started_at": utc_now().isoformat(),
        }
    except (OSError, ValueError) as error:
        return {"status": "error", "error": str(error)}


def process_incident(record_path: Path) -> None:
    record = read_json(record_path)
    if record["status"].lower() not in {"firing", "alerting"}:
        record["assistant"] = {"status": "skipped", "reason": "alert is not firing"}
        write_json(record_path, record)
        return

    record["enrichment"] = {
        "logs": collect_logs(record["endpoint"]),
        "traces": collect_traces(),
    }
    record["assistant"] = start_assistant(record_path, record)
    write_json(record_path, record)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/alerts", status_code=202)
def receive_alert(webhook: GrafanaWebhook, background_tasks: BackgroundTasks) -> dict[str, Any]:
    if not webhook.alerts:
        raise HTTPException(status_code=400, detail="Grafana payload must contain alerts")

    received_at = utc_now().isoformat()
    incident_ids: list[str] = []
    for alert in webhook.alerts:
        incident_id = incident_id_for(alert)
        path = INCIDENTS_DIR / f"{incident_id}.json"
        existing = read_json(path) if path.exists() else {}
        record = {
            **existing,
            "incident_id": incident_id,
            "received_at": received_at,
            "status": str(alert.get("status") or webhook.status),
            "endpoint": endpoint_for(alert),
            "time_window": annotation(alert, "time_window", f"{LOOKBACK_SECONDS} seconds"),
            "alert": alert,
            "webhook": webhook.model_dump(by_alias=True),
        }
        write_json(path, record)
        incident_ids.append(incident_id)
        if existing.get("assistant", {}).get("status") != "started":
            background_tasks.add_task(process_incident, path)

    return {"status": "accepted", "incidents": incident_ids}
