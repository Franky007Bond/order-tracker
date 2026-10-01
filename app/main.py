import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from opentelemetry import _logs, metrics, trace
from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import (
    ConsoleLogRecordExporter,
    SimpleLogRecordProcessor,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from pydantic import BaseModel, Field


DB_PATH = Path(os.getenv("ORDER_DB_PATH", "data/orders.db"))
STATUSES = {"received", "preparing", "shipped", "delivered"}
TELEMETRY_RESOURCE = Resource.create({"service.name": "order-tracker"})


def configure_telemetry():
    tracer_provider = TracerProvider(resource=TELEMETRY_RESOURCE)
    tracer_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(tracer_provider)

    metric_reader = PeriodicExportingMetricReader(
        ConsoleMetricExporter(),
        export_interval_millis=5000,
    )
    metrics.set_meter_provider(
        MeterProvider(resource=TELEMETRY_RESOURCE, metric_readers=[metric_reader])
    )

    logger_provider = LoggerProvider(resource=TELEMETRY_RESOURCE)
    logger_provider.add_log_record_processor(
        SimpleLogRecordProcessor(ConsoleLogRecordExporter())
    )
    _logs.set_logger_provider(logger_provider)
    return _logs.get_logger("order_tracker.orders")


order_logger = configure_telemetry()
tracer = trace.get_tracer(__name__)
meter = metrics.get_meter(__name__)
request_counter = meter.create_counter(
    "http.server.request.count",
    unit="{request}",
    description="Number of HTTP requests",
)


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect() as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                customer TEXT NOT NULL,
                item TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        if db.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0:
            now = datetime.now(timezone.utc)
            previous_month_end = now.replace(day=1) - timedelta(days=1)
            for order in (
                ("standard-1001", "Avery", "Notebook", "standard", "received", now),
                ("express-1002", "Sam", "Headphones", "express", "preparing", previous_month_end),
                ("standard-1003", "Riley", "Water bottle", "standard", "shipped", now),
            ):
                db.execute(
                    "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)",
                    (*order[:5], order[5].isoformat()),
                )


def as_dict(row):
    return dict(row) if row else None


def order_detail(row):
    order = as_dict(row)
    if order["priority"] == "express":
        placed_at = datetime.fromisoformat(order["created_at"])
        estimated_at = placed_at.replace(day=placed_at.day + 2)
        order["estimated_delivery"] = estimated_at.date().isoformat()
    return order


class NewOrder(BaseModel):
    customer: str = Field(min_length=1, max_length=80)
    item: str = Field(min_length=1, max_length=120)
    priority: str = "standard"


class StatusUpdate(BaseModel):
    status: str


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Order Tracker", lifespan=lifespan)


@app.middleware("http")
async def record_request_metrics(request: Request, call_next):
    response = await call_next(request)
    route = request.scope.get("route")
    route_name = getattr(route, "path", request.url.path)
    request_counter.add(
        1,
        {
            "http.method": request.method,
            "http.route": route_name,
            "http.status_code": response.status_code,
        },
    )
    return response


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent.parent / "static" / "index.html")


@app.get("/healthz")
def health():
    with connect() as db:
        db.execute("SELECT 1")
    return {"status": "ok"}


@app.get("/api/orders")
def list_orders():
    with connect() as db:
        rows = db.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
    return [as_dict(row) for row in rows]


@app.get("/api/orders/{order_id}")
def get_order(order_id: str):
    with tracer.start_as_current_span(
        "order.lookup",
        attributes={"order.id": order_id},
    ) as span:
        with connect() as db:
            row = db.execute(
                "SELECT * FROM orders WHERE id = ?", (order_id,)
            ).fetchone()
        if row is None:
            span.set_attribute("order.found", False)
            order_logger.emit(
                severity_number=SeverityNumber.WARN,
                severity_text="WARN",
                body=f"Order lookup failed: {order_id}",
                attributes={"order.id": order_id, "order.found": False},
            )
            raise HTTPException(404, "Order not found")
        span.set_attribute("order.found", True)
        order_logger.emit(
            severity_number=SeverityNumber.INFO,
            severity_text="INFO",
            body=f"Order lookup succeeded: {order_id}",
            attributes={"order.id": order_id, "order.found": True},
        )
        return order_detail(row)


@app.post("/api/orders", status_code=201)
def create_order(order: NewOrder):
    if order.priority not in {"standard", "express"}:
        raise HTTPException(422, "Priority must be standard or express")
    order_id = str(uuid4())
    with connect() as db:
        db.execute(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)",
            (order_id, order.customer, order.item, order.priority, "received",
             datetime.now(timezone.utc).isoformat()),
        )
    return get_order(order_id)


@app.patch("/api/orders/{order_id}")
def update_status(order_id: str, update: StatusUpdate):
    if update.status not in STATUSES:
        raise HTTPException(422, "Invalid status")
    with connect() as db:
        cursor = db.execute(
            "UPDATE orders SET status = ? WHERE id = ?",
            (update.status, order_id),
        )
    if cursor.rowcount == 0:
        raise HTTPException(404, "Order not found")
    return get_order(order_id)
