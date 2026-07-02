"""aiohttp web server for the Tirri-Shield dashboard."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from aiohttp import web, WSMsgType

from tirri_shield.models import AlertEvent
from tirri_shield.monitor import BLEMonitor
from tirri_shield.scanner import TirriScanner

logger = logging.getLogger(__name__)


def _find_static_dir() -> Path:
    pkg_dir = Path(__file__).parent.parent
    candidates = [
        pkg_dir.parent / "web",
        pkg_dir / "web_assets",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


STATIC_DIR = _find_static_dir()


class DashboardServer:
    """Serves the Tirri-Shield web dashboard."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self._scanner = TirriScanner(scan_duration=10.0)
        self._monitor = BLEMonitor()
        self._ws_clients: set[web.WebSocketResponse] = set()
        self._app = web.Application()
        self._latest_scan: list[dict] | None = None
        self._monitor_task: asyncio.Task | None = None
        self._setup_routes()

    def _setup_routes(self) -> None:
        self._app.router.add_get("/", self._serve_index)
        self._app.router.add_get("/ws", self._handle_ws)
        self._app.router.add_post("/api/scan", self._api_scan)
        self._app.router.add_get("/api/scan/results", self._api_scan_results)
        self._app.router.add_post("/api/monitor/start", self._api_monitor_start)
        self._app.router.add_post("/api/monitor/stop", self._api_monitor_stop)
        self._app.router.add_get("/api/status", self._api_status)

        static_path = STATIC_DIR / "static"
        if static_path.is_dir():
            self._app.router.add_static("/static/", path=str(static_path), name="static")

    async def _serve_index(self, request: web.Request) -> web.Response:
        index_path = STATIC_DIR / "templates" / "index.html"
        if not index_path.exists():
            return web.Response(
                text="Dashboard files not found. Run from the project directory.",
                status=404,
            )
        return web.FileResponse(index_path)

    async def _handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self._ws_clients.add(ws)
        logger.info("WebSocket client connected (%d total)", len(self._ws_clients))

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except json.JSONDecodeError:
                        continue
                    await self._handle_ws_message(ws, data)
                elif msg.type == WSMsgType.ERROR:
                    logger.error("WebSocket error: %s", ws.exception())
        finally:
            self._ws_clients.discard(ws)
            logger.info("WebSocket client disconnected (%d total)", len(self._ws_clients))

        return ws

    async def _handle_ws_message(
        self, ws: web.WebSocketResponse, data: dict
    ) -> None:
        action = data.get("action")
        if action == "ping":
            await ws.send_json({"type": "pong", "timestamp": time.time()})

    async def _broadcast_ws(self, message: dict) -> None:
        if not self._ws_clients:
            return
        data = json.dumps(message)
        stale = set()
        for ws in list(self._ws_clients):
            try:
                await ws.send_str(data)
            except Exception:
                stale.add(ws)
        self._ws_clients -= stale

    def _on_monitor_alert(self, alert: AlertEvent) -> None:
        message = {
            "type": "alert",
            "data": {
                "message": alert.message,
                "severity": alert.severity.value,
                "timestamp": alert.timestamp,
                "device": None,
            },
        }
        if alert.device:
            message["data"]["device"] = {
                "address": alert.device.address,
                "name": alert.device.name,
                "rssi": alert.device.rssi,
            }
        loop = asyncio.get_event_loop()
        loop.create_task(self._broadcast_ws(message))

    async def _parse_json_body(self, request: web.Request) -> dict:
        if not request.can_read_body:
            return {}
        try:
            return await request.json()
        except (json.JSONDecodeError, Exception):
            return {}

    async def _api_scan(self, request: web.Request) -> web.Response:
        body = await self._parse_json_body(request)
        duration = body.get("duration", 10.0)
        deep = body.get("deep", False)

        self._scanner = TirriScanner(scan_duration=duration, deep_inspect=deep)

        await self._broadcast_ws({"type": "scan_started"})

        try:
            reports = await self._scanner.scan()
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

        results = _serialize_reports(reports)
        self._latest_scan = results
        await self._broadcast_ws({"type": "scan_complete", "data": results})

        return web.json_response({"status": "ok", "results": results})

    async def _api_scan_results(self, request: web.Request) -> web.Response:
        if self._latest_scan is None:
            return web.json_response({"status": "no_scan", "results": []})
        return web.json_response({"status": "ok", "results": self._latest_scan})

    async def _api_monitor_start(self, request: web.Request) -> web.Response:
        if self._monitor.is_running:
            return web.json_response({"status": "already_running"})

        body = await self._parse_json_body(request)
        target = body.get("target")

        self._monitor = BLEMonitor(
            target_address=target,
            poll_interval=body.get("interval", 5.0),
        )
        self._monitor.on_alert(self._on_monitor_alert)
        self._monitor_task = asyncio.create_task(self._monitor.start())

        return web.json_response({"status": "started"})

    async def _api_monitor_stop(self, request: web.Request) -> web.Response:
        if not self._monitor.is_running:
            return web.json_response({"status": "not_running"})

        await self._monitor.stop()
        if self._monitor_task:
            self._monitor_task.cancel()
            self._monitor_task = None

        return web.json_response({"status": "stopped"})

    async def _api_status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok",
            "monitor_running": self._monitor.is_running,
            "ws_clients": len(self._ws_clients),
            "latest_scan_available": self._latest_scan is not None,
        })

    async def start(self) -> None:
        runner = web.AppRunner(self._app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        logger.info("Dashboard running at http://%s:%d", self.host, self.port)

        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass
        finally:
            await runner.cleanup()


def _serialize_reports(reports: list) -> list[dict]:
    results = []
    for report in reports:
        dist = report.device.estimated_distance_m
        results.append({
            "device": {
                "address": report.device.address,
                "name": report.device.name,
                "type": report.device.device_type.value,
                "rssi": report.device.rssi,
                "signal_strength": report.device.signal_strength,
                "estimated_distance_m": round(dist, 1) if dist >= 0 else -1,
            },
            "overall_level": report.overall_level.value,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in report.findings
            ],
        })
    return results
