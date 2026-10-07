"""Small local web UI: streams search results to the browser over SSE."""

from __future__ import annotations

import asyncio
import json
import webbrowser
from datetime import datetime
from pathlib import Path

from aiohttp import web

from . import __version__, report
from .engine import SearchConfig, Searcher
from .history import History
from .mutations import mutations, numbered, parse_range
from .sites import all_tags, filter_sites, load_sites

STATIC = Path(__file__).parent / "static"
MAX_USERNAMES = 5


def _clamp(value: str | None, default: float, lo: float, hi: float) -> float:
    try:
        return max(lo, min(hi, float(value))) if value not in (None, "") else default
    except ValueError:
        return default


def create_app(db: str | None = None, history: str | None = None) -> web.Application:
    app = web.Application()
    app["all_sites"] = load_sites(db)

    async def open_history(app_: web.Application):
        try:
            app_["history"] = History(history)
        except Exception as e:  # unwritable home folder: search still works, just without history/cache
            print(f"history disabled: {e}")
            app_["history"] = None
        yield
        if app_["history"]:
            app_["history"].close()

    app.cleanup_ctx.append(open_history)

    async def index(_: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC / "index.html")

    async def sites(_: web.Request) -> web.Response:
        s = app["all_sites"]
        return web.json_response({
            "version": __version__,
            "tags": all_tags(s),
            "sites": [{"name": x.name, "main": x.main, "tags": x.tags} for x in s],
        })

    async def search(request: web.Request) -> web.StreamResponse:
        q = request.query
        usernames = [u.strip().lstrip("@") for u in q.get("u", "").replace(",", " ").split() if u.strip()]
        usernames = list(dict.fromkeys(usernames))[:MAX_USERNAMES]
        if not usernames:
            raise web.HTTPBadRequest(text="missing ?u=username")
        tags = [t for t in q.get("tags", "").split(",") if t]
        selected = filter_sites(app["all_sites"], tags=tags or None)
        cfg = SearchConfig(
            timeout=_clamp(q.get("timeout"), 12, 3, 60),
            depth=int(_clamp(q.get("depth"), 1, 0, 3)),
            max_usernames=10,
            concurrency=40,
            variants=q.get("variants") == "1",
            max_candidates=int(_clamp(q.get("max_candidates"), 12, 0, 30)),
            archive=q.get("archive", "1") == "1",
            avatars=q.get("avatars", "1") == "1",
            domains=q.get("domains", "1") == "1",
            web_search=q.get("websearch", "1") == "1",
            cache=q.get("cache", "1") == "1",
            host_interval=0.3,
            numbers=parse_range(q.get("numbers")),
        )

        resp = web.StreamResponse(headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        })
        await resp.prepare(request)
        searcher = Searcher(selected, cfg, all_sites=app["all_sites"],
                            history=app["history"] if q.get("history", "1") == "1" else None)
        gen = searcher.run(usernames)
        try:
            async for ev in gen:
                await resp.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode())
        except (ConnectionResetError, asyncio.CancelledError):
            pass  # browser closed the stream / pressed Stop
        finally:
            await gen.aclose()
        return resp

    async def make_report(request: web.Request) -> web.Response:
        fmt = request.match_info["fmt"]
        if fmt not in report.ALL_FORMATS:
            raise web.HTTPNotFound()
        data = await request.json()
        results = [r for r in data.get("results", []) if isinstance(r, dict) and "status" in r]
        def dicts(key: str) -> list[dict]:
            v = data.get(key)
            return [i for i in v if isinstance(i, dict)] if isinstance(v, list) else []

        def obj(key: str) -> dict:
            v = data.get(key)
            return v if isinstance(v, dict) else {}

        graph = obj("graph")
        search_data = obj("search")
        usernames = [u for u in data.get("usernames", []) if isinstance(u, str)][:MAX_USERNAMES] \
            if isinstance(data.get("usernames"), list) else []
        meta = {"date": datetime.now().strftime("%Y-%m-%d %H:%M"), "usernames": usernames,
                "identity": dicts("identity"), "connections": dicts("connections"), "clusters": dicts("clusters"),
                "domains": dicts("domains"), "queries": dicts("queries"), "findings": dicts("findings"),
                "timeline": dicts("timeline"), "changes": dicts("changes"), "summary": obj("summary"),
                "search": {"hits": [h for h in search_data.get("hits", []) if isinstance(h, dict)],
                           "engines": [e for e in search_data.get("engines", []) if isinstance(e, dict)]},
                "graph": {"nodes": [n for n in graph.get("nodes", []) if isinstance(n, dict)],
                          "edges": [e for e in graph.get("edges", []) if isinstance(e, dict)]}}
        names = "_".join(usernames or sorted({r.get("username", "") for r in results}))[:50] or "report"
        names = "".join(c if c.isalnum() or c in "._-" else "_" for c in names)
        if fmt == "pdf":
            html = report.to_html(results, meta)
            try:
                pdf = await asyncio.get_running_loop().run_in_executor(None, report.to_pdf, html)
            except RuntimeError as e:
                # no Chrome/Edge on this machine: the page falls back to the browser's own print dialog
                raise web.HTTPNotImplemented(text=str(e))
            return web.Response(body=pdf, headers={"Content-Type": "application/pdf",
                                                    "Content-Disposition": f'attachment; filename="sleuth_{names}.pdf"'})
        body = report.render(fmt, results, meta)
        ctype = {"html": "text/html", "json": "application/json", "csv": "text/csv", "txt": "text/plain",
                 "md": "text/markdown"}[fmt]
        return web.Response(
            body=(("﻿" if fmt == "csv" else "") + body).encode("utf-8"),
            headers={"Content-Type": f"{ctype}; charset=utf-8",
                     "Content-Disposition": f'attachment; filename="sleuth_{names}.{fmt}"'},
        )

    async def history_view(request: web.Request) -> web.Response:
        h: History | None = request.app["history"]
        if not h:
            return web.json_response({"enabled": False, "runs": [], "changes": []})
        names = [u.strip().lstrip("@") for u in request.query.get("u", "").replace(",", " ").split() if u.strip()]
        runs = h.list_runs(names[0] if len(names) == 1 else None)
        return web.json_response({"enabled": True, "path": str(h.path), "runs": runs,
                                  "changes": h.changes_for(names or None, limit=100)})

    async def clear_cache(request: web.Request) -> web.Response:
        h: History | None = request.app["history"]
        return web.json_response({"cleared": h.clear_cache() if h else 0})

    async def mutation_preview(request: web.Request) -> web.Response:
        u = request.query.get("u", "").strip().lstrip("@")[:40]
        n = int(_clamp(request.query.get("n"), 12, 1, 30))
        cands = mutations(u, n) if u and request.query.get("variants", "1") == "1" else []
        rng = parse_range(request.query.get("numbers"))
        if u and rng:
            cands += numbered(u, *rng)
        return web.json_response([{"username": c.username, "rule": c.rule} for c in cands])

    app.router.add_get("/", index)
    app.router.add_get("/api/sites", sites)
    app.router.add_get("/api/search", search)
    app.router.add_post("/api/report/{fmt}", make_report)
    app.router.add_get("/api/history", history_view)
    app.router.add_post("/api/cache/clear", clear_cache)
    app.router.add_get("/api/mutations", mutation_preview)
    app.router.add_static("/static", STATIC)
    add_scan_routes(app)
    return app


def add_scan_routes(app: web.Application) -> None:
    """SpiderFoot-style scan endpoints."""
    from .scan import ALL_MODULES, EVENT_TYPES, ScanConfig, Store, detect_target, get_modules, run_scan
    from .scan import report as scan_report

    async def open_store(app_: web.Application):
        app_["store"] = Store()
        yield
        app_["store"].close()

    app.cleanup_ctx.append(open_store)

    async def scan_page(_: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC / "scan.html")

    async def modules(_: web.Request) -> web.Response:
        return web.json_response({
            "modules": [cls().info() for cls in ALL_MODULES],
            "event_types": {k: {"label": v[0], "group": v[1]} for k, v in EVENT_TYPES.items()},
        })

    async def detect(request: web.Request) -> web.Response:
        t, v = detect_target(request.query.get("target", ""))
        return web.json_response({"type": t, "value": v})

    async def scan(request: web.Request) -> web.StreamResponse:
        target = request.query.get("target", "").strip()
        if not target or len(target) > 200:
            raise web.HTTPBadRequest(text="missing ?target=")
        names = [n for n in request.query.get("modules", "").split(",") if n]
        try:
            mods = get_modules(names or None)
        except ValueError as e:
            raise web.HTTPBadRequest(text=str(e))
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache",
                                           "X-Accel-Buffering": "no"})
        await resp.prepare(request)
        gen = run_scan(target, mods, ScanConfig(), request.app["store"])
        try:
            async for msg in gen:
                await resp.write(f"data: {json.dumps(msg, ensure_ascii=False)}\n\n".encode())
        except (ConnectionResetError, asyncio.CancelledError):
            pass  # browser pressed Stop / closed the tab
        finally:
            await gen.aclose()
        return resp

    def _scan_id(request: web.Request) -> int:
        try:
            return int(request.match_info["id"])
        except ValueError:
            raise web.HTTPNotFound()

    async def scans(request: web.Request) -> web.Response:
        return web.json_response(request.app["store"].list_scans())

    async def scan_detail(request: web.Request) -> web.Response:
        s = request.app["store"].get_scan(_scan_id(request))
        if not s:
            raise web.HTTPNotFound()
        return web.json_response(s)

    async def scan_delete(request: web.Request) -> web.Response:
        ok = request.app["store"].delete_scan(_scan_id(request))
        return web.json_response({"deleted": ok})

    async def scan_report_view(request: web.Request) -> web.Response:
        s = request.app["store"].get_scan(_scan_id(request))
        fmt = request.match_info["fmt"]
        if not s or fmt not in ("html", "json"):
            raise web.HTTPNotFound()
        body = scan_report.to_html(s) if fmt == "html" else scan_report.to_json(s)
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in s["target"])[:50]
        return web.Response(text=body, content_type="text/html" if fmt == "html" else "application/json",
                            headers={"Content-Disposition": f'attachment; filename="sleuth_scan_{s["id"]}_{safe}.{fmt}"'})

    app.router.add_get("/scan", scan_page)
    app.router.add_get("/api/modules", modules)
    app.router.add_get("/api/detect", detect)
    app.router.add_get("/api/scan", scan)
    app.router.add_get("/api/scans", scans)
    app.router.add_get(r"/api/scans/{id:\d+}", scan_detail)
    app.router.add_delete(r"/api/scans/{id:\d+}", scan_delete)
    app.router.add_get(r"/api/scans/{id:\d+}/report.{fmt}", scan_report_view)


def serve(host: str = "127.0.0.1", port: int = 8787, db: str | None = None, open_browser: bool = True) -> None:
    url = f"http://{'localhost' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}"
    print(f"Sleuth web UI running at {url}  (Ctrl+C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    web.run_app(create_app(db), host=host, port=port, print=None)
