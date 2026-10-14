"""Small local web UI: streams search results to the browser over SSE.

Also serves the investigation workspace (cases, watchlist + alerts, the
local intelligence database) and runs due watchlist targets in the
background while the server is open.
"""

from __future__ import annotations

import asyncio
import json
import webbrowser
from datetime import datetime
from pathlib import Path

from aiohttp import web

from . import __version__, report, websearch
from .engine import SearchConfig, Searcher, make_session
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
        return web.FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

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
                "entities": dicts("entities"), "contradictions": dicts("contradictions"), "plan": dicts("plan"),
                "replay": dicts("replay"), "intel": obj("intel"), "redact": bool(data.get("redact")),
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
        if fmt == "xlsx":
            try:
                data_bytes = report.to_xlsx(results, meta)
            except RuntimeError as e:  # openpyxl missing
                raise web.HTTPNotImplemented(text=str(e))
            if not isinstance(data_bytes, bytes):  # openpyxl missing: fell back to CSV text
                return web.Response(body=("﻿" + data_bytes).encode("utf-8"),
                                    headers={"Content-Type": "text/csv; charset=utf-8",
                                             "Content-Disposition": f'attachment; filename="sleuth_{names}.csv"'})
            return web.Response(body=data_bytes, headers={
                "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "Content-Disposition": f'attachment; filename="sleuth_{names}.xlsx"'})
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
    add_workspace_routes(app)
    add_v3_routes(app)
    return app


WATCH_TICK = 60  # seconds between looks at the watchlist


def add_workspace_routes(app: web.Application) -> None:
    """Runs, cases, watchlist, alerts, intelligence DB and the custom query builder."""
    from .watch import DEFAULT_INTERVAL_HOURS, check_target, run_due

    app["watch_lock"] = asyncio.Lock()
    app["watch_status"] = {"running": None, "last": None}

    async def watcher(app_: web.Application):
        async def loop() -> None:
            while True:
                await asyncio.sleep(WATCH_TICK)
                h = app_["history"]
                if not h or app_["watch_lock"].locked():
                    continue
                async with app_["watch_lock"]:
                    for w in h.watch_due():
                        app_["watch_status"]["running"] = w["target"]
                        res = await check_target(h, w["target"], w["options"], app_["all_sites"], app_["all_sites"])
                        app_["watch_status"].update(running=None, last=res)
        task = asyncio.create_task(loop())
        yield
        task.cancel()

    app.cleanup_ctx.append(watcher)

    def hist(request: web.Request) -> History:
        h = request.app["history"]
        if not h:
            raise web.HTTPServiceUnavailable(text="history database is disabled")
        return h

    def _id(request: web.Request) -> int:
        try:
            return int(request.match_info["id"])
        except ValueError:
            raise web.HTTPNotFound()

    async def body(request: web.Request) -> dict:
        try:
            data = await request.json()
        except (ValueError, json.JSONDecodeError):
            raise web.HTTPBadRequest(text="expected JSON")
        if not isinstance(data, dict):
            raise web.HTTPBadRequest(text="expected a JSON object")
        return data

    async def workspace(_: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC / "workspace.html", headers={"Cache-Control": "no-cache"})

    # -- runs (replay / reopen) --
    async def runs(request: web.Request) -> web.Response:
        return web.json_response(hist(request).list_runs(request.query.get("u") or None, limit=50))

    async def run_detail(request: web.Request) -> web.Response:
        r = hist(request).get_run(_id(request))
        if not r:
            raise web.HTTPNotFound()
        return web.json_response(r)

    # -- cases --
    async def cases(request: web.Request) -> web.Response:
        h = hist(request)
        if request.method == "POST":
            data = await body(request)
            targets = [t for t in data.get("targets", []) if isinstance(t, str)][:20]
            cid = h.create_case(str(data.get("name", "Case"))[:120], targets, str(data.get("notes", ""))[:20000])
            if isinstance(data.get("run_id"), int):
                h.update_case(cid, add_run=data["run_id"])
            return web.json_response({"id": cid})
        return web.json_response(h.list_cases())

    async def case_detail(request: web.Request) -> web.Response:
        h, cid = hist(request), _id(request)
        if request.method == "DELETE":
            return web.json_response({"deleted": h.delete_case(cid)})
        if request.method == "PATCH":
            data = await body(request)
            ok = h.update_case(
                cid, name=str(data["name"])[:120] if "name" in data else None,
                notes=str(data["notes"])[:20000] if "notes" in data else None,
                status=data.get("status") if data.get("status") in ("open", "closed") else None,
                add_targets=[t for t in data.get("add_targets", []) if isinstance(t, str)][:20],
                remove_targets=[t for t in data.get("remove_targets", []) if isinstance(t, str)],
                add_run=data.get("add_run") if isinstance(data.get("add_run"), int) else None)
            if not ok:
                raise web.HTTPNotFound()
        c = h.get_case(cid)
        if not c:
            raise web.HTTPNotFound()
        return web.json_response(c)

    # -- watchlist + alerts --
    async def watch(request: web.Request) -> web.Response:
        h = hist(request)
        if request.method == "POST":
            data = await body(request)
            target = str(data.get("target", "")).strip().lstrip("@")[:60]
            if not target:
                raise web.HTTPBadRequest(text="missing target")
            opts = data.get("options") if isinstance(data.get("options"), dict) else {}
            h.watch_add(target, float(_clamp(str(data.get("interval_hours", "")), DEFAULT_INTERVAL_HOURS, 0.25, 24 * 30)),
                        {k: v for k, v in opts.items() if k in ("depth", "variants", "websearch", "avatars")})
        return web.json_response({"items": h.watch_list(), "status": request.app["watch_status"],
                                  "unseen": len(h.alerts(unseen_only=True))})

    async def watch_delete(request: web.Request) -> web.Response:
        return web.json_response({"deleted": hist(request).watch_remove(request.match_info["target"])})

    async def watch_run(request: web.Request) -> web.Response:
        h = hist(request)
        data = await body(request) if request.can_read_body else {}
        targets = [data["target"]] if isinstance(data.get("target"), str) else [w["target"] for w in h.watch_list()]
        if request.app["watch_lock"].locked():
            return web.json_response({"started": False, "reason": "busy"})

        async def go() -> None:
            async with request.app["watch_lock"]:
                request.app["watch_status"]["running"] = ", ".join(targets)
                results = await run_due(h, request.app["all_sites"], request.app["all_sites"], targets)
                request.app["watch_status"].update(running=None, last=results[-1] if results else None)

        asyncio.create_task(go())
        return web.json_response({"started": True, "targets": targets})

    async def alerts(request: web.Request) -> web.Response:
        h = hist(request)
        if request.method == "POST":
            data = await body(request)
            ids = [i for i in data.get("ids", []) if isinstance(i, int)] or None
            return web.json_response({"marked": h.mark_alerts_seen(ids)})
        return web.json_response(h.alerts(unseen_only=request.query.get("unseen") == "1"))

    # -- intelligence database --
    async def intel(request: web.Request) -> web.Response:
        h, q = hist(request), request.query.get("q", "").strip()[:100]
        return web.json_response({"stats": h.intel_stats(), "results": h.intel_search(q) if q else None})

    # -- custom query builder --
    async def query(request: web.Request) -> web.Response:
        data = await body(request)
        items = []
        for q in data.get("queries", [])[:10]:
            if isinstance(q, dict) and isinstance(q.get("query"), str) and q["query"].strip():
                items.append({"query": q["query"].strip()[:300], "username": str(q.get("username", ""))[:60],
                              "label": str(q.get("label", "custom"))[:60]})
        if not items and any(data.get(k) for k in ("username", "keywords", "platform")):
            built = websearch.build_query(str(data.get("username", "")), str(data.get("platform", "")),
                                          str(data.get("keywords", "")), str(data.get("after", "")),
                                          str(data.get("before", "")))
            items = [{"query": built, "username": str(data.get("username", "")), "label": "custom"}]
        if not items:
            raise web.HTTPBadRequest(text="nothing to search")
        if data.get("dry_run"):
            return web.json_response({"queries": items, "links": [
                {"google": "https://www.google.com/search?q=" + websearch.quote_plus(i["query"]),
                 "bing": "https://www.bing.com/search?q=" + websearch.quote_plus(i["query"]),
                 "duckduckgo": "https://duckduckgo.com/?q=" + websearch.quote_plus(i["query"])} for i in items]})
        async with make_session(SearchConfig()) as session:
            out = await websearch.search(session, [], custom=items, sites=request.app["all_sites"],
                                         now=lambda: datetime.now().isoformat(timespec="seconds"))
        return web.json_response(out)

    app.router.add_get("/workspace", workspace)
    app.router.add_get("/api/runs", runs)
    app.router.add_get(r"/api/runs/{id:\d+}", run_detail)
    app.router.add_route("*", "/api/cases", cases)
    app.router.add_route("*", r"/api/cases/{id:\d+}", case_detail)
    app.router.add_route("*", "/api/watch", watch)
    app.router.add_post("/api/watch/run", watch_run)
    app.router.add_delete("/api/watch/{target}", watch_delete)
    app.router.add_route("*", "/api/alerts", alerts)
    app.router.add_get("/api/intel", intel)
    async def purge(request: web.Request) -> web.Response:
        h = hist(request)
        if request.match_info.get("target"):
            return web.json_response({"deleted": h.purge_target(request.match_info["target"])})
        data = await body(request)
        if data.get("wipe"):
            h.wipe()
            return web.json_response({"wiped": True})
        if data.get("old_days") is not None:
            return web.json_response({"deleted": h.purge_older_than(float(data["old_days"]))})
        raise web.HTTPBadRequest(text="specify target, old_days or wipe")

    app.router.add_delete("/api/target/{target}", purge)
    app.router.add_post("/api/purge", purge)

    async def settings_view(request: web.Request) -> web.Response:
        from . import settings as st
        if request.method == "POST":
            data = await body(request)
            keys = data.get("keys") if isinstance(data.get("keys"), dict) else {}
            return web.json_response({"status": st.save_keys(keys)})
        return web.json_response({"status": st.status()})

    app.router.add_route("*", "/api/settings", settings_view)
    app.router.add_post("/api/query", query)


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
        return web.FileResponse(STATIC / "scan.html", headers={"Cache-Control": "no-cache"})

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


def add_v3_routes(app: web.Application) -> None:
    """v3.0 endpoints: dorks, IOCs, STIX/MISP/Maltego, privacy, graph, timeline,
    geo, playbooks, forensics, behavior, auto-investigate, schedules, notes,
    annotations, custody."""

    async def dorks(request: web.Request) -> web.Response:
        from .deepsearch import build_dorks
        target = request.query.get("target", "")
        if not target:
            raise web.HTTPBadRequest(text="missing ?target=")
        return web.json_response([{"query": d.query, "url": d.url, "category": d.category,
                                   "description": d.description} for d in build_dorks(target)])

    async def iocs(request: web.Request) -> web.Response:
        from .threatintel import extract_iocs
        text = request.query.get("text", "")
        if not text:
            raise web.HTTPBadRequest(text="missing ?text=")
        return web.json_response(extract_iocs(text))

    async def stix_export(request: web.Request) -> web.Response:
        from .threatintel import to_stix
        import json as _json
        data = await request.json()
        return web.json_response(to_stix(data.get("results", [])))

    async def misp_export(request: web.Request) -> web.Response:
        from .threatintel import to_misp
        data = await request.json()
        return web.json_response(to_misp(data.get("results", [])))

    async def maltego_export(request: web.Request) -> web.Response:
        from .threatintel import to_maltego
        data = await request.json()
        xml = to_maltego(data.get("results", []), data.get("connections"))
        return web.Response(text=xml, content_type="application/xml")

    async def privacy(request: web.Request) -> web.Response:
        from .counter import assess_privacy_risk, check_footprint
        data = await request.json()
        results = data.get("results", [])
        risk = assess_privacy_risk(results)
        footprint = check_footprint(results)
        return web.json_response({
            "score": risk.score, "level": risk.level,
            "factors": [{"category": f.category, "severity": f.severity,
                         "description": f.description, "remediation": f.remediation,
                         "points": f.points} for f in risk.factors],
            "recommendations": risk.recommendations,
            "exposed_types": risk.exposed_data_types,
            "footprint": {"accounts": footprint.accounts_found,
                           "platforms": footprint.platforms,
                           "data_exposed": footprint.data_exposed,
                           "summary": footprint.summary},
        })

    async def remediation(request: web.Request) -> web.Response:
        from .counter import generate_remediation_plan
        data = await request.json()
        plan = generate_remediation_plan(data.get("results", []))
        return web.json_response(plan)

    async def graph(request: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC / "graph.html", headers={"Cache-Control": "no-cache"})

    async def graph_data(request: web.Request) -> web.Response:
        from .viz import build_network_graph
        data = await request.json()
        g = build_network_graph(data.get("results", []),
                                data.get("connections"),
                                data.get("intel"))
        return web.json_response(g)

    async def timeline_data(request: web.Request) -> web.Response:
        from .viz import build_timeline
        data = await request.json()
        tl = build_timeline(data.get("results", []), data.get("connections"))
        return web.json_response(tl)

    async def geo_data(request: web.Request) -> web.Response:
        from .viz import build_geo_data
        data = await request.json()
        points = build_geo_data(data.get("results", []), data.get("geo_info"))
        return web.json_response(points)

    async def dashboard(request: web.Request) -> web.Response:
        from .viz import build_dashboard_data
        data = await request.json()
        dash = build_dashboard_data(data.get("results", []),
                                    data.get("connections"),
                                    data.get("intel"))
        return web.json_response(dash)

    async def playbooks(_: web.Request) -> web.Response:
        from .casemgmt import list_playbooks, ResultAnnotations
        return web.json_response({
            "playbooks": list_playbooks(),
            "tags": ResultAnnotations.available_tags(),
        })

    async def playbook(request: web.Request) -> web.Response:
        from .casemgmt import get_playbook
        pb = get_playbook(request.match_info["category"])
        if not pb:
            raise web.HTTPNotFound(text="playbook not found")
        return web.json_response({
            "name": pb.name, "category": pb.category, "description": pb.description,
            "legal_notes": pb.legal_notes,
            "steps": [{"step": s.step, "title": s.title, "description": s.description,
                       "tools": s.tools, "expected_output": s.expected_output} for s in pb.steps],
        })

    async def forensics(request: web.Request) -> web.Response:
        from .forensics import analyze_avatar
        data = await request.json()
        url = data.get("url", "")
        if not url:
            raise web.HTTPBadRequest(text="missing url")
        from .engine import make_session, SearchConfig
        async with make_session(SearchConfig()) as session:
            result = await analyze_avatar(session, url)
        return web.json_response({k: (v.__dict__ if hasattr(v, "__dict__") else v)
                                 for k, v in result.items() if not isinstance(v, (str,))},
                                dumps=lambda x: __import__("json").dumps(x, default=str))

    async def behavior(request: web.Request) -> web.Response:
        from .behavior import build_behavioral_profile
        data = await request.json()
        texts = data.get("texts", [])
        timestamps = data.get("timestamps", [])
        profile = build_behavioral_profile(texts, timestamps)
        # Convert dataclasses to dicts
        def _to_dict(obj):
            if hasattr(obj, "__dict__"):
                return {k: _to_dict(v) for k, v in obj.__dict__.items()}
            if isinstance(obj, list):
                return [_to_dict(x) for x in obj]
            return obj
        return web.json_response({k: _to_dict(v) for k, v in profile.items()})

    async def auto_investigate(request: web.Request) -> web.Response:
        from .realtime import AutoInvestigator
        data = await request.json()
        ai = AutoInvestigator()
        plan = ai.plan(data.get("results", []))
        return web.json_response({
            "steps": [{"action": s.action, "target": s.target, "reason": s.reason,
                       "priority": s.priority, "status": s.status} for s in plan],
            "summary": ai.get_summary(),
        })

    async def schedules(request: web.Request) -> web.Response:
        from .realtime import scan_scheduler
        if request.method == "POST":
            data = await request.json()
            scan_scheduler.add(data.get("target", ""), int(data.get("interval", 24)),
                              data.get("email"))
            return web.json_response({"status": "added"})
        return web.json_response(scan_scheduler.list_schedules())

    async def notes(request: web.Request) -> web.Response:
        from .casemgmt import CaseNotes
        cn = CaseNotes()
        if request.method == "POST":
            data = await request.json()
            note_id = cn.add(data.get("case_id", "default"), data.get("author", "anonymous"),
                             data.get("content", ""), data.get("tags"),
                             data.get("pinned", False))
            return web.json_response({"id": note_id})
        case_id = request.query.get("case_id", "default")
        return web.json_response(cn.get_notes(case_id))

    async def annotations(request: web.Request) -> web.Response:
        from .casemgmt import ResultAnnotations
        ra = ResultAnnotations()
        if request.method == "POST":
            data = await request.json()
            anno_id = ra.annotate(data.get("result_key", ""), data.get("author", ""),
                                  data.get("note", ""), data.get("tags"),
                                  int(data.get("confidence", 0)),
                                  data.get("case_id", "default"))
            return web.json_response({"id": anno_id})
        result_key = request.query.get("result_key", "")
        if result_key:
            return web.json_response(ra.get_annotations(result_key))
        return web.json_response({"tags": ResultAnnotations.available_tags()})

    async def custody(request: web.Request) -> web.Response:
        from .casemgmt import ChainOfCustody
        coc = ChainOfCustody()
        if request.method == "POST":
            data = await request.json()
            coc.log(data.get("case_id", ""), data.get("action", ""),
                    data.get("actor", ""), data.get("evidence_id", ""),
                    data.get("description", ""))
            return web.json_response({"status": "logged"})
        case_id = request.query.get("case_id", "")
        if case_id:
            return web.json_response(coc.get_chain(case_id))
        raise web.HTTPBadRequest(text="missing ?case_id=")

    async def archive_check(request: web.Request) -> web.Response:
        from .archive import check_archives, wayback_url
        url = request.query.get("url", "")
        if not url:
            raise web.HTTPBadRequest(text="missing ?url=")
        from .engine import make_session, SearchConfig
        async with make_session(SearchConfig()) as session:
            result = await check_archives(session, url)
        return web.json_response({
            "url": result.url,
            "total_snapshots": result.total_snapshots,
            "earliest": {"date": result.earliest.display_date, "url": result.earliest.snapshot_url}
                        if result.earliest else None,
            "latest": {"date": result.latest.display_date, "url": result.latest.snapshot_url}
                      if result.latest else None,
            "archive_today_url": result.archive_today_url,
            "google_cache_url": result.google_cache_url,
            "wayback_url": wayback_url(url),
        })

    async def infra_scan(request: web.Request) -> web.Response:
        from .infra_intel import infra_scan, is_valid_domain
        domain = request.query.get("domain", "")
        if not domain or not is_valid_domain(domain):
            raise web.HTTPBadRequest(text="missing or invalid ?domain=")
        from .engine import make_session, SearchConfig
        async with make_session(SearchConfig()) as session:
            from .settings import get_key
            result = await infra_scan(session, domain, shodan_key=get_key("shodan"))
        # Convert dataclasses to dicts
        def _to_dict(obj):
            if hasattr(obj, "__dict__"):
                return {k: _to_dict(v) for k, v in obj.__dict__.items()}
            if isinstance(obj, list):
                return [_to_dict(x) for x in obj]
            return obj
        return web.json_response(_to_dict(result))

    async def deepsearch(request: web.Request) -> web.Response:
        from .deepsearch import deep_search
        target = request.query.get("target", "")
        if not target:
            raise web.HTTPBadRequest(text="missing ?target=")
        from .engine import make_session, SearchConfig
        async with make_session(SearchConfig()) as session:
            result = await deep_search(session, target)
        return web.json_response(result, dumps=lambda x: __import__("json").dumps(x, default=str))

    async def feeds(request: web.Request) -> web.Response:
        from .realtime import monitor_feeds
        target = request.query.get("target", "")
        if not target:
            raise web.HTTPBadRequest(text="missing ?target=")
        from .engine import make_session, SearchConfig
        async with make_session(SearchConfig()) as session:
            result = await monitor_feeds(session, target)
        return web.json_response(result)

    # Register routes
    app.router.add_get("/api/dorks", dorks)
    app.router.add_get("/api/iocs", iocs)
    app.router.add_get("/api/deepsearch", deepsearch)
    app.router.add_get("/api/feeds", feeds)
    app.router.add_post("/api/stix", stix_export)
    app.router.add_post("/api/misp", misp_export)
    app.router.add_post("/api/maltego", maltego_export)
    app.router.add_post("/api/privacy", privacy)
    app.router.add_post("/api/remediation", remediation)
    app.router.add_get("/graph", graph)
    app.router.add_post("/api/graph", graph_data)
    app.router.add_post("/api/timeline", timeline_data)
    app.router.add_post("/api/geo", geo_data)
    app.router.add_post("/api/dashboard", dashboard)
    app.router.add_get("/api/playbooks", playbooks)
    app.router.add_get("/api/playbook/{category}", playbook)
    app.router.add_post("/api/forensics", forensics)
    app.router.add_post("/api/behavior", behavior)
    app.router.add_post("/api/auto-investigate", auto_investigate)
    app.router.add_route("*", "/api/schedules", schedules)
    app.router.add_route("*", "/api/notes", notes)
    app.router.add_route("*", "/api/annotations", annotations)
    app.router.add_route("*", "/api/custody", custody)
    app.router.add_get("/api/archive", archive_check)
    app.router.add_get("/api/infra", infra_scan)


def serve(host: str = "127.0.0.1", port: int = 8787, db: str | None = None, open_browser: bool = True) -> None:
    url = f"http://{'localhost' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}"
    print(f"Sleuth web UI running at {url}  (Ctrl+C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    web.run_app(create_app(db), host=host, port=port, print=None)
