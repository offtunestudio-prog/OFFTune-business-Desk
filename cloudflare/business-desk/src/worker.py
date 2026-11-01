"""Cloudflare Worker entry point for the hosted OFFTune Business Desk.

Business routes are intentionally not exposed until the port from app.py is
complete. This entry point provides a safe readiness probe and serves assets.
"""

from workers import Response, WorkerEntrypoint


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        url = request.url
        path = url.split("?", 1)[0].rstrip("/") or "/"

        if path == "/healthz":
            try:
                result = await self.env.DB.prepare(
                    "SELECT COUNT(*) AS count FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).first()
                return Response.json(
                    {"status": "ready", "schema_tables": result["count"]}
                )
            except Exception:
                return Response.json({"status": "database_unavailable"}, status=503)

        if path.startswith("/api/"):
            return Response.json(
                {"error": "The hosted API is not ready yet."}, status=503
            )

        return await self.env.ASSETS.fetch(request)
