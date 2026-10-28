from collections import defaultdict, deque
from pathlib import Path
import json
import logging
import secrets
from time import monotonic
from typing import Literal
from uuid import UUID, uuid4

from fastapi import FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import SQLAlchemyError
from starlette.datastructures import Headers
from anyio import to_thread
from pydantic import BaseModel, Field

from .auth import Authentication, verify_password
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import PROJECT_ROOT, Settings
from .contracts import CVEReviewCreate, AuditCreate, ContextUpdate, FindingUpdate, RunCreate
from .database import make_engine
from .domain import AppError
from .comparison import compare_snapshot
from .exports import render_csv, render_pdf
from .repository import Repository
from .services import Services

logger = logging.getLogger("riskengine.api")


class LoginBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class GuardMiddleware:
    def __init__(self, app, authentication, settings):
        self.app, self.authentication, self.settings = app, authentication, settings
        self.max_bytes = settings.max_upload_bytes
        self.requests = defaultdict(deque)
        self.login_attempts = deque()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            return await self.app(scope, receive, send)
        request_id = str(uuid4())
        headers = Headers(scope=scope)
        async def fail(status, code, message):
            response = JSONResponse({"error": {"code": code, "message": message}, "request_id": request_id}, status_code=status, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
            await response(scope, receive, send)
        client = scope.get("client")
        client_id = client[0] if client else "local"
        clock = monotonic()
        if client_id not in self.requests and len(self.requests) > 1024:
            self.requests = defaultdict(deque, {key: times for key, times in self.requests.items() if times and times[-1] > clock - 60})
        recent = self.requests[client_id]
        while recent and recent[0] < clock - 60:
            recent.popleft()
        if len(recent) >= 120:
            return await fail(429, "rate_limit", "Demasiadas solicitudes. Espera un minuto.")
        recent.append(clock)
        if scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            if headers.get("x-riskengine-request") != "1" or headers.get("origin") not in self.settings.allowed_origins:
                return await fail(403, "csrf_rejected", "Solicitud no autorizada desde este origen.")
        is_login = scope["path"] == "/api/auth/login" and scope["method"] == "POST"
        if is_login:
            while self.login_attempts and self.login_attempts[0] < clock - 900:
                self.login_attempts.popleft()
            if len(self.login_attempts) >= 10:
                return await fail(429, "login_rate_limit", "Demasiados intentos de acceso. Espera 15 minutos.")
            self.login_attempts.append(clock)
        else:
            token = Request(scope).cookies.get(self.settings.cookie_name, "")
            try:
                authenticated = await to_thread.run_sync(self.authentication.authenticated, token)
            except SQLAlchemyError:
                return await fail(503, "database_error", "No se pudo comprobar la sesión. Inténtalo de nuevo.")
            if not authenticated:
                return await fail(401, "unauthorized", "Inicia sesión para continuar.")
        size = 0
        async def limited_receive():
            nonlocal size
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > (4096 if is_login else self.max_bytes + 64 * 1024):
                    raise HTTPException(413, "La solicitud supera el tamaño permitido.")
            return message
        async def logged_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [(b"x-request-id", request_id.encode()), (b"x-content-type-options", b"nosniff"), (b"cache-control", b"no-store")]
                logger.info(json.dumps({"event": "request", "request_id": request_id, "method": scope["method"], "path": scope["path"], "status": message["status"], "duration_ms": round((monotonic() - clock) * 1000, 2)}))
            await send(message)
        await self.app(scope, limited_receive, logged_send)


def create_app(settings: Settings | None = None, engine=None):
    settings = settings or Settings.from_env()
    repository = Repository(engine if engine is not None else make_engine(settings.database_url))
    services = Services(repository)
    app = FastAPI(title="RiskEngine", version="0.1.0", description="MVP local. Motor experimental configurable; no validado académicamente.")
    app.state.repository, app.state.services = repository, services
    authentication = Authentication(repository.engine, settings)
    app.state.authentication = authentication
    app.add_middleware(GuardMiddleware, authentication=authentication, settings=settings)

    @app.post("/api/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        if not settings.admin_email or not settings.admin_password_hash:
            raise AppError("auth_not_configured", "El administrador debe configurar el acceso personal.", 503)
        valid_password = verify_password(body.password, settings.admin_password_hash)
        if not secrets.compare_digest(body.email.strip().casefold().encode(), settings.admin_email.encode()) or not valid_password:
            raise AppError("invalid_credentials", "Correo o contraseña incorrectos.", 401)
        token = authentication.create_session(request.cookies.get(settings.cookie_name, ""))
        response.set_cookie(settings.cookie_name, token, max_age=8 * 3600, httponly=True,
                            secure=settings.secure_cookie, samesite="strict", path="/")
        return {"email": settings.admin_email}

    @app.get("/api/auth/me")
    def current_user():
        return {"email": settings.admin_email}

    @app.post("/api/auth/logout", status_code=204)
    def logout(request: Request):
        authentication.revoke(request.cookies.get(settings.cookie_name, ""))
        response = Response(status_code=204)
        response.delete_cookie(settings.cookie_name, path="/", secure=settings.secure_cookie,
                               httponly=True, samesite="strict")
        return response

    @app.exception_handler(AppError)
    async def app_error(request: Request, exc: AppError):
        return JSONResponse({"error": {"code": exc.code, "message": exc.message}}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return JSONResponse({"error": {"code": "validation_error", "message": "Revisa los campos, sus tipos y los límites permitidos.",
                                       "fields": [".".join(str(part) for part in error["loc"]) for error in exc.errors()]}}, status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse({"error": {"code": "http_error", "message": str(exc.detail)}}, status_code=exc.status_code)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        logger.error(json.dumps({"event": "database_error", "type": type(exc).__name__}))
        return JSONResponse({"error": {"code": "database_error", "message": "No se pudo completar la operación de datos."}}, status_code=503)

    @app.get("/health")
    def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/api/audits")
    def list_audits(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return repository.audits(limit, offset)

    @app.post("/api/audits", status_code=201)
    def create_audit(body: AuditCreate):
        return repository.create_audit(body.name, body.scope)

    @app.get("/api/audits/{audit_id}/imports")
    def imports(audit_id: UUID, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return repository.imports(str(audit_id), limit, offset)

    @app.post("/api/audits/{audit_id}/imports", status_code=201)
    def import_xml(audit_id: UUID, response: Response, file: UploadFile = File()):
        try:
            content = file.file.read(settings.max_upload_bytes + 1)
            if len(content) > settings.max_upload_bytes:
                raise AppError("file_too_large", "El archivo supera 10 MiB.", 413)
            result = services.import_report(str(audit_id), Path(file.filename or "report.xml").name[:255], content)
            if result["reused"]:
                response.status_code = 200
            return result
        finally:
            file.file.close()

    @app.get("/api/audits/{audit_id}/findings")
    def findings(audit_id: UUID, import_id: UUID | None = None, limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0), q: str = Query("", max_length=200), sort: Literal["original", "name", "cvss_desc", "cvss_asc", "host"] = "original"):
        return repository.findings(str(audit_id), str(import_id) if import_id else None, limit, offset, q, sort)

    @app.get("/api/audits/{audit_id}/findings/{finding_id}/detector")
    def finding_detector(audit_id: UUID, finding_id: UUID):
        return repository.finding_detector(str(audit_id), str(finding_id))

    @app.get("/api/audits/{audit_id}/assets")
    def assets(audit_id: UUID, limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0)):
        return repository.assets(str(audit_id), limit, offset)

    @app.patch("/api/audits/{audit_id}/assets/{asset_id}")
    def context(audit_id: UUID, asset_id: UUID, body: ContextUpdate):
        return repository.update_asset(str(audit_id), str(asset_id), body.model_dump(exclude_unset=True))

    @app.patch("/api/audits/{audit_id}/findings/{finding_id}")
    def finding_status(audit_id: UUID, finding_id: UUID, body: FindingUpdate):
        return repository.update_finding(str(audit_id), str(finding_id), body.status)

    @app.post("/api/audits/{audit_id}/findings/{finding_id}/cves/{cve}/reviews", status_code=201)
    def review_cve(audit_id: UUID, finding_id: UUID, cve: str, body: CVEReviewCreate):
        return repository.review_cve(str(audit_id), str(finding_id), cve, body.model_dump())

    @app.post("/api/audits/{audit_id}/enrichments")
    def enrich(audit_id: UUID):
        return services.enrich(str(audit_id))

    @app.post("/api/audits/{audit_id}/runs", status_code=201)
    def prioritize(audit_id: UUID, body: RunCreate):
        return services.create_run(str(audit_id), body)

    @app.get("/api/audits/{audit_id}/runs")
    def runs(audit_id: UUID, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return repository.runs(str(audit_id), limit, offset)

    @app.get("/api/audits/{audit_id}/runs/{run_id}/results")
    def results(audit_id: UUID, run_id: UUID, limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0)):
        return repository.results(str(audit_id), str(run_id), limit, offset)

    @app.get("/api/audits/{audit_id}/runs/{run_id}/comparison")
    def comparison(audit_id: UUID, run_id: UUID):
        payload = repository.results(str(audit_id), str(run_id), 10_000, 0)
        return JSONResponse(compare_snapshot(payload), headers={"Content-Disposition": f'attachment; filename="comparacion-{run_id}.json"'})

    @app.get("/api/audits/{audit_id}/runs/{run_id}/export")
    def export(audit_id: UUID, run_id: UUID, format: Literal["json", "pdf", "csv"] = "json"):
        payload = repository.results(str(audit_id), str(run_id), 10_000, 0)
        headers = {"Content-Disposition": f'attachment; filename="riskengine-{run_id}.{format}"'}
        if format == "pdf":
            return Response(content=render_pdf(payload), media_type="application/pdf", headers=headers)
        if format == "csv":
            return Response(content=render_csv(payload), media_type="text/csv", headers=headers)
        return JSONResponse(payload, headers=headers)

    frontend = PROJECT_ROOT / "frontend/dist"
    if frontend.is_dir():
        app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
    return app
