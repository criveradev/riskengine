from collections import defaultdict
from hashlib import sha256
from sqlalchemy import func, select, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer

from .domain import AppError
from .diagnostics import cvss_admission
from .models import CVEReview, Asset, Audit, CVE, Evidence, Finding, FindingCVE, Import, Result, Run
from .parser import ParsedReport
from .detector import detector_information


class Repository:
    def __init__(self, engine):
        self.engine = engine

    def session(self):
        return Session(self.engine, expire_on_commit=False)

    @staticmethod
    def require_audit(session, audit_id):
        if session.get(Audit, audit_id) is None:
            raise AppError("not_found", "Auditoría no encontrada.", 404)

    def audits(self, limit, offset):
        with self.session() as session:
            rows = session.scalars(select(Audit).order_by(Audit.created_at.desc(), Audit.id).limit(limit).offset(offset)).all()
            return {"items": [{"id": row.id, "name": row.name, "scope": row.scope, "created_at": row.created_at} for row in rows], "total": session.scalar(select(func.count()).select_from(Audit))}

    def create_audit(self, name, scope):
        with self.session() as session, session.begin():
            audit = Audit(name=name, scope=scope)
            session.add(audit)
            session.flush()
            return {"id": audit.id, "name": name, "scope": scope}

    def save_import(self, audit_id: str, filename: str, content: bytes, parsed: ParsedReport):
        digest = sha256(content).hexdigest()
        for attempt in range(2):
            try:
                with self.session() as session, session.begin():
                    self.require_audit(session, audit_id)
                    existing = session.scalar(select(Import).options(defer(Import.content)).where(Import.audit_id == audit_id, Import.sha256 == digest))
                    if existing:
                        return self.import_summary(session, existing, True)
                    report = Import(audit_id=audit_id, filename=filename, sha256=digest, content=content, report_metadata=parsed.metadata)
                    session.add(report)
                    session.flush()
                    assets = {row.identifier: row for row in session.scalars(select(Asset).where(Asset.audit_id == audit_id))}
                    for identifier in sorted({finding.host for finding in parsed.findings} - assets.keys()):
                        asset = Asset(audit_id=audit_id, identifier=identifier)
                        session.add(asset)
                        assets[identifier] = asset
                    desired_cves = {cve for finding in parsed.findings for cve in finding.cves}
                    known_cves = set(session.scalars(select(CVE.id).where(CVE.id.in_(desired_cves))))
                    session.add_all(CVE(id=cve) for cve in desired_cves - known_cves)
                    session.flush()
                    mappings = []
                    for position, item in enumerate(parsed.findings, start=1):
                        row = Finding(audit_id=audit_id, import_id=report.id, asset_id=assets[item.host].id, external_id=item.external_id,
                                      position=position, name=item.name, oid=item.oid, port=item.port, description=item.description, severity=item.severity, cvss=item.cvss, vector=item.vector, original_vectors=list(item.original_vectors))
                        session.add(row)
                        mappings.append((row, item.cves))
                    session.flush()
                    session.add_all(FindingCVE(finding_id=row.id, cve=cve) for row, cves in mappings for cve in cves)
                    session.flush()
                    return self.import_summary(session, report, False)
            except IntegrityError as exc:
                if attempt == 1:
                    raise AppError("import_conflict", "Otra carga modificó estos datos. Reintenta la importación.", 409) from exc
        raise AssertionError("Import retry exhausted")

    @staticmethod
    def import_summary(session, row, reused=False):
        return {"id": row.id, "audit_id": row.audit_id, "filename": row.filename, "sha256": row.sha256,
                "created_at": row.created_at, "reused": reused, "metadata": row.report_metadata,
                "finding_count": session.scalar(select(func.count()).select_from(Finding).where(Finding.import_id == row.id))}

    def imports(self, audit_id, limit, offset):
        with self.session() as session:
            self.require_audit(session, audit_id)
            rows = session.scalars(select(Import).options(defer(Import.content)).where(Import.audit_id == audit_id).order_by(Import.created_at.desc(), Import.id).limit(limit).offset(offset))
            # Counts are aggregated once; large report payloads are never serialized.
            counts = dict(session.execute(select(Finding.import_id, func.count()).where(Finding.audit_id == audit_id).group_by(Finding.import_id)).all())
            return {"items": [{"id": r.id, "filename": r.filename, "sha256": r.sha256, "created_at": r.created_at, "finding_count": counts.get(r.id, 0), "metadata": r.report_metadata} for r in rows], "total": session.scalar(select(func.count()).select_from(Import).where(Import.audit_id == audit_id))}

    def findings(self, audit_id, import_id=None, limit=100, offset=0, q="", sort="original"):
        with self.session() as session:
            self.require_audit(session, audit_id)
            if import_id and not session.scalar(select(Import.id).where(Import.id == import_id, Import.audit_id == audit_id)):
                raise AppError("not_found", "Importación no encontrada en esta auditoría.", 404)
            conditions = [Finding.audit_id == audit_id]
            if import_id:
                conditions.append(Finding.import_id == import_id)
            if q.strip():
                term = q.strip().lower()
                matching_cve = select(FindingCVE.finding_id).where(
                    FindingCVE.finding_id == Finding.id,
                    func.lower(FindingCVE.cve).contains(term, autoescape=True),
                ).exists()
                conditions.append(or_(
                    func.lower(Finding.name).contains(term, autoescape=True),
                    func.lower(Asset.identifier).contains(term, autoescape=True),
                    func.lower(Finding.port).contains(term, autoescape=True),
                    matching_cve,
                ))
            orders = {
                "original": (Finding.import_id, Finding.position, Finding.id),
                "name": (func.lower(Finding.name), Finding.id),
                "cvss_desc": (Finding.cvss.desc().nulls_last(), func.lower(Finding.name), Finding.id),
                "cvss_asc": (Finding.cvss.asc().nulls_last(), func.lower(Finding.name), Finding.id),
                "host": (Asset.identifier, func.lower(Finding.name), Finding.id),
            }
            if sort not in orders:
                raise AppError("validation", "Orden de hallazgos inválido.", 422)
            rows = session.execute(select(Finding, Asset).join(Asset, Finding.asset_id == Asset.id).where(*conditions).order_by(*orders[sort]).limit(limit).offset(offset)).all()
            cves = defaultdict(list)
            for finding_id, cve in session.execute(select(FindingCVE.finding_id, FindingCVE.cve).where(FindingCVE.finding_id.in_([f.id for f, _ in rows])).order_by(FindingCVE.cve)):
                cves[finding_id].append(cve)
            reviews = defaultdict(dict)
            latest_review_ids = (
                select(func.max(CVEReview.id))
                .where(CVEReview.finding_id.in_([f.id for f, _ in rows]))
                .group_by(CVEReview.finding_id, CVEReview.cve)
            )
            for review in session.scalars(select(CVEReview).where(CVEReview.id.in_(latest_review_ids))):
                reviews[review.finding_id].setdefault(review.cve, self.review_dict(review))
            return {"items": [{"id": f.id, "external_id": f.external_id, "import_id": f.import_id, "asset_id": a.id, "host": a.identifier,
                               "name": f.name, "port": f.port, "description": f.description, "severity": f.severity, "cvss": f.cvss, "vector": f.vector, "original_vectors": f.original_vectors,
                               "cvss_admission": cvss_admission({"cvss": f.cvss, "severity": f.severity, "original_vectors": f.original_vectors}),
                               "cves": cves[f.id], "cve_reviews": [reviews[f.id].get(cve, {"cve": cve, "status": "pending", "reviewer": None, "rationale": None, "reviewed_at": None}) for cve in cves[f.id]], "criticality": a.criticality, "exposure": a.exposure, "status": f.status} for f, a in rows],
                    "total": session.scalar(select(func.count()).select_from(Finding).join(Asset, Finding.asset_id == Asset.id).where(*conditions))}

    def finding_detector(self, audit_id: str, finding_id: str):
        with self.session() as session:
            row = session.execute(
                select(Finding.external_id, Import.content, Import.filename, Import.sha256)
                .join(Import, Finding.import_id == Import.id)
                .where(Finding.id == finding_id, Finding.audit_id == audit_id, Import.audit_id == audit_id)
            ).one_or_none()
            if row is None:
                raise AppError("not_found", "Hallazgo no encontrado en esta auditoría.", 404)
        return {"detector": detector_information(row.content, row.external_id),
                "source": {"filename": row.filename, "sha256": row.sha256}}

    def assets(self, audit_id, limit, offset):
        with self.session() as session:
            self.require_audit(session, audit_id)
            rows = session.scalars(select(Asset).where(Asset.audit_id == audit_id).order_by(Asset.identifier).limit(limit).offset(offset))
            return {"items": [{"id": a.id, "identifier": a.identifier, "criticality": a.criticality, "exposure": a.exposure} for a in rows], "total": session.scalar(select(func.count()).select_from(Asset).where(Asset.audit_id == audit_id))}

    def update_asset(self, audit_id, asset_id, values):
        with self.session() as session, session.begin():
            row = session.scalar(select(Asset).where(Asset.id == asset_id, Asset.audit_id == audit_id))
            if not row:
                raise AppError("not_found", "Activo no encontrado.", 404)
            for key, value in values.items():
                setattr(row, key, value)
            return {"id": row.id, "criticality": row.criticality, "exposure": row.exposure}

    def update_finding(self, audit_id, finding_id, status):
        with self.session() as session, session.begin():
            row = session.scalar(select(Finding).where(Finding.id == finding_id, Finding.audit_id == audit_id))
            if not row:
                raise AppError("not_found", "Hallazgo no encontrado.", 404)
            row.status = status
            return {"id": row.id, "status": status}

    def cves(self, audit_id):
        with self.session() as session:
            self.require_audit(session, audit_id)
            return sorted(set(session.scalars(select(FindingCVE.cve).join(Finding, Finding.id == FindingCVE.finding_id).where(Finding.audit_id == audit_id))))

    def save_evidence(self, entries):
        with self.session() as session, session.begin():
            session.add_all(Evidence(**entry) for entry in entries)

    def latest_evidence(self, cves):
        with self.session() as session:
            rows = session.scalars(select(Evidence).where(Evidence.cve.in_(cves)).order_by(Evidence.fetched_at.desc(), Evidence.id))
            latest = {}
            for row in rows:
                latest.setdefault((row.cve, row.source), {"id": row.id, "cve": row.cve, "source": row.source, "state": row.state, "value": row.value,
                                                         "data_date": row.data_date, "fetched_at": row.fetched_at, "provenance": row.provenance})
            return latest

    def save_run(self, audit_id, version, configuration, results):
        with self.session() as session, session.begin():
            self.require_audit(session, audit_id)
            run = Run(audit_id=audit_id, version=version, configuration=configuration)
            session.add(run)
            session.flush()
            session.add_all(Result(audit_id=audit_id, run_id=run.id, finding_id=finding_id, status=output.status, score=output.score,
                                   explanation=output.explanation, snapshot=snapshot) for finding_id, output, snapshot in results)
            session.flush()
            return {"id": run.id, "version": run.version, "created_at": run.created_at, "configuration": configuration}

    def runs(self, audit_id, limit, offset):
        with self.session() as session:
            self.require_audit(session, audit_id)
            rows = session.scalars(select(Run).where(Run.audit_id == audit_id).order_by(Run.created_at.desc(), Run.id).limit(limit).offset(offset))
            return {"items": [{"id": r.id, "version": r.version, "created_at": r.created_at, "configuration": r.configuration} for r in rows], "total": session.scalar(select(func.count()).select_from(Run).where(Run.audit_id == audit_id))}

    def results(self, audit_id, run_id, limit, offset):
        with self.session() as session:
            run = session.scalar(select(Run).where(Run.id == run_id, Run.audit_id == audit_id))
            if not run:
                raise AppError("not_found", "Ejecución no encontrada en esta auditoría.", 404)
            rows = session.scalars(select(Result).where(Result.run_id == run_id).order_by(Result.score.desc().nulls_last(), Result.finding_id).limit(limit).offset(offset))
            return {"items": [{"id": r.id, "finding_id": r.finding_id, "score": r.score, "status": r.status, "explanation": r.explanation, "snapshot": r.snapshot} for r in rows],
                    "total": session.scalar(select(func.count()).select_from(Result).where(Result.run_id == run_id)),
                    "run": {"id": run.id, "version": run.version, "configuration": run.configuration, "created_at": run.created_at}}


    @staticmethod
    def review_dict(row):
        return {"id": row.id, "cve": row.cve, "status": row.status,
                "reviewer": row.reviewer, "rationale": row.rationale, "reviewed_at": row.reviewed_at}

    def review_cve(self, audit_id: str, finding_id: str, cve: str, values: dict):
        with self.session() as session, session.begin():
            reference = session.scalar(select(FindingCVE).join(Finding, Finding.id == FindingCVE.finding_id).where(
                Finding.audit_id == audit_id, Finding.id == finding_id, FindingCVE.cve == cve))
            if reference is None:
                raise AppError("not_found", "Referencia CVE no encontrada en este hallazgo y auditoría.", 404)
            row = CVEReview(finding_id=finding_id, cve=cve, **values)
            session.add(row)
            session.flush()
            return self.review_dict(row)
