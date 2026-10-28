from datetime import datetime, UTC
from uuid import uuid4
from sqlalchemy import JSON, CheckConstraint, ForeignKey, ForeignKeyConstraint, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    return str(uuid4())


def now() -> str:
    return datetime.now(UTC).isoformat()


class Base(DeclarativeBase):
    pass


class Audit(Base):
    __tablename__ = "audits"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(160))
    scope: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class Import(Base):
    __tablename__ = "imports"
    __table_args__ = (UniqueConstraint("audit_id", "sha256"), UniqueConstraint("id", "audit_id"))
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str] = mapped_column(ForeignKey("audits.id"), index=True)
    sha256: Mapped[str] = mapped_column(String(64))
    filename: Mapped[str] = mapped_column(String(255))
    content: Mapped[bytes] = mapped_column(LargeBinary)
    report_metadata: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("audit_id", "identifier"), UniqueConstraint("id", "audit_id"),
        CheckConstraint("criticality IS NULL OR criticality BETWEEN 1 AND 5"),
        CheckConstraint("exposure IS NULL OR exposure BETWEEN 1 AND 5"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str] = mapped_column(ForeignKey("audits.id"), index=True)
    identifier: Mapped[str] = mapped_column(String(255))
    criticality: Mapped[int | None]
    exposure: Mapped[int | None]


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        ForeignKeyConstraint(["import_id", "audit_id"], ["imports.id", "imports.audit_id"]),
        ForeignKeyConstraint(["asset_id", "audit_id"], ["assets.id", "assets.audit_id"]),
        UniqueConstraint("import_id", "external_id"), UniqueConstraint("id", "audit_id"),
        CheckConstraint("status IN ('open', 'reviewing', 'resolved')"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str] = mapped_column(String(36), index=True)
    import_id: Mapped[str] = mapped_column(String(36), index=True)
    asset_id: Mapped[str] = mapped_column(String(36), index=True)
    external_id: Mapped[str] = mapped_column(String(255))
    position: Mapped[int] = mapped_column(default=0, server_default="0")
    name: Mapped[str] = mapped_column(Text)
    oid: Mapped[str] = mapped_column(Text)
    port: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[float | None]
    cvss: Mapped[float | None]
    vector: Mapped[str | None] = mapped_column(Text)
    original_vectors: Mapped[list[str] | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="open")


class CVE(Base):
    __tablename__ = "cves"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)


class FindingCVE(Base):
    __tablename__ = "finding_cves"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    cve: Mapped[str] = mapped_column(ForeignKey("cves.id"), primary_key=True)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    cve: Mapped[str] = mapped_column(ForeignKey("cves.id"), index=True)
    source: Mapped[str] = mapped_column(String(16), index=True)
    state: Mapped[str] = mapped_column(String(20))
    value: Mapped[float | bool | None] = mapped_column(JSON)
    data_date: Mapped[str | None] = mapped_column(String(40))
    fetched_at: Mapped[str] = mapped_column(String(40), default=now)
    provenance: Mapped[str] = mapped_column(Text)


class Run(Base):
    __tablename__ = "runs"
    __table_args__ = (UniqueConstraint("id", "audit_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str] = mapped_column(ForeignKey("audits.id"), index=True)
    version: Mapped[str] = mapped_column(String(100))
    configuration: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class Result(Base):
    __tablename__ = "results"
    __table_args__ = (
        ForeignKeyConstraint(["run_id", "audit_id"], ["runs.id", "runs.audit_id"]),
        ForeignKeyConstraint(["finding_id", "audit_id"], ["findings.id", "findings.audit_id"]),
        UniqueConstraint("run_id", "finding_id"),
        CheckConstraint("score IS NULL OR score BETWEEN 0 AND 100"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    audit_id: Mapped[str] = mapped_column(String(36))
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    finding_id: Mapped[str] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(20))
    score: Mapped[float | None]
    explanation: Mapped[str] = mapped_column(Text)
    snapshot: Mapped[dict] = mapped_column(JSON)



class CVEReview(Base):
    """Append-only decisions; the declared reviewer is not an authenticated identity."""
    __tablename__ = "cve_reviews"
    __table_args__ = (
        ForeignKeyConstraint(["finding_id", "cve"], ["finding_cves.finding_id", "finding_cves.cve"]),
        CheckConstraint("status IN ('pending', 'applicable', 'not_applicable')"),
        CheckConstraint("length(trim(reviewer)) > 0 AND length(trim(rationale)) > 0"),
    )
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(36), index=True)
    cve: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(20))
    reviewer: Mapped[str] = mapped_column(String(160))
    rationale: Mapped[str] = mapped_column(Text)
    reviewed_at: Mapped[str] = mapped_column(String(40), default=now)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    credential_revision: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[str] = mapped_column(String(40), index=True)


class PersonalAccount(Base):
    __tablename__ = "personal_account"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    email: Mapped[str] = mapped_column(String(254))
    password_hash: Mapped[str] = mapped_column(String(256))
