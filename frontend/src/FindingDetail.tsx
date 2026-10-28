import { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { api } from './api';
import { DetectorDetails } from './DetectorDetails';
import { CVEReviewEditor } from './CVEReviewEditor';
import type { Finding } from './types';

type DetailTab = 'evidence' | 'detector' | 'reviews';
export function FindingDetail({ finding, auditId, refresh }: {
  finding: Finding; auditId: string; refresh: () => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<DetailTab>('evidence');
  const [notice, setNotice] = useState('');
  useEffect(() => {
    if (!open) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    dialog.current?.showModal();
    return () => { document.body.style.overflow = previous; };
  }, [open]);
  function close() {
    dialog.current?.close(); setOpen(false); trigger.current?.focus();
  }
  const pending = (finding.cve_reviews ?? []).filter(review => review.status === 'pending').length;
  return <>
    <button ref={trigger} type="button" className="finding-detail-button" aria-label={`Ver detalle de ${finding.name}, ${finding.port || 'sin puerto'}`} onClick={() => { setTab('evidence'); setNotice(''); setOpen(true); }}>Ver detalle <span aria-hidden="true">↗</span></button>
    {open && createPortal(<dialog ref={dialog} className="finding-dialog" aria-labelledby={titleId} onCancel={event => { event.preventDefault(); close(); }}>
      <header className="finding-dialog-header">
        <div><span className="detail-kicker">DETALLE DEL HALLAZGO</span><h2 id={titleId}>{finding.name}</h2></div>
        <button type="button" className="quiet" onClick={close} autoFocus aria-label="Cerrar detalle">Cerrar ×</button>
      </header>
      <div className="finding-facts">
        <div><span>Activo</span><strong>{finding.host}</strong></div>
        <div><span>Puerto</span><strong>{finding.port || 'No indicado'}</strong></div>
        <div><span>CVSS 3.1</span><strong>{finding.cvss?.toFixed(1) ?? 'No disponible'}</strong></div>
        <div><span>Revisión CVE</span><strong>{!finding.cves.length ? 'Sin CVE' : pending ? `${pending} ${pending === 1 ? 'pendiente' : 'pendientes'}` : 'Completada'}</strong></div>
      </div>
      <nav className="detail-tabs" aria-label="Contenido del hallazgo">
        {([['evidence', 'Evidencia'], ['detector', 'Información del detector'], ['reviews', 'Revisión de CVE']] as const).map(([value, label]) => <button type="button" key={value} className={tab === value ? 'active' : ''} aria-pressed={tab === value} onClick={() => setTab(value)}>{label}</button>)}
      </nav>
      <div className="finding-dialog-body">
        {notice && <p className="detail-notice" role="status">{notice}</p>}
        {tab === 'evidence' && <section>
          <h3>Evidencia del escaneo</h3>
          {finding.description.trim() ? <p className="finding-description">{finding.description}</p> : <div className="evidence-empty"><strong>Sin evidencia detallada en el reporte</strong><p>El escáner registró este hallazgo, pero dejó vacía su descripción. Consulta la información del detector para conocer el contexto.</p><button type="button" className="quiet" onClick={() => setTab('detector')}>Ver información del detector</button></div>}
          <h3>Referencias CVE</h3><p className="detail-cves">{finding.cves.join(' · ') || 'Este hallazgo no incluye referencias CVE.'}</p>
          <details className="technical-details"><summary>Datos técnicos de la puntuación</summary><p>Severidad original: {finding.severity ?? 'No indicada'}.</p><p>{finding.cvss_admission?.message ?? 'Solo se admite un vector CVSS Base 3.1 explícito.'}</p>{finding.vector && <p className="detail-cves">{finding.vector}</p>}</details>
        </section>}
        {tab === 'detector' && <DetectorDetails auditId={auditId} findingId={finding.id} expanded/>}
        {tab === 'reviews' && <section className="cve-review-list"><h3>¿Estos CVE afectan a este activo?</h3><p>Revisa producto, versión y configuración antes de decidir. La referencia del escáner no basta para confirmar su aplicabilidad.</p><p className="muted">El responsable se registra como una declaración, no como una identidad verificada.</p>
          {!finding.cves.length && <p>Este hallazgo no tiene CVE asociados para revisar.</p>}
          {(finding.cve_reviews ?? []).map(review => <CVEReviewEditor key={`${review.cve}-${review.id ?? 'pending'}`} review={review} save={async decision => {
            await api(`/audits/${auditId}/findings/${finding.id}/cves/${review.cve}/reviews`, 'POST', decision);
            await refresh(); setNotice('Revisión guardada. Genera una nueva ejecución para utilizarla.');
          }}/>)}</section>}
      </div>
    </dialog>, document.body)}
  </>;
}
