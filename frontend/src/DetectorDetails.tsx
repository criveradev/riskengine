import { useEffect, useRef, useState } from 'react';
import { api } from './api';

type DetectorInfo = {
  name: string; oid: string; family: string; version: string;
  summary: string; affected: string; insight: string; impact: string;
  detection: string; solution: string; references: string[];
};
type DetectorResponse = { detector: DetectorInfo; source: { filename: string; sha256: string } };
const fields: [keyof Omit<DetectorInfo, 'references'>, string][] = [
  ['summary', 'Resumen'], ['affected', 'Productos y versiones afectados'],
  ['insight', 'Detalles técnicos'], ['impact', 'Impacto descrito'],
  ['detection', 'Método de detección'], ['solution', 'Solución indicada'],
];

export function DetectorDetails({ auditId, findingId, token, expanded = false }: { auditId: string; findingId: string; token: string; expanded?: boolean }) {
  const [data, setData] = useState<DetectorResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const inFlight = useRef(false);
  async function load() {
    if (inFlight.current || data) return;
    inFlight.current = true; setLoading(true); setError('');
    try { setData(await api<DetectorResponse>(`/audits/${auditId}/findings/${findingId}/detector`, token)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'No se pudo cargar la información del detector.'); }
    finally { inFlight.current = false; setLoading(false); }
  }
  useEffect(() => { if (expanded) void load(); }, [expanded]);
  const content = <>
    <p className="muted">Información general del detector incluida en el XML. No es evidencia específica de este equipo ni confirma por sí sola la aplicabilidad del CVE.</p>
    {loading && <p role="status">Cargando información…</p>}
    {error && <div role="alert"><p>{error}</p><button type="button" className="quiet" onClick={() => void load()}>Reintentar</button></div>}
    {data && <div className="detector-info">
      <p><strong>{data.detector.name || 'Detector sin nombre'}</strong></p>
      <p className="muted">OID: {data.detector.oid || 'No indicado'} · Familia: {data.detector.family || 'No indicada'} · Versión del detector: {data.detector.version || 'No indicada'}</p>
      {fields.map(([key, title]) => <div key={key}><h4>{title}</h4><p className="finding-description">{data.detector[key] || 'No informado en el XML.'}</p></div>)}
      <h4>Referencias del detector</h4>
      {data.detector.references.length ? <ul>{data.detector.references.map(url => <li key={url}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a></li>)}</ul> : <p>No se incluyen enlaces web en el XML.</p>}
      <p className="muted">Fuente: {data.source.filename}</p>
    </div>}
  </>;
  return expanded ? <section>{content}</section> : <details className="finding-secondary" onToggle={event => { if (event.currentTarget.open && !error) void load(); }}><summary>Información del detector</summary>{content}</details>;
}
