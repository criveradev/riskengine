import { AssetEditor, Pager } from './AuditControls';
import { useOperation } from './useOperation';
import { FindingDetail } from './FindingDetail';
import { useEffect, useState, type FormEvent } from 'react';
import { api, apiFile } from './api';
import { profiles } from './profiles';
import type { Asset, Audit, Feature, Finding, Page, RankingResult, Report, ResultPage, Run } from './types';

const emptyPage = <T,>(): Page<T> => ({ items: [], total: 0 });
const FINDINGS_PAGE_SIZE = 10;
const features: Feature[] = ['cvss', 'epss', 'kev', 'criticality', 'exposure'];
const labels: Record<Feature, string> = { cvss: 'CVSS Base 3.1', epss: 'EPSS', kev: 'CISA KEV', criticality: 'Criticidad', exposure: 'Exposición' };
const formatDate = (value: string) => new Date(value).toLocaleString('es-CL');

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('riskengine-token') ?? '');
  const [keyInput, setKeyInput] = useState('');
  const { busy, error, notice, setNotice, perform } = useOperation();
  const [audits, setAudits] = useState<Page<Audit>>(emptyPage());
  const [audit, setAudit] = useState<Audit | null>(null);
  const [reports, setReports] = useState<Page<Report>>(emptyPage());
  const [reportId, setReportId] = useState('');
  const [findings, setFindings] = useState<Page<Finding>>(emptyPage());
  const [findingOffset, setFindingOffset] = useState(0);
  const [searchInput, setSearchInput] = useState('');
  const [sortInput, setSortInput] = useState('original');
  const [findingFilter, setFindingFilter] = useState({ q: '', sort: 'original' });
  function resetFindingFilter() {
    setSearchInput(''); setSortInput('original'); setFindingFilter({ q: '', sort: 'original' });
  }
  const [assets, setAssets] = useState<Page<Asset>>(emptyPage());
  const [assetOffset, setAssetOffset] = useState(0);
  const [runs, setRuns] = useState<Page<Run>>(emptyPage());
  const [ranking, setRanking] = useState<ResultPage | null>(null);
  const [rankingOffset, setRankingOffset] = useState(0);
  const [weights, setWeights] = useState<Record<Feature, string>>({ cvss: '', epss: '', kev: '', criticality: '', exposure: '' });
  const [profile, setProfile] = useState('custom');
  const [age, setAge] = useState('');
  const [tab, setTab] = useState<'findings' | 'context' | 'ranking'>('findings');

  useEffect(() => {
    if (token) void perform(async () => setAudits(await api<Page<Audit>>('/audits?limit=100', token)));
  }, [token]);

  function fetchFindings(auditId: string, importId: string, offset = 0, filter = { q: '', sort: 'original' }) {
    return api<Page<Finding>>(`/audits/${auditId}/findings?import_id=${importId}&limit=${FINDINGS_PAGE_SIZE}&offset=${offset}${filter.q ? `&q=${encodeURIComponent(filter.q)}` : ''}${filter.sort !== 'original' ? `&sort=${encodeURIComponent(filter.sort)}` : ''}`, token);
  }

  async function loadFindings(auditId: string, importId: string, offset = 0) {
    setFindings(await fetchFindings(auditId, importId, offset, findingFilter));
    setFindingOffset(offset);
  }

  async function applyFindingFilter(clear = false) {
    if (!audit || !reportId) return;
    const filter = clear ? { q: '', sort: 'original' } : { q: searchInput.trim(), sort: sortInput };
    await perform(async () => {
      const page = await fetchFindings(audit.id, reportId, 0, filter);
      setFindings(page); setFindingOffset(0); setFindingFilter(filter);
      if (clear) resetFindingFilter();
    });
  }

  async function loadReport(importId: string) {
    if (!audit) return;
    const findingPage = await fetchFindings(audit.id, importId);
    resetFindingFilter();
    setReportId(importId); setFindings(findingPage); setFindingOffset(0);
    setRanking(null); setRankingOffset(0);
  }

  async function loadAudit(selected: Audit, preferredImport?: string) {
    const [imports, assetPage, runPage] = await Promise.all([
      api<Page<Report>>(`/audits/${selected.id}/imports?limit=100`, token),
      api<Page<Asset>>(`/audits/${selected.id}/assets?limit=100`, token),
      api<Page<Run>>(`/audits/${selected.id}/runs?limit=100`, token),
    ]);
    const nextImport = preferredImport ?? imports.items[0]?.id ?? '';
    const findingPage = nextImport ? await fetchFindings(selected.id, nextImport) : emptyPage<Finding>();
    resetFindingFilter();
    setAudit(selected); setReports(imports); setAssets(assetPage); setRuns(runPage);
    setAssetOffset(0); setRanking(null); setRankingOffset(0);
    setReportId(nextImport);
    setFindings(findingPage); setFindingOffset(0);
  }

  async function login(event: FormEvent) {
    event.preventDefault();
    await perform(async () => {
      await api<Page<Audit>>('/audits?limit=1', keyInput);
      sessionStorage.setItem('riskengine-token', keyInput);
      setToken(keyInput); setKeyInput('');
    });
  }

  async function createAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget, data = new FormData(form);
    await perform(async () => {
      const created = await api<Audit>('/audits', token, 'POST', { name: data.get('name'), scope: data.get('scope') });
      setAudits(await api<Page<Audit>>('/audits?limit=100', token));
      await loadAudit(created); form.reset(); setNotice('Auditoría creada. Ya puedes cargar un reporte.');
    });
  }

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!audit) return;
    const form = event.currentTarget, body = new FormData(form);
    await perform(async () => {
      const imported = await api<{ id: string; reused: boolean; finding_count: number }>(`/audits/${audit.id}/imports`, token, 'POST', body);
      await loadAudit(audit, imported.id); form.reset(); setTab('findings');
      setNotice(imported.reused ? 'Este archivo ya estaba importado. Se reutilizó sin duplicar hallazgos.' : `Reporte importado: ${imported.finding_count} hallazgos.`);
    });
  }

  async function loadRanking(runId: string, offset = 0) {
    if (!audit) return;
    setRanking(await api<ResultPage>(`/audits/${audit.id}/runs/${runId}/results?limit=100&offset=${offset}`, token));
    setRankingOffset(offset); setTab('ranking');
  }

  async function createRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!audit || !reportId) return;
    await perform(async () => {
      const numbers = Object.fromEntries(features.map(key => [key, Number(weights[key])]));
      if (features.some(key => weights[key] === '') || Math.abs(Object.values(numbers).reduce((a, b) => a + b, 0) - 1) > 0.000001) throw new Error('Indica los cinco pesos. Deben sumar uno; cero desactiva una entrada.');
      const run = await api<Run>(`/audits/${audit.id}/runs`, token, 'POST', { import_id: reportId, weights: numbers, max_evidence_age_days: Number(age), acknowledge_experimental: true });
      setRuns(await api<Page<Run>>(`/audits/${audit.id}/runs?limit=100`, token));
      await loadRanking(run.id); setNotice('Ejecución guardada con sus entradas y evidencias.');
    });
  }

  async function downloadComparison() {
    if (!audit || !ranking) return;
    await perform(async () => {
      const result = await api<{ total: number; common_count: number; coverage: Record<string, number> }>(`/audits/${audit.id}/runs/${ranking.run.id}/comparison`, token);
      const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = `comparacion-${ranking.run.id}.json`; anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice(`Comparación descargada sobre las mismas entradas: ${result.common_count} de ${result.total} casos comparables. Cobertura: CVSS ${result.coverage['cvss-only-v1']}, iguales ${result.coverage['equal-weights-v1']}, ROC ${result.coverage['roc-autores-v1']}.`);
    });
  }

  async function download(format: 'pdf' | 'csv' | 'json') {
    if (!audit || !ranking) return;
    await perform(async () => {
      const file = await apiFile(`/audits/${audit.id}/runs/${ranking.run.id}/export?format=${format}`, token);
      const url = URL.createObjectURL(file);
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = `riskengine-${ranking.run.id}.${format}`; anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }

  return <div className="app-shell">
    <header className="topbar"><div className="brand"><span className="brand-icon">R</span><div><strong>RiskEngine</strong><span>Priorización con contexto</span></div></div><div className="top-actions"><span className="pill">Prototipo · v0.1</span>{token && <button className="quiet" disabled={busy} onClick={() => { sessionStorage.removeItem('riskengine-token'); setToken(''); setAudit(null); }}>Salir</button>}</div></header>
    {error && <div className="message error" role="alert">{error}</div>}
    {notice && <div className="message success" role="status">{notice}</div>}
    {busy && <div className="busy" role="status">Procesando…</div>}
    {!token ? <main className="login"><span className="eyebrow">LABORATORIO LOCAL</span><h1>Comprende qué atender primero.</h1><p>Importa hallazgos, incorpora el contexto del activo y conserva la explicación de cada decisión.</p><form onSubmit={login}><label>Clave de acceso<input type="password" autoComplete="off" value={keyInput} onChange={event => setKeyInput(event.target.value)} required minLength={32}/></label><button disabled={busy}>Entrar al laboratorio</button></form><p className="muted">Utiliza la clave generada durante la configuración. Se conserva solo en esta sesión del navegador.</p></main> :
    <fieldset disabled={busy} className="workspace">
      <aside className="sidebar"><span className="eyebrow">ESPACIO DE TRABAJO</span><h2>Auditorías</h2><div className="audit-list">{audits.items.map(item => <button type="button" key={item.id} className={`audit-item ${audit?.id === item.id ? 'selected' : ''}`} onClick={() => void perform(() => loadAudit(item))}><strong>{item.name}</strong><span>{item.scope}</span></button>)}</div>
        {audits.total > audits.items.length && <button className="quiet" onClick={() => void perform(async () => { const more = await api<Page<Audit>>(`/audits?limit=100&offset=${audits.items.length}`, token); setAudits({ items: [...audits.items, ...more.items], total: more.total }); })}>Cargar más auditorías</button>}
        <form onSubmit={createAudit} className="new-audit"><h3>Nueva auditoría</h3><label>Nombre<input name="name" required maxLength={160} placeholder="Laboratorio de pruebas"/></label><label>Alcance<textarea name="scope" required maxLength={3000} placeholder="Objetivos y límites del entorno controlado"/></label><button>Crear auditoría</button></form>
        <a className="sample-link" href="/ejemplo-sintetico.xml" download>Descargar XML sintético de prueba ↓</a>
      </aside>
      <main className="content">
        {!audit ? <section className="empty"><span className="eyebrow">PRIMER PASO</span><h1>Crea tu primera auditoría.</h1><p>Define el alcance y carga un reporte XML de Greenbone. También puedes descargar el ejemplo sintético para comprobar el recorrido.</p><p className="muted">La compatibilidad del importador debe contrastarse con el XML real de tu laboratorio.</p></section> : <>
          <div className="page-heading"><div><span className="eyebrow">AUDITORÍA ACTIVA</span><h1>{audit.name}</h1><p>{audit.scope}</p></div></div>
          <div className="stats"><article><span>Hallazgos en el reporte</span><strong>{reports.items.find(report => report.id === reportId)?.finding_count ?? 0}</strong></article><article><span>Activos de la auditoría</span><strong>{assets.total}</strong></article><article><span>Ejecuciones guardadas</span><strong>{runs.total}</strong></article></div>
          <section className="panel"><div className="section-heading"><div><span className="eyebrow">01 · IMPORTAR</span><h2>Reportes de Greenbone</h2></div></div><form className="upload-form" onSubmit={upload}><label>Archivo XML · hasta 10 MiB<input type="file" name="file" accept=".xml,application/xml,text/xml" required/></label><button>Importar reporte</button></form>
            {reports.items.length > 0 && <label>Reporte seleccionado<select value={reportId} onChange={event => { const id = event.target.value; void perform(() => loadReport(id)); }}>{reports.items.map(report => <option key={report.id} value={report.id}>{report.filename} · {report.finding_count} hallazgos · {formatDate(report.created_at)}</option>)}</select></label>}
            {reports.total > reports.items.length && <button className="quiet" onClick={() => void perform(async () => { const more = await api<Page<Report>>(`/audits/${audit.id}/imports?limit=100&offset=${reports.items.length}`, token); setReports({ items: [...reports.items, ...more.items], total: more.total }); })}>Cargar más reportes</button>}
            <p className="muted">Se conserva lo incluido en el archivo. Los filtros o la paginación del reporte pueden limitar los resultados.</p>
          </section>
          <nav className="tabs" aria-label="Secciones de auditoría">{(['findings', 'context', 'ranking'] as const).map(value => <button type="button" key={value} aria-current={tab === value ? 'page' : undefined} className={tab === value ? 'active' : ''} onClick={() => setTab(value)}>{{ findings: 'Hallazgos', context: 'Contexto y fuentes', ranking: 'Priorización' }[value]}</button>)}</nav>
          {tab === 'findings' && <section className="panel findings-panel"><h2>Hallazgos importados</h2><form className="finding-tools" onSubmit={event => { event.preventDefault(); void applyFindingFilter(); }}><label>Buscar hallazgos<input type="search" maxLength={200} placeholder="Nombre, CVE, activo o puerto" value={searchInput} onChange={event => setSearchInput(event.target.value)}/></label><label>Ordenar por<select value={sortInput} onChange={event => setSortInput(event.target.value)}><option value="original">Orden original</option><option value="name">Nombre A–Z</option><option value="cvss_desc">CVSS: mayor a menor</option><option value="cvss_asc">CVSS: menor a mayor</option><option value="host">Activo</option></select></label><button disabled={!reportId}>Buscar</button><button type="button" className="quiet" disabled={!reportId} onClick={() => void applyFindingFilter(true)}>Limpiar</button></form><p role="status" className="muted">{findings.total} coincidencias en todo el reporte{findingFilter.q ? ` para “${findingFilter.q}”` : ''}.</p>{findings.total === 0 && <p>No se encontraron hallazgos. Prueba otro término o limpia la búsqueda.</p>}<div className="table-wrap"><table><thead><tr><th>Hallazgo</th><th>Activo / puerto</th><th>CVSS 3.1</th><th>Seguimiento</th><th><span className="sr-only">Detalle</span></th></tr></thead><tbody>{findings.items.map(item => <tr key={item.id}><td><strong className="finding-title">{item.name}</strong><span className="finding-reference">{item.cves.length === 1 ? item.cves[0] : item.cves.length ? `${item.cves.length} referencias CVE` : 'Sin CVE asociado'}</span></td><td>{item.host}<small>{item.port || 'No indicado'}</small></td><td><span className="finding-score">{item.cvss?.toFixed(1) ?? '—'}</span>{item.cvss === null && <small>No admisible</small>}</td><td><select aria-label={`Estado de ${item.name}`} value={item.status} onChange={event => { const status = event.target.value; void perform(async () => { await api(`/audits/${audit.id}/findings/${item.id}`, token, 'PATCH', { status }); await loadFindings(audit.id, reportId, findingOffset); }); }}><option value="open">Abierto</option><option value="reviewing">En revisión</option><option value="resolved">Resuelto</option></select></td><td><FindingDetail finding={item} auditId={audit.id} token={token} refresh={() => loadFindings(audit.id, reportId, findingOffset)}/></td></tr>)}</tbody></table></div><Pager offset={findingOffset} total={findings.total} size={FINDINGS_PAGE_SIZE} change={offset => void perform(() => loadFindings(audit.id, reportId, offset))}/></section>}
          {tab === 'context' && <><section className="panel"><span className="eyebrow">02 · CONTEXTUALIZAR</span><h2>Contexto de los activos</h2><p className="muted">Escalas exploratorias de 1 (menor) a 5 (mayor). Un valor desconocido se conserva como ausente. Sus definiciones deben cerrarse en el modelo académico.</p>{assets.items.map(asset => <AssetEditor key={`${asset.id}-${asset.criticality}-${asset.exposure}`} asset={asset} save={(id, criticality, exposure) => void perform(async () => { await api(`/audits/${audit.id}/assets/${id}`, token, 'PATCH', { criticality, exposure }); setAssets(await api<Page<Asset>>(`/audits/${audit.id}/assets?limit=100&offset=${assetOffset}`, token)); if (reportId) await loadFindings(audit.id, reportId, findingOffset); setNotice('Contexto guardado. Las ejecuciones anteriores conservan sus valores originales.'); })}/>)}<Pager offset={assetOffset} total={assets.total} size={100} change={offset => void perform(async () => { setAssets(await api<Page<Asset>>(`/audits/${audit.id}/assets?limit=100&offset=${offset}`, token)); setAssetOffset(offset); })}/></section><section className="panel"><h2>Evidencias de amenaza</h2><p>Consulta EPSS y el catálogo KEV para los CVE de esta auditoría. Los fallos quedan registrados como desconocidos.</p><button onClick={() => void perform(async () => { const result = await api<{ unique_cves: number; sources: Record<string, Record<string, number>> }>(`/audits/${audit.id}/enrichments`, token, 'POST'); setNotice(`${result.unique_cves} CVE consultados. EPSS: ${JSON.stringify(result.sources.epss)}. KEV: ${JSON.stringify(result.sources.kev)}.`); })}>Actualizar EPSS y KEV</button><p className="muted">Esta acción consulta servicios externos. Las evidencias utilizadas se guardan con cada ejecución.</p></section></>}
          {tab === 'ranking' && <><section className="panel"><span className="eyebrow">03 · PRIORIZAR</span><h2>Configura un experimento</h2><p>EPSS y KEV requieren revisar la aplicabilidad de todas las referencias CVE del hallazgo. Hazlo en Hallazgos. Las ejecuciones anteriores conservan su política original.</p><p>El motor calcula un índice de 0 a 100 mediante una suma ponderada. Es una fórmula exploratoria pendiente de validación, no una probabilidad de riesgo.</p><form onSubmit={createRun}><label>Perfil de pesos<select value={profile} onChange={event => {
            const selected = event.target.value; setProfile(selected);
            if (selected !== 'custom') setWeights(Object.fromEntries(features.map(key => [key, String(profiles[selected].weights[key])])) as Record<Feature, string>);
          }}><option value="custom">Personalizado</option>{Object.entries(profiles).map(([id, entry]) => <option key={id} value={id}>{entry.label}</option>)}</select></label>
          {profile === 'roc-autores-v1' && <p>ROC experimental: KEV &gt; EPSS &gt; criticidad &gt; exposición &gt; CVSS. Este orden es una hipótesis de diseño, no una validación de importancia.</p>}
          <div className="weights">{features.map(key => <label key={key}>{labels[key]}<input type="number" min="0" max="1" step="0.01" required value={weights[key]} placeholder="Peso 0–1" onChange={event => { setProfile('custom'); setWeights({ ...weights, [key]: event.target.value }); }}/></label>)}</div><p className="muted">Los pesos deben sumar 1. Un peso 0 desactiva esa entrada; un dato desconocido con peso positivo deja el caso pendiente.</p><label>Antigüedad máxima admisible de fuentes, en días<input className="short-input" type="number" min="0" max="365" step="1" required value={age} onChange={event => setAge(event.target.value)} placeholder="Por definir"/></label><label className="checkbox"><input type="checkbox" required/>Entiendo que esta configuración es experimental y requiere revisión académica.</label><button disabled={!reportId || !reports.items.find(report => report.id === reportId)?.finding_count}>Calcular y guardar ejecución</button></form></section>
            <section className="panel"><div className="section-heading"><h2>Ejecuciones guardadas</h2>{ranking && <div className="export-actions">{(['pdf', 'csv', 'json'] as const).map(format => <button key={format} className="quiet" onClick={() => void download(format)}>Descargar {format.toUpperCase()} ↓</button>)}</div>}</div>{runs.items.length ? <label>Ejecución<select value={ranking?.run.id ?? ''} onChange={event => { const id = event.target.value; if (id) void perform(() => loadRanking(id)); }}><option value="">Selecciona una ejecución</option>{runs.items.map(run => <option key={run.id} value={run.id}>{formatDate(run.created_at)} · {run.id.slice(0, 8)}</option>)}</select></label> : <p className="muted">Todavía no hay ejecuciones.</p>}
              {runs.total > runs.items.length && <button className="quiet" onClick={() => void perform(async () => { const more = await api<Page<Run>>(`/audits/${audit.id}/runs?limit=100&offset=${runs.items.length}`, token); setRuns({ items: [...runs.items, ...more.items], total: more.total }); })}>Cargar más ejecuciones</button>}
              {ranking && <><button type="button" onClick={() => void downloadComparison()}>Comparar tres perfiles y descargar JSON</button><p className="muted">Modelo: {ranking.run.version}. Orden por índice descendente; los casos no calculables aparecen al final. Los empates conservan igual puntuación.</p><div className="table-wrap"><table><thead><tr><th>Orden</th><th>Hallazgo</th><th>Índice</th><th>Explicación y evidencia</th></tr></thead><tbody>{ranking.items.map((item: RankingResult, index) => <tr key={item.id}><td>{item.score === null ? '—' : rankingOffset + index + 1}</td><td><strong>{item.snapshot.finding.name}</strong><small>{item.snapshot.finding.host} · {item.snapshot.finding.cves.join(', ') || 'Sin CVE'}</small></td><td><span className={item.score === null ? 'score pending' : 'score'}>{item.score === null ? 'Pendiente' : item.score.toFixed(2)}</span></td><td><details><summary>{item.score === null ? 'Revisar datos ausentes' : 'Ver cálculo'}</summary><p>{item.explanation}</p><p>Severidad original: {item.snapshot.finding.severity ?? 'No registrada'}. {item.snapshot.finding.cvss_admission?.message}</p><pre>{JSON.stringify({ inputs: item.snapshot.inputs, contributions: item.snapshot.contributions, evidence: item.snapshot.evidence }, null, 2)}</pre></details></td></tr>)}</tbody></table></div><Pager offset={rankingOffset} total={ranking.total} size={100} change={offset => void perform(() => loadRanking(ranking.run.id, offset))}/></>}
            </section></>}
        </>}
      </main>
    </fieldset>}
    <footer>RiskEngine · Desarrollo iterativo e incremental · Evidencia antes de conclusiones</footer>
  </div>;
}
