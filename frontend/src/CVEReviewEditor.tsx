import { useState, type FormEvent } from 'react';
import type { CVEReview } from './types';

type Decision = { status: CVEReview['status']; reviewer: string; rationale: string };
export function CVEReviewEditor({ review, save }: { review: CVEReview; save: (decision: Decision) => Promise<void> }) {
  const [status, setStatus] = useState(review.status);
  const [reviewer, setReviewer] = useState(review.reviewer ?? '');
  const [rationale, setRationale] = useState(review.rationale ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try { await save({ status, reviewer, rationale }); }
    catch (error) { setError(error instanceof Error ? error.message : 'No se pudo guardar la revisión.'); }
    finally { setBusy(false); }
  }
  return <details><summary>{review.cve} · {{ pending: 'Pendiente', applicable: 'Aplicable', not_applicable: 'No aplicable' }[review.status]}</summary>
    {review.reviewed_at && <p>Última revisión: {review.reviewed_at} · {review.reviewer}</p>}
    <form onSubmit={submit}>
      <label>Aplicabilidad<select value={status} onChange={e => setStatus(e.target.value as CVEReview['status'])}><option value="pending">Pendiente</option><option value="applicable">Aplicable</option><option value="not_applicable">No aplicable</option></select></label>
      <label>Responsable declarado<input required maxLength={160} value={reviewer} onChange={e => setReviewer(e.target.value)}/></label>
      <label>Justificación y evidencia<textarea required maxLength={3000} value={rationale} onChange={e => setRationale(e.target.value)} placeholder="Producto, versión, configuración y fuente que sustentan la decisión"/></label>
      <button disabled={busy}>{busy ? 'Guardando…' : 'Guardar revisión'}</button>
      {error && <p role="alert">{error}</p>}
    </form>
  </details>;
}
