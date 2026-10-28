import { useState } from 'react';
import type { Asset } from './types';

export function Pager({ offset, total, size, change }: { offset: number; total: number; size: number; change: (offset: number) => void }) {
  return <div className="pager"><span>{total ? `${offset + 1}–${Math.min(offset + size, total)} de ${total}` : 'Sin registros'}</span><div><button type="button" className="quiet" disabled={offset === 0} onClick={() => change(Math.max(0, offset - size))}>Anterior</button><button type="button" className="quiet" disabled={offset + size >= total} onClick={() => change(offset + size)}>Siguiente</button></div></div>;
}

export function AssetEditor({ asset, save }: { asset: Asset; save: (id: string, criticality: number | null, exposure: number | null) => void }) {
  const [criticality, setCriticality] = useState(asset.criticality?.toString() ?? '');
  const [exposure, setExposure] = useState(asset.exposure?.toString() ?? '');
  return <form className="asset-row" onSubmit={event => { event.preventDefault(); save(asset.id, criticality ? Number(criticality) : null, exposure ? Number(exposure) : null); }}>
    <strong>{asset.identifier}</strong>
    <label>Criticidad<select value={criticality} onChange={event => setCriticality(event.target.value)}><option value="">Desconocida</option>{[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n}</option>)}</select></label>
    <label>Exposición<select value={exposure} onChange={event => setExposure(event.target.value)}><option value="">Desconocida</option>{[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n}</option>)}</select></label>
    <button type="submit" className="quiet">Guardar contexto</button>
  </form>;
}
