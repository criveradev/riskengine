// @vitest-environment jsdom
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, test, vi } from 'vitest';
import { CVEReviewEditor } from './CVEReviewEditor';

test('submits the decision and exposes save errors without losing evidence', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const container = document.createElement('div');
  const root = createRoot(container);
  const save = vi.fn().mockRejectedValue(new Error('No se pudo guardar'));
  try {
    await act(async () => root.render(<CVEReviewEditor review={{cve:'CVE-2020-1234',status:'pending',reviewer:'Analista',rationale:'Producto comprobado',reviewed_at:null}} save={save}/>));
    await act(async () => {
      const select = container.querySelector('select')!;
      select.value = 'applicable';
      select.dispatchEvent(new Event('change', {bubbles:true}));
    });
    await act(async () => { container.querySelector('form')!.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})); });
    expect(save).toHaveBeenCalledWith({status:'applicable',reviewer:'Analista',rationale:'Producto comprobado'});
    expect(container.querySelector('[role="alert"]')?.textContent).toBe('No se pudo guardar');
    expect(container.querySelector('textarea')?.value).toBe('Producto comprobado');
    expect(container.querySelector('button')?.disabled).toBe(false);
  } finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
});
