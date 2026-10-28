// @vitest-environment jsdom
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, test, vi } from 'vitest';
import { DetectorDetails } from './DetectorDetails';
import { api } from './api';
vi.mock('./api', () => ({ api: vi.fn() }));

test('loads only on opening, retries errors and renders detector text safely', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const container = document.createElement('div');
  const root = createRoot(container);
  vi.mocked(api).mockReset();
  vi.mocked(api).mockRejectedValueOnce(new Error('Error de carga')).mockResolvedValue({
    detector: { name: 'Detector', oid: 'test', family: '', version: '', summary: '<img src=x onerror=alert(1)>', affected: 'Example 1.0', insight: '', impact: '', detection: '', solution: '', references: ['https://example.org/'] },
    source: { filename: 'report.xml', sha256: 'test' },
  });
  try {
    await act(async () => root.render(<DetectorDetails auditId="audit" findingId="finding"/>));
    expect(api).not.toHaveBeenCalled();
    await act(async () => { const details = container.querySelector('details')!; details.open = true; await new Promise(resolve => setTimeout(resolve, 0)); });
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Error de carga');
    await act(async () => container.querySelector('button')!.click());
    expect(api).toHaveBeenLastCalledWith('/audits/audit/findings/finding/detector');
    expect(container.textContent).toContain('Example 1.0');
    expect(container.textContent).toContain('No informado en el XML.');
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('a')?.getAttribute('rel')).toContain('noopener');
    expect(container.textContent).toContain('No es evidencia específica');
    const calls = vi.mocked(api).mock.calls.length;
    await act(async () => container.querySelector('details')!.dispatchEvent(new Event('toggle')));
    expect(vi.mocked(api).mock.calls.length).toBe(calls);
  } finally { await act(async () => root.unmount()); vi.unstubAllGlobals(); }
});
