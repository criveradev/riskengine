// @vitest-environment jsdom
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { expect, test, vi } from 'vitest';
import { FindingDetail } from './FindingDetail';
import { api } from './api';
import type { Finding } from './types';
vi.mock('./api', () => ({ api: vi.fn() }));

test('detail separates evidence, detector and editable reviews and restores focus', async () => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  const show = vi.fn(function(this: HTMLDialogElement) { this.open = true; });
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', {value: show, configurable: true});
  Object.defineProperty(HTMLDialogElement.prototype, 'close', {value: function(this: HTMLDialogElement) { this.open = false; }, configurable: true});
  const container = document.createElement('div'); document.body.append(container);
  const root = createRoot(container);
  const refresh = vi.fn().mockResolvedValue(undefined);
  const finding: Finding = {id:'f',external_id:'f',import_id:'i',asset_id:'a',host:'192.0.2.1',name:'vsftpd',description:'',port:'21/tcp',cves:['CVE-2011-2523'],severity:9.8,cvss:9.8,vector:null,status:'open',criticality:1,exposure:1,cve_reviews:[{cve:'CVE-2011-2523',status:'pending',reviewer:'Analista',rationale:'Evidencia de prueba',reviewed_at:null}]};
  vi.mocked(api).mockResolvedValue({});
  try {
    await act(async () => root.render(<FindingDetail finding={finding} auditId="audit" token="test" refresh={refresh}/>));
    const trigger = container.querySelector('button')!;
    await act(async () => trigger.click());
    expect(show).toHaveBeenCalled();
    expect(document.querySelector('dialog')?.textContent).toContain('Sin evidencia detallada');
    expect(api).not.toHaveBeenCalled();
    const reviews = Array.from(document.querySelectorAll<HTMLButtonElement>('.detail-tabs button')).find(b => b.textContent === 'Revisión de CVE')!;
    await act(async () => reviews.click());
    expect(document.querySelector('dialog')?.textContent).not.toContain('Sin evidencia detallada');
    await act(async () => { const select = document.querySelector<HTMLSelectElement>('dialog select')!; select.value='not_applicable';select.dispatchEvent(new Event('change',{bubbles:true})); });
    await act(async () => document.querySelector('dialog form')!.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
    expect(api).toHaveBeenCalledWith('/audits/audit/findings/f/cves/CVE-2011-2523/reviews','test','POST',{status:'not_applicable',reviewer:'Analista',rationale:'Evidencia de prueba'});
    expect(refresh).toHaveBeenCalledOnce();
    expect(document.querySelector('dialog [role="status"]')?.textContent).toContain('Revisión guardada');
    await act(async () => document.querySelector('dialog')!.dispatchEvent(new Event('cancel',{cancelable:true})));
    expect(document.querySelector('dialog')).toBeNull();
    expect(document.activeElement).toBe(trigger);
  } finally { await act(async () => root.unmount());container.remove();vi.restoreAllMocks();vi.unstubAllGlobals(); }
});
