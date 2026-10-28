// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import App from './App';
import { api, apiFile } from './api';
import type { Finding } from './types';

vi.mock('./api', () => ({ api: vi.fn(), apiFile: vi.fn() }));

let container: HTMLDivElement;
let root: Root;
let failedReport: string;

const audits = [
  { id: 'audit-a', name: 'Auditoría A', scope: 'Alcance A' },
  { id: 'audit-b', name: 'Auditoría B', scope: 'Alcance B' },
  { id: 'audit-empty', name: 'Auditoría vacía', scope: 'Sin reportes' },
];

function finding(reportId: string): Finding {
  return {
    id: `finding-${reportId}`, external_id: reportId, import_id: reportId,
    asset_id: 'asset', host: '192.0.2.1', name: `Hallazgo ${reportId}`,
    description: '', port: '', cves: [], severity: null, cvss: null, vector: null,
    status: 'open', criticality: null, exposure: null,
  };
}

beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  sessionStorage.setItem('riskengine-token', 'synthetic-test-token');
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
  failedReport = '';
  vi.mocked(api).mockReset();
  vi.mocked(apiFile).mockReset();
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/audits?limit=100') return { items: audits, total: audits.length };
    if (path.includes('/imports?')) {
      const ids = path.includes('/audit-a/') ? ['report-a1', 'report-a2'] : path.includes('/audit-b/') ? ['report-b1'] : [];
      return { items: ids.map(id => ({ id, filename: `${id}.xml`, finding_count: 1, created_at: '2026-10-19T12:00:00Z', metadata: {} })), total: ids.length };
    }
    if (path.includes('/findings?')) {
      const reportId = new URL(path, 'http://localhost').searchParams.get('import_id')!;
      if (reportId === failedReport) throw new Error('No se pudo cargar el reporte.');
      return { items: [finding(reportId)], total: 1 };
    }
    if (path.includes('/runs?') && path.includes('/audit-a/')) return { items: [{ id: 'run-a', created_at: '2026-10-19T12:00:00Z' }], total: 1 };
    if (path.includes('/runs/run-a/results?')) return { items: [], total: 0, run: { id: 'run-a', version: 'synthetic-model' } };
    if (path.includes('/assets?') || path.includes('/runs?')) return { items: [], total: 0 };
    throw new Error(`Solicitud inesperada en la prueba: ${path}`);
  });
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  sessionStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

async function openAudit(name: string) {
  const button = Array.from(container.querySelectorAll<HTMLButtonElement>('.audit-item'))
    .find(element => element.querySelector('strong')?.textContent === name);
  expect(button).toBeDefined();
  await act(async () => button!.click());
}

function reportSelector() {
  return container.querySelector<HTMLSelectElement>('.upload-form + label select')!;
}

async function selectReport(reportId: string) {
  await act(async () => {
    const select = reportSelector();
    select.value = reportId;
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
}

async function renderAuditA() {
  await act(async () => root.render(<App />));
  await openAudit('Auditoría A');
  expect(reportSelector().value).toBe('report-a1');
  expect(container.querySelector('tbody')?.textContent).toContain('Hallazgo report-a1');
}

test('un fallo al cambiar de reporte conserva la selección y sus hallazgos', async () => {
  await renderAuditA();
  failedReport = 'report-a2';
  await selectReport('report-a2');
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('No se pudo cargar');
  expect(reportSelector().value).toBe('report-a1');
  expect(container.querySelector('tbody')?.textContent).toContain('Hallazgo report-a1');
  expect(container.querySelector('tbody')?.textContent).not.toContain('Hallazgo report-a2');
});

test('un fallo al cargar hallazgos de otra auditoría conserva la auditoría anterior', async () => {
  await renderAuditA();
  failedReport = 'report-b1';
  await openAudit('Auditoría B');
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('No se pudo cargar');
  expect(container.querySelector('.page-heading h1')?.textContent).toBe('Auditoría A');
  expect(reportSelector().value).toBe('report-a1');
  expect(container.querySelector('tbody')?.textContent).toContain('Hallazgo report-a1');
});

test('una carga exitosa cambia juntos el reporte y sus hallazgos', async () => {
  await renderAuditA();
  await selectReport('report-a2');
  expect(reportSelector().value).toBe('report-a2');
  expect(container.querySelector('tbody')?.textContent).toContain('Hallazgo report-a2');
  expect(container.querySelector('tbody')?.textContent).not.toContain('Hallazgo report-a1');
  await openAudit('Auditoría B');
  expect(container.querySelector('.page-heading h1')?.textContent).toBe('Auditoría B');
  expect(reportSelector().value).toBe('report-b1');
  expect(container.querySelector('tbody')?.textContent).toContain('Hallazgo report-b1');
});

test('una auditoría sin reportes limpia los hallazgos anteriores', async () => {
  await renderAuditA();
  await openAudit('Auditoría vacía');
  expect(container.querySelector('.page-heading h1')?.textContent).toBe('Auditoría vacía');
  expect(reportSelector()).toBeNull();
  expect(container.querySelector('tbody')?.children.length).toBe(0);
  expect(container.querySelector('.stats')?.textContent).toContain('Hallazgos en el reporte0');
});

async function openRanking() {
  await renderAuditA();
  const tab = Array.from(container.querySelectorAll<HTMLButtonElement>('.tabs button'))
    .find(element => element.textContent === 'Priorización')!;
  await act(async () => tab.click());
  const select = Array.from(container.querySelectorAll<HTMLSelectElement>('select'))
    .find(element => element.closest('label')?.firstChild?.textContent === 'Ejecución')!;
  await act(async () => {
    select.value = 'run-a';
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
}

test('los botones descargan PDF, CSV y JSON de la ejecución seleccionada', async () => {
  await openRanking();
  vi.useFakeTimers();
  vi.stubGlobal('URL', class extends URL {
    static createObjectURL = vi.fn(() => 'blob:synthetic');
    static revokeObjectURL = vi.fn();
  });
  vi.mocked(apiFile).mockResolvedValue(new Blob(['synthetic content']));
  const downloads: string[] = [];
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { downloads.push(this.download); });
  for (const format of ['pdf', 'csv', 'json']) {
    const button = Array.from(container.querySelectorAll<HTMLButtonElement>('.export-actions button'))
      .find(element => element.textContent === `Descargar ${format.toUpperCase()} ↓`)!;
    await act(async () => button.click());
    expect(apiFile).toHaveBeenLastCalledWith(`/audits/audit-a/runs/run-a/export?format=${format}`, 'synthetic-test-token');
  }
  expect(downloads).toEqual(['riskengine-run-a.pdf', 'riskengine-run-a.csv', 'riskengine-run-a.json']);
  vi.runAllTimers();
});

test('un fallo al descargar se muestra sin crear un archivo falso', async () => {
  await openRanking();
  vi.mocked(apiFile).mockRejectedValue(new Error('No se pudo exportar la ejecución.'));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  const button = container.querySelector<HTMLButtonElement>('.export-actions button')!;
  await act(async () => button.click());
  expect(container.querySelector('[role="alert"]')?.textContent).toBe('No se pudo exportar la ejecución.');
  expect(click).not.toHaveBeenCalled();
});

test('los perfiles cargan los cinco pesos y editar uno vuelve a personalizado', async () => {
  await renderAuditA();
  const tab = Array.from(container.querySelectorAll<HTMLButtonElement>('button')).find(button => button.textContent?.includes('Priorización'));
  expect(tab).toBeDefined();
  await act(async () => tab!.click());
  const select = Array.from(container.querySelectorAll<HTMLSelectElement>('select')).find(element => element.parentElement?.textContent?.includes('Perfil de pesos'))!;
  expect(select).toBeDefined();
  for (const [id, expected] of [
    ['cvss-only-v1', ['1','0','0','0','0']],
    ['equal-weights-v1', ['0.2','0.2','0.2','0.2','0.2']],
    ['roc-autores-v1', ['0.04','0.26','0.46','0.15','0.09']],
  ] as const) {
    await act(async () => { select.value=id; select.dispatchEvent(new Event('change',{bubbles:true})); });
    expect(Array.from(container.querySelectorAll<HTMLInputElement>('.weights input')).map(input => input.value)).toEqual(expected);
  }
  const first = container.querySelector<HTMLInputElement>('.weights input')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')!.set!.call(first,'0.05');
    first.dispatchEvent(new Event('input',{bubbles:true}));
  });
  expect(select.value).toBe('custom');
});

test('buscar y ordenar consulta el reporte y cambiar reporte limpia los filtros', async () => {
  await renderAuditA();
  const input = container.querySelector<HTMLInputElement>('input[type="search"]')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, 'vsftpd');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    const select = container.querySelector<HTMLSelectElement>('.finding-tools select')!;
    select.value = 'cvss_desc';
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await act(async () => container.querySelector('.finding-tools')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(vi.mocked(api).mock.calls.some(([path]) => path.includes('q=vsftpd') && path.includes('sort=cvss_desc') && path.includes('offset=0'))).toBe(true);
  await selectReport('report-a2');
  expect(input.value).toBe('');
  expect(container.querySelector<HTMLSelectElement>('.finding-tools select')!.value).toBe('original');
});

test('hallazgos pagina de diez en diez y reinicia la página al buscar', async () => {
  const original = vi.mocked(api).getMockImplementation()!;
  vi.mocked(api).mockImplementation(async (...args) => {
    const [path] = args;
    if (path.includes('/findings?')) {
      const query = new URL(path, 'http://localhost').searchParams;
      expect(query.get('limit')).toBe('10');
      const offset = Number(query.get('offset'));
      const total = query.has('q') ? 2 : 65;
      return { total, items: Array.from({length: Math.min(10, Math.max(0, total-offset))}, (_, i) => ({...finding('report-a1'),id:`f-${offset+i}`,name:`Hallazgo ${offset+i}`})) };
    }
    return original(...args);
  });
  await act(async () => root.render(<App />));
  await openAudit('Auditoría A');
  expect(container.querySelectorAll('tbody tr')).toHaveLength(10);
  expect(container.querySelector('.pager')?.textContent).toContain('1–10 de 65');
  const next = () => Array.from(container.querySelectorAll<HTMLButtonElement>('.pager button')).find(b=>b.textContent==='Siguiente')!;
  for (let page=1;page<=6;page++) await act(async () => next().click());
  expect(container.querySelectorAll('tbody tr')).toHaveLength(5);
  expect(container.querySelector('.pager')?.textContent).toContain('61–65 de 65');
  expect(next().disabled).toBe(true);
  await act(async () => {
    const input=container.querySelector<HTMLInputElement>('input[type="search"]')!;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')!.set!.call(input,'vsftpd');
    input.dispatchEvent(new Event('input',{bubbles:true}));
  });
  await act(async () => container.querySelector('.finding-tools')!.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  expect(container.querySelectorAll('tbody tr')).toHaveLength(2);
  expect(container.querySelector('.pager')?.textContent).toContain('1–2 de 2');
  expect(next().disabled).toBe(true);
});
