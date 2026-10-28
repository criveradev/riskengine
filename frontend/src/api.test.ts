import { afterEach, expect, test, vi } from 'vitest';
import { api, apiFile } from './api';

afterEach(() => vi.unstubAllGlobals());

test.each([
  ['pdf', 'application/pdf', '%PDF-synthetic'],
  ['csv', 'text/csv', 'hallazgo,indice\nPrueba,98'],
  ['json', 'application/json', '{"synthetic":true}'],
])('la descarga %s conserva el contenido y envía la clave en la cabecera', async (format, contentType, content) => {
  const fetchMock = vi.fn().mockResolvedValue(new Response(content, { headers: { 'Content-Type': contentType } }));
  vi.stubGlobal('fetch', fetchMock);
  const path = `/audits/test/runs/run/export?format=${format}`;
  const blob = await apiFile(path, 'synthetic-token');
  expect(await blob.text()).toBe(content);
  expect(blob.type).toContain(contentType);
  const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
  expect(url).toBe(`/api${path}`);
  expect(new Headers(options.headers).get('Authorization')).toBe('Bearer synthetic-token');
  expect(url).not.toContain('synthetic-token');
});

test('un fallo de descarga muestra el mensaje de la API', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ error: { message: 'Ejecución no encontrada.' } }, { status: 404 })));
  await expect(apiFile('/audits/test/runs/missing/export?format=pdf', 'synthetic-token')).rejects.toThrow('Ejecución no encontrada.');
});

test('las consultas JSON conservan su comportamiento', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ items: [], total: 0 })));
  await expect(api('/audits', 'synthetic-token')).resolves.toEqual({ items: [], total: 0 });
});
