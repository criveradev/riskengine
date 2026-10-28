import { afterEach, expect, test, vi } from 'vitest';
import { api, apiFile } from './api';

afterEach(() => vi.unstubAllGlobals());

test.each([
  ['pdf', 'application/pdf', '%PDF-synthetic'],
  ['csv', 'text/csv', 'hallazgo,indice\nPrueba,98'],
  ['json', 'application/json', '{"synthetic":true}'],
])('la descarga %s conserva el contenido y usa la cookie de sesión', async (format, contentType, content) => {
  const fetchMock = vi.fn().mockResolvedValue(new Response(content, { headers: { 'Content-Type': contentType } }));
  vi.stubGlobal('fetch', fetchMock);
  const path = `/audits/test/runs/run/export?format=${format}`;
  const blob = await apiFile(path);
  expect(await blob.text()).toBe(content);
  expect(blob.type).toContain(contentType);
  const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
  expect(url).toBe(`/api${path}`);
  expect(new Headers(options.headers).has('Authorization')).toBe(false);
  expect(options.credentials).toBe('same-origin');
  expect(url).not.toContain('synthetic-token');
});

test('un fallo de descarga muestra el mensaje de la API', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ error: { message: 'Ejecución no encontrada.' } }, { status: 404 })));
  await expect(apiFile('/audits/test/runs/missing/export?format=pdf')).rejects.toThrow('Ejecución no encontrada.');
});

test('las consultas JSON conservan su comportamiento', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ items: [], total: 0 })));
  await expect(api('/audits')).resolves.toEqual({ items: [], total: 0 });
});

test('el inicio de sesión usa JSON, cookie y cabecera contra CSRF sin Bearer', async () => {
  const fetchMock = vi.fn().mockResolvedValue(Response.json({ email: 'owner@example.test' }));
  vi.stubGlobal('fetch', fetchMock);
  await api('/auth/login', 'POST', { email: 'owner@example.test', password: 'synthetic' });
  const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
  expect(url).toBe('/api/auth/login');
  expect(options.credentials).toBe('same-origin');
  expect(new Headers(options.headers).get('X-RiskEngine-Request')).toBe('1');
  expect(new Headers(options.headers).has('Authorization')).toBe(false);
});

test('cerrar sesión admite una respuesta sin contenido', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
  await expect(api('/auth/logout', 'POST')).resolves.toBeUndefined();
});
