// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import App from './App';
import { api, ApiError } from './api';

vi.mock('./api', async importOriginal => ({ ...await importOriginal<typeof import('./api')>(), api: vi.fn(), apiFile: vi.fn() }));
let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  container = document.createElement('div'); document.body.append(container); root = createRoot(container);
  vi.mocked(api).mockReset();
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/auth/me') throw new ApiError('Inicia sesión', 401);
    if (path === '/auth/login') return { email: 'owner@example.test' };
    if (path === '/auth/logout') return undefined;
    if (path === '/audits?limit=100') return { items: [], total: 0 };
    throw new Error(`Unexpected request ${path}`);
  });
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); sessionStorage.clear(); vi.unstubAllGlobals(); });
async function fill(name: string, value: string) {
  await act(async () => {
    const input = container.querySelector<HTMLInputElement>(`input[name="${name}"]`)!;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
async function submit() {
  await act(async () => container.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
}

test('personal login sends credentials once and logout revokes the session', async () => {
  await act(async () => root.render(<App/>));
  expect(container.textContent).toContain('Correo electrónico');
  await fill('email', 'owner@example.test'); await fill('password', 'synthetic-password'); await submit();
  expect(api).toHaveBeenCalledWith('/auth/login', 'POST', { email: 'owner@example.test', password: 'synthetic-password' });
  expect(container.textContent).toContain('Crea tu primera auditoría');
  expect(sessionStorage.length).toBe(0);
  await act(async () => Array.from(container.querySelectorAll('button')).find(b => b.textContent === 'Salir')!.click());
  expect(api).toHaveBeenCalledWith('/auth/logout', 'POST');
  expect(container.querySelector('input[name="password"]')).not.toBeNull();
});

test('session expiration returns to personal login and clears workspace', async () => {
  vi.mocked(api).mockImplementation(async path => path === '/auth/me' ? { email: 'owner@example.test' } : { items: [], total: 0 });
  sessionStorage.setItem('riskengine-token', 'obsolete-key');
  await act(async () => root.render(<App/>));
  expect(sessionStorage.getItem('riskengine-token')).toBeNull();
  expect(container.textContent).toContain('Crea tu primera auditoría');
  await act(async () => window.dispatchEvent(new Event('riskengine-session-expired')));
  expect(container.textContent).toContain('Correo electrónico');
  expect(container.querySelector('.workspace')).toBeNull();
});

test('invalid credentials keep login visible with a clear error', async () => {
  vi.mocked(api).mockRejectedValue(new ApiError('Correo o contraseña incorrectos.', 401));
  await act(async () => root.render(<App/>));
  await fill('email', 'owner@example.test'); await fill('password', 'wrong'); await submit();
  expect(container.querySelector('[role="alert"]')?.textContent).toBe('Correo o contraseña incorrectos.');
  expect(container.querySelector('.workspace')).toBeNull();
});
