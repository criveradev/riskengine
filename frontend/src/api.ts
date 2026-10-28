export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}

async function request(path: string, method = 'GET', body?: unknown): Promise<Response> {
  const headers = new Headers({ Accept: 'application/json' });
  if (!['GET', 'HEAD'].includes(method)) headers.set('X-RiskEngine-Request', '1');
  const multipart = body instanceof FormData;
  if (body !== undefined && !multipart) headers.set('Content-Type', 'application/json');
  const response = await fetch(`/api${path}`, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : multipart ? body : JSON.stringify(body), signal: AbortSignal.timeout(90_000) });
  if (!response.ok) {
    if (response.status === 401 && path !== '/auth/login' && typeof window !== 'undefined') window.dispatchEvent(new Event('riskengine-session-expired'));
    const payload: unknown = await response.json().catch(() => null);
    let message = 'No se pudo completar la operación.';
    if (typeof payload === 'object' && payload !== null && 'error' in payload) {
      const error = payload.error;
      if (typeof error === 'object' && error !== null && 'message' in error && typeof error.message === 'string') message = error.message;
    }
    throw new ApiError(message, response.status);
  }
  return response;
}

export async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await request(path, method, body);
  return (response.status === 204 ? undefined : await response.json()) as T;
}

export async function apiFile(path: string): Promise<Blob> {
  return (await request(path)).blob();
}
