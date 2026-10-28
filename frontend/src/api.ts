async function request(path: string, token: string, method = 'GET', body?: unknown): Promise<Response> {
  const headers = new Headers({ Authorization: `Bearer ${token}`, Accept: 'application/json' });
  const multipart = body instanceof FormData;
  if (body !== undefined && !multipart) headers.set('Content-Type', 'application/json');
  const response = await fetch(`/api${path}`, { method, headers, body: body === undefined ? undefined : multipart ? body : JSON.stringify(body), signal: AbortSignal.timeout(90_000) });
  if (!response.ok) {
    const payload: unknown = await response.json();
    let message = 'No se pudo completar la operación.';
    if (typeof payload === 'object' && payload !== null && 'error' in payload) {
      const error = payload.error;
      if (typeof error === 'object' && error !== null && 'message' in error && typeof error.message === 'string') message = error.message;
    }
    throw new Error(message);
  }
  return response;
}

export async function api<T>(path: string, token: string, method = 'GET', body?: unknown): Promise<T> {
  return (await request(path, token, method, body)).json() as Promise<T>;
}

export async function apiFile(path: string, token: string): Promise<Blob> {
  return (await request(path, token)).blob();
}
