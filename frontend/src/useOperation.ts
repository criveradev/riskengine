import { useState } from 'react';

export function useOperation() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function perform(work: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('');
    try { await work(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Ocurrió un error inesperado.'); }
    finally { setBusy(false); }
  }

  return { busy, error, notice, setNotice, perform };
}
