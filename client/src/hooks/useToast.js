import { useCallback, useMemo, useState } from 'react';

let nextToastId = 1;

export default function useToast() {
  const [toasts, setToasts] = useState([]);

  const removeToast = useCallback((id) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const pushToast = useCallback((message, type = 'info', timeoutMs = 3500) => {
    const id = nextToastId;
    nextToastId += 1;

    setToasts((current) => [...current, { id, message, type }]);

    window.setTimeout(() => {
      removeToast(id);
    }, timeoutMs);
  }, [removeToast]);

  return useMemo(
    () => ({
      toasts,
      pushToast,
      removeToast,
    }),
    [toasts, pushToast, removeToast],
  );
}
