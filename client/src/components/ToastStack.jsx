const TOAST_CLASS = {
  success: 'toast-success',
  error: 'toast-error',
  info: 'toast-info',
};

export default function ToastStack({ toasts, onDismiss }) {
  return (
    <div className="toast-stack" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast-item ${TOAST_CLASS[toast.type] || TOAST_CLASS.info}`}>
          <span>{toast.message}</span>
          <button type="button" className="toast-close" onClick={() => onDismiss(toast.id)}>
            x
          </button>
        </div>
      ))}
    </div>
  );
}
