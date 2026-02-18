export default function Modal({ open, title, onClose, children }) {
  if (!open) {
    return null;
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-panel"
        onClick={(event) => {
          event.stopPropagation();
        }}
      >
        <header className="modal-header">
          <h3>{title}</h3>
          <button type="button" className="ghost-button" onClick={onClose}>
            Close
          </button>
        </header>
        <div className="modal-content">{children}</div>
      </div>
    </div>
  );
}
