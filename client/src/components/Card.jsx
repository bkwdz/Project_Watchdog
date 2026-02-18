export default function Card({ title, subtitle, actions, className = '', children }) {
  return (
    <section className={`ui-card ${className}`.trim()}>
      {(title || subtitle || actions) && (
        <header className="ui-card-header">
          <div>
            {title && <h3 className="ui-card-title">{title}</h3>}
            {subtitle && <p className="ui-card-subtitle">{subtitle}</p>}
          </div>
          {actions && <div className="ui-card-actions">{actions}</div>}
        </header>
      )}
      <div className="ui-card-body">{children}</div>
    </section>
  );
}
