import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { getGreenboneProfileDescription } from '../utils/greenboneProfiles';

const TOOLTIP_DELAY_MS = 300;

export default function HoverProfileSelect({
  id,
  className = '',
  ariaLabel = 'Scan Profile',
  disabled = false,
  value = '',
  options = [],
  placeholder = 'No scan profiles available',
  onChange,
}) {
  const rootRef = useRef(null);
  const tooltipTimerRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [tooltip, setTooltip] = useState({
    visible: false,
    text: '',
    x: 0,
    y: 0,
  });

  const selectedOption = useMemo(() => {
    if (!Array.isArray(options) || options.length === 0) {
      return null;
    }

    return options.find((option) => option.id === value) || options[0];
  }, [options, value]);

  const clearTooltipTimer = useCallback(() => {
    if (tooltipTimerRef.current) {
      window.clearTimeout(tooltipTimerRef.current);
      tooltipTimerRef.current = null;
    }
  }, []);

  const hideTooltip = useCallback(() => {
    clearTooltipTimer();
    setTooltip((current) => (current.visible ? { ...current, visible: false } : current));
  }, [clearTooltipTimer]);

  useEffect(() => () => hideTooltip(), [hideTooltip]);

  useEffect(() => {
    const handlePointerDown = (event) => {
      if (!rootRef.current) {
        return;
      }

      if (!rootRef.current.contains(event.target)) {
        setOpen(false);
        hideTooltip();
      }
    };

    document.addEventListener('pointerdown', handlePointerDown);
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, [hideTooltip]);

  const showDelayedTooltip = (option, event) => {
    clearTooltipTimer();

    const text = getGreenboneProfileDescription(option?.name, option?.comment);

    if (!text) {
      return;
    }

    const x = event.clientX + 14;
    const y = event.clientY + 14;

    tooltipTimerRef.current = window.setTimeout(() => {
      setTooltip({
        visible: true,
        text,
        x,
        y,
      });
    }, TOOLTIP_DELAY_MS);
  };

  const updateTooltipPosition = (event) => {
    setTooltip((current) => (
      current.visible
        ? {
          ...current,
          x: event.clientX + 14,
          y: event.clientY + 14,
        }
        : current
    ));
  };

  const handleSelect = (nextValue) => {
    if (typeof onChange === 'function') {
      onChange(nextValue);
    }

    setOpen(false);
    hideTooltip();
  };

  const triggerDisabled = disabled || options.length === 0;
  const triggerLabel = selectedOption?.name || placeholder;

  return (
    <div ref={rootRef} className={`hover-profile-select ${className}`.trim()}>
      <button
        id={id}
        type="button"
        className="hover-profile-trigger"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        disabled={triggerDisabled}
        onClick={() => {
          if (triggerDisabled) {
            return;
          }

          setOpen((current) => !current);
        }}
        onKeyDown={(event) => {
          if (event.key === 'Escape') {
            setOpen(false);
            hideTooltip();
          }
        }}
      >
        <span className="hover-profile-label">{triggerLabel}</span>
        <span className={`hover-profile-caret ${open ? 'open' : ''}`} aria-hidden="true">
          ▼
        </span>
      </button>

      {open && options.length > 0 && (
        <div className="hover-profile-menu" role="listbox" aria-label={ariaLabel}>
          {options.map((option) => (
            <button
              key={option.id}
              type="button"
              className={`hover-profile-option ${value === option.id ? 'selected' : ''}`}
              role="option"
              aria-selected={value === option.id}
              onClick={() => handleSelect(option.id)}
              onMouseEnter={(event) => showDelayedTooltip(option, event)}
              onMouseMove={updateTooltipPosition}
              onMouseLeave={hideTooltip}
              onBlur={hideTooltip}
            >
              {option.name || option.id}
            </button>
          ))}
        </div>
      )}

      {tooltip.visible && (
        <div
          className="hover-profile-tooltip"
          style={{
            left: `${tooltip.x}px`,
            top: `${tooltip.y}px`,
          }}
        >
          {tooltip.text}
        </div>
      )}
    </div>
  );
}
