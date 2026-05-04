import React, { useEffect } from 'react';
import { CheckCircle, XCircle } from 'lucide-react';

export const Badge = ({ children, level }) => {
  const cn = `badge badge-${(level || 'low').toLowerCase()}`;
  return <span className={cn}>{children}</span>;
};

export const ScoreRing = ({ score, size = 120, color, label }) => {
  const strokeWidth = 8;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const ringColor = color || (score >= 90 ? '#10b981' : score >= 70 ? '#eab308' : '#ef4444');
  return (
    <div className="score-ring-container">
      <div className="score-ring" style={{ width: size, height: size }}>
        <svg width={size} height={size}>
          <circle className="score-ring-bg" cx={size / 2} cy={size / 2} r={radius} />
          <circle className="score-ring-fill" cx={size / 2} cy={size / 2} r={radius}
            stroke={ringColor} strokeDasharray={circumference} strokeDashoffset={offset} />
        </svg>
        <span className="score-ring-value" style={{ color: ringColor }}>{score}%</span>
      </div>
      {label && <span className="score-ring-label">{label}</span>}
    </div>
  );
};

export const Toast = ({ message, type = 'success', onClose }) => {
  useEffect(() => {
    const timer = setTimeout(onClose, 4000);
    return () => clearTimeout(timer);
  }, [onClose]);
  return (
    <div className={`toast toast-${type}`}>
      {type === 'success' ? <CheckCircle size={20} color="#10b981" /> : <XCircle size={20} color="#ef4444" />}
      <span>{message}</span>
    </div>
  );
};
