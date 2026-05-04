import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Gauge, RefreshCw, AlertTriangle, TrendingUp } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line, Legend } from 'recharts';
import { Badge, ScoreRing } from './SharedComponents';

const API_URL = 'http://localhost:8000/api';

const RiskScoreTab = ({ showToast }) => {
  const [risk, setRisk] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchRisk = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/risk/score`);
      setRisk(res.data.data);
    } catch (err) {
      showToast('Failed to fetch risk score', 'error');
    }
    setLoading(false);
  };

  useEffect(() => { fetchRisk(); }, []);

  if (!risk) {
    return (
      <div className="dashboard-grid animate-fade-in">
        <div className="panel col-span-12" style={{ textAlign: 'center', padding: '60px' }}>
          <RefreshCw size={32} className="animate-spin" style={{ color: 'var(--accent-blue)', margin: '0 auto' }} />
          <p className="mt-4 text-muted">Calculating unified risk score...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-grid animate-fade-in">
      {/* Unified Risk Score Hero */}
      <div className="panel col-span-12">
        <div className="flex-between mb-4">
          <h2 className="section-title" style={{ marginBottom: 0 }}><Gauge /> Unified Risk Score</h2>
          <button className="btn" onClick={fetchRisk} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Recalculate
          </button>
        </div>
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '48px', flexWrap: 'wrap' }}>
          <ScoreRing score={risk.unified_risk_score} size={160}
            color={risk.unified_risk_color} label="System Risk" />
          <div className="flex gap-4">
            {risk.risk_breakdown_chart.map((c, i) => (
              <div key={i} className="framework-card" style={{ minWidth: '140px', padding: '16px' }}>
                <ScoreRing score={c.score} size={90} color={c.color} label={c.name} />
                <span className="text-xs text-muted">Weight: {(c.weight * 100)}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Risk Trend Chart */}
      {risk.trend && (
        <div className="panel col-span-6">
          <h2 className="section-title"><TrendingUp /> Risk Trend (7 Days)</h2>
          <div style={{ height: '280px' }}>
            <ResponsiveContainer>
              <LineChart data={risk.trend}>
                <XAxis dataKey="period" stroke="#8b949e" tick={{ fontSize: 11 }} />
                <YAxis stroke="#8b949e" domain={[0, 100]} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ backgroundColor: 'rgba(20,27,45,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
                <Line type="monotone" dataKey="score" stroke="#8b5cf6" strokeWidth={2} dot={{ fill: '#8b5cf6', r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Component Breakdown Chart */}
      <div className="panel col-span-6">
        <h2 className="section-title"><Gauge /> Component Breakdown</h2>
        <div style={{ height: '280px' }}>
          <ResponsiveContainer>
            <BarChart data={risk.risk_breakdown_chart}>
              <XAxis dataKey="name" stroke="#8b949e" tick={{ fontSize: 11 }} />
              <YAxis stroke="#8b949e" domain={[0, 100]} tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: 'rgba(20,27,45,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
              <Bar dataKey="score" radius={[6, 6, 0, 0]}>
                {risk.risk_breakdown_chart.map((entry, i) => (
                  <rect key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recommendations */}
      <div className="panel col-span-6">
        <h2 className="section-title"><AlertTriangle /> Risk Recommendations</h2>
        <div className="data-list">
          {risk.recommendations.map((rec, i) => (
            <div key={i} className="data-item">
              <div className="item-header">
                <span className="item-title">{rec.category}</span>
                <Badge level={rec.priority}>{rec.priority}</Badge>
              </div>
              <p className="text-sm text-muted mb-2">{rec.recommendation}</p>
              <div className="text-xs" style={{ color: 'var(--accent-cyan)' }}>Action: {rec.action}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Threshold Actions */}
      <div className="panel col-span-6">
        <h2 className="section-title"><AlertTriangle /> Automated Threshold Actions</h2>
        <div className="data-list">
          {Object.entries(risk.threshold_actions.actions).map(([action, triggered], i) => (
            <div key={i} className="control-row">
              <span className="control-name">{action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
              <Badge level={triggered ? 'critical' : 'completed'}>
                {triggered ? 'TRIGGERED' : 'INACTIVE'}
              </Badge>
            </div>
          ))}
        </div>
        <div className="mt-4 stat-pill" style={{ justifyContent: 'center' }}>
          <AlertTriangle size={14} style={{ color: risk.threshold_actions.triggered_count > 0 ? '#ef4444' : '#10b981' }} />
          {risk.threshold_actions.triggered_count} Actions Triggered
        </div>
      </div>
    </div>
  );
};

export default RiskScoreTab;
