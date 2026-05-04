import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Cpu, RefreshCw, Trophy } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';
import { Badge } from './SharedComponents';

const API_URL = 'http://localhost:8000/api';

const MLComparisonTab = ({ showToast }) => {
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchComparison = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/ml/compare?normal=100&attacks=20`);
      setComparison(res.data.data);
      showToast('ML model comparison completed');
    } catch (err) {
      showToast('ML comparison failed', 'error');
    }
    setLoading(false);
  };

  useEffect(() => { fetchComparison(); }, []);

  if (!comparison) {
    return (
      <div className="dashboard-grid animate-fade-in">
        <div className="panel col-span-12" style={{ textAlign: 'center', padding: '60px' }}>
          <RefreshCw size={32} className="animate-spin" style={{ color: 'var(--accent-purple)', margin: '0 auto' }} />
          <p className="mt-4 text-muted">Training and comparing PyOD models...</p>
        </div>
      </div>
    );
  }

  const chartData = comparison.chart_data || [];
  const radarData = chartData.map(m => ({
    model: m.model, Accuracy: m.accuracy, Precision: m.precision, Recall: m.recall, F1: m.f1_score
  }));

  return (
    <div className="dashboard-grid animate-fade-in">
      {/* Header */}
      <div className="panel col-span-12">
        <div className="flex-between">
          <div>
            <h2 className="section-title" style={{ marginBottom: 4 }}><Cpu /> PyOD Multi-Algorithm Comparison</h2>
            <p className="text-sm text-muted">
              {comparison.total_events} events ({comparison.total_normal} normal, {comparison.total_attacks} attacks) •
              Best: <strong style={{ color: '#10b981' }}>{comparison.best_model}</strong> (F1: {comparison.best_f1}%)
            </p>
          </div>
          <button className="btn" onClick={fetchComparison} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Re-train
          </button>
        </div>
      </div>

      {/* Model Cards */}
      {Object.entries(comparison.models).map(([name, m], i) => {
        if (m.error) return null;
        const isBest = name === comparison.best_model;
        return (
          <div key={i} className={`panel col-span-3 ${isBest ? 'best-model-card' : ''}`}
            style={isBest ? { borderColor: 'rgba(16, 185, 129, 0.4)', boxShadow: '0 0 20px rgba(16, 185, 129, 0.1)' } : {}}>
            <div className="item-header mb-2">
              <span className="item-title">{name}</span>
              {isBest && <Badge level="completed"><Trophy size={10} /> Best</Badge>}
            </div>
            <div className="flex-col gap-2 text-sm">
              <div className="flex-between"><span className="text-muted">Accuracy</span><strong>{m.accuracy}%</strong></div>
              <div className="flex-between"><span className="text-muted">Precision</span><strong>{m.precision}%</strong></div>
              <div className="flex-between"><span className="text-muted">Recall</span><strong>{m.recall}%</strong></div>
              <div className="flex-between"><span className="text-muted">F1 Score</span><strong style={{ color: isBest ? '#10b981' : 'inherit' }}>{m.f1_score}%</strong></div>
              <div className="flex-between"><span className="text-muted">Anomalies</span><strong>{m.anomalies_detected}</strong></div>
            </div>
            <div className="score-track mt-4">
              <div className="score-fill" style={{ width: `${m.f1_score}%`, background: isBest ? '#10b981' : '#8b5cf6', boxShadow: `0 0 10px ${isBest ? '#10b981' : '#8b5cf6'}` }}></div>
            </div>
          </div>
        );
      })}

      {/* Comparison Bar Chart */}
      <div className="panel col-span-6">
        <h2 className="section-title"><Cpu /> Performance Metrics</h2>
        <div style={{ height: '300px' }}>
          <ResponsiveContainer>
            <BarChart data={chartData}>
              <XAxis dataKey="model" stroke="#8b949e" tick={{ fontSize: 11 }} />
              <YAxis stroke="#8b949e" domain={[0, 100]} tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: 'rgba(20,27,45,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
              <Legend />
              <Bar dataKey="accuracy" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              <Bar dataKey="precision" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
              <Bar dataKey="recall" fill="#06b6d4" radius={[4, 4, 0, 0]} />
              <Bar dataKey="f1_score" fill="#10b981" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Radar Chart */}
      <div className="panel col-span-6">
        <h2 className="section-title"><Cpu /> Model Radar Comparison</h2>
        <div style={{ height: '300px' }}>
          <ResponsiveContainer>
            <RadarChart data={[
              { metric: 'Accuracy', ...Object.fromEntries(radarData.map(r => [r.model, r.Accuracy])) },
              { metric: 'Precision', ...Object.fromEntries(radarData.map(r => [r.model, r.Precision])) },
              { metric: 'Recall', ...Object.fromEntries(radarData.map(r => [r.model, r.Recall])) },
              { metric: 'F1', ...Object.fromEntries(radarData.map(r => [r.model, r.F1])) },
            ]}>
              <PolarGrid stroke="rgba(255,255,255,0.1)" />
              <PolarAngleAxis dataKey="metric" stroke="#8b949e" tick={{ fontSize: 12 }} />
              <PolarRadiusAxis domain={[0, 100]} stroke="rgba(255,255,255,0.1)" tick={{ fontSize: 10 }} />
              {radarData.map((r, i) => (
                <Radar key={i} name={r.model} dataKey={r.model}
                  stroke={['#3b82f6', '#8b5cf6', '#06b6d4', '#10b981'][i]}
                  fill={['#3b82f6', '#8b5cf6', '#06b6d4', '#10b981'][i]}
                  fillOpacity={0.15} strokeWidth={2} />
              ))}
              <Legend />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default MLComparisonTab;
