import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Crosshair, Play, RefreshCw, AlertTriangle, CheckCircle, XCircle, Zap, Target } from 'lucide-react';
import { Badge } from './SharedComponents';

const API_URL = 'http://localhost:8000/api';

const FALLBACK_SCENARIO_INFO = {
  brute_force: { icon: '🔨', color: '#ef4444' },
  privilege_escalation: { icon: '⬆️', color: '#f97316' },
  data_exfiltration: { icon: '📤', color: '#8b5cf6' },
  abnormal_access: { icon: '🌐', color: '#06b6d4' },
};

const INTENSITY_OPTIONS = ['low', 'medium', 'high', 'extreme'];

const formatLabel = (value) => value.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());

const formatMetricValue = (key, value) => {
  if (value == null) return null;
  if (key === 'total_bytes_exfiltrated') return `${(value / 1e9).toFixed(2)} GB`;
  return String(value);
};

const AttackSimulationTab = ({ showToast }) => {
  const [scenarios, setScenarios] = useState([]);
  const [simResult, setSimResult] = useState(null);
  const [fullResult, setFullResult] = useState(null);
  const [executing, setExecuting] = useState(false);
  const [activeScenario, setActiveScenario] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [selectedIntensity, setSelectedIntensity] = useState('high');

  useEffect(() => {
    axios.get(`${API_URL}/simulation/scenarios`)
      .then((r) => {
        setScenarios(r.data.data);
        setLoadError('');
      })
      .catch((err) => {
        console.error(err);
        setLoadError('Could not load attack scenarios from the Python backend.');
      });
  }, []);

  const runScenario = async (scenario) => {
    setExecuting(true);
    setActiveScenario(scenario);
    try {
      const res = await axios.post(`${API_URL}/simulation/run/${scenario}?intensity=${selectedIntensity}`);
      setSimResult(res.data.data);
      showToast(`Attack simulation "${scenario}" completed`);
    } catch (err) {
      console.error(err);
      const detail = err.response?.data?.detail || err.message || 'Unknown backend error';
      showToast(`Simulation failed: ${detail}`, 'error');
    }
    setActiveScenario(null);
    setExecuting(false);
  };

  const runFullSim = async () => {
    setExecuting(true);
    setActiveScenario('full');
    try {
      const res = await axios.post(`${API_URL}/simulation/full?intensity=${selectedIntensity}`);
      setFullResult(res.data.data);
      showToast('Full attack simulation completed');
    } catch (err) {
      console.error(err);
      const detail = err.response?.data?.detail || err.message || 'Unknown backend error';
      showToast(`Full simulation failed: ${detail}`, 'error');
    }
    setActiveScenario(null);
    setExecuting(false);
  };

  return (
    <div className="dashboard-grid animate-fade-in">
      {/* Full Simulation Banner */}
      <div className="panel col-span-12">
        <div className="flex-between">
          <div>
            <h2 className="section-title" style={{ marginBottom: 4 }}><Target /> Full Attack Simulation</h2>
            <p className="text-sm text-muted">Run all 4 attack scenarios → ML detection → Risk scoring → Auto-remediation</p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={selectedIntensity}
              onChange={(e) => setSelectedIntensity(e.target.value)}
              disabled={executing}
              style={{
                background: 'rgba(255,255,255,0.05)',
                color: 'var(--text-primary)',
                border: '1px solid var(--panel-border)',
                borderRadius: '8px',
                padding: '10px 12px',
                fontSize: '14px'
              }}
            >
              {INTENSITY_OPTIONS.map((level) => (
                <option key={level} value={level} style={{ background: '#141b2d' }}>
                  {formatLabel(level)}
                </option>
              ))}
            </select>
            <button className="btn btn-danger" onClick={runFullSim} disabled={executing}>
              {executing ? <RefreshCw size={16} className="animate-spin" /> : <Zap size={16} />}
              {executing ? 'Simulating...' : 'Launch Full Simulation'}
            </button>
          </div>
        </div>

        {fullResult && (
          <div className="mt-4 animate-slide-up">
            <div className="flex gap-4 flex-wrap mt-4">
              <div className="stat-pill">
                <Crosshair size={14} style={{ color: '#ef4444' }} />
                {fullResult.simulation_summary.scenarios_run} Scenarios
              </div>
              <div className="stat-pill">
                <Target size={14} style={{ color: '#3b82f6' }} />
                {formatLabel(fullResult.simulation_summary.intensity)}
              </div>
              <div className="stat-pill">
                <AlertTriangle size={14} style={{ color: '#f97316' }} />
                {fullResult.simulation_summary.total_attack_events} Attack Events
              </div>
              <div className="stat-pill">
                {fullResult.detection.detection_success
                  ? <CheckCircle size={14} style={{ color: '#10b981' }} />
                  : <XCircle size={14} style={{ color: '#ef4444' }} />}
                {fullResult.detection.detection_rate}% Detected
              </div>
              <div className="stat-pill">
                <Target size={14} style={{ color: fullResult.risk_score.level === 'critical' ? '#ef4444' : '#f97316' }} />
                Risk: {fullResult.risk_score.unified} ({fullResult.risk_score.level})
              </div>
              <div className="stat-pill">
                <Zap size={14} style={{ color: '#10b981' }} />
                {fullResult.auto_remediation.triggered} Remediations
              </div>
            </div>

            <div className="flex gap-4 flex-wrap mt-4 text-xs text-muted">
              <span>Run ID: {fullResult.simulation_summary.simulation_id}</span>
              <span>Generated: {fullResult.simulation_summary.generated_at}</span>
            </div>

            {/* Per-Scenario Results */}
            <div className="dashboard-grid mt-4" style={{ gap: '12px' }}>
              {fullResult.scenarios.map((s, i) => (
                <div key={i} className="data-item col-span-3">
                  <div className="item-header">
                    <span className="item-title">{FALLBACK_SCENARIO_INFO[s.scenario]?.icon || '⚡'} {formatLabel(s.scenario)}</span>
                    <Badge level={s.expected_detection ? 'completed' : 'fail'}>
                      {s.expected_detection ? 'Expected' : 'Missed'}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted">{s.description}</p>
                  <div className="text-xs mt-2">Events: {s.total_events}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Individual Scenarios */}
      <div className="panel col-span-6">
        <h2 className="section-title"><Crosshair /> Attack Scenarios</h2>
        {loadError && <p className="text-sm" style={{ color: '#ef4444', marginBottom: 12 }}>{loadError}</p>}
        <div className="data-list">
          {scenarios.map((scenario, i) => {
            const info = FALLBACK_SCENARIO_INFO[scenario.id] || { icon: '⚡', color: '#8b949e' };
            return (
              <div key={i} className="data-item">
                <div className="item-header">
                  <span className="item-title">{info.icon} {scenario.title}</span>
                  <button className="btn btn-sm btn-danger" onClick={() => runScenario(scenario.id)} disabled={executing}>
                    {executing && activeScenario === scenario.id ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />}
                    {executing && activeScenario === scenario.id ? 'Running...' : 'Simulate'}
                  </button>
                </div>
                <p className="text-sm text-muted">{scenario.description}</p>
              </div>
            );
          })}
          {!loadError && scenarios.length === 0 && (
            <div className="data-item">
              <p className="text-sm text-muted">No scenarios were returned by the Python backend.</p>
            </div>
          )}
        </div>
      </div>

      {/* Simulation Result */}
      <div className="panel col-span-6">
        <h2 className="section-title"><CheckCircle /> Detection Verification</h2>
        {simResult ? (
          <div className="animate-slide-up">
            <div className="data-item mb-4">
              <div className="item-header mb-2">
                <span className="item-title">{formatLabel(simResult.simulation.scenario)}</span>
                <Badge level={simResult.detection.detection_success ? 'completed' : 'fail'}>
                  {simResult.detection.detection_success ? 'DETECTED' : 'MISSED'}
                </Badge>
              </div>
              <p className="text-sm text-muted mb-4">{simResult.simulation.description}</p>

              <div className="flex-col gap-3">
                <div className="flex-between">
                  <span className="text-sm">Simulated Events</span>
                  <strong>{simResult.detection.total_sim_events}</strong>
                </div>
                <div className="flex-between">
                  <span className="text-sm">Detected as Anomaly</span>
                  <strong style={{ color: '#10b981' }}>{simResult.detection.detected_as_anomaly}</strong>
                </div>
                <div className="flex-between">
                  <span className="text-sm">Detection Rate</span>
                  <strong style={{ color: simResult.detection.detection_rate > 70 ? '#10b981' : '#ef4444' }}>
                    {simResult.detection.detection_rate}%
                  </strong>
                </div>
              </div>

              <div className="flex gap-4 flex-wrap mt-4 text-xs text-muted">
                <span>Run ID: {simResult.simulation.simulation_id}</span>
                <span>Generated: {simResult.simulation.generated_at}</span>
                <span>Intensity: {formatLabel(simResult.simulation.intensity || 'high')}</span>
              </div>

              <div className="score-track mt-4">
                <div className={`score-fill ${simResult.detection.detection_rate > 70 ? 'high' : 'critical'}`}
                  style={{ width: `${simResult.detection.detection_rate}%` }}></div>
              </div>
            </div>

            <div className="data-item mb-4">
              <div className="item-header mb-2">
                <span className="item-title">Run Details</span>
              </div>
              <div className="flex-col gap-3">
                {Object.entries(simResult.simulation)
                  .filter(([key, value]) => !['scenario', 'description', 'expected_detection'].includes(key) && value != null)
                  .map(([key, value]) => (
                    <div className="flex-between" key={key}>
                      <span className="text-sm">{formatLabel(key)}</span>
                      <strong>{formatMetricValue(key, value)}</strong>
                    </div>
                  ))}
              </div>
            </div>

            <div className="data-item">
              <div className="item-header mb-2">
                <span className="item-title">Sample Generated Events</span>
              </div>
              <div className="data-list">
                {(simResult.sample_sim_events || []).map((event) => (
                  <div key={event.id} className="data-item" style={{ padding: 12 }}>
                    <div className="item-header">
                      <span className="item-title">{event.action}</span>
                      <Badge level={event.severity}>{event.severity}</Badge>
                    </div>
                    <p className="text-xs text-muted">{event.description}</p>
                    <div className="flex gap-4 flex-wrap mt-2 text-xs text-muted">
                      <span>User: {event.user}</span>
                      <span>IP: {event.src_ip}</span>
                      <span>Time: {event.timestamp}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="empty-state">
            <Target size={40} />
            <p>Run an attack scenario to verify detection</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AttackSimulationTab;
