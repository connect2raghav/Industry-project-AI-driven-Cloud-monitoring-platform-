import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Crosshair, Play, RefreshCw, AlertTriangle, CheckCircle, XCircle, Zap, Target } from 'lucide-react';
import { Badge } from './SharedComponents';

const API_URL = 'http://localhost:8000/api';

const AttackSimulationTab = ({ showToast }) => {
  const [scenarios, setScenarios] = useState([]);
  const [simResult, setSimResult] = useState(null);
  const [fullResult, setFullResult] = useState(null);
  const [executing, setExecuting] = useState(false);

  useEffect(() => {
    axios.get(`${API_URL}/simulation/scenarios`).then(r => setScenarios(r.data.data)).catch(console.error);
  }, []);

  const runScenario = async (scenario) => {
    setExecuting(true);
    try {
      const res = await axios.post(`${API_URL}/simulation/run/${scenario}?intensity=high`);
      setSimResult(res.data.data);
      showToast(`Attack simulation "${scenario}" completed`);
    } catch (err) {
      showToast('Simulation failed', 'error');
    }
    setExecuting(false);
  };

  const runFullSim = async () => {
    setExecuting(true);
    try {
      const res = await axios.post(`${API_URL}/simulation/full`);
      setFullResult(res.data.data);
      showToast('Full attack simulation completed');
    } catch (err) {
      showToast('Full simulation failed', 'error');
    }
    setExecuting(false);
  };

  const scenarioInfo = {
    brute_force: { icon: '🔨', desc: 'Multiple failed login attempts followed by successful breach', color: '#ef4444' },
    privilege_escalation: { icon: '⬆️', desc: 'User escalates to admin via policy manipulation', color: '#f97316' },
    data_exfiltration: { icon: '📤', desc: 'Large data transfers to external destinations', color: '#8b5cf6' },
    abnormal_access: { icon: '🌐', desc: 'Login from unusual geo-location and suspicious API calls', color: '#06b6d4' },
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
          <button className="btn btn-danger" onClick={runFullSim} disabled={executing}>
            {executing ? <RefreshCw size={16} className="animate-spin" /> : <Zap size={16} />}
            {executing ? 'Simulating...' : 'Launch Full Simulation'}
          </button>
        </div>

        {fullResult && (
          <div className="mt-4 animate-slide-up">
            <div className="flex gap-4 flex-wrap mt-4">
              <div className="stat-pill">
                <Crosshair size={14} style={{ color: '#ef4444' }} />
                {fullResult.simulation_summary.scenarios_run} Scenarios
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

            {/* Per-Scenario Results */}
            <div className="dashboard-grid mt-4" style={{ gap: '12px' }}>
              {fullResult.scenarios.map((s, i) => (
                <div key={i} className="data-item col-span-3">
                  <div className="item-header">
                    <span className="item-title">{scenarioInfo[s.scenario]?.icon} {s.scenario.replace('_', ' ')}</span>
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
        <div className="data-list">
          {scenarios.map((s, i) => {
            const info = scenarioInfo[s] || { icon: '⚡', desc: 'Attack simulation', color: '#8b949e' };
            return (
              <div key={i} className="data-item">
                <div className="item-header">
                  <span className="item-title">{info.icon} {s.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
                  <button className="btn btn-sm btn-danger" onClick={() => runScenario(s)} disabled={executing}>
                    <Play size={12} /> Simulate
                  </button>
                </div>
                <p className="text-sm text-muted">{info.desc}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Simulation Result */}
      <div className="panel col-span-6">
        <h2 className="section-title"><CheckCircle /> Detection Verification</h2>
        {simResult ? (
          <div className="animate-slide-up">
            <div className="data-item mb-4">
              <div className="item-header mb-2">
                <span className="item-title">{simResult.simulation.scenario}</span>
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

              <div className="score-track mt-4">
                <div className={`score-fill ${simResult.detection.detection_rate > 70 ? 'high' : 'critical'}`}
                  style={{ width: `${simResult.detection.detection_rate}%` }}></div>
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
