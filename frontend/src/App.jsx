import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { ShieldAlert, Fingerprint, Activity, Server, RefreshCw, AlertTriangle, Zap, FileText, CheckCircle, XCircle, Play, Shield, Download, Lock, Unlock, Settings, BarChart3, ChevronRight, Cpu, Gauge, Crosshair, LogOut, User } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Legend } from 'recharts';
import { Badge, ScoreRing, Toast } from './components/SharedComponents';
import LoginPage from './components/LoginPage';
import AttackSimulationTab from './components/AttackSimulationTab';
import RiskScoreTab from './components/RiskScoreTab';
import MLComparisonTab from './components/MLComparisonTab';
import './index.css';

const API_URL = 'http://localhost:8000/api';

const Dashboard = () => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [data, setData] = useState({ summary: null, events: [], cspm: [], ciem: [] });
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState(null);
  const [playbooks, setPlaybooks] = useState([]);
  const [remediationResult, setRemediationResult] = useState(null);
  const [pipelineResult, setPipelineResult] = useState(null);
  const [executing, setExecuting] = useState(false);
  const [complianceDashboard, setComplianceDashboard] = useState(null);
  const [complianceReport, setComplianceReport] = useState(null);
  const [selectedFramework, setSelectedFramework] = useState(null);

  const showToast = useCallback((message, type = 'success') => setToast({ message, type }), []);

  // Check saved auth on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const handleLogin = (userData, tokenData) => { setUser(userData); setToken(tokenData); };
  const handleLogout = () => { setUser(null); setToken(null); localStorage.removeItem('token'); localStorage.removeItem('user'); };
  const hasPermission = (perm) => user?.permissions?.includes(perm) ?? false;

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [summaryRes, eventsRes, cspmRes, ciemRes] = await Promise.all([
        axios.get(`${API_URL}/dashboard/summary`), axios.get(`${API_URL}/simulate/events?hours=6&normal=50&attacks=10`),
        axios.get(`${API_URL}/cspm/scan`), axios.get(`${API_URL}/ciem/scan`)
      ]);
      setData({ summary: summaryRes.data.data, events: eventsRes.data.data, cspm: cspmRes.data.data, ciem: ciemRes.data.data });
    } catch (error) { console.error("Error fetching data:", error); }
    setLoading(false);
  };

  useEffect(() => { if (user) fetchDashboardData(); }, [user]);

  const fetchPlaybooks = async () => { try { const res = await axios.get(`${API_URL}/remediation/playbooks`); setPlaybooks(res.data.data); } catch (err) { console.error(err); } };
  const executePlaybook = async (attackType) => { setExecuting(true); try { const res = await axios.post(`${API_URL}/remediation/execute/${attackType}`); setRemediationResult(res.data.data); showToast(`Playbook "${res.data.data.playbook_name}" executed`); } catch (err) { showToast('Playbook failed', 'error'); } setExecuting(false); };
  const runFullPipeline = async () => { setExecuting(true); try { const res = await axios.get(`${API_URL}/remediation/full-pipeline`); setPipelineResult(res.data.data); showToast('Full pipeline completed'); } catch (err) { showToast('Pipeline failed', 'error'); } setExecuting(false); };
  const fixConfig = async (vulnId) => { try { const res = await axios.post(`${API_URL}/remediation/config-fix/${vulnId}`); showToast(`Config fix: ${res.data.data.description}`); } catch (err) { showToast('Fix failed', 'error'); } };
  const revokeAccess = async (n, t, r) => { try { await axios.post(`${API_URL}/remediation/revoke-access?entity_name=${n}&entity_type=${t}&risk_level=${r}`); showToast(`Access revoked for "${n}"`); } catch (err) { showToast('Revocation failed', 'error'); } };
  const fetchComplianceDashboard = async () => { try { const res = await axios.get(`${API_URL}/compliance/dashboard`); setComplianceDashboard(res.data.data); } catch (err) { console.error(err); } };
  const fetchComplianceReport = async () => { try { const res = await axios.get(`${API_URL}/compliance/report?format=json`); setComplianceReport(res.data.data); showToast('Report generated'); } catch (err) { showToast('Report failed', 'error'); } };
  const downloadCSVReport = async () => { try { const res = await axios.get(`${API_URL}/compliance/report?format=csv`, { responseType: 'blob' }); const url = window.URL.createObjectURL(new Blob([res.data])); const link = document.createElement('a'); link.href = url; link.setAttribute('download', 'compliance_report.csv'); document.body.appendChild(link); link.click(); link.remove(); showToast('CSV downloaded'); } catch (err) { showToast('Download failed', 'error'); } };

  useEffect(() => {
    if (activeTab === 'remediation') { fetchPlaybooks(); if (data.cspm.length === 0) fetchDashboardData(); }
    if (activeTab === 'compliance') fetchComplianceDashboard();
  }, [activeTab]);

  if (!user) return <LoginPage onLogin={handleLogin} />;
  if (loading && !data.summary) return (
    <div className="app-container flex flex-col justify-center items-center" style={{ minHeight: '100vh', gap: '20px' }}>
      <RefreshCw size={48} className="animate-spin" style={{ color: 'var(--accent-blue)' }} />
      <h2 className="animate-pulse">Initializing AI Cloud Security Platform...</h2>
    </div>
  );

  const chartData = [...data.events].reverse().map(e => ({ time: e.timestamp.split('T')[1].substring(0, 5), score: e.ml_anomaly_score, isAttack: e.is_anomaly })).slice(0, 40);

  const allTabs = [
    { id: 'overview', label: 'Overview', icon: <BarChart3 size={16} />, perm: 'dashboard:read' },
    { id: 'risk', label: 'Risk Score', icon: <Gauge size={16} />, perm: 'risk:read' },
    { id: 'ml', label: 'ML Comparison', icon: <Cpu size={16} />, perm: 'ml:read' },
    { id: 'remediation', label: 'Remediation', icon: <Zap size={16} />, perm: 'remediation:read' },
    { id: 'compliance', label: 'Compliance', icon: <FileText size={16} />, perm: 'compliance:read' },
    { id: 'simulation', label: 'Attack Sim', icon: <Crosshair size={16} />, perm: 'simulation:read' },
  ];
  const tabs = allTabs.filter(t => hasPermission(t.perm));

  return (
    <div className="app-container">
      <header className="header">
        <h1><ShieldAlert size={32} color="#3b82f6" /> Ram Antivirus — Cloud Security AI</h1>
        <div className="header-stats">
          <div className="stat-pill"><span style={{ color: 'var(--critical-color)' }}>●</span> {data.summary?.threats.critical} Critical</div>
          <div className="stat-pill"><span style={{ color: 'var(--high-color)' }}>●</span> {data.summary?.posture.cspm_open_issues} CSPM Issues</div>
          <div className="stat-pill user-pill"><User size={14} /> {user.username} <Badge level={user.role === 'admin' ? 'critical' : user.role === 'analyst' ? 'medium' : 'low'}>{user.role}</Badge></div>
          <button className="btn" onClick={fetchDashboardData} disabled={loading}><RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Re-scan</button>
          <button className="btn btn-outline" onClick={handleLogout}><LogOut size={16} /> Logout</button>
        </div>
      </header>

      <nav className="tabs-nav">
        {tabs.map(tab => (<button key={tab.id} className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`} onClick={() => setActiveTab(tab.id)}>{tab.icon} {tab.label}</button>))}
      </nav>

      {/* OVERVIEW TAB */}
      {activeTab === 'overview' && (
        <div className="dashboard-grid animate-fade-in">
          <div className="panel col-span-8">
            <h2 className="section-title"><Activity /> Real-time PyOD ML Anomaly Detection</h2>
            <div style={{ height: '300px', width: '100%' }}>
              <ResponsiveContainer><AreaChart data={chartData}>
                <defs><linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4}/><stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/></linearGradient></defs>
                <XAxis dataKey="time" stroke="#8b949e" tick={{fontSize: 12}} /><YAxis stroke="#8b949e" domain={[0, 1]} tick={{fontSize: 12}} />
                <Tooltip contentStyle={{ backgroundColor: 'rgba(20,27,45,0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="score" stroke="#8b5cf6" fillOpacity={1} fill="url(#colorScore)" />
              </AreaChart></ResponsiveContainer>
            </div>
          </div>
          <div className="panel col-span-4" style={{ overflowY: 'auto', maxHeight: '400px' }}>
            <h2 className="section-title text-critical"><AlertTriangle /> Active Threats</h2>
            <div className="data-list">
              {data.summary?.recent_critical_alerts.map((alert, i) => (
                <div key={i} className="data-item">
                  <div className="item-header"><span className="item-title">{alert.attack_type?.replace('_', ' ')}</span><Badge level={alert.ml_severity}>{alert.ml_severity}</Badge></div>
                  <div className="text-sm text-muted mb-4">{alert.description}</div>
                  <div className="flex-between text-xs"><span>User: <strong style={{color: '#f0f6fc'}}>{alert.user}</strong></span><span>IP: {alert.src_ip}</span></div>
                  <div className="score-track mt-4"><div className={`score-fill ${alert.ml_severity.toLowerCase()}`} style={{ width: `${alert.ml_anomaly_score * 100}%` }}></div></div>
                </div>
              ))}
            </div>
          </div>
          <div className="panel col-span-6">
            <h2 className="section-title"><Server /> CSPM — Misconfigurations</h2>
            <div className="data-list">{data.cspm.map((issue, i) => (
              <div key={i} className="data-item"><div className="item-header"><span className="item-title">{issue.title}</span><Badge level={issue.severity}>{issue.severity}</Badge></div>
              <p className="text-sm text-muted">{issue.description}</p>
              <div className="mt-4 p-2 text-xs" style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '6px', borderLeft: '3px solid #3b82f6' }}><strong>Remediation:</strong> {issue.remediation}</div></div>
            ))}</div>
          </div>
          <div className="panel col-span-6">
            <h2 className="section-title"><Fingerprint /> CIEM — Identity Risk</h2>
            <div className="data-list">{data.ciem.map((risk, i) => (
              <div key={i} className="data-item"><div className="item-header"><span className="item-title">{risk.title}</span><Badge level={risk.risk_level}>{risk.risk_level}</Badge></div>
              <div className="flex-between text-sm mt-4 mb-4"><span>Entity: <strong>{risk.entity_name}</strong></span><span style={{ color: 'var(--text-secondary)'}}>{risk.entity_type}</span></div>
              <div className="p-2 text-xs" style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '6px', borderLeft: '3px solid #8b5cf6' }}><strong>Remediation:</strong> {risk.remediation}</div></div>
            ))}</div>
          </div>
        </div>
      )}

      {/* RISK SCORE TAB */}
      {activeTab === 'risk' && <RiskScoreTab showToast={showToast} />}

      {/* ML COMPARISON TAB */}
      {activeTab === 'ml' && <MLComparisonTab showToast={showToast} />}

      {/* REMEDIATION TAB */}
      {activeTab === 'remediation' && (
        <div className="dashboard-grid animate-fade-in">
          <div className="panel col-span-12">
            <div className="flex-between"><div><h2 className="section-title" style={{ marginBottom: 4 }}><Zap /> Full Auto-Remediation Pipeline</h2><p className="text-sm text-muted">Simulate → ML Analyze → CSPM/CIEM → Auto-Remediate → Config Fix</p></div>
            {hasPermission('remediation:execute') && <button className="btn btn-success" onClick={runFullPipeline} disabled={executing}>{executing ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}{executing ? 'Executing...' : 'Run Full Pipeline'}</button>}
            </div>
            {pipelineResult && (<div className="mt-4 animate-slide-up"><div className="flex gap-4 flex-wrap mt-4">
              <div className="stat-pill"><Cpu size={14} style={{color: 'var(--accent-purple)'}} />{pipelineResult.ml_analysis.total_events} Events</div>
              <div className="stat-pill"><AlertTriangle size={14} style={{color: 'var(--critical-color)'}} />{pipelineResult.ml_analysis.anomalies_detected} Anomalies</div>
              <div className="stat-pill"><Zap size={14} style={{color: 'var(--accent-green)'}} />{pipelineResult.threat_remediation.remediations_triggered} Playbooks</div>
              <div className="stat-pill"><Settings size={14} style={{color: 'var(--accent-blue)'}} />{pipelineResult.config_fixes.length} Fixes</div>
              <div className="stat-pill"><Lock size={14} style={{color: 'var(--high-color)'}} />{pipelineResult.access_revocations.length} Revocations</div>
            </div></div>)}
          </div>
          <div className="panel col-span-6">
            <h2 className="section-title"><Shield /> Playbooks</h2>
            <div className="data-list">{playbooks.map((pb, i) => (
              <div key={i} className="data-item"><div className="item-header"><span className="item-title">{pb.name}</span><Badge level={pb.severity_trigger}>{pb.severity_trigger}</Badge></div>
              <p className="text-sm text-muted mb-2">{pb.description}</p>
              <div className="flex-between mt-2"><div className="flex gap-3 text-xs text-muted"><span>{pb.num_steps} steps</span><span>~{pb.estimated_time_seconds}s</span></div>
              {hasPermission('remediation:execute') && <button className="btn btn-sm" onClick={() => executePlaybook(pb.attack_type)} disabled={executing}><Play size={12} /> Execute</button>}</div></div>
            ))}</div>
          </div>
          <div className="panel col-span-6">
            <h2 className="section-title"><CheckCircle /> Execution Result</h2>
            {remediationResult ? (<div className="animate-slide-up">
              <div className="item-header mb-4"><span className="item-title">{remediationResult.playbook_name}</span><Badge level={remediationResult.overall_status}>{remediationResult.overall_status}</Badge></div>
              <div className="flex gap-3 text-xs text-muted mb-4"><span>ID: {remediationResult.execution_id}</span><span>{remediationResult.total_duration_ms}ms</span><span>{remediationResult.steps_succeeded}/{remediationResult.steps_executed} passed</span></div>
              <div className="step-timeline">{remediationResult.steps.map((step, i) => (
                <div key={i} className="step-item"><div className={`step-dot ${step.status}`}></div><div style={{ flex: 1 }}><div className="flex-between"><span className="text-sm" style={{ fontWeight: 500 }}>{step.description}</span><span className="text-xs text-muted">{step.duration_ms}ms</span></div><span className="text-xs text-muted">{step.action}</span></div></div>
              ))}</div>
            </div>) : (<div className="empty-state"><Play size={40} /><p>Execute a playbook to see results</p></div>)}
          </div>
          <div className="panel col-span-6">
            <h2 className="section-title"><Settings /> CSPM Config Correction</h2>
            <div className="data-list">{data.cspm.map((issue, i) => (
              <div key={i} className="data-item"><div className="item-header"><span className="item-title">{issue.title}</span><Badge level={issue.severity}>{issue.severity}</Badge></div>
              <p className="text-sm text-muted mb-2">{issue.description}</p>
              <div className="flex-between mt-2"><span className="text-xs" style={{ color: 'var(--accent-cyan)' }}>{issue.vulnerability_id}</span>
              {hasPermission('remediation:execute') && <button className="btn btn-sm btn-success" onClick={() => fixConfig(issue.vulnerability_id)}><Settings size={12} /> Auto-Fix</button>}</div></div>
            ))}</div>
          </div>
          <div className="panel col-span-6">
            <h2 className="section-title"><Lock /> CIEM Access Revocation</h2>
            <div className="data-list">{data.ciem.map((risk, i) => (
              <div key={i} className="data-item"><div className="item-header"><span className="item-title">{risk.title}</span><Badge level={risk.risk_level}>{risk.risk_level}</Badge></div>
              <div className="flex-between text-sm mt-2 mb-2"><span>Entity: <strong>{risk.entity_name}</strong></span><span className="text-xs text-muted">{risk.entity_type}</span></div>
              <div className="flex-between mt-2"><span className="text-xs text-muted">{risk.description}</span>
              {hasPermission('remediation:execute') && <button className="btn btn-sm btn-danger" onClick={() => revokeAccess(risk.entity_name, risk.entity_type, risk.risk_level)}><Unlock size={12} /> Revoke</button>}</div></div>
            ))}</div>
          </div>
        </div>
      )}

      {/* COMPLIANCE TAB */}
      {activeTab === 'compliance' && (
        <div className="dashboard-grid animate-fade-in">
          <div className="panel col-span-12">
            <div className="flex-between mb-4"><h2 className="section-title" style={{ marginBottom: 0 }}><Shield /> Compliance Dashboard</h2>
            <div className="flex gap-2"><button className="btn" onClick={fetchComplianceDashboard}><RefreshCw size={16} /> Refresh</button>
            {hasPermission('compliance:generate') && <button className="btn btn-success" onClick={fetchComplianceReport}><FileText size={16} /> Generate Report</button>}
            <button className="btn btn-outline" onClick={downloadCSVReport}><Download size={16} /> CSV</button></div></div>
            {complianceDashboard && (<div>
              <div className="flex items-center gap-4 mb-4" style={{ justifyContent: 'center' }}><ScoreRing score={complianceDashboard.overall_score} size={140} label="Overall Compliance" />
              <div className="ml-2 flex-col gap-2"><div className="stat-pill">{complianceDashboard.trend?.direction === 'improving' ? <span style={{ color: 'var(--success-color)' }}>↑</span> : <span style={{ color: 'var(--critical-color)' }}>↓</span>}{complianceDashboard.trend?.change_7d > 0 ? '+' : ''}{complianceDashboard.trend?.change_7d}% (7d)</div></div></div>
              <div className="dashboard-grid" style={{ gap: '16px' }}>{Object.entries(complianceDashboard.frameworks).map(([key, fw]) => (
                <div key={key} className="framework-card col-span-4" onClick={() => setSelectedFramework(selectedFramework === key ? null : key)} style={{ cursor: 'pointer' }}>
                <ScoreRing score={fw.score} size={100} label={fw.name} /><Badge level={fw.status}>{fw.status.replace('_', ' ')}</Badge>
                <div className="framework-stats"><div className="framework-stat"><div className="stat-val text-success">{fw.passing}</div><div className="stat-label">Passing</div></div>
                <div className="framework-stat"><div className="stat-val" style={{ color: 'var(--critical-color)' }}>{fw.failing}</div><div className="stat-label">Failing</div></div>
                <div className="framework-stat"><div className="stat-val">{fw.total}</div><div className="stat-label">Total</div></div></div></div>
              ))}</div>
            </div>)}
          </div>
          {selectedFramework && complianceDashboard?.frameworks[selectedFramework] && (
            <div className="panel col-span-12 animate-slide-up"><h2 className="section-title"><ChevronRight /> {complianceDashboard.frameworks[selectedFramework].name} — Controls</h2>
            {complianceDashboard.frameworks[selectedFramework].critical_gaps.length > 0 && (<>
              <h3 className="text-sm mb-2 mt-4" style={{ color: 'var(--critical-color)', fontWeight: 600 }}><XCircle size={14} style={{ display: 'inline', verticalAlign: 'middle' }} /> Failing Controls</h3>
              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '12px', overflow: 'hidden' }}>{complianceDashboard.frameworks[selectedFramework].critical_gaps.map((gap, i) => (
                <div key={i} className="control-row"><span className="control-id">{gap.control}</span><span className="control-name">{gap.name}</span><Badge level="fail">FAIL</Badge><span className="text-xs text-muted ml-2">{gap.source}</span></div>
              ))}</div></>)}
            </div>
          )}
          {complianceDashboard && (<div className="panel col-span-6"><h2 className="section-title"><BarChart3 /> Framework Comparison</h2><div style={{ height: '300px' }}>
            <ResponsiveContainer><BarChart data={Object.entries(complianceDashboard.frameworks).map(([key, fw]) => ({ name: key, Passing: fw.passing, Failing: fw.failing }))}>
            <XAxis dataKey="name" stroke="#8b949e" tick={{ fontSize: 12 }} /><YAxis stroke="#8b949e" tick={{ fontSize: 12 }} />
            <Tooltip contentStyle={{ backgroundColor: 'rgba(20,27,45,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }} /><Legend />
            <Bar dataKey="Passing" fill="#10b981" radius={[4, 4, 0, 0]} /><Bar dataKey="Failing" fill="#ef4444" radius={[4, 4, 0, 0]} />
            </BarChart></ResponsiveContainer></div></div>)}
          <div className="panel col-span-6"><h2 className="section-title"><FileText /> Report Preview</h2>
          {complianceReport ? (<div className="animate-slide-up"><div className="data-item mb-4"><div className="item-header mb-2"><span className="text-xs text-muted">Report ID</span><span className="text-sm" style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>{complianceReport.report_id}</span></div>
          <div className="flex-col gap-3"><div className="flex-between"><span className="text-sm">Overall</span><strong style={{ color: complianceReport.executive_summary.overall_compliance_score >= 80 ? 'var(--success-color)' : 'var(--high-color)' }}>{complianceReport.executive_summary.overall_compliance_score}%</strong></div>
          <div className="flex-between"><span className="text-sm">Total Findings</span><strong>{complianceReport.executive_summary.total_findings}</strong></div>
          <div className="flex-between"><span className="text-sm">Critical</span><strong style={{ color: 'var(--critical-color)' }}>{complianceReport.executive_summary.critical_findings}</strong></div>
          <div className="flex-between"><span className="text-sm">ML Anomalies</span><strong style={{ color: 'var(--accent-purple)' }}>{complianceReport.executive_summary.ml_anomalies_detected}</strong></div></div></div></div>
          ) : (<div className="empty-state"><FileText size={40} /><p>Generate a report to preview</p></div>)}</div>
        </div>
      )}

      {/* ATTACK SIMULATION TAB */}
      {activeTab === 'simulation' && <AttackSimulationTab showToast={showToast} />}

      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

export default Dashboard;
