import React, { useState } from 'react';
import axios from 'axios';
import { ShieldAlert, Lock, User, Mail, KeyRound, Eye, EyeOff } from 'lucide-react';

const API_URL = 'http://localhost:8000/api';

const LoginPage = ({ onLogin }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [form, setForm] = useState({ username: '', password: '', email: '', role: 'viewer', full_name: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (isRegister) {
        await axios.post(`${API_URL}/auth/register`, form);
        setIsRegister(false);
        setError('');
        setForm(f => ({ ...f, email: '', role: 'viewer', full_name: '' }));
      } else {
        const res = await axios.post(`${API_URL}/auth/login`, {
          username: form.username, password: form.password
        });
        const data = res.data.data;
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        onLogin(data.user, data.token);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed');
    }
    setLoading(false);
  };

  const demoLogin = async (username, password) => {
    setForm({ ...form, username, password });
    setLoading(true);
    setError('');
    try {
      const res = await axios.post(`${API_URL}/auth/login`, { username, password });
      const data = res.data.data;
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      onLogin(data.user, data.token);
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed');
    }
    setLoading(false);
  };

  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-header">
          <ShieldAlert size={48} color="#3b82f6" />
          <h1>Ram Antivirus</h1>
          <p className="text-muted">Cloud Security AI Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <h2>{isRegister ? 'Create Account' : 'Sign In'}</h2>

          {error && <div className="login-error">{error}</div>}

          <div className="form-group">
            <User size={16} className="form-icon" />
            <input type="text" placeholder="Username" value={form.username}
              onChange={e => setForm({ ...form, username: e.target.value })} required />
          </div>

          <div className="form-group">
            <Lock size={16} className="form-icon" />
            <input type={showPassword ? 'text' : 'password'} placeholder="Password"
              value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} required />
            <button type="button" className="toggle-pass" onClick={() => setShowPassword(!showPassword)}>
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>

          {isRegister && (
            <>
              <div className="form-group">
                <Mail size={16} className="form-icon" />
                <input type="email" placeholder="Email" value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })} required />
              </div>
              <div className="form-group">
                <User size={16} className="form-icon" />
                <input type="text" placeholder="Full Name" value={form.full_name}
                  onChange={e => setForm({ ...form, full_name: e.target.value })} />
              </div>
              <div className="form-group">
                <KeyRound size={16} className="form-icon" />
                <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                  <option value="viewer">Viewer — Read Only</option>
                  <option value="analyst">Analyst — View + Alerts</option>
                  <option value="admin">Admin — Full Access</option>
                </select>
              </div>
            </>
          )}

          <button type="submit" className="btn login-btn" disabled={loading}>
            {loading ? 'Processing...' : isRegister ? 'Register' : 'Sign In'}
          </button>

          <p className="toggle-mode">
            {isRegister ? 'Already have an account?' : "Don't have an account?"}
            <button type="button" onClick={() => { setIsRegister(!isRegister); setError(''); }}>
              {isRegister ? 'Sign In' : 'Register'}
            </button>
          </p>
        </form>

        <div className="demo-accounts">
          <p className="text-xs text-muted">Quick Demo Login:</p>
          <div className="demo-btns">
            <button className="btn btn-sm" onClick={() => demoLogin('admin', 'admin123')}>
              <KeyRound size={12} /> Admin
            </button>
            <button className="btn btn-sm btn-outline" onClick={() => demoLogin('analyst1', 'analyst123')}>
              <KeyRound size={12} /> Analyst
            </button>
            <button className="btn btn-sm btn-outline" onClick={() => demoLogin('viewer1', 'viewer123')}>
              <KeyRound size={12} /> Viewer
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
