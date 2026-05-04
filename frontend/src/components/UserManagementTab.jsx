import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Users, UserCheck, UserX, RefreshCw, Shield, Mail, Clock } from 'lucide-react';
import { Badge } from './SharedComponents';

const API_URL = 'http://localhost:8000/api';

const UserManagementTab = ({ token, showToast }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);

  const headers = { Authorization: `Bearer ${token}` };

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/auth/users`, { headers });
      setUsers(res.data.data);
    } catch (err) {
      showToast('Failed to load users', 'error');
    }
    setLoading(false);
  };

  useEffect(() => { fetchUsers(); }, []);

  const toggleUser = async (username, isActive) => {
    const action = isActive ? 'deactivate' : 'reactivate';
    try {
      await axios.post(`${API_URL}/auth/users/${username}/${action}`, {}, { headers });
      showToast(`User "${username}" ${action}d`);
      fetchUsers();
    } catch (err) {
      showToast(`Failed to ${action} user`, 'error');
    }
  };

  const roleCounts = users.reduce((acc, u) => {
    acc[u.role] = (acc[u.role] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="dashboard-grid animate-fade-in">
      {/* Header */}
      <div className="panel col-span-12">
        <div className="flex-between">
          <div>
            <h2 className="section-title" style={{ marginBottom: 4 }}><Users /> User Management</h2>
            <p className="text-sm text-muted">Manage user accounts and role-based access control</p>
          </div>
          <button className="btn" onClick={fetchUsers} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>

        {/* Stats */}
        <div className="flex gap-4 mt-4 flex-wrap">
          <div className="stat-pill"><Users size={14} /> {users.length} Total Users</div>
          <div className="stat-pill"><UserCheck size={14} style={{ color: '#10b981' }} /> {users.filter(u => u.is_active).length} Active</div>
          <div className="stat-pill"><UserX size={14} style={{ color: '#ef4444' }} /> {users.filter(u => !u.is_active).length} Inactive</div>
          {Object.entries(roleCounts).map(([role, count]) => (
            <div key={role} className="stat-pill">
              <Shield size={14} /> {count} {role}
            </div>
          ))}
        </div>
      </div>

      {/* User Table */}
      <div className="panel col-span-12">
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                {['User', 'Email', 'Role', 'Status', 'Last Login', 'Created', 'Actions'].map(h => (
                  <th key={h} style={{ padding: '10px 12px', textAlign: 'left', fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map((user, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', opacity: user.is_active ? 1 : 0.5 }}>
                  <td style={{ padding: '12px' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{user.full_name}</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>@{user.username}</div>
                  </td>
                  <td style={{ padding: '12px' }}>
                    <div className="flex gap-1 items-center text-sm text-muted">
                      <Mail size={12} /> {user.email}
                    </div>
                  </td>
                  <td style={{ padding: '12px' }}>
                    <Badge level={user.role === 'admin' ? 'critical' : user.role === 'analyst' ? 'medium' : 'low'}>
                      {user.role}
                    </Badge>
                  </td>
                  <td style={{ padding: '12px' }}>
                    <Badge level={user.is_active ? 'completed' : 'fail'}>
                      {user.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </td>
                  <td style={{ padding: '12px' }}>
                    <div className="flex gap-1 items-center text-xs text-muted">
                      <Clock size={11} />
                      {user.last_login ? user.last_login.replace('T', ' ').replace('Z', '') : 'Never'}
                    </div>
                  </td>
                  <td style={{ padding: '12px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                    {user.created_at?.split('T')[0]}
                  </td>
                  <td style={{ padding: '12px' }}>
                    {user.username !== 'admin' && (
                      <button
                        className={`btn btn-sm ${user.is_active ? 'btn-danger' : 'btn-success'}`}
                        onClick={() => toggleUser(user.username, user.is_active)}
                      >
                        {user.is_active ? <><UserX size={12} /> Deactivate</> : <><UserCheck size={12} /> Reactivate</>}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default UserManagementTab;
