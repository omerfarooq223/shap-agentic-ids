import { useState } from 'react';
import { Activity, AlertCircle, Lock, Cpu, Zap, Shield, ChevronRight, Loader2, CheckCircle2, Eye, EyeOff } from 'lucide-react';

const DashboardTab = ({
  alerts,
  filteredAlerts,
  selectedAlert,
  setSelectedAlert,
  setAlerts,
  showBenignDetections,
  setShowBenignDetections,
  benignDetectionCount = 0
}) => {
  const [actionState, setActionState] = useState({ alertId: null, status: 'idle' });
  const actionStatus = actionState.alertId === selectedAlert?.id ? actionState.status : 'idle';
  const selectedIsBenign = selectedAlert?.anomaly === false || selectedAlert?.threat_type === 'benign';
  const setCurrentActionStatus = (status) => {
    setActionState({ alertId: selectedAlert?.id ?? null, status });
  };

  const handleIsolate = () => {
    setCurrentActionStatus('isolating');
    setTimeout(() => {
      setCurrentActionStatus('isolated');
      if (setAlerts) {
        setAlerts(prevAlerts => 
          prevAlerts.map(alert => 
            alert.id === selectedAlert.id 
              ? { ...alert, status: 'RESOLVED', recommendation: `🔴 HOST ISOLATED: All network traffic from source IP ${selectedAlert.src_ip} has been blocked.` } 
              : alert
          )
        );
      }
      setSelectedAlert(prev => ({
        ...prev,
        status: 'RESOLVED',
        recommendation: `🔴 HOST ISOLATED: All network traffic from source IP ${selectedAlert.src_ip} has been blocked.`
      }));
    }, 1200);
  };

  const handleWhitelist = () => {
    setCurrentActionStatus('whitelisting');
    setTimeout(() => {
      setCurrentActionStatus('whitelisted');
      if (setAlerts) {
        setAlerts(prevAlerts => 
          prevAlerts.map(alert => 
            alert.id === selectedAlert.id 
              ? { ...alert, status: 'RESOLVED', recommendation: `🟢 IP WHITELISTED: IP address ${selectedAlert.src_ip} has been added to the secure whitelist.` } 
              : alert
          )
        );
      }
      setSelectedAlert(prev => ({
        ...prev,
        status: 'RESOLVED',
        recommendation: `🟢 IP WHITELISTED: IP address ${selectedAlert.src_ip} has been added to the secure whitelist.`
      }));
    }, 1200);
  };

  return (
    <div className="tab-panel dashboard-panel">
      <div className="panel-header">
        <div className="header-info">
          <h2><Activity size={24} /> THREAT DASHBOARD</h2>
          <p>Real-time intrusion detection and analysis</p>
        </div>
        <div className="header-stats">
          <div className="quick-stat">
            <span className="stat-label">Total Alerts</span>
            <span className="stat-number">{alerts.length}</span>
          </div>
          <div className="quick-stat critical">
            <span className="stat-label">Critical</span>
            <span className="stat-number">{alerts.filter(a => a.status === 'CRITICAL').length}</span>
          </div>
          <div className="quick-stat">
            <span className="stat-label">Avg Risk</span>
            <span className="stat-number">
              {alerts.length > 0 ? (alerts.reduce((sum, a) => sum + (a.risk_score || 0), 0) / alerts.length).toFixed(1) : '0.0'}
            </span>
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        <section className="alert-feed-section">
          <div className="section-header">
            <h3><AlertCircle size={18} /> ACTIVE THREAT FEED</h3>
            <div className="section-actions">
              <button
                type="button"
                className={`benign-toggle-btn ${showBenignDetections ? 'active' : ''}`}
                onClick={() => setShowBenignDetections(prev => !prev)}
                title={showBenignDetections ? 'Hide benign simulator results' : 'Show benign simulator results'}
              >
                {showBenignDetections ? <EyeOff size={13} /> : <Eye size={13} />}
                <span>{showBenignDetections ? 'Hide Benign' : 'Show Benign'}</span>
                <span className="benign-count">{benignDetectionCount}</span>
              </button>
              <span className="alert-count">{filteredAlerts.length} alerts</span>
            </div>
          </div>
          <div className="alerts-list">
            {filteredAlerts.map(alert => (
              <div
                key={alert.id}
                className={`alert-item ${alert.status.toLowerCase()} ${selectedAlert?.id === alert.id ? 'selected' : ''}`}
                onClick={() => setSelectedAlert(alert)}
              >
                <div className="alert-status">
                  <div className={`status-badge ${alert.status.toLowerCase()}`}></div>
                </div>
                <div className="alert-content">
                  <div className="alert-title">
                    <span className="threat-type" style={{ display: 'inline-flex', alignItems: 'center', flexWrap: 'wrap' }}>
	                      {alert.threat_type}
                      {alert.anomaly === false && (
                        <span className="benign-badge" title="Benign simulator result">
                          Benign
                        </span>
                      )}
                      {alert.ml_confidence < 0.50 && alert.risk_score > 0 && (
                        <span className="evasion-badge" title="Borderline flow escalated by Evasion Guard">
                          🛡️ Evasion Escalation
                        </span>
                      )}
                    </span>
                    <span className="risk-score">Risk: {alert.risk_score}</span>
                  </div>
                  <div className="alert-details">
                    <span className="ip-info">{alert.src_ip} → {alert.dst_port}</span>
                    <span className="timestamp">{alert.timestamp}</span>
                  </div>
                </div>
                <ChevronRight size={16} className="alert-arrow" />
              </div>
            ))}
          </div>
        </section>

        <section className="analysis-section">
          {selectedAlert ? (
            <div className="analysis-panel">
              <div className="analysis-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                <h3><Lock size={18} /> DEEP ANALYSIS</h3>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  {selectedAlert.ml_confidence < 0.50 && selectedAlert.risk_score > 0 && (
                    <span className="evasion-badge big" title="Borderline flow escalated by Evasion Guard">
                      🛡️ EVASION GUARD ESCALATED
                    </span>
                  )}
                  <span className={`status-tag ${selectedAlert.status.toLowerCase()}`}>{selectedAlert.status}</span>
                </div>
              </div>

              <div className="info-grid">
                <div className="info-card">
                  <label>Source IP</label>
                  <div className="val">{selectedAlert.src_ip}</div>
                </div>
                <div className="info-card">
                  <label>Destination Port</label>
                  <div className="val">{selectedAlert.dst_port}</div>
                </div>
                <div className="info-card">
                  <label>MITRE ATT&CK</label>
                  <div className="val">{selectedAlert.mitre || 'T1046 (Scanning)'}</div>
                </div>
                <div className="info-card">
	                  <label>Risk Score</label>
	                  <div className="val">{selectedAlert.risk_score}/10</div>
	                </div>
                <div className="info-card">
                  <label>ML Score</label>
                  <div className="val">{(((selectedAlert.ml_confidence || 0) * 100)).toFixed(1)}%</div>
                </div>
                <div className="info-card">
                  <label>AbuseIPDB Score</label>
                  <div className="val">{selectedAlert.threat_intel?.abuse_score ?? 'N/A'}%</div>
                </div>
                <div className="info-card">
                  <label>Intel Source</label>
                  <div className="val">{selectedAlert.threat_intel?.intel_source ?? 'Local ML'}</div>
                </div>
              </div>

              <div className="shap-panel">
	                <h4><Cpu size={16} /> FEATURE IMPORTANCE</h4>
	                <div className="shap-list">
                  {selectedAlert?.shap_explanation?.length ? selectedAlert.shap_explanation.map((item, idx) => (
	                    <div key={idx} className="shap-item">
                      <div className="shap-info">
                        <span>{item.feature}</span>
                        <span className="val">{item.value}</span>
                      </div>
                      <div className="shap-bar-container">
                        <div
                          className="shap-bar"
                          style={{ width: `${((item.impact || item.contribution) || 0) * 100}%` }}
                        ></div>
                        <span className="impact-val">{(((item.impact || item.contribution) || 0) * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                  )) : (
                    <div className="empty-shap-note">
                      {selectedIsBenign ? 'Skipped SHAP and agent review because the ML score stayed below the alert threshold.' : 'No feature explanation available for this record.'}
                    </div>
                  )}
	                </div>
	              </div>

              <div className="recommendation-section">
                <h4><Zap size={16} /> AGENT RECOMMENDATION</h4>
                <div className="recommendation-box">
                  <p style={{ minHeight: '40px' }}>
                    {selectedIsBenign ? (
                      <>The simulated flow was classified as <strong>benign</strong>. The ML score stayed below the alert threshold, so no incident response action is required.</>
                    ) : selectedAlert.recommendation?.includes('HOST ISOLATED') || selectedAlert.recommendation?.includes('IP WHITELISTED') ? (
                      <strong>{selectedAlert.recommendation}</strong>
                    ) : (
                      <>IP <strong>{selectedAlert.src_ip}</strong> exhibits behavior consistent with <strong>{selectedAlert.threat_type}</strong>.</>
                    )}
                  </p>
                  <div className="action-buttons">
                    <style>{`
                      @keyframes dashboard-spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                      }
                      .dashboard-spin-icon {
                        animation: dashboard-spin 1s linear infinite;
                      }
                    `}</style>
                    <button 
                      className={`action-btn primary`}
                      onClick={handleIsolate}
                      disabled={selectedIsBenign || actionStatus !== 'idle' || selectedAlert.status === 'RESOLVED'}
                      style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                    >
                      {actionStatus === 'isolating' ? (
                        <>
                          <Loader2 size={14} className="dashboard-spin-icon" />
                          ISOLATING...
                        </>
                      ) : actionStatus === 'isolated' || selectedAlert.recommendation?.includes('HOST ISOLATED') ? (
                        <>
                          <CheckCircle2 size={14} />
                          HOST ISOLATED
                        </>
                      ) : (
                        selectedAlert.status === 'CRITICAL' ? '🛑 ISOLATE HOST' : '⚠️ MONITOR'
                      )}
                    </button>
                    <button 
                      className="action-btn secondary"
                      onClick={handleWhitelist}
                      disabled={selectedIsBenign || actionStatus !== 'idle' || selectedAlert.status === 'RESOLVED'}
                      style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
                    >
                      {actionStatus === 'whitelisting' ? (
                        <>
                          <Loader2 size={14} className="dashboard-spin-icon" />
                          WHITELISTING...
                        </>
                      ) : actionStatus === 'whitelisted' || selectedAlert.recommendation?.includes('IP WHITELISTED') ? (
                        <>
                          <CheckCircle2 size={14} />
                          WHITELISTED
                        </>
                      ) : (
                        'WHITELIST'
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="empty-analysis">
              <Shield size={40} />
              <p>Select an alert to view analysis</p>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};

export default DashboardTab;
