import { Terminal } from 'lucide-react';

const AgentLogsTab = ({ alerts }) => {
  return (
    <div className="tab-panel log-panel">
      <div className="panel-header">
        <div className="header-info">
          <h2><Terminal size={24} /> AGENT REASONING LOGS</h2>
          <p>AI decision-making process and inference chains</p>
        </div>
      </div>

      <div className="logs-container">
        <div className="terminal-view">
          {alerts.length > 0 ? (
            <>
              {alerts.slice(0, 15).map((alert, idx) => (
                <div key={idx} className="log-section">
                  <div className="log-section-header">
                    <span className="alert-indicator">→</span>
                    <strong>{alert.threat_type || 'Anomaly'}</strong>
                    <span className="log-time">{alert.timestamp}</span>
                  </div>
                  {/* Support multiple reasoning formats (Array or String) */}
                  {Array.isArray(alert.agent_reasoning || alert.observation) ?
                    (alert.agent_reasoning || alert.observation).map((log, logIdx) => (
                      <div key={logIdx} className="log-line">
                        <span className="log-prefix">[AGENT]</span>
                        <span className="log-text">{log}</span>
                      </div>
                    )) : (
                      <div className="log-line">
                        <span className="log-prefix">[AGENT]</span>
                        <span className="log-text">{alert.llm_reasoning || alert.observation || 'Analyzing threat patterns...'}</span>
                      </div>
                    )
                  }
                </div>
              ))}
            </>
          ) : (
            <div className="empty-logs">
              <Terminal size={32} />
              <p>No alerts to display</p>
            </div>
          )}
          <div className="log-line typing">█</div>
        </div>
      </div>
    </div>
  );
};

export default AgentLogsTab;