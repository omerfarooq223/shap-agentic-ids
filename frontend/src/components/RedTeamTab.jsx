import React, { useState, useMemo } from 'react';
import {
  Sword, ShieldAlert, MessageSquare, Target, ChevronRight, Activity,
  AlertTriangle, CheckCircle2, TrendingUp, Zap, Clock, BarChart3, Flame, Shield
} from 'lucide-react';
import { API_CONFIG } from '../constants';

const RedTeamTab = () => {
  const [battleHistory, setBattleHistory] = useState([]);
  const [isFighting, setIsFighting] = useState(false);
  const [iterations, setIterations] = useState(3);
  const [error, setError] = useState(null);
  const [expandedRound, setExpandedRound] = useState(null);

  const startBattle = async () => {
    setIsFighting(true);
    setError(null);
    setBattleHistory([]);
    setExpandedRound(null);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}/api/v1/red-team/battle`, {
        method: 'POST',
        headers: API_CONFIG.HEADERS,
        body: JSON.stringify({ iterations })
      });

      if (!response.ok) throw new Error('Battle failed. Check backend connection.');

      const data = await response.json();
      setBattleHistory(data.battle_history);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsFighting(false);
    }
  };

  // Calculate battle statistics
  const stats = useMemo(() => {
    if (battleHistory.length === 0) return { caught: 0, bypassed: 0, avgRisk: 0, successRate: 0 };

    const caught = battleHistory.filter(r => r.defender_result.risk_score > 5).length;
    const bypassed = battleHistory.length - caught;
    const avgRisk = (battleHistory.reduce((sum, r) => sum + r.defender_result.risk_score, 0) / battleHistory.length).toFixed(1);
    const successRate = ((caught / battleHistory.length) * 100).toFixed(0);

    return { caught, bypassed, avgRisk, successRate };
  }, [battleHistory]);

  return (
    <div className="red-team-container">
      <style>{`
        .red-team-container {
          padding: 32px;
          max-width: 1400px;
          margin: 0 auto;
        }

        .tab-header-card {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 32px;
          padding: 28px;
          background: linear-gradient(135deg, #1a1f2a 0%, #14181f 100%);
          border: 1px solid rgba(255, 61, 77, 0.2);
          border-radius: 16px;
          margin-bottom: 32px;
          box-shadow: 0 8px 32px rgba(255, 61, 77, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        }

        .tab-header-content {
          display: flex;
          align-items: center;
          gap: 20px;
          flex: 1;
        }

        .icon-badge {
          width: 60px;
          height: 60px;
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 0;
        }

        .icon-badge.red {
          background: linear-gradient(135deg, rgba(255, 61, 77, 0.2) 0%, rgba(255, 61, 77, 0.1) 100%);
          border: 1px solid rgba(255, 61, 77, 0.3);
          color: #ff3d4d;
          box-shadow: 0 0 20px rgba(255, 61, 77, 0.2);
        }

        .tab-header-content h2 {
          font-family: 'Syne', sans-serif;
          font-size: 24px;
          font-weight: 700;
          color: #f0f4f8;
          margin-bottom: 4px;
          letter-spacing: 0.5px;
        }

        .subtitle {
          font-size: 13px;
          color: #a8b5c8;
          font-weight: 500;
        }

        .tab-header-actions {
          display: flex;
          align-items: center;
          gap: 16px;
        }

        .iteration-selector {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          background: rgba(13, 159, 255, 0.1);
          border: 1px solid rgba(13, 159, 255, 0.2);
          border-radius: 8px;
          font-size: 13px;
          color: #a8b5c8;
          font-weight: 600;
        }

        .iteration-selector select {
          background: transparent;
          border: none;
          color: #0d9fff;
          font-family: 'IBM Plex Mono', monospace;
          font-weight: 700;
          font-size: 14px;
          cursor: pointer;
          outline: none;
        }

        .iteration-selector select:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .battle-btn {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 14px 28px;
          background: linear-gradient(135deg, #ff3d4d 0%, #ff1744 100%);
          color: white;
          border: none;
          border-radius: 10px;
          font-weight: 700;
          font-size: 12px;
          font-family: 'Syne', sans-serif;
          letter-spacing: 0.5px;
          text-transform: uppercase;
          cursor: pointer;
          transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
          box-shadow: 0 6px 20px rgba(255, 61, 77, 0.3);
          position: relative;
          overflow: hidden;
        }

        .battle-btn::before {
          content: '';
          position: absolute;
          inset: 0;
          background: linear-gradient(135deg, transparent 0%, rgba(255, 255, 255, 0.2) 50%, transparent 100%);
          transform: translateX(-100%);
          transition: transform 300ms;
        }

        .battle-btn:hover:not(:disabled) {
          transform: translateY(-2px);
          box-shadow: 0 8px 28px rgba(255, 61, 77, 0.4);
        }

        .battle-btn:hover:not(:disabled)::before {
          transform: translateX(100%);
        }

        .battle-btn:disabled {
          opacity: 0.8;
          cursor: not-allowed;
        }

        .battle-btn.loading {
          background: linear-gradient(135deg, #ff6b7a 0%, #ff4461 100%);
        }

        .battle-btn .spinning {
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        .error-alert {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 16px;
          background: rgba(255, 61, 77, 0.1);
          border: 1px solid rgba(255, 61, 77, 0.3);
          border-radius: 10px;
          color: #ff6b7a;
          margin-bottom: 24px;
          font-weight: 500;
          font-size: 13px;
          animation: slideDown 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes slideDown {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }

        /* Battle Stats Section */
        .battle-stats {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px;
          margin-bottom: 32px;
        }

        .stat-card {
          padding: 20px;
          background: linear-gradient(135deg, #14181f 0%, #1a1f2a 100%);
          border: 1px solid rgba(13, 159, 255, 0.15);
          border-radius: 12px;
          transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
        }

        .stat-card:hover {
          border-color: rgba(13, 159, 255, 0.3);
          box-shadow: 0 4px 16px rgba(13, 159, 255, 0.1);
          transform: translateY(-2px);
        }

        .stat-label {
          font-size: 11px;
          color: #7a8494;
          text-transform: uppercase;
          font-weight: 600;
          letter-spacing: 0.5px;
          margin-bottom: 8px;
          display: flex;
          align-items: center;
          gap: 6px;
        }

        .stat-label svg {
          color: #0d9fff;
        }

        .stat-value {
          font-size: 28px;
          font-weight: 800;
          font-family: 'IBM Plex Mono', monospace;
          color: #0d9fff;
          text-shadow: 0 0 12px rgba(13, 159, 255, 0.2);
        }

        .stat-card.success .stat-value {
          color: #10b981;
        }

        .stat-card.danger .stat-value {
          color: #ff3d4d;
        }

        /* Battle Timeline */
        .battle-timeline {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .empty-battle-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 24px;
          padding: 80px 40px;
          text-align: center;
          background: linear-gradient(135deg, rgba(13, 159, 255, 0.05) 0%, rgba(13, 159, 255, 0.02) 100%);
          border: 2px dashed rgba(13, 159, 255, 0.2);
          border-radius: 16px;
        }

        .empty-illustration {
          opacity: 0.4;
        }

        .faint-icon {
          color: #0d9fff;
          opacity: 0.5;
        }

        .empty-battle-state h3 {
          font-size: 18px;
          font-weight: 700;
          color: #f0f4f8;
        }

        .empty-battle-state p {
          font-size: 13px;
          color: #a8b5c8;
          max-width: 300px;
        }

        .battle-loader {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 20px;
          padding: 60px 40px;
        }

        .scanner-line {
          width: 200px;
          height: 2px;
          background: linear-gradient(90deg, transparent, #ff3d4d, transparent);
          animation: scan 1.5s ease-in-out infinite;
        }

        @keyframes scan {
          0%, 100% { transform: translateX(0); opacity: 0; }
          50% { opacity: 1; }
          100% { transform: translateX(200px); }
        }

        .battle-loader p {
          color: #a8b5c8;
          font-size: 13px;
          font-weight: 600;
        }

        /* Battle Round Card */
        .battle-round-card {
          padding: 24px;
          background: linear-gradient(135deg, #1a1f2a 0%, #14181f 100%);
          border: 1px solid rgba(255, 61, 77, 0.15);
          border-radius: 14px;
          animation: slideUp 0.4s cubic-bezier(0.4, 0, 0.2, 1);
          transition: all 250ms cubic-bezier(0.4, 0, 0.2, 1);
          cursor: pointer;
        }

        .battle-round-card:hover {
          border-color: rgba(255, 61, 77, 0.3);
          box-shadow: 0 8px 32px rgba(255, 61, 77, 0.1);
          transform: translateY(-2px);
        }

        @keyframes slideUp {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .round-badge {
          display: inline-block;
          padding: 6px 12px;
          background: linear-gradient(135deg, rgba(255, 61, 77, 0.2) 0%, rgba(255, 61, 77, 0.1) 100%);
          border: 1px solid rgba(255, 61, 77, 0.3);
          border-radius: 6px;
          font-size: 10px;
          font-weight: 800;
          color: #ff3d4d;
          letter-spacing: 1px;
          margin-bottom: 20px;
          box-shadow: 0 0 12px rgba(255, 61, 77, 0.2);
        }

        .battle-grid {
          display: grid;
          grid-template-columns: 1fr auto 1fr;
          gap: 24px;
          align-items: start;
          margin-bottom: 24px;
        }

        .battle-side {
          padding: 20px;
          background: rgba(0, 0, 0, 0.3);
          border-radius: 10px;
          border: 1px solid var(--side-border);
          transition: all 250ms;
        }

        .battle-side.attacker {
          --side-border: rgba(255, 61, 77, 0.2);
          background: linear-gradient(135deg, rgba(255, 61, 77, 0.08) 0%, rgba(255, 61, 77, 0.04) 100%);
        }

        .battle-side.defender {
          --side-border: rgba(13, 159, 255, 0.2);
          background: linear-gradient(135deg, rgba(13, 159, 255, 0.08) 0%, rgba(13, 159, 255, 0.04) 100%);
        }

        .battle-side:hover {
          border-color: var(--side-border);
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
        }

        .side-label {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 10px;
          font-weight: 800;
          text-transform: uppercase;
          letter-spacing: 0.8px;
          margin-bottom: 12px;
          padding-bottom: 12px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .battle-side.attacker .side-label {
          color: #ff3d4d;
        }

        .battle-side.defender .side-label {
          color: #0d9fff;
        }

        .side-label svg {
          filter: drop-shadow(0 0 6px currentColor);
        }

        .payload-box {
          font-family: 'IBM Plex Mono', monospace;
          font-size: 11px;
        }

        .payload-header {
          font-size: 12px;
          font-weight: 600;
          color: #ff6b7a;
          margin-bottom: 10px;
          padding-bottom: 8px;
          border-bottom: 1px solid rgba(255, 61, 77, 0.2);
        }

        .payload-content pre {
          margin: 0;
          color: #a8b5c8;
          line-height: 1.6;
          max-height: 150px;
          overflow-y: auto;
          background: rgba(0, 0, 0, 0.3);
          padding: 10px;
          border-radius: 6px;
          border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .defense-result {
          padding: 16px;
          background: rgba(0, 0, 0, 0.3);
          border-radius: 8px;
          border-left: 4px solid var(--result-color);
          transition: all 250ms;
        }

        .defense-result.caught {
          --result-color: #ff3d4d;
          background: linear-gradient(90deg, rgba(255, 61, 77, 0.1) 0%, transparent 100%);
          border-color: #ff3d4d;
        }

        .defense-result.bypassed {
          --result-color: #10b981;
          background: linear-gradient(90deg, rgba(16, 185, 129, 0.1) 0%, transparent 100%);
          border-color: #10b981;
        }

        .result-status {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 14px;
          font-weight: 800;
          margin-bottom: 10px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .defense-result.caught .result-status {
          color: #ff6b7a;
        }

        .defense-result.bypassed .result-status {
          color: #10b981;
        }

        .risk-metric {
          font-size: 12px;
          color: #a8b5c8;
          margin-bottom: 12px;
          font-family: 'IBM Plex Mono', monospace;
        }

        .risk-metric strong {
          font-weight: 800;
          color: #f0f4f8;
        }

        .defense-result.caught .risk-metric strong {
          color: #ff3d4d;
          text-shadow: 0 0 8px rgba(255, 61, 77, 0.3);
        }

        .reasoning-snippet {
          font-size: 11px;
          color: #7a8494;
          line-height: 1.5;
          font-style: italic;
          padding: 10px;
          background: rgba(0, 0, 0, 0.2);
          border-radius: 6px;
          border-left: 2px solid rgba(13, 159, 255, 0.2);
        }

        .battle-vs {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 12px;
        }

        .vs-line {
          width: 2px;
          height: 40px;
          background: linear-gradient(180deg, transparent, rgba(255, 61, 77, 0.3), transparent);
        }

        .vs-circle {
          width: 50px;
          height: 50px;
          border-radius: 50%;
          background: linear-gradient(135deg, rgba(255, 61, 77, 0.15) 0%, rgba(255, 61, 77, 0.05) 100%);
          border: 2px solid rgba(255, 61, 77, 0.3);
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 800;
          font-size: 12px;
          color: #ff3d4d;
          letter-spacing: 0.5px;
          box-shadow: 0 0 16px rgba(255, 61, 77, 0.2);
        }

        .critic-feedback-section {
          padding-top: 20px;
          border-top: 1px solid rgba(255, 255, 255, 0.1);
          margin-top: 20px;
        }

        .critic-feedback-section .side-label {
          color: #0d9fff;
          border-bottom-color: rgba(13, 159, 255, 0.2);
        }

        .feedback-content {
          display: flex;
          gap: 12px;
          padding: 14px;
          background: linear-gradient(135deg, rgba(13, 159, 255, 0.08) 0%, rgba(13, 159, 255, 0.04) 100%);
          border: 1px solid rgba(13, 159, 255, 0.15);
          border-radius: 8px;
          font-size: 13px;
          color: #a8b5c8;
          line-height: 1.6;
        }

        .feedback-content .bullet {
          color: #0d9fff;
          flex-shrink: 0;
          margin-top: 1px;
        }

        .feedback-content p {
          margin: 0;
        }

        /* Responsive */
        @media (max-width: 1200px) {
          .battle-grid {
            grid-template-columns: 1fr;
            gap: 16px;
          }

          .battle-vs {
            flex-direction: row;
            height: 2px;
            margin: 12px 0;
          }

          .vs-line {
            width: 40px;
            height: 2px;
            background: linear-gradient(90deg, transparent, rgba(255, 61, 77, 0.3), transparent);
          }

          .vs-circle {
            width: 45px;
            height: 45px;
            font-size: 10px;
          }
        }

        @media (max-width: 768px) {
          .red-team-container {
            padding: 16px;
          }

          .tab-header-card {
            flex-direction: column;
            gap: 16px;
            padding: 20px;
          }

          .tab-header-actions {
            width: 100%;
            flex-direction: column;
          }

          .battle-btn {
            width: 100%;
            justify-content: center;
          }

          .battle-stats {
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
          }
        }

        .animate-fade-in {
          animation: fadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        .animate-slide-up {
          animation: slideUp 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
      `}</style>

      {/* Header */}
      <div className="tab-header-card">
        <div className="tab-header-content">
          <div className="icon-badge red">
            <Sword size={28} />
          </div>
          <div>
            <h2>Autonomous Red Teaming</h2>
            <p className="subtitle">Adversarial Multi-Agent Battleground: Attacker vs. Defender</p>
          </div>
        </div>
        <div className="tab-header-actions">
          <div className="iteration-selector">
            <span>Rounds:</span>
            <select
              value={iterations}
              onChange={(e) => setIterations(parseInt(e.target.value))}
              disabled={isFighting}
            >
              {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          <button
            className={`battle-btn ${isFighting ? 'loading' : ''}`}
            onClick={startBattle}
            disabled={isFighting}
          >
            {isFighting ? (
              <>
                <Activity className="spinning" size={18} />
                <span>BATTLE IN PROGRESS...</span>
              </>
            ) : (
              <>
                <Sword size={18} />
                <span>START ADVERSARIAL BATTLE</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="error-alert">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Battle Statistics */}
      {battleHistory.length > 0 && (
        <div className="battle-stats">
          <div className="stat-card danger">
            <div className="stat-label">
              <Flame size={14} />
              Caught by IDS
            </div>
            <div className="stat-value">{stats.caught}</div>
          </div>
          <div className="stat-card success">
            <div className="stat-label">
              <Target size={14} />
              Successfully Bypassed
            </div>
            <div className="stat-value">{stats.bypassed}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">
              <TrendingUp size={14} />
              Average Risk Score
            </div>
            <div className="stat-value">{stats.avgRisk}</div>
          </div>
          <div className="stat-card success">
            <div className="stat-label">
              <BarChart3 size={14} />
              Detection Rate
            </div>
            <div className="stat-value">{stats.successRate}%</div>
          </div>
        </div>
      )}

      {/* Battle Timeline */}
      <div className="battle-timeline">
        {battleHistory.length === 0 && !isFighting && (
          <div className="empty-battle-state">
            <div className="empty-illustration">
              <Sword size={80} className="faint-icon" />
            </div>
            <h3>Ready for Battle</h3>
            <p>Trigger an autonomous red-teaming session to stress-test your IDS with adversarial attacks.</p>
          </div>
        )}

        {isFighting && battleHistory.length === 0 && (
          <div className="battle-loader">
            <div className="scanner-line"></div>
            <p>AI Agents are formulating strategies...</p>
          </div>
        )}

        {battleHistory.map((round, idx) => (
          <div
            key={idx}
            className="battle-round-card"
            style={{ animationDelay: `${idx * 0.1}s` }}
            onClick={() => setExpandedRound(expandedRound === idx ? null : idx)}
          >
            <div className="round-badge">ROUND {round.round}</div>

            <div className="battle-grid">
              {/* Attacker Section */}
              <div className="battle-side attacker">
                <div className="side-label">
                  <Flame size={16} />
                  <span>ATTACKER AGENT</span>
                </div>
                <div className="payload-box">
                  <div className="payload-header">
                    Targeting {round.attacker_payload.dst_ip}:{round.attacker_payload.dst_port}
                  </div>
                  <div className="payload-content">
                    <pre>{JSON.stringify({
                      protocol: round.attacker_payload.protocol,
                      fwd_packet_len: round.attacker_payload['Fwd Packet Length Mean'],
                      bwd_packet_len: round.attacker_payload['Bwd Packet Length Mean']
                    }, null, 2)}</pre>
                  </div>
                </div>
              </div>

              <div className="battle-vs">
                <div className="vs-line"></div>
                <div className="vs-circle">VS</div>
                <div className="vs-line"></div>
              </div>

              {/* Defender Section */}
              <div className="battle-side defender">
                <div className="side-label">
                  <Shield size={16} />
                  <span>DEFENDER AGENT (IDS)</span>
                </div>
                <div className={`defense-result ${round.defender_result.risk_score > 5 ? 'caught' : 'bypassed'}`}>
                  <div className="result-status">
                    {round.defender_result.risk_score > 5 ? (
                      <>
                        <ShieldAlert size={20} />
                        <span>CAUGHT</span>
                      </>
                    ) : (
                      <>
                        <CheckCircle2 size={20} />
                        <span>BYPASSED</span>
                      </>
                    )}
                  </div>
                  <div className="risk-metric">
                    Risk Score: <strong>{round.defender_result.risk_score}/10</strong>
                  </div>
                  <div className="reasoning-snippet">
                    {round.defender_result.llm_reasoning || "Analyzing patterns..."}
                  </div>
                </div>
              </div>
            </div>

            {/* Critic Feedback */}
            <div className="critic-feedback-section">
              <div className="side-label">
                <MessageSquare size={16} />
                <span>CRITIC FEEDBACK</span>
              </div>
              <div className="feedback-content">
                <ChevronRight size={16} className="bullet" />
                <p>{round.critic_feedback}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RedTeamTab;