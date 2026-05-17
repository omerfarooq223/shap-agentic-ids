import { Zap, RefreshCw } from 'lucide-react';
import { API_CONFIG } from '../constants';

const SimulatorModal = ({
  simOpen,
  setSimOpen,
  simPreset,
  setSimPreset,
  simRunning,
  setSimRunning,
  simResult,
  setSimResult,
  setAlerts,
  ATTACK_PRESETS
}) => {
  if (!simOpen) return null;

  return (
    <div className="sim-modal-backdrop" onClick={e => e.target === e.currentTarget && setSimOpen(false)}>
      <div className="sim-modal">
        <div className="sim-modal-header">
          <h3><Zap size={17} /> ATTACK SIMULATOR</h3>
          <button className="sim-close-btn" onClick={() => setSimOpen(false)}>✕</button>
        </div>
        <p className="sim-modal-desc">
          Inject a crafted flow into the real ML pipeline to demonstrate the
          <strong> Random Forest → SHAP → LangGraph Agent</strong> chain.
        </p>
        <div className="sim-presets">
          {ATTACK_PRESETS.map((p, i) => (
            <button key={p.label}
              className={`sim-preset-btn ${simPreset === i ? 'active' : ''}`}
              onClick={() => { setSimPreset(i); setSimResult(null); }}>
              <span>{p.icon}</span> {p.label}
            </button>
          ))}
          <button className={`sim-preset-btn ${simPreset === -1 ? 'active' : ''}`}
            onClick={() => { setSimPreset(-1); setSimResult(null); }}>
            <span>✍️</span> Custom
          </button>
        </div>

        {simPreset === -1 ? (
          <div className="sim-flow-preview">
            <textarea
              className="sim-custom-input"
              defaultValue={JSON.stringify(ATTACK_PRESETS[0].flow, null, 2)}
              id="custom-flow-input"
              style={{ width: '100%', height: '150px', background: '#000', color: '#10b981', border: 'none', outline: 'none', fontFamily: 'monospace', resize: 'vertical' }}
            />
          </div>
        ) : (
          <div className="sim-flow-preview">
            <div className="sim-flow-row"><span>Source IP</span><code>{ATTACK_PRESETS[simPreset].src_ip}</code></div>
            <div className="sim-flow-row"><span>Destination Port</span><code>{ATTACK_PRESETS[simPreset].dst_port}</code></div>
            <div className="sim-flow-row"><span>Attack Type</span><code>{ATTACK_PRESETS[simPreset].label}</code></div>
          </div>
        )}

        <button className="sim-run-btn" disabled={simRunning} onClick={async () => {
          setSimRunning(true);
          setSimResult(null);
          let flowData = simPreset === -1
            ? JSON.parse(document.getElementById('custom-flow-input').value)
            : ATTACK_PRESETS[simPreset].flow;

          try {
            const res = await fetch(`${API_CONFIG.BASE_URL}/detect`, {
              method: 'POST',
              headers: API_CONFIG.HEADERS,
              body: JSON.stringify({ flow: flowData })
            });
            const data = await res.json();
            setSimResult(data);
            if (data.anomaly) setAlerts(p => [data, ...p].slice(0, 50));
          } catch {
            setSimResult({ error: 'Backend offline.' });
          }
          setSimRunning(false);
        }}>
          {simRunning ? <><RefreshCw size={15} className="spin" /> ANALYZING...</> : <>▶ RUN DETECTION</>}
        </button>
        {simResult && (
          <div className={`sim-result ${simResult.error ? 'sim-error' : simResult.anomaly ? 'sim-anomaly' : 'sim-benign'}`}>
            {simResult.error ? <p>❌ {simResult.error}</p>
              : simResult.anomaly ? (
                <><p>🚨 <strong>THREAT DETECTED</strong></p>
                  <p>Type: <strong>{simResult.threat_type}</strong></p>
                  <p>Risk: <strong>{simResult.risk_score}/10</strong></p>
                  <p>MITRE: <strong>{simResult.mitre}</strong></p>
                  <p className="sim-rec">{simResult.recommendation}</p></>
              ) : <p>✅ Classified as <strong>BENIGN</strong> (ML: {((simResult.ml_confidence || 0) * 100).toFixed(1)}%)</p>
            }
          </div>
        )}
      </div>
    </div>
  );
};

export default SimulatorModal;
