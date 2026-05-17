import { Globe, Zap } from 'lucide-react';
import ThreatGlobe from '../ThreatGlobe';

const ThreatMapTab = ({ alerts, setSimOpen, setSimResult }) => {
  return (
    <div className="tab-panel map-panel">
      <div className="panel-header compact-header">
        <div className="header-info">
          <h2><Globe size={24} /> GLOBAL THREAT TOPOLOGY</h2>
          <p>Real-time geolocation and threat distribution mapping</p>
        </div>
        <button className="sim-trigger-btn" onClick={() => { setSimOpen(true); setSimResult(null); }}>
          <Zap size={14} /> SIMULATE ATTACK
        </button>
      </div>
      <div className="map-container">
        <ThreatGlobe alerts={alerts} />
      </div>
    </div>
  );
};

export default ThreatMapTab;
