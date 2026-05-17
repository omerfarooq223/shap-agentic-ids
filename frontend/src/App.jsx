import { useState, useEffect, useRef } from 'react';
import {
  Shield, Terminal, Search,
  RefreshCw, BarChart3, Zap, Bug,
  Activity, TrendingUp, Globe, Volume2, VolumeX, Cpu, Brain, ExternalLink
} from 'lucide-react';
import Analytics from './Analytics';
import DashboardTab from './components/DashboardTab';
import AgentLogsTab from './components/AgentLogsTab';
import ThreatMapTab from './components/ThreatMapTab';
import ForensicLabTab from './components/ForensicLabTab';
import RedTeamTab from './components/RedTeamTab';
import ChatWidget from './components/ChatWidget';
import SimulatorModal from './components/SimulatorModal';
import { Sword } from 'lucide-react';
import { ATTACK_PRESETS, DEMO_ALERTS, INITIAL_CHAT_MESSAGE, API_CONFIG } from './constants';
import ErrorBoundary from './components/ErrorBoundary';
import { sanitizeInput, isValidAPIResponse } from './utils/sanitization';
import './App.css';

const GitHubIcon = ({ size = 16, color = "currentColor" }) => (
  <svg
    height={size}
    width={size}
    viewBox="0 0 16 16"
    fill={color}
    style={{ display: 'inline-block', verticalAlign: 'middle' }}
  >
    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
  </svg>
);

const App = () => {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [alerts, setAlerts] = useState(DEMO_ALERTS);
  const [selectedAlert, setSelectedAlert] = useState(DEMO_ALERTS[0]);
  const [isScanning, setIsScanning] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [backendStatus, setBackendStatus] = useState('offline');
  const [isVoiceEnabled, setIsVoiceEnabled] = useState(false);
  const [voicePersona, setVoicePersona] = useState(() => localStorage.getItem('voicePersona') || 'jarvis');
  const [profileOpen, setProfileOpen] = useState(false);
  const lastSpokenId = useRef(null);

  // Simulator state
  const [simOpen, setSimOpen] = useState(false);
  const [simRunning, setSimRunning] = useState(false);
  const [simResult, setSimResult] = useState(null);
  const [simPreset, setSimPreset] = useState(0);

  // Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatFullscreen, setChatFullscreen] = useState(false);
  const [chatMessages, setChatMessages] = useState([INITIAL_CHAT_MESSAGE]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [stressing, setStressing] = useState(false);
  const [benchmarks, setBenchmarks] = useState(null);
  const chatEndRef = useRef(null);
  const pollIntervalRef = useRef(null);
  const benchmarkAbortRef = useRef(null);


  const sendChat = async () => {
    if (!chatInput.trim() || chatLoading) return;
    const msg = sanitizeInput(chatInput);
    if (!msg) return;
    setChatMessages(p => [...p, { role: 'user', content: msg }]);
    setChatInput('');
    setChatLoading(true);
    const abortController = new AbortController();
    try {
      const res = await fetch(`${API_CONFIG.BASE_URL}/chat`, {
        method: 'POST',
        headers: API_CONFIG.HEADERS,
        body: JSON.stringify({ message: msg }),
        signal: abortController.signal
      });
      const data = await res.json();
      if (isValidAPIResponse(data)) {
        setChatMessages(p => [...p, { role: 'assistant', content: data.response || 'No response.' }]);
      } else {
        setChatMessages(p => [...p, { role: 'assistant', content: 'Received an invalid response from the backend.' }]);
      }
    } catch {
      setChatMessages(p => [...p, { role: 'assistant', content: 'Cannot reach backend. Ensure Flask is running on port 5005.' }]);
    } finally {
      setChatLoading(false);
    }
  };

  const runStressTest = async () => {
    setStressing(true);
    try {
      await fetch(`${API_CONFIG.BASE_URL}/api/test/stress`, {
        method: 'POST',
        headers: API_CONFIG.HEADERS
      });
      // Alerts will start flowing in via the existing poll effect
    } catch (e) {
      console.error("Stress test failed", e);
    }
    setTimeout(() => setStressing(false), 5000);
  };

  const [injecting, setInjecting] = useState(false);
  const injectMalicious = async () => {
    setInjecting(true);
    try {
      await fetch(`${API_CONFIG.BASE_URL}/api/test/malicious`, {
        method: 'POST',
        headers: API_CONFIG.HEADERS
      });
      // specific single high-grade alert will flow in via polling
    } catch (e) {
      console.error("Malicious inject failed", e);
    }
    setTimeout(() => setInjecting(false), 2000);
  };




  useEffect(() => {
    // Poll real Flask backend every 5 seconds
    const fetchAlerts = async () => {
      if (!isScanning) return;
      try {
        const res = await fetch(`${API_CONFIG.BASE_URL}/api/v1/alerts`);
        if (res.ok) {
          const data = await res.json();
          setBackendStatus('online');
          if (Array.isArray(data) && data.length > 0) {
            setAlerts(prev => {
              const realIds = new Set(data.map(a => a.id));
              const demoOnly = prev.filter(a => String(a.id).startsWith('demo-') && !realIds.has(a.id));
              return [...data, ...demoOnly].slice(0, 50);
            });
            setSelectedAlert(s => s?.id === 'demo-1' ? data[0] : s);
          }
        } else {
          setBackendStatus('offline');
        }
      } catch {
        setBackendStatus('offline');
        /* Backend offline — demo data stays */
      }
    };

    fetchAlerts();
    pollIntervalRef.current = setInterval(fetchAlerts, 5000);

    // Fetch benchmarks once
    const fetchBenchmarks = async () => {
      benchmarkAbortRef.current?.abort();
      benchmarkAbortRef.current = new AbortController();
      try {
        const res = await fetch(`${API_CONFIG.BASE_URL}/api/metrics/benchmarks`);
        if (res.ok) {
          const data = await res.json();
          if (isValidAPIResponse(data)) {
            setBenchmarks(data);
          }
        }
      } catch (e) { console.error("Could not load benchmarks", e); }
    };
    fetchBenchmarks();

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      benchmarkAbortRef.current?.abort();
    };
  }, [isScanning]);

  // Sync Voice Persona with backend
  useEffect(() => {
    localStorage.setItem('voicePersona', voicePersona);

    fetch(`${API_CONFIG.BASE_URL}/api/v1/voice/persona`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': API_CONFIG.API_KEY
      },
      body: JSON.stringify({ persona: voicePersona })
    })
      .then(res => res.json())
      .then(data => console.log('Backend voice persona updated:', data))
      .catch(err => console.error('Failed to sync voice persona with backend:', err));
  }, [voicePersona]);

  // Sync Voice Enable/Disable State with backend & handle immediate mute cancellation
  useEffect(() => {
    fetch(`${API_CONFIG.BASE_URL}/api/v1/voice/toggle`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': API_CONFIG.API_KEY
      },
      body: JSON.stringify({ enabled: isVoiceEnabled })
    })
      .then(res => res.json())
      .then(data => console.log('Backend voice enabled status updated:', data))
      .catch(err => console.error('Failed to sync voice toggle state with backend:', err));

    // Immediately stop speech synthesis when user clicks the mute button
    if (!isVoiceEnabled) {
      window.speechSynthesis.cancel();
    }
  }, [isVoiceEnabled]);

  // Frontend Voice Assistant Logic (Premium Conversational Personas)
  useEffect(() => {
    if (!isVoiceEnabled || alerts.length === 0) return;

    const latestAlert = alerts[0];
    if (latestAlert.id !== lastSpokenId.current && latestAlert.risk_score >= 7.0) {
      lastSpokenId.current = latestAlert.id;

      let message = '';
      let rate = 0.88; // Deliberate speed (sounds less robotic and more calculated)
      let pitch = 0.96; // Deeper, more human pitch

      if (voicePersona === 'jarvis') {
        // Conversational punctuation (...) injects human breathing pauses in Web Speech API
        message = `Sir, ... I have detected a critical threat anomaly. ... A ${latestAlert.threat_type} attack has been initiated. ... The risk assessment is extremely high, at ${latestAlert.risk_score} out of 10. ... I highly advise checking the threat dashboard immediately.`;
        rate = 0.88;
        pitch = 0.94;
      } else if (voicePersona === 'friday') {
        message = `Warning. ... Critical threat active. ... ${latestAlert.threat_type} pattern detected. ... Risk factor is high, at ${latestAlert.risk_score}. ... Quarantine protocol is highly recommended.`;
        rate = 0.94;
        pitch = 1.02;
      } else {
        message = `Security Alert. ... Critical ${latestAlert.threat_type} detected. ... Risk score ${latestAlert.risk_score}.`;
        rate = 0.90;
        pitch = 1.1;
      }

      const utterance = new SpeechSynthesisUtterance(message);

      // Load available system voices
      const voices = window.speechSynthesis.getVoices();
      let selectedVoice = null;

      // Look for natural neural, Siri, or high-fidelity premium conversational voices first
      if (voicePersona === 'jarvis') {
        selectedVoice = voices.find(v => v.lang === 'en-GB' && v.name.includes('Siri') && v.name.includes('Male')) ||
          voices.find(v => v.lang === 'en-GB' && v.name.toLowerCase().includes('daniel') && v.name.toLowerCase().includes('premium')) ||
          voices.find(v => v.lang === 'en-GB' && v.name.toLowerCase().includes('daniel')) ||
          voices.find(v => v.lang === 'en-GB' && v.name.includes('Google') && v.name.toLowerCase().includes('male')) ||
          voices.find(v => v.lang === 'en-GB' && v.name.toLowerCase().includes('male')) ||
          voices.find(v => v.lang.startsWith('en-GB'));
      } else if (voicePersona === 'friday') {
        selectedVoice = voices.find(v => v.lang === 'en-US' && v.name.includes('Siri') && v.name.includes('Female')) ||
          voices.find(v => v.lang === 'en-US' && v.name.toLowerCase().includes('samantha') && v.name.toLowerCase().includes('premium')) ||
          voices.find(v => v.lang === 'en-US' && v.name.toLowerCase().includes('samantha')) ||
          voices.find(v => v.lang === 'en-US' && v.name.includes('Google') && !v.name.toLowerCase().includes('male')) ||
          voices.find(v => v.lang === 'en-US' && v.name.toLowerCase().includes('female')) ||
          voices.find(v => v.lang.startsWith('en-US'));
      }

      // Fallback search if the target persona voices are not available
      if (!selectedVoice) {
        selectedVoice = voices.find(v => v.lang.startsWith('en') && v.name.includes('Siri')) ||
          voices.find(v => v.lang.startsWith('en') && v.name.includes('Google')) ||
          voices.find(v => v.lang.startsWith('en') && v.name.toLowerCase().includes('premium')) ||
          voices.find(v => v.lang.startsWith('en'));
      }

      if (selectedVoice) {
        utterance.voice = selectedVoice;
      }

      utterance.rate = rate;
      utterance.pitch = pitch;
      window.speechSynthesis.speak(utterance);
    }
  }, [alerts, isVoiceEnabled, voicePersona]);


  const exportReport = () => {
    const report = {
      generated_at: new Date().toISOString(),
      system: 'Agentic IDS v1.0 — LangGraph + Random Forest',
      summary: {
        total_threats: alerts.length,
        critical: alerts.filter(a => a.status === 'CRITICAL').length,
        warning: alerts.filter(a => a.status === 'WARNING').length,
        avg_risk: alerts.length
          ? (alerts.reduce((s, a) => s + (a.risk_score || 0), 0) / alerts.length).toFixed(2)
          : 0,
        attack_types: [...new Set(alerts.map(a => a.threat_type))],
      },
      incidents: alerts.map(a => ({
        id: a.id, timestamp: a.timestamp,
        src_ip: a.src_ip, dst_ip: a.dst_ip, dst_port: a.dst_port,
        threat_type: a.threat_type, status: a.status,
        risk_score: a.risk_score, mitre: a.mitre,
        ml_confidence: a.ml_confidence,
        shap_features: a.shap_explanation,
        agent_reasoning: a.agent_reasoning,
        threat_intel: a.threat_intel,
      })),
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `IDS_Report_${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleScanToggle = () => {
    setIsScanning(!isScanning);
  };

  const filteredAlerts = alerts.filter(a =>
    a.src_ip.includes(searchQuery) ||
    a.threat_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.status.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const renderContent = () => {
    switch (activeTab) {
      case 'Dashboard':
        return (
          <DashboardTab
            alerts={alerts}
            filteredAlerts={filteredAlerts}
            selectedAlert={selectedAlert}
            setSelectedAlert={setSelectedAlert}
            setAlerts={setAlerts}
          />
        );

      case 'Agent Logs':
        return <AgentLogsTab alerts={alerts} />;

      case 'Threat Map':
        return (
          <ThreatMapTab
            alerts={alerts}
            setSimOpen={setSimOpen}
            setSimResult={setSimResult}
          />
        );

      case 'Forensic Lab':
        return <ForensicLabTab benchmarks={benchmarks} />;

      case 'Red Team':
        return <RedTeamTab />;

      case 'Analytics':
        return <Analytics alerts={alerts} onExport={exportReport} />;

      default:
        return null;
    }
  };

  return (
    <ErrorBoundary>
      <div className="soc-container">
        {/* Sidebar Navigation */}
        <nav className="soc-sidebar">
          <div className="logo">
            <Shield className="logo-icon" size={28} />
            <span>AGENTIC IDS</span>
          </div>

          <ul className="nav-links">
            <li
              className={activeTab === 'Dashboard' ? 'active' : ''}
              onClick={() => setActiveTab('Dashboard')}
              title="Main threat dashboard"
            >
              <Activity size={20} />
              <span>Dashboard</span>
            </li>
            <li
              className={activeTab === 'Agent Logs' ? 'active' : ''}
              onClick={() => setActiveTab('Agent Logs')}
              title="View AI reasoning logs"
            >
              <Terminal size={20} />
              <span>Agent Logs</span>
            </li>
            <li
              className={activeTab === 'Analytics' ? 'active' : ''}
              onClick={() => setActiveTab('Analytics')}
              title="View threat analytics"
            >
              <TrendingUp size={20} />
              <span>Analytics</span>
            </li>
            <li
              className={activeTab === 'Threat Map' ? 'active' : ''}
              onClick={() => setActiveTab('Threat Map')}
              title="Geographic threat distribution"
            >
              <Globe size={20} />
              <span>Threat Map</span>
            </li>
            <li
              className={activeTab === 'Forensic Lab' ? 'active' : ''}
              onClick={() => setActiveTab('Forensic Lab')}
              title="Performance metrics"
            >
              <BarChart3 size={20} />
              <span>Forensic Lab</span>
            </li>
            <li
              className={activeTab === 'Red Team' ? 'active' : ''}
              onClick={() => setActiveTab('Red Team')}
              title="Adversarial AI Battleground"
            >
              <Sword size={20} />
              <span>Red Team</span>
            </li>
          </ul>

          <div className="system-status">
            <div className={`status-card ${backendStatus}`}>
              <div className="status-icon">
                <Cpu size={14} />
              </div>
              <div className="status-info">
                <span className="status-label">ML ENGINE</span>
                <div className="status-indicator">
                  <span className="dot"></span>
                  <span className="status-text">{backendStatus === 'online' ? 'Active' : 'Offline'}</span>
                </div>
              </div>
            </div>

            <div className={`status-card ${backendStatus}`}>
              <div className="status-icon">
                <Brain size={14} />
              </div>
              <div className="status-info">
                <span className="status-label">AI AGENT</span>
                <div className="status-indicator">
                  <span className="dot"></span>
                  <span className="status-text">{backendStatus === 'online' ? 'Online' : 'Standby'}</span>
                </div>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content Area */}
        <main className="soc-main">
          <header className="soc-header">
            <div className="search-bar">
              <Search size={18} />
              <input
                type="text"
                placeholder="Search IP, threat type, status..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search alerts"
              />
            </div>
            <div className="header-status-badge">
              {backendStatus === 'online' ? (
                <span className="badge live">● LIVE SYSTEM</span>
              ) : (
                <span className="badge demo">○ DEMO MODE</span>
              )}
            </div>
            <div className="header-actions">
              <button
                className={`stress-btn-header ${injecting ? 'active malicious' : 'malicious'}`}
                onClick={injectMalicious}
                disabled={injecting}
                title="Inject a high-level APT signature for LLM review"
              >
                <Bug size={16} />
                <span>{injecting ? 'INJECTING...' : 'MALICIOUS'}</span>
              </button>
              <button
                className={`stress-btn-header ${stressing ? 'active' : ''}`}
                onClick={runStressTest}
                disabled={stressing}
                title="Simulate a burst of threats"
              >
                <Zap size={16} />
                <span>{stressing ? 'STRESSING' : 'STRESS TEST'}</span>
              </button>
              <div className="voice-control-group" style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255,255,255,0.05)', padding: '4px 8px', borderRadius: '8px', border: '1px solid var(--border-color)', height: '36px' }}>
                <button
                  className={`voice-toggle-btn ${isVoiceEnabled ? 'active' : ''}`}
                  onClick={() => setIsVoiceEnabled(!isVoiceEnabled)}
                  title={isVoiceEnabled ? 'Disable voice alerts' : 'Enable voice alerts'}
                  style={{ border: 'none', background: 'transparent', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', color: isVoiceEnabled ? 'var(--accent-primary)' : 'var(--text-muted)', padding: '4px', transition: 'color 0.2s' }}
                >
                  {isVoiceEnabled ? <Volume2 size={18} /> : <VolumeX size={18} />}
                </button>
                <select
                  value={voicePersona}
                  onChange={(e) => setVoicePersona(e.target.value)}
                  title="Choose Voice Assistant Persona"
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-secondary)',
                    fontSize: '12px',
                    fontWeight: '600',
                    fontFamily: 'var(--font-display)',
                    cursor: 'pointer',
                    outline: 'none',
                    paddingRight: '4px'
                  }}
                >
                  <option value="jarvis" style={{ background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}>JARVIS</option>
                  <option value="friday" style={{ background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}>FRIDAY</option>
                  <option value="classic" style={{ background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}>CLASSIC</option>
                </select>
              </div>
              <div className="user-profile" title="View Developer Credits" onClick={() => setProfileOpen(true)}>
                <div className="avatar">IDS</div>
              </div>
            </div>
          </header>

          <div className="content-wrapper">
            {renderContent()}
          </div>
        </main>

        {/* ── Floating Chat FAB ── */}
        <ChatWidget
          chatOpen={chatOpen}
          setChatOpen={setChatOpen}
          chatFullscreen={chatFullscreen}
          setChatFullscreen={setChatFullscreen}
          chatMessages={chatMessages}
          chatLoading={chatLoading}
          chatInput={chatInput}
          setChatInput={setChatInput}
          sendChat={sendChat}
          chatEndRef={chatEndRef}
        />

        {/* ── Attack Simulator Modal ── */}
        <SimulatorModal
          simOpen={simOpen}
          setSimOpen={setSimOpen}
          simPreset={simPreset}
          setSimPreset={setSimPreset}
          simRunning={simRunning}
          setSimRunning={setSimRunning}
          simResult={simResult}
          setSimResult={setSimResult}
          setAlerts={setAlerts}
          ATTACK_PRESETS={ATTACK_PRESETS}
        />

        {/* ── Developer Credits Modal ── */}
        {profileOpen && (
          <div
            className="modal-backdrop"
            onClick={() => setProfileOpen(false)}
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              width: '100vw',
              height: '100vh',
              background: 'rgba(5, 7, 12, 0.85)',
              backdropFilter: 'blur(8px)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 9999
            }}
          >
            <div
              className="profile-modal-card"
              onClick={(e) => e.stopPropagation()}
              style={{
                background: 'rgba(15, 23, 42, 0.95)',
                border: '1px solid rgba(0, 242, 254, 0.35)',
                borderRadius: '16px',
                padding: '36px 32px',
                width: '380px',
                textAlign: 'center',
                boxShadow: '0 12px 40px rgba(0, 242, 254, 0.2), 0 0 25px rgba(0, 242, 254, 0.1)',
                position: 'relative',
                fontFamily: 'var(--font-display)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center'
              }}
            >
              {/* Top Accent Tech Bar */}
              <div style={{
                position: 'absolute',
                top: 0,
                left: '50%',
                transform: 'translateX(-50%)',
                width: '120px',
                height: '4px',
                background: 'linear-gradient(90deg, #00f2fe, #4facfe)',
                borderRadius: '0 0 6px 6px'
              }} />

              <button
                onClick={() => setProfileOpen(false)}
                style={{
                  position: 'absolute',
                  top: '16px',
                  right: '20px',
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '24px',
                  fontWeight: '300',
                  outline: 'none'
                }}
              >
                &times;
              </button>

              {/* High-Tech Avatar Badge */}
              <div style={{
                width: '80px',
                height: '80px',
                borderRadius: '50%',
                background: 'linear-gradient(135deg, #00f2fe 0%, #4facfe 100%)',
                margin: '10px 0 20px 0',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#090d16',
                fontSize: '26px',
                fontWeight: '800',
                letterSpacing: '1px',
                boxShadow: '0 0 20px rgba(0, 242, 254, 0.5)',
                border: '2px solid rgba(255, 255, 255, 0.15)'
              }}>
                UF
              </div>

              {/* Developer Details */}
              <h3 style={{
                color: 'var(--text-primary)',
                fontSize: '22px',
                fontWeight: '700',
                marginBottom: '6px',
                letterSpacing: '0.3px'
              }}>
                Muhammad Umar Farooq
              </h3>

              <span style={{
                color: '#00f2fe',
                fontSize: '12px',
                fontWeight: '600',
                textTransform: 'uppercase',
                letterSpacing: '1.5px',
                marginBottom: '20px',
                display: 'inline-block'
              }}>
                AI Engineer
              </span>

              <div style={{
                color: 'var(--text-secondary)',
                fontSize: '13px',
                lineHeight: '1.6',
                marginBottom: '28px',
                padding: '16px',
                background: 'rgba(5, 7, 12, 0.5)',
                borderRadius: '10px',
                border: '1px solid rgba(255,255,255,0.05)',
                width: '100%',
                boxSizing: 'border-box'
              }}>
                <strong>Department of Artificial Intelligence</strong><br />
                University of Management and Technology<br />
                Lahore, Pakistan
              </div>

              {/* High-Tech CTA Links */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', width: '100%' }}>
                <a
                  href="https://github.com/omerfarooq223/shap-agentic-ids"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '10px',
                    background: '#1b2230',
                    color: '#ffffff',
                    padding: '12px',
                    borderRadius: '8px',
                    fontWeight: '600',
                    fontSize: '14px',
                    textDecoration: 'none',
                    transition: 'all 0.2s ease',
                    border: '1px solid rgba(255, 255, 255, 0.08)'
                  }}
                  onMouseOver={(e) => { e.currentTarget.style.background = '#252e3f'; e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.2)'; }}
                  onMouseOut={(e) => { e.currentTarget.style.background = '#1b2230'; e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)'; }}
                >
                  <GitHubIcon size={16} />
                  <span>GitHub Repository</span>
                </a>

                <a
                  href="https://omerfarooq223.github.io/"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '10px',
                    background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.1), rgba(79, 172, 254, 0.1))',
                    color: '#00f2fe',
                    padding: '12px',
                    borderRadius: '8px',
                    fontWeight: '600',
                    fontSize: '14px',
                    textDecoration: 'none',
                    border: '1px solid rgba(0, 242, 254, 0.3)',
                    transition: 'all 0.2s ease'
                  }}
                  onMouseOver={(e) => { e.currentTarget.style.background = 'linear-gradient(135deg, rgba(0, 242, 254, 0.2), rgba(79, 172, 254, 0.2))'; e.currentTarget.style.borderColor = '#00f2fe'; }}
                  onMouseOut={(e) => { e.currentTarget.style.background = 'linear-gradient(135deg, rgba(0, 242, 254, 0.1), rgba(79, 172, 254, 0.1))'; e.currentTarget.style.borderColor = 'rgba(0, 242, 254, 0.3)'; }}
                >
                  <ExternalLink size={16} />
                  <span>Visit Developer Portfolio</span>
                </a>
              </div>
            </div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
};

export default App;