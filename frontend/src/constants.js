export const ATTACK_PRESETS = [
  {
    label: 'DDoS Flood', icon: '⚡', src_ip: '185.220.101.47', dst_port: 80,
    flow: {
      src_ip: '185.220.101.47', dst_ip: '192.168.1.1', dst_port: 80,
      'Destination Port': 80, 'Flow Duration': 711, 'Total Fwd Packets': 1,
      'Total Backward Packets': 2, 'Total Length of Fwd Packets': 668100,
      'Total Length of Bwd Packets': 3, 'Fwd Packet Length Mean': 2064,
      'Bwd Packet Length Mean': 2671, 'Flow Bytes/s': 1150832,
      'Flow Packets/s': 198395, 'Fwd Packets/s': 121, 'Bwd Packets/s': 669
    }
  },
  {
    label: 'Port Scan', icon: '🔍', src_ip: '45.33.32.156', dst_port: 139,
    flow: {
      src_ip: '45.33.32.156', dst_ip: '192.168.1.1', dst_port: 139,
      'Destination Port': 139, 'Flow Duration': 446330, 'Total Fwd Packets': 1,
      'Total Backward Packets': 5, 'Total Length of Fwd Packets': 570018,
      'Total Length of Bwd Packets': 9314, 'Fwd Packet Length Mean': 2962,
      'Bwd Packet Length Mean': 2934, 'Flow Bytes/s': 62446612,
      'Flow Packets/s': 153449, 'Fwd Packets/s': 14858, 'Bwd Packets/s': 15492
    }
  },
  {
    label: 'Brute Force', icon: '🔨', src_ip: '91.213.50.4', dst_port: 22,
    flow: {
      src_ip: '91.213.50.4', dst_ip: '192.168.1.1', dst_port: 22,
      'Destination Port': 22, 'Flow Duration': 10413, 'Total Fwd Packets': 9,
      'Total Backward Packets': 5, 'Total Length of Fwd Packets': 121976,
      'Total Length of Bwd Packets': 2829, 'Fwd Packet Length Mean': 2640,
      'Bwd Packet Length Mean': 3171, 'Flow Bytes/s': 3577,
      'Flow Packets/s': 6, 'Fwd Packets/s': 3, 'Bwd Packets/s': 360941
    }
  },
  {
    label: 'Data Exfil', icon: '📤', src_ip: '103.251.167.20', dst_port: 443,
    flow: {
      src_ip: '103.251.167.20', dst_ip: '10.0.0.5', dst_port: 443,
      'Destination Port': 443, 'Flow Duration': 329262, 'Total Fwd Packets': 1,
      'Total Backward Packets': 2, 'Total Length of Fwd Packets': 672457,
      'Total Length of Bwd Packets': 10914, 'Fwd Packet Length Mean': 2414,
      'Bwd Packet Length Mean': 2272, 'Flow Bytes/s': 11400790,
      'Flow Packets/s': 76, 'Fwd Packets/s': 22, 'Bwd Packets/s': 45694
    }
  },
];

export const DEMO_ALERTS = [
  {
    id: 'demo-1', timestamp: new Date().toLocaleTimeString(),
    src_ip: '192.168.1.105', dst_ip: '10.0.0.1', dst_port: 22,
    risk_score: 8.7, threat_type: 'Brute-Force', status: 'CRITICAL', mitre: 'T1110',
    ml_confidence: 0.98,
    agent_reasoning: [
      'OBSERVE: Detected flow to port 22 with high packet rate.',
      'HYPOTHESIZE: Behavior consistent with SSH Brute-Force attack.',
      'VERIFY: Source IP flagged via behavioral ML features.',
      'CONCLUDE: CRITICAL alert raised. Risk 8.7/10.'
    ],
    shap_explanation: [
      { feature: 'Destination Port', value: 22, contribution: 0.35, absolute_contribution: 0.35 },
      { feature: 'Flow Duration', value: '1.2s', contribution: 0.20, absolute_contribution: 0.20 },
      { feature: 'Fwd Packets/s', value: 450, contribution: 0.15, absolute_contribution: 0.15 }
    ],
    threat_intel: { abuse_score: 0, intel_source: 'Behavioral ML' }
  },
  {
    id: 'demo-2', timestamp: new Date().toLocaleTimeString(),
    src_ip: '45.33.22.11', dst_ip: '10.0.0.5', dst_port: 80,
    risk_score: 6.2, threat_type: 'Anomaly', status: 'WARNING', mitre: 'T1046',
    ml_confidence: 0.74,
    agent_reasoning: [
      'OBSERVE: Unusual HTTP flow entropy detected.',
      'HYPOTHESIZE: Possible web-shell or C2 traffic.',
      'VERIFY: AbuseIPDB score 0 — no public reputation data.',
      'CONCLUDE: Flagging as WARNING for manual review.'
    ],
    shap_explanation: [
      { feature: 'Flow Bytes/s', value: 98000, contribution: 0.45, absolute_contribution: 0.45 },
      { feature: 'Bwd Packet Length Mean', value: 1500, contribution: 0.10, absolute_contribution: 0.10 }
    ],
    threat_intel: { abuse_score: 0, intel_source: 'Behavioral ML' }
  }
];

export const INITIAL_CHAT_MESSAGE = {
  role: 'assistant',
  content: "I'm your IDS AI Analyst (LLaMA-3.3-70B with RAG). I retrieve MITRE playbooks, threat patterns, and live alerts before answering. Ask about recent threats, attack types, or how the system works."
};

export const API_CONFIG = {
  BASE_URL: import.meta.env.VITE_API_URL || 'http://localhost:5005',
  CREDENTIALS: 'include',
  HEADERS: {
    'Content-Type': 'application/json'
  }
};

export const SESSION_TOKEN_KEY = 'idsSessionToken';

export const getSessionToken = () => {
  try {
    return window.sessionStorage?.getItem?.(SESSION_TOKEN_KEY) || '';
  } catch {
    return '';
  }
};

export const setSessionToken = (token) => {
  try {
    if (token) {
      window.sessionStorage?.setItem?.(SESSION_TOKEN_KEY, token);
    } else {
      window.sessionStorage?.removeItem?.(SESSION_TOKEN_KEY);
    }
  } catch {
    // Hardened browser settings can disable web storage.
  }
};

export const getAuthHeaders = () => {
  const headers = { ...API_CONFIG.HEADERS };
  const token = getSessionToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
};
