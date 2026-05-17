export const ATTACK_PRESETS = [
  {
    label: 'DDoS Flood', icon: '⚡', src_ip: '185.220.101.47', dst_port: 80,
    flow: {
      src_ip: '185.220.101.47', dst_ip: '192.168.1.1', dst_port: 80,
      'Destination Port': 80, 'Flow Duration': 1200, 'Total Fwd Packets': 9800,
      'Total Length of Fwd Packets': 980000, 'Fwd Packet Length Max': 100,
      'Fwd Packet Length Mean': 100, 'Flow Bytes/s': 815000, 'Flow Packets/s': 8166,
      'Fwd Packets/s': 8166, 'SYN Flag Count': 9800, 'Max Packet Length': 100,
      'Average Packet Size': 100
    }
  },
  {
    label: 'Port Scan', icon: '🔍', src_ip: '45.33.32.156', dst_port: 22,
    flow: {
      src_ip: '45.33.32.156', dst_ip: '192.168.1.1', dst_port: 22,
      'Destination Port': 22, 'Flow Duration': 500, 'Total Fwd Packets': 200,
      'Total Length of Fwd Packets': 200, 'Fwd Packet Length Mean': 1,
      'Flow Bytes/s': 400, 'Flow Packets/s': 400, 'Fwd Packets/s': 400,
      'RST Flag Count': 200, 'SYN Flag Count': 200, 'Max Packet Length': 1,
      'Average Packet Size': 1
    }
  },
  {
    label: 'Brute Force', icon: '🔨', src_ip: '91.213.50.4', dst_port: 22,
    flow: {
      src_ip: '91.213.50.4', dst_ip: '192.168.1.1', dst_port: 22,
      'Destination Port': 22, 'Flow Duration': 30000000, 'Total Fwd Packets': 5000,
      'Total Backward Packets': 3000, 'Total Length of Fwd Packets': 300000,
      'Total Length of Bwd Packets': 360000, 'Fwd Packet Length Mean': 60,
      'Bwd Packet Length Mean': 120, 'Flow Bytes/s': 8500, 'Flow Packets/s': 260,
      'Fwd Packets/s': 166, 'PSH Flag Count': 5000, 'ACK Flag Count': 8000,
      'Max Packet Length': 200, 'Average Packet Size': 82
    }
  },
  {
    label: 'Data Exfil', icon: '📤', src_ip: '103.251.167.20', dst_port: 443,
    flow: {
      src_ip: '103.251.167.20', dst_ip: '10.0.0.5', dst_port: 443,
      'Destination Port': 443, 'Flow Duration': 120000000, 'Total Fwd Packets': 600,
      'Total Backward Packets': 800, 'Total Length of Bwd Packets': 1120000,
      'Bwd Packet Length Max': 1500, 'Bwd Packet Length Mean': 1400,
      'Flow Bytes/s': 9800, 'Flow Packets/s': 11, 'Fwd Packets/s': 5,
      'ACK Flag Count': 1400, 'PSH Flag Count': 800,
      'Max Packet Length': 1500, 'Packet Length Variance': 480000, 'Average Packet Size': 820
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
  content: "I'm your IDS AI Analyst powered by LLaMA-3.3-70B. Ask me about detected threats, attack patterns, MITRE tactics, or how the system works."
};

export const API_CONFIG = {
  BASE_URL: import.meta.env.VITE_API_URL || 'http://localhost:5005',
  HEADERS: {
    'Content-Type': 'application/json',
    'X-API-KEY': import.meta.env.VITE_API_KEY || ''
  }
};
