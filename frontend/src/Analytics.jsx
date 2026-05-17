import { useMemo } from 'react';
import { Download, TrendingUp, AlertTriangle, Shield, Zap } from 'lucide-react';

// ── Bar Chart (SVG) ────────────────────────────────────────────────────────────
const BarChart = ({ data, title }) => {
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <div className="chart-card">
      <h4 className="chart-heading">{title}</h4>
      {data.length === 0 ? <div className="chart-empty">No data yet</div> : (
        <div className="bar-chart-grid">
          {data.map((item) => (
            <div key={item.label} className="bar-col">
              <span className="bar-count">{item.value}</span>
              <div className="bar-track">
                <div className="bar-fill" style={{ height: `${(item.value / max) * 100}%`, background: item.color }} />
              </div>
              <span className="bar-label">{item.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ── Donut Chart (SVG) ──────────────────────────────────────────────────────────
const DonutChart = ({ data, title }) => {
  const total = data.reduce((s, d) => s + d.value, 0);
  const R = 54, CX = 70, CY = 70, circ = 2 * Math.PI * R;
  let off = 0;
  const segs = data.map(item => {
    const d = total > 0 ? (item.value / total) * circ : 0;
    const s = { ...item, dash: d, gap: circ - d, offset: off };
    off += d;
    return s;
  });

  return (
    <div className="chart-card">
      <h4 className="chart-heading">{title}</h4>
      <div className="donut-wrap">
        <svg width="140" height="140" viewBox="0 0 140 140">
          {total === 0
            ? <circle cx={CX} cy={CY} r={R} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="16" />
            : segs.map((s, i) => (
              <circle key={i} cx={CX} cy={CY} r={R} fill="none" stroke={s.color} strokeWidth="16"
                strokeDasharray={`${s.dash} ${s.gap}`} strokeDashoffset={-s.offset}
                style={{ transform: 'rotate(-90deg)', transformOrigin: `${CX}px ${CY}px` }} />
            ))
          }
          <text x={CX} y={CY - 6} textAnchor="middle" fill="white" fontSize="18" fontWeight="700">{total}</text>
          <text x={CX} y={CY + 10} textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="9">TOTAL</text>
        </svg>
        <div className="donut-legend">
          {data.map((item, i) => (
            <div key={i} className="legend-row">
              <span className="legend-dot" style={{ background: item.color }} />
              <span className="legend-name">{item.label}</span>
              <span className="legend-val">{item.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ── Risk Timeline (SVG line chart) ────────────────────────────────────────────
const RiskTimeline = ({ alerts, title }) => {
  const pts = alerts.slice(-20).map((a, i) => ({ x: i, y: Number(a.risk_score) || 0, status: a.status }));
  const W = 360, H = 100, PL = 28, PB = 18, PT = 8, PR = 8;
  const xS = i => PL + (i / Math.max(pts.length - 1, 1)) * (W - PL - PR);
  const yS = v => H - PB - (v / 10) * (H - PT - PB);
  const path = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${xS(i)},${yS(p.y)}`).join(' ');
  const area = pts.length > 1 ? `${path} L${xS(pts.length - 1)},${H - PB} L${xS(0)},${H - PB} Z` : '';

  return (
    <div className="chart-card chart-card-wide">
      <h4 className="chart-heading">{title}</h4>
      {pts.length === 0 ? <div className="chart-empty">No events yet</div> : (
        <svg width="100%" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
          <defs>
            <linearGradient id="rg" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#0d9fff" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#0d9fff" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0, 5, 10].map(v => (
            <g key={v}>
              <line x1={PL} y1={yS(v)} x2={W - PR} y2={yS(v)} stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
              <text x={PL - 4} y={yS(v)} textAnchor="end" dominantBaseline="middle" fill="rgba(255,255,255,0.3)" fontSize="8">{v}</text>
            </g>
          ))}
          {area && <path d={area} fill="url(#rg)" />}
          {pts.length > 1 && <path d={path} fill="none" stroke="#0d9fff" strokeWidth="2" strokeLinejoin="round" />}
          {pts.map((p, i) => (
            <circle key={i} cx={xS(i)} cy={yS(p.y)} r="3.5"
              fill={p.status === 'CRITICAL' ? '#ff3d4d' : p.status === 'WARNING' ? '#ffc107' : '#10b981'} />
          ))}
        </svg>
      )}
    </div>
  );
};

// ── Alert Severity Timeline ────────────────────────────────────────────────────
const AlertTimeline = ({ alerts }) => (
  <div className="chart-card timeline-card">
    <h4 className="chart-heading">⏱ ALERT SEVERITY TIMELINE</h4>
    <div className="timeline-scroll">
      {alerts.length === 0
        ? <div className="chart-empty">No events yet</div>
        : alerts.slice(0, 40).map((a, i) => (
          <div key={a.id || i} className="tl-event" style={{ animationDelay: `${i * 20}ms` }}>
            <div className={`tl-dot ${(a.status || 'info').toLowerCase()}`} />
            <div className="tl-connector" />
            <div className="tl-body">
              <span className={`tl-badge ${(a.status || 'info').toLowerCase()}`}>{a.status || 'INFO'}</span>
              <span className="tl-type">{a.threat_type}</span>
              <span className="tl-ip">{a.src_ip}</span>
              <span className="tl-risk">Risk {a.risk_score}</span>
              <span className="tl-time">{a.timestamp}</span>
            </div>
          </div>
        ))
      }
    </div>
  </div>
);

// ── Main Analytics Component ───────────────────────────────────────────────────
const Analytics = ({ alerts, onExport }) => {
  const typeData = useMemo(() => {
    const COLORS = ['#0d9fff', '#ff3d4d', '#ffc107', '#10b981', '#a855f7', '#f97316'];
    const counts = {};
    alerts.forEach(a => { const t = a.threat_type || 'Unknown'; counts[t] = (counts[t] || 0) + 1; });
    return Object.entries(counts).map(([label, value], i) => ({ label, value, color: COLORS[i % COLORS.length] }));
  }, [alerts]);

  const severityData = useMemo(() => {
    const c = { CRITICAL: 0, WARNING: 0, INFO: 0 };
    alerts.forEach(a => { c[a.status || 'INFO'] = (c[a.status || 'INFO'] || 0) + 1; });
    return [
      { label: 'Critical', value: c.CRITICAL, color: '#ff3d4d' },
      { label: 'Warning', value: c.WARNING, color: '#ffc107' },
      { label: 'Info/Benign', value: c.INFO, color: '#10b981' },
    ];
  }, [alerts]);

  const avgRisk = alerts.length
    ? (alerts.reduce((s, a) => s + (Number(a.risk_score) || 0), 0) / alerts.length).toFixed(1)
    : '0.0';

  const summaryCards = [
    { label: 'Total Threats', value: alerts.length, color: '#0d9fff', icon: <Shield size={20} /> },
    { label: 'Critical', value: alerts.filter(a => a.status === 'CRITICAL').length, color: '#ff3d4d', icon: <AlertTriangle size={20} /> },
    { label: 'Avg Risk Score', value: avgRisk, color: '#ffc107', icon: <TrendingUp size={20} /> },
    { label: 'Attack Types', value: typeData.length, color: '#10b981', icon: <Zap size={20} /> },
  ];

  return (
    <div className="tab-panel analytics-panel">
      <div className="panel-header">
        <div className="header-info">
          <h2><TrendingUp size={22} /> ANALYTICS DASHBOARD</h2>
          <p>Real-time threat intelligence, attack breakdown, and incident patterns</p>
        </div>
        <button className="export-btn" onClick={onExport}>
          <Download size={15} /> EXPORT REPORT
        </button>
      </div>

      {/* Summary cards */}
      <div className="analytics-summary-row">
        {summaryCards.map(c => (
          <div key={c.label} className="a-card" style={{ '--accent': c.color }}>
            <div className="a-card-icon">{c.icon}</div>
            <div>
              <div className="a-card-value">{c.value}</div>
              <div className="a-card-label">{c.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="charts-row">
        <BarChart data={typeData} title="🔥 THREATS BY TYPE" />
        <DonutChart data={severityData} title="⚠️ SEVERITY SPLIT" />
        <RiskTimeline alerts={alerts} title="📈 RISK SCORE TIMELINE" />
      </div>

      {/* Alert timeline */}
      <AlertTimeline alerts={alerts} />
    </div>
  );
};

export default Analytics;