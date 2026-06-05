import { BarChart3, Cpu, Gauge, ListChecks, Trophy } from 'lucide-react';

const formatPercent = (value) => (
  Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(1)}%` : 'N/A'
);

const formatNumber = (value, digits = 3) => (
  Number.isFinite(Number(value)) ? Number(value).toFixed(digits) : 'N/A'
);

const getRowsForDataset = (benchmarks, dataset) => (
  Array.isArray(benchmarks?.baseline_efficiency)
    ? benchmarks.baseline_efficiency.filter(row => row.dataset === dataset)
    : []
);

const getPerClassForDataset = (benchmarks, dataset) => (
  Array.isArray(benchmarks?.per_attack_class)
    ? benchmarks.per_attack_class.find(row => row.dataset === dataset)
    : null
);

const ForensicLabTab = ({ benchmarks }) => {
  const cicidsRows = getRowsForDataset(benchmarks, 'CICIDS2017');
  const unswRows = getRowsForDataset(benchmarks, 'UNSW-NB15');
  const allRows = [...cicidsRows, ...unswRows];
  const activeRows = unswRows.length ? unswRows : cicidsRows;
  const bestF1 = activeRows.length ? [...activeRows].sort((a, b) => b.f1 - a.f1)[0] : null;
  const fastest = activeRows.length ? [...activeRows].sort((a, b) => a.inference_time_ms_per_sample - b.inference_time_ms_per_sample)[0] : null;
  const smallest = activeRows.length ? [...activeRows].sort((a, b) => a.model_size_mb - b.model_size_mb)[0] : null;
  const perClass = getPerClassForDataset(benchmarks, 'UNSW-NB15') || getPerClassForDataset(benchmarks, 'CICIDS2017');
  const perClassRows = perClass?.classes?.slice(0, 12) || [];

  return (
    <div className="tab-panel lab-panel">
      <div className="panel-header">
        <div className="header-info">
          <h2><BarChart3 size={24} /> FORENSIC BENCHMARKING</h2>
          <p>Performance metrics, baseline classifiers, and attack-class diagnostics</p>
        </div>
      </div>

      <div className="forensic-grid">
        <div className="benchmark-section">
          <h3><BarChart3 size={18} /> System Performance Metrics</h3>
          <div className="metrics-table-wrapper">
            <table className="benchmark-table">
              <thead>
                <tr>
                  <th>Detection Method</th>
                  <th>Recall (TPR)</th>
                  <th>Precision</th>
                  <th>False Positives</th>
                  <th>F1-Score</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Traditional Rules (Snort)</td>
                  <td>{formatPercent(benchmarks?.snort?.[1])}</td>
                  <td>{formatPercent(benchmarks?.snort?.[0])}</td>
                  <td>14.8%</td>
                  <td>{formatNumber(benchmarks?.snort?.[2])}</td>
                </tr>
                <tr className="highlight">
                  <td><strong>Agentic IDS (Ours)</strong></td>
                  <td><strong>{formatPercent(benchmarks?.agentic_ids?.[1])}</strong></td>
                  <td><strong>{formatPercent(benchmarks?.agentic_ids?.[0])}</strong></td>
                  <td><strong>{formatPercent(benchmarks?.fpr)}</strong></td>
                  <td><strong>{formatNumber(benchmarks?.agentic_ids?.[2])}</strong></td>
                </tr>
                <tr>
                  <td>Traditional Rules (Suricata)</td>
                  <td>{formatPercent(benchmarks?.suricata?.[1])}</td>
                  <td>{formatPercent(benchmarks?.suricata?.[0])}</td>
                  <td>12.4%</td>
                  <td>{formatNumber(benchmarks?.suricata?.[2])}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div className="benchmark-section">
          <h3><Trophy size={18} /> Model Benchmark Summary</h3>
          <div className="metrics-cards benchmark-cards">
            <div className="metric-card">
              <div className="metric-icon"><Trophy size={22} /></div>
              <div className="metric-info">
                <label>Best F1</label>
                <span className="val">{bestF1 ? `${bestF1.model} (${formatNumber(bestF1.f1)})` : 'Run Eval'}</span>
              </div>
            </div>
            <div className="metric-card">
              <div className="metric-icon"><Gauge size={22} /></div>
              <div className="metric-info">
                <label>Fastest Inference</label>
                <span className="val">{fastest ? `${fastest.model} (${formatNumber(fastest.inference_time_ms_per_sample, 4)} ms)` : 'Run Eval'}</span>
              </div>
            </div>
            <div className="metric-card">
              <div className="metric-icon"><Cpu size={22} /></div>
              <div className="metric-info">
                <label>Smallest Model</label>
                <span className="val">{smallest ? `${smallest.model} (${formatNumber(smallest.model_size_mb, 2)} MB)` : 'Run Eval'}</span>
              </div>
            </div>
            <div className="metric-card">
              <div className="metric-icon"><ListChecks size={22} /></div>
              <div className="metric-info">
                <label>Report Source</label>
                <span className="val">{benchmarks?.baseline_generated_at ? 'Baseline report loaded' : 'Run Eval'}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="benchmark-section">
          <h3><BarChart3 size={18} /> Baseline Classifier Leaderboard</h3>
          <div className="metrics-table-wrapper">
            <table className="benchmark-table compact-table">
              <thead>
                <tr>
                  <th>Dataset</th>
                  <th>Model</th>
                  <th>Accuracy</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1</th>
                  <th>ROC-AUC</th>
                </tr>
              </thead>
              <tbody>
                {allRows
                  .sort((a, b) => a.dataset.localeCompare(b.dataset) || b.f1 - a.f1)
                  .map((row) => (
                    <tr key={`${row.dataset}-${row.model}`} className={row.model === 'Random Forest' ? 'highlight' : ''}>
                      <td>{row.dataset}</td>
                      <td>{row.model}</td>
                      <td>{formatPercent(row.accuracy)}</td>
                      <td>{formatPercent(row.precision)}</td>
                      <td>{formatPercent(row.recall)}</td>
                      <td>{formatNumber(row.f1)}</td>
                      <td>{formatNumber(row.roc_auc)}</td>
                    </tr>
                  ))}
                {!allRows.length && (
                  <tr>
                    <td colSpan="7">Run the evaluation script to load classifier baselines.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="benchmark-section">
          <h3><Gauge size={18} /> Efficiency Comparison</h3>
          <div className="metrics-table-wrapper">
            <table className="benchmark-table compact-table">
              <thead>
                <tr>
                  <th>Dataset</th>
                  <th>Model</th>
                  <th>Train Time</th>
                  <th>Inference</th>
                  <th>Peak Memory</th>
                  <th>Model Size</th>
                </tr>
              </thead>
              <tbody>
                {allRows
                  .sort((a, b) => a.dataset.localeCompare(b.dataset) || a.inference_time_ms_per_sample - b.inference_time_ms_per_sample)
                  .map((row) => (
                    <tr key={`eff-${row.dataset}-${row.model}`} className={row.model === 'Random Forest' ? 'highlight' : ''}>
                      <td>{row.dataset}</td>
                      <td>{row.model}</td>
                      <td>{formatNumber(row.train_time_s, 2)}s</td>
                      <td>{formatNumber(row.inference_time_ms_per_sample, 4)} ms/sample</td>
                      <td>{formatNumber(row.peak_train_memory_mb, 2)} MB</td>
                      <td>{formatNumber(row.model_size_mb, 2)} MB</td>
                    </tr>
                  ))}
                {!allRows.length && (
                  <tr>
                    <td colSpan="6">Run the evaluation script to load efficiency metrics.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="benchmark-section">
          <h3><ListChecks size={18} /> Per-Attack-Class Metrics</h3>
          <div className="class-summary-row">
            <span className="source-tag">Dataset: {perClass?.dataset || 'Run Eval'}</span>
            <span className="source-tag">Model: {perClass?.model || 'Random Forest'}</span>
            <span className="source-tag">Macro F1: {formatNumber(perClass?.macro_f1)}</span>
            <span className="source-tag">Weighted F1: {formatNumber(perClass?.weighted_f1)}</span>
          </div>
          <div className="metrics-table-wrapper">
            <table className="benchmark-table compact-table">
              <thead>
                <tr>
                  <th>Attack Class</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1</th>
                  <th>Support</th>
                </tr>
              </thead>
              <tbody>
                {perClassRows.map(row => (
                  <tr key={row.attack_class}>
                    <td>{row.attack_class}</td>
                    <td>{formatPercent(row.precision)}</td>
                    <td>{formatPercent(row.recall)}</td>
                    <td>{formatNumber(row.f1)}</td>
                    <td>{row.support}</td>
                  </tr>
                ))}
                {!perClassRows.length && (
                  <tr>
                    <td colSpan="5">Run the evaluation script to load per-attack-class metrics.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="benchmark-section">
          <h3><ListChecks size={18} /> Methodology & Data Sources</h3>
          <div className="methodology-card">
            <p>
              Rule-system baselines are retained for Snort and Suricata comparison. Classifier baselines are generated locally from CICIDS2017 and UNSW-NB15 using the same benchmark runner.
            </p>
            <p>
              The production detector remains <strong>Random Forest + SHAP + LangGraph</strong>. The baseline tables explain why: simpler models are faster and smaller, but Random Forest gives a stronger balance of detection quality and explainability.
            </p>
            <div className="source-links">
              <span className="source-tag">Reference: Sharafaldin et al. (2018)</span>
              <span className="source-tag">Engine: Random Forest + LangGraph</span>
              <span className="source-tag">Baselines: Logistic Regression, NB, Decision Tree</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForensicLabTab;
