# Expected CSV Format for Agentic IDS

The machine learning and agentic reasoning pipeline relies on a specific CSV schema, originally based on the **CICIDS2017** dataset.

## Core Requirements
1. **Format**: Comma-Separated Values (`.csv`).
2. **Missing Values**: Handled automatically, but excessive `NaN` or `Infinity` values will cause rows to be dropped.
3. **Headers**: The first row MUST contain exactly matching column names.

## Target Column
- **Column Name**: `Label` (Configurable in `src/config.py`)
- **Values**: Must contain the exact string `"BENIGN"` for normal traffic. All other strings (e.g., `"DDoS"`, `"PortScan"`) are treated as malicious anomalies (class `1`).

## Required Numeric Features (78 Columns)
The model expects 78 specific network flow features. A subset of the most critical features includes:
- `Destination Port`
- `Flow Duration`
- `Total Fwd Packets`
- `Total Backward Packets`
- `Flow Bytes/s`
- `Flow Packets/s`

*(Note: The system now auto-detects features dynamically at runtime via `src/config.py`, meaning it will adapt to slight variations, but for optimal Random Forest performance, the 78 features listed in the config fallback should be present).*

## UNSW-NB15 Cross-Evaluation
If using the UNSW-NB15 dataset for evaluation, ensure you have pre-processed the headers to map to the CICIDS2017 schema, or the pipeline will throw a "Schema Validation Warning."
