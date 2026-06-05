# Baseline Classifier & Efficiency Comparison

**Purpose:** Compare the production Random Forest detector against classical IDS baselines.  

The production pipeline remains **Random Forest + SHAP + Agentic verification**. This benchmark adds academic baselines and efficiency metrics so the model choice can be justified empirically.

## CICIDS2017

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Train Time (s) | Inference (ms/sample) | Peak Train Memory (MB) | Model Size (MB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Decision Tree | 0.9920 | 0.9845 | 0.9745 | 0.9795 | 0.9854 | 0.05 | 0.0015 | 10.52 | 0.02 |
| Random Forest | 0.9900 | 0.9947 | 0.9541 | 0.9740 | 0.9985 | 0.49 | 0.0161 | 10.52 | 1.02 |
| Logistic Regression | 0.8960 | 0.6655 | 0.9439 | 0.7806 | 0.9755 | 0.04 | 0.0018 | 10.56 | 0.01 |
| GaussianNB | 0.8370 | 0.5478 | 0.9643 | 0.6987 | 0.9278 | 0.02 | 0.0018 | 10.53 | 0.01 |
| MultinomialNB | 0.8440 | 0.7000 | 0.3571 | 0.4730 | 0.7205 | 0.02 | 0.0015 | 10.52 | 0.01 |
| ComplementNB | 0.7810 | 0.4372 | 0.4082 | 0.4222 | 0.7205 | 0.02 | 0.0014 | 10.52 | 0.01 |

**Finding:** Decision Tree has the strongest F1 score on this run. ComplementNB is fastest at inference, and Logistic Regression has the smallest serialized footprint.

## UNSW-NB15

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Train Time (s) | Inference (ms/sample) | Peak Train Memory (MB) | Model Size (MB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.9370 | 0.9384 | 0.9636 | 0.9508 | 0.9868 | 0.46 | 0.0151 | 5.31 | 3.31 |
| Decision Tree | 0.9240 | 0.9371 | 0.9430 | 0.9401 | 0.9213 | 0.04 | 0.0012 | 5.31 | 0.04 |
| Logistic Regression | 0.8680 | 0.8799 | 0.9161 | 0.8977 | 0.9447 | 0.03 | 0.0013 | 5.32 | 0.01 |
| GaussianNB | 0.7830 | 0.8083 | 0.8608 | 0.8337 | 0.8700 | 0.02 | 0.0012 | 5.31 | 0.01 |
| ComplementNB | 0.7080 | 0.8498 | 0.6535 | 0.7388 | 0.8052 | 0.02 | 0.0012 | 5.31 | 0.01 |
| MultinomialNB | 0.6910 | 0.8198 | 0.6551 | 0.7282 | 0.8052 | 0.02 | 0.0011 | 5.31 | 0.01 |

**Finding:** Random Forest has the strongest F1 score on this run. MultinomialNB is fastest at inference, and Logistic Regression has the smallest serialized footprint.

## Interpretation

- Logistic Regression and Naive Bayes variants provide lightweight baselines for speed, memory, and model-size comparisons.
- Decision Tree gives a transparent tree baseline, useful for explaining the value of the production ensemble.
- Random Forest remains the production model because it balances tabular IDS accuracy with SHAP-compatible explainability.
- XGBoost is treated as optional so the benchmark works in the base environment without adding a mandatory dependency.

## Per-Attack-Class Metrics

Per-class metrics use Random Forest because it is the production detector. They show which attack families are easiest or hardest for the model.

### CICIDS2017

Accuracy: 0.9910; Macro F1: 0.7138; Weighted F1: 0.9888

Excluded rare classes with fewer than two sampled rows: Web Attack - Brute Force

| Attack Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| BENIGN | 0.9901 | 0.9988 | 0.9944 | 805 |
| DoS Hulk | 1.0000 | 0.9753 | 0.9875 | 81 |
| PortScan | 1.0000 | 1.0000 | 1.0000 | 54 |
| DDoS | 0.9783 | 1.0000 | 0.9890 | 45 |
| FTP-Patator | 1.0000 | 1.0000 | 1.0000 | 5 |
| DoS GoldenEye | 1.0000 | 0.3333 | 0.5000 | 3 |
| DoS Slowhttptest | 0.0000 | 0.0000 | 0.0000 | 2 |
| DoS slowloris | 1.0000 | 0.5000 | 0.6667 | 2 |
| SSH-Patator | 1.0000 | 1.0000 | 1.0000 | 2 |
| Bot | 0.0000 | 0.0000 | 0.0000 | 1 |

### UNSW-NB15

Accuracy: 0.8030; Macro F1: 0.4563; Weighted F1: 0.7939

| Attack Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Normal | 0.8923 | 0.9457 | 0.9182 | 368 |
| Generic | 0.9956 | 0.9702 | 0.9828 | 235 |
| Exploits | 0.6200 | 0.7561 | 0.6813 | 164 |
| Fuzzers | 0.6349 | 0.4444 | 0.5229 | 90 |
| DoS | 0.4000 | 0.3582 | 0.3780 | 67 |
| Reconnaissance | 0.7872 | 0.7255 | 0.7551 | 51 |
| Analysis | 0.0000 | 0.0000 | 0.0000 | 9 |
| Backdoor | 0.2000 | 0.1111 | 0.1429 | 9 |
| Shellcode | 0.2000 | 0.1667 | 0.1818 | 6 |
| Worms | 0.0000 | 0.0000 | 0.0000 | 1 |

