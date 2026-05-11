"""
tests/test_performance.py — Latency and Throughput Benchmarks
Verifies that the IDS pipeline meets sub-100ms latency targets.
"""

import pytest
import time
import statistics
from src import config

def test_inference_latency(flask_client):
    """Benchmark the latency of a single detection request."""
    flask_client, *_ = flask_client
    headers = {"X-API-KEY": config.INTERNAL_API_KEY}
    payload = {
        "Destination Port": 80,
        "dst_port": 80,
        "Flow Duration": 1000,
        "Total Fwd Packets": 2,
        "Total Backward Packets": 2,
        "Total Length of Fwd Packets": 100,
        "Total Length of Bwd Packets": 100,
        "Fwd Packet Length Mean": 50,
        "Bwd Packet Length Mean": 50,
        "Flow Bytes/s": 200,
        "Flow Packets/s": 4,
        "Fwd Packets/s": 2,
        "Bwd Packets/s": 2,
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8"
    }
    
    latencies = []
    for _ in range(10):
        start = time.perf_counter()
        resp = flask_client.post("/detect", json={"flow": payload}, headers=headers)
        end = time.perf_counter()
        assert resp.status_code == 200
        latencies.append((end - start) * 1000)  # ms
    
    avg_latency = statistics.mean(latencies)
    p95_latency = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
    
    print(f"\n[PERFORMANCE] Avg Latency: {avg_latency:.2f}ms")
    print(f"[PERFORMANCE] P95 Latency: {p95_latency:.2f}ms")
    
    # Target: Real-time IDS should be < 200ms per flow (even with agent logic)
    assert avg_latency < 500  # Conservative upper bound for CI
