"""
src/schemas.py

Pydantic v2 schema definitions for all API input and output contracts.
Replacing raw dict-passing with typed, validated models prevents
silent data corruption and provides clear API documentation.
"""

from __future__ import annotations
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, create_model, ConfigDict
from src import config


# ---------------------------------------------------------------------------
# INPUT SCHEMAS (Strict Dynamic Validation)
# ---------------------------------------------------------------------------

class _NetworkFlowBase(BaseModel):
    """Base fields that apply to all flows with strict validation."""
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination port")
    protocol: Optional[str] = Field("TCP", description="Protocol type")
    timestamp: Optional[str] = Field(None, description="Flow timestamp")

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def validate_ip(cls, v: Any) -> str:
        """Validate IP address format using centralized utility."""
        if not isinstance(v, str) or not v.strip():
            raise ValueError("IP address must be a non-empty string")
        v_stripped = v.strip()
        if not config.validate_ip_address(v_stripped):
            raise ValueError(f"Invalid IP address format: {v_stripped}")
        return v_stripped

    @field_validator("dst_port", mode="before")
    @classmethod
    def coerce_port(cls, v: Any) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            raise ValueError(f"dst_port must be an integer, got: {v!r}")

# Feature validation ranges — realistic bounds for network flow metrics
# These constraints prevent injection of nonsensical values that would break the ML model
FEATURE_RANGES = {
    # Port-related features (0-65535)
    "Destination Port": (0, 65535),
    "destination port": (0, 65535),
    
    # Duration (0 to 24 hours in seconds)
    "Flow Duration": (0, 86400),
    "flow duration": (0, 86400),
    
    # Packet counts (0 to 1 million packets per flow is reasonable)
    "Total Fwd Packets": (0, 1_000_000),
    "Total Backward Packets": (0, 1_000_000),
    "Fwd Packets/s": (0, 1_000_000),
    "Bwd Packets/s": (0, 1_000_000),
    "Flow Packets/s": (0, 1_000_000),
    
    # Byte lengths (0 to 4GB per flow)
    "Total Length of Fwd Packets": (0, 4_000_000_000),
    "Total Length of Bwd Packets": (0, 4_000_000_000),
    "Fwd Packet Length Max": (0, 65535),  # Max IP packet = 65535 bytes
    "Bwd Packet Length Max": (0, 65535),
    "Fwd Packet Length Mean": (0, 65535),
    "Bwd Packet Length Mean": (0, 65535),
    "Max Packet Length": (0, 65535),
    "Average Packet Size": (0, 65535),
    
    # Rates (0 to reasonable max)
    "Flow Bytes/s": (0, 10_000_000),  # 10 MB/s
    
    # IAT (inter-arrival time) in milliseconds
    "Flow IAT Mean": (0, 3_600_000),  # Up to 1 hour
    "Flow IAT Max": (0, 3_600_000),
    "Flow IAT Min": (0, 3_600_000),
    "Fwd IAT Mean": (0, 3_600_000),
    "Bwd IAT Mean": (0, 3_600_000),
}

# Dynamically bind the exact ML features the model was trained on with validation
_dynamic_fields = {}
for feature in config.NUMERIC_FEATURES:
    safe_attr_name = feature.replace(" ", "_").replace("/", "_").replace(".", "_").lower()
    
    # Look up range constraints (case-insensitive)
    range_constraint = None
    for key, range_val in FEATURE_RANGES.items():
        if key.lower() == feature.lower():
            range_constraint = range_val
            break
    
    # If we have a range constraint, apply it; otherwise use default non-negative constraint
    if range_constraint:
        min_val, max_val = range_constraint
        _dynamic_fields[safe_attr_name] = (float, Field(
            0.0, 
            alias=feature,
            ge=min_val,
            le=max_val,
            description=f"Must be between {min_val} and {max_val}"
        ))
    else:
        # For unmapped features, enforce non-negative (no negative network metrics)
        _dynamic_fields[safe_attr_name] = (float, Field(
            0.0, 
            alias=feature,
            ge=0,
            description="Network metrics must be non-negative"
        ))

# Create the strict Pydantic model inheriting from the base
NetworkFlowInput = create_model(
    "NetworkFlowInput",
    __base__=_NetworkFlowBase,
    __config__=ConfigDict(
        extra="forbid",           # STRICT GATE: Reject any field not explicitly defined
        populate_by_name=True     # Allow accessing by either safe_name or alias
    ),
    **_dynamic_fields
)


class DetectRequest(BaseModel):
    """Wrapper for the /detect POST body."""
    flow: NetworkFlowInput


class ChatRequest(BaseModel):
    """Wrapper for the /chat POST body."""
    message: str = Field(..., min_length=1, max_length=2000)


# ---------------------------------------------------------------------------
# OUTPUT SCHEMAS
# ---------------------------------------------------------------------------

class ShapFeature(BaseModel):
    feature: str
    value: str
    contribution: float
    absolute_contribution: float


class GeoLocation(BaseModel):
    lat: float = 0.0
    lon: float = 0.0
    country: str = "Unknown"
    city: Optional[str] = None


class ThreatIntel(BaseModel):
    abuse_score: int = 0
    intel_source: str = "None"
    intel_status: str = "skipped"
    zero_day_potential: bool = False
    mitre_mapping: Optional[str] = None


class BackendMeta(BaseModel):
    agent_latency_ms: float
    agent_error: str = ""


class DetectResponse(BaseModel):
    id: int
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    anomaly: bool
    ml_confidence: float
    shap_explanation: list[ShapFeature] = []
    threat_type: str = "benign"
    llm_reasoning: Optional[str] = None
    llm_confidence: Optional[float] = None
    threat_intel: ThreatIntel = Field(default_factory=ThreatIntel)
    risk_score: float = 0.0
    status: str = "INFO"
    mitre: Optional[str] = None
    zero_day_potential: bool = False
    recommendation: str = "No action required."
    agent_reasoning: list[str] = []
    geo_location: GeoLocation = Field(default_factory=GeoLocation)
    _backend: Optional[BackendMeta] = None

    model_config = {"populate_by_name": True}


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    agent_ready: bool
    message: Optional[str] = None


class StatusResponse(BaseModel):
    status: str
    timestamp: str
    components: dict[str, str]
