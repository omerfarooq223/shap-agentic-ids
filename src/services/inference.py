"""
src/services/inference.py

InferenceService — Single Responsibility: owns the ML pipeline.
Extracted from the 629-line monolith in app.py.

Responsibilities:
  - Load / hold the RF model, scaler, and SHAP explainer
  - Extract and scale features from a validated flow dict
  - Produce SHAP explanations with memory cleanup
  - Return raw ML probability

Memory Management:
  - SHAP explainer accumulates intermediate data; we explicitly clean up after each explain()
  - Garbage collection is called to release TreeExplainer temporary structures
  - Optional in-memory cache to avoid redundant SHAP computations (reduces GC pressure)

Nothing in here touches HTTP, databases, or external APIs.
"""

from __future__ import annotations

import logging
import gc
import hashlib
import joblib
import numpy as np
import pandas as pd
import shap
from typing import Any

from src import config

logger = logging.getLogger(__name__)


class InferenceService:
    """Wraps the Random Forest + SHAP pipeline with memory management."""

    def __init__(self) -> None:
        self._model = None
        self._scaler = None
        self._explainer = None
        # Optional SHAP explanation cache to reduce garbage collection pressure
        # Maps feature vector hash -> SHAP contributions (disabled by default)
        self._shap_cache = {}
        self._cache_enabled = False  # Set to True if caching is needed

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load model artifacts from disk.  Raises on missing files."""
        logger.info("InferenceService: loading RF model …")
        self._model = joblib.load(config.RF_MODEL_PATH)
        # Compatibility shim for joblib / Python 3.14+
        if hasattr(self._model, "n_jobs"):
            self._model.n_jobs = 1

        if config.SCALER_PATH.exists():
            logger.info("InferenceService: loading scaler …")
            self._scaler = joblib.load(config.SCALER_PATH)
        else:
            logger.warning("InferenceService: SCALER_PATH not found — proceeding without scaling (raw features)")
            self._scaler = None

        logger.info("InferenceService: loading SHAP explainer …")
        if config.SHAP_EXPL_PATH.exists():
            self._explainer = joblib.load(config.SHAP_EXPL_PATH)
        else:
            logger.warning("SHAP explainer .pkl not found — rebuilding (slow) …")
            self._explainer = shap.TreeExplainer(self._model)

        logger.info("✓ InferenceService ready")

    @property
    def is_ready(self) -> bool:
        return self._model is not None

    # ------------------------------------------------------------------
    # Core inference
    # ------------------------------------------------------------------

    def predict_proba(self, flow: dict[str, Any]) -> float:
        """Return P(attack) for the given flow dict."""
        scaled = self._scale_features(flow)
        probs = self._model.predict_proba(scaled)[0]
        return float(probs[1])

    def explain(
        self, flow: dict[str, Any], top_n: int = 5
    ) -> list[dict[str, Any]]:
        """Return the top-N SHAP feature contributions for this flow.
        
        Args:
            flow: Network flow dict with validated features (from schemas.DetectRequest)
            top_n: Number of top SHAP contributions to return (default=5). 
                   Lower values reduce output verbosity; higher values (>10) increase computation time.
        
        Returns:
            List of dicts with keys: 'feature', 'value', 'contribution', 'absolute_contribution'
            Sorted by absolute contribution (descending). Returns empty list on error.
        
        CRITICAL: Explicitly cleans up SHAP temporary data structures after computation.
        SHAP's TreeExplainer accumulates intermediate data during shap_values() calls.
        Garbage collection is triggered to release these temporaries.
        
        Memory Management Strategy:
        1. Compute SHAP values
        2. Extract contributions 
        3. Delete SHAP values to release temporary arrays
        4. Force garbage collection to clean up TreeExplainer state
        
        Optional: Use caching (disabled by default) to reduce SHAP computation frequency.
        """
        scaled = self._scale_features(flow)
        
        try:
            # Optional: Check cache before expensive SHAP computation
            if self._cache_enabled:
                cache_key = self._hash_features(scaled)
                if cache_key in self._shap_cache:
                    logger.debug(f"SHAP cache hit for feature vector")
                    return self._shap_cache[cache_key]
            
            # Compute SHAP values
            shap_values = self._explainer.shap_values(scaled)

            if isinstance(shap_values, list):
                single = shap_values[1][0]
            elif len(shap_values.shape) == 3:
                single = shap_values[0, :, 1]
            else:
                single = shap_values[0]

            contributions = []
            for i, feature in enumerate(config.NUMERIC_FEATURES):
                # At this point, all features are validated to exist (from _scale_features above)
                raw_val = flow[feature]  # Direct access, no silent default
                contributions.append(
                    {
                        "feature": feature,
                        "value": f"{raw_val:.2f}"
                        if isinstance(raw_val, float)
                        else str(raw_val),
                        "contribution": float(single[i]),
                        "absolute_contribution": float(abs(single[i])),
                    }
                )

            contributions.sort(
                key=lambda x: x["absolute_contribution"], reverse=True
            )
            result = contributions[:top_n]
            
            # CRITICAL: Memory cleanup to prevent SHAP memory accumulation
            # Delete temporary SHAP arrays explicitly
            del shap_values
            del single
            del contributions
            
            # Force garbage collection to release TreeExplainer intermediate data
            # This is aggressive but necessary because SHAP accumulates state
            gc.collect()
            
            # Optional: Store in cache (if enabled)
            if self._cache_enabled:
                cache_key = self._hash_features(scaled)
                self._shap_cache[cache_key] = result
                if len(self._shap_cache) > 1000:  # Prevent unbounded cache growth
                    logger.warning("SHAP cache exceeded 1000 entries - clearing")
                    self._shap_cache.clear()
            
            return result

        except (ValueError, KeyError, RuntimeError) as exc:
            # Specific exceptions for validation/computation errors, not generic Exception
            logger.warning(f"SHAP explanation failed ({type(exc).__name__}): {exc}")
            # Ensure cleanup even on exception
            gc.collect()
            return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    
    def _hash_features(self, scaled: np.ndarray) -> str:
        """Hash feature vector for caching (optional)."""
        return hashlib.md5(scaled.tobytes()).hexdigest()

    def _scale_features(self, flow: dict[str, Any]) -> np.ndarray:
        """
        Build a scaled feature vector from a validated flow dict.
        
        CRITICAL: Validates that ALL required features are present.
        Raises ValueError if any feature is missing (no silent zero-filling).
        
        Args:
            flow: Network flow dict with NUMERIC_FEATURES keys
            
        Returns:
            Scaled feature vector ready for model prediction
            
        Raises:
            ValueError: If required features are missing
        """
        # Strict validation: Check ALL required features are present
        missing_features = [f for f in config.NUMERIC_FEATURES if f not in flow]
        
        if missing_features:
            logger.error(f"\nFEATURE VALIDATION ERROR:")
            logger.error(f"Missing {len(missing_features)} required features in flow:")
            for f in sorted(missing_features)[:5]:
                logger.error(f"  - {f}")
            if len(missing_features) > 5:
                logger.error(f"  ... and {len(missing_features) - 5} more")
            logger.error(f"\nExpected features: {len(config.NUMERIC_FEATURES)}")
            logger.error(f"Provided features: {len(flow)}")
            raise ValueError(
                f"Cannot predict: Missing {len(missing_features)} required features. "
                f"All {len(config.NUMERIC_FEATURES)} features must be provided. "
                f"Check request schema: {missing_features[:3]}..."
            )
        
        # Extract feature values in the correct order (no silent defaults)
        values = []
        for feature in config.NUMERIC_FEATURES:
            value = flow[feature]  # Will raise KeyError if missing (should never happen after validation above)
            try:
                values.append(float(value))
            except (TypeError, ValueError) as e:
                logger.error(f"Feature '{feature}' has invalid value: {value} (type: {type(value).__name__})")
                raise ValueError(f"Feature '{feature}' must be numeric, got {type(value).__name__}")
        
        # Build DataFrame for scaler
        df = pd.DataFrame([values], columns=config.NUMERIC_FEATURES)
        
        # Transform with scaler (optional - trees are scale-invariant)
        if self._scaler is not None:
            scaled = self._scaler.transform(df)
            logger.debug(f"✓ Features scaled: {len(config.NUMERIC_FEATURES)} features from flow")
        else:
            scaled = df.values
            logger.debug(f"✓ Using raw features (no scaling): {len(config.NUMERIC_FEATURES)} features")
        return scaled
    
    def clear_cache(self) -> None:
        """Clear SHAP explanation cache (call if memory pressure detected)."""
        self._shap_cache.clear()
        gc.collect()
        logger.info("SHAP cache cleared")


# Module-level singleton — imported by app.py
inference_service = InferenceService()
