# IoTIVP-Verify v1.5  
**Internet of Things Integrity Verification Protocol — Verification Engine**

IoTIVP-Verify is the **integrity engine** of the IoTIVP ecosystem.

It takes decoded IoTIVP-Core packets (or decoded IoTIVP-Binary packets mapped to Core format),  
validates them, and produces a **trust score from 0–100** plus a detailed verdict.

This engine is designed to be used by:

- Gateways  
- n8n nodes  
- Cloud functions  
- Robotics controllers  
- Dashboards and analytics pipelines  

---

## 1. Role in the IoTIVP Ecosystem

IoTIVP-Verify sits between the decoding layer and the application layer:

```text
+------------------------------------------------------------+
|                    Applications / Dashboards               |
+------------------------------------------------------------+
|                  IoTIVP-Verify Engine v1.5                 |
+------------------------------------------------------------+
|      IoTIVP-Core JSON (from gateway or IoTIVP-Binary)      |
+------------------------------------------------------------+
|       IoTIVP-Binary v1.0 (wire packets from devices)       |
+------------------------------------------------------------+
|           Device Firmware (ESP32, LoRa, BLE, Robots)       |
+------------------------------------------------------------+
```

**Inputs:**  A single IoTIVP-Core JSON packet  
**Outputs:** A normalized verification result + Integrity Score v2.0  

---

## 2. Input Packet Format (IoTIVP-Core)

IoTIVP-Verify expects packets in the **Core JSON structure**, e.g.:

```json
{
  "header": 1,
  "timestamp": 1732212000,
  "device_id": 42,
  "nonce": 77,
  "fields": {
    "temperature": 23.5,
    "humidity": 60,
    "battery": 91
  },
  "hash": "baf24977"
}
```

The gateway or decoder is responsible for:

- Parsing IoTIVP-Binary  
- Mapping TLV → field names  
- Constructing this Core JSON payload  

---

## 3. Output Format (Verification Result)

IoTIVP-Verify produces a structured result like:

```json
{
  "valid": true,
  "integrity_score": 94,
  "dimensions": {
    "hash_validity": 1.0,
    "timestamp_validity": 0.9,
    "nonce_behavior": 1.0,
    "value_anomalies": 0.9,
    "device_behavior": 0.8
  },
  "weights": {
    "hash_validity": 0.40,
    "timestamp_validity": 0.20,
    "nonce_behavior": 0.15,
    "value_anomalies": 0.15,
    "device_behavior": 0.10
  },
  "flags": {
    "hash_mismatch": false,
    "timestamp_expired": false,
    "nonce_reuse": false,
    "value_out_of_range": [],
    "device_suspicious": false
  }
}
```

- `integrity_score` is 0–100  
- `dimensions` are normalized 0–1  
- `flags` describe what went wrong (if anything)

---

## 4. Integrity Score v2.0 Model

The score is made up of **five dimensions**:

| Dimension           | Weight | Description                          |
|---------------------|--------|--------------------------------------|
| `hash_validity`     | 0.40   | Is the hash correct?                 |
| `timestamp_validity`| 0.20   | Is the packet fresh in time window?  |
| `nonce_behavior`    | 0.15   | Replay detection / monotonicity      |
| `value_anomalies`   | 0.15   | Are field values plausible?          |
| `device_behavior`   | 0.10   | Frequency, stability, expected usage |

Final score:

```text
integrity_score = 100 * Σ(weight_i * dimension_i)
```

If **hash is invalid**, the engine can immediately drop the score to `0` and mark `valid = false`.

---

## 5. Reference Implementation (Python)

The reference engine is provided as a Python module:

Create a file named:

`iotivp_verify.py`

```python
import time
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import hashlib


@dataclass
class VerifyConfig:
    """
    Configuration for IoTIVP-Verify v1.5
    """
    # Time window in seconds for "fresh" packets
    max_age_seconds: int = 60

    # Hash settings (must match IoTIVP-Core / IoTIVP-Binary settings)
    hash_alg: str = "blake2s"
    hash_len: int = 4

    # Weightings for Integrity Score v2.0
    w_hash_validity: float = 0.40
    w_timestamp_validity: float = 0.20
    w_nonce_behavior: float = 0.15
    w_value_anomalies: float = 0.15
    w_device_behavior: float = 0.10

    # Simple field ranges for anomaly checking (optional)
    field_ranges: Dict[str, Dict[str, float]] = None

    # Known last nonce per device, if you want in-memory replay detection
    # This can be managed externally (e.g., Redis, DB, or injected map).
    last_nonce_map: Optional[Dict[Any, Any]] = None


def _compute_core_hash(packet: Dict[str, Any], secret: bytes, cfg: VerifyConfig) -> str:
    """
    Recompute the IoTIVP-Core hash from a packet.
    Must match iotivp_core_hash rules.
    """
    header = packet["header"]
    timestamp = packet["timestamp"]
    device_id = packet["device_id"]
    nonce = packet.get("nonce")
    fields = packet["fields"]

    sorted_items = sorted(fields.items(), key=lambda x: x[0])

    hash_input = (
        str(header) +
        str(timestamp) +
        str(device_id)
    )

    for k, v in sorted_items:
        hash_input += f"{k}:{v}"

    if nonce is not None:
        hash_input += str(nonce)

    hash_input += secret.decode()

    if cfg.hash_alg == "blake2s":
        digest = hashlib.blake2s(hash_input.encode()).digest()
    elif cfg.hash_alg == "sha256":
        digest = hashlib.sha256(hash_input.encode()).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {cfg.hash_alg}")

    return digest[:cfg.hash_len].hex()


def verify_packet(
    packet: Dict[str, Any],
    secret: bytes,
    cfg: Optional[VerifyConfig] = None,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Verify an IoTIVP-Core packet and compute Integrity Score v2.0.

    Args:
        packet: IoTIVP-Core JSON dict.
        secret: Shared secret used in hash computation.
        cfg: VerifyConfig (optional).
        now: Override current time (for tests). Defaults to time.time().

    Returns:
        dict with:
          - valid: bool
          - integrity_score: float 0–100
          - dimensions: { hash_validity, timestamp_validity, ... }
          - flags: { hash_mismatch, timestamp_expired, ... }
    """
    if cfg is None:
        cfg = VerifyConfig()

    if cfg.field_ranges is None:
        cfg.field_ranges = {}

    if cfg.last_nonce_map is None:
        cfg.last_nonce_map = {}

    if now is None:
        now = int(time.time())

    device_id = packet["device_id"]
    timestamp = packet["timestamp"]
    received_hash = packet.get("hash", "")
    nonce = packet.get("nonce")

    flags = {
        "hash_mismatch": False,
        "timestamp_expired": False,
        "nonce_reuse": False,
        "value_out_of_range": [],
        "device_suspicious": False
    }

    # 1) Hash validity
    try:
        computed_hash = _compute_core_hash(packet, secret, cfg)
        hash_validity = 1.0 if computed_hash == received_hash else 0.0
        if hash_validity == 0.0:
            flags["hash_mismatch"] = True
    except Exception:
        hash_validity = 0.0
        flags["hash_mismatch"] = True

    # 2) Timestamp validity
    age = now - timestamp
    if age < 0:
        # Allow slight negative? For now treat as invalid
        timestamp_validity = 0.0
        flags["timestamp_expired"] = True
    else:
        if age <= cfg.max_age_seconds:
            timestamp_validity = 1.0
        else:
            # linearly degrade after window (simple model)
            # e.g. up to 2 * max_age → down to 0
            if age >= 2 * cfg.max_age_seconds:
                timestamp_validity = 0.0
            else:
                timestamp_validity = (2 * cfg.max_age_seconds - age) / cfg.max_age_seconds
            flags["timestamp_expired"] = True

    # 3) Nonce behavior (basic replay check)
    last_nonce = cfg.last_nonce_map.get(device_id)
    if nonce is None:
        nonce_behavior = 0.5  # neutral if no nonce used
    else:
        if last_nonce is not None and nonce <= last_nonce:
            nonce_behavior = 0.0
            flags["nonce_reuse"] = True
        else:
            nonce_behavior = 1.0
        cfg.last_nonce_map[device_id] = nonce

    # 4) Value anomalies (range-based check)
    fields = packet["fields"]
    value_out_of_range: List[str] = []
    for name, value in fields.items():
        if name in cfg.field_ranges:
            min_v = cfg.field_ranges[name].get("min", None)
            max_v = cfg.field_ranges[name].get("max", None)
            try:
                v = float(value)
            except Exception:
                # Non-numeric where numeric expected → anomaly
                value_out_of_range.append(name)
                continue

            if min_v is not None and v < min_v:
                value_out_of_range.append(name)
            elif max_v is not None and v > max_v:
                value_out_of_range.append(name)

    if len(value_out_of_range) == 0:
        value_anomalies = 1.0
    else:
        value_anomalies = max(0.0, 1.0 - 0.25 * len(value_out_of_range))
        flags["value_out_of_range"] = value_out_of_range

    # 5) Device behavior (placeholder for advanced logic)
    # For v1.5 reference, we treat device behavior as neutral (1.0)
    # You can plug in frequency checks, battery curves, etc.
    device_behavior = 1.0

    # Compute weighted score
    dim = {
        "hash_validity": hash_validity,
        "timestamp_validity": timestamp_validity,
        "nonce_behavior": nonce_behavior,
        "value_anomalies": value_anomalies,
        "device_behavior": device_behavior,
    }

    score = (
        cfg.w_hash_validity * dim["hash_validity"] +
        cfg.w_timestamp_validity * dim["timestamp_validity"] +
        cfg.w_nonce_behavior * dim["nonce_behavior"] +
        cfg.w_value_anomalies * dim["value_anomalies"] +
        cfg.w_device_behavior * dim["device_behavior"]
    ) * 100.0

    # Hard drop if hash fails
    if hash_validity == 0.0:
        score = 0.0

    valid = (score >= 70.0) and (hash_validity == 1.0)

    return {
        "valid": valid,
        "integrity_score": round(score, 2),
        "dimensions": dim,
        "weights": {
            "hash_validity": cfg.w_hash_validity,
            "timestamp_validity": cfg.w_timestamp_validity,
            "nonce_behavior": cfg.w_nonce_behavior,
            "value_anomalies": cfg.w_value_anomalies,
            "device_behavior": cfg.w_device_behavior,
        },
        "flags": flags,
    }
```

---

## 6. Simple Usage Example

Create a test file:

`test_verify.py`

```python
from iotivp_verify import VerifyConfig, verify_packet

# Example secret used for hashing
secret = b"demo-secret"

packet = {
    "header": 1,
    "timestamp": 1732212000,
    "device_id": 42,
    "nonce": 10,
    "fields": {
        "temperature": 23.5,
        "humidity": 60,
        "battery": 91
    },
    "hash": ""  # we'll fill this with the correct value or test a mismatch
}

# For a real test, you should compute the correct hash using iotivp_core_hash,
# but for now this demonstrates structure.
cfg = VerifyConfig(
    max_age_seconds=60,
    field_ranges={
        "temperature": {"min": -40, "max": 85},
        "humidity": {"min": 0, "max": 100},
        "battery": {"min": 0, "max": 100},
    }
)

result = verify_packet(packet, secret, cfg)
print(result)
```

In a real environment:

- The gateway decodes IoTIVP-Binary → IoTIVP-Core JSON  
- The gateway computes and/or checks `hash`  
- Then passes the JSON to `verify_packet()`  

---

## 7. Integration Targets

IoTIVP-Verify is designed to be imported by:

- **Gateway scripts** (Binary → Core → Verify)  
- **n8n custom node** (IoTIVP Verify Node)  
- **Cloud functions** (AWS Lambda, GCP Cloud Functions, etc.)  
- **Robotics controllers** (check every packet before acting)  

---

## 8. Versioning

- IoTIVP-Verify v1.5 — you are here  
- Integrated with IoTIVP-Core v1.5  
- Compatible with IoTIVP-Binary v1.0  

---

IoTIVP-Verify v1.5 is the **trust engine**  
that turns raw sensor data into **scored, defensible telemetry**.
