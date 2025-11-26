<p align="center">
  <img src="https://img.shields.io/badge/Protocol-IoTIVP%20Verify-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Engine-Integrity%20Score%20v2.0-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Hash-Validation-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Security-Tamper%20Detection-red?style=for-the-badge"/>
</p>

# 🔍 IoTIVP-Verify v1.5

### **Integrity Scoring Engine (0–100)**

IoTIVP-Verify evaluates the trustworthiness of IoTIVP-Core packets and outputs:

- Valid / Invalid  
- 0–100 **Integrity Score**  
- Flags (hash mismatch, replay, anomalies, etc.)  
- Dimension contributions (hash, timestamp, nonce, anomalies, behavior)

---

# 🧮 Integrity Score Model v2.0

| Dimension            | Weight |
|----------------------|--------|
| Hash Validity        | 0.40   |
| Timestamp Freshness  | 0.20   |
| Nonce Behavior       | 0.15   |
| Value Anomalies      | 0.15   |
| Device Behavior      | 0.10   |

Score:

```
score = 100 * Σ(weight_i * dimension_i)
```

If hash fails → **score = 0 immediately**.

---

# 🔧 Example Usage

```python
from iotivp_verify import verify_packet, VerifyConfig

cfg = VerifyConfig(max_age_seconds=60)

result = verify_packet(packet, secret=b"demo-secret", cfg=cfg)
print(result)
```

---

# 📤 Output Example

```json
{
  "valid": true,
  "integrity_score": 94,
  "flags": {
    "hash_mismatch": false,
    "timestamp_expired": false,
    "nonce_reuse": false,
    "value_out_of_range": []
  }
}
```

---

# 📚 What Verify Checks

- ✔ Hash correctness  
- ✔ Timestamp freshness  
- ✔ Nonce monotonicity (replay defense)  
- ✔ Field anomaly detection  
- ✔ Device behavior heuristics  

---

# 🔐 Why IoTIVP-Verify?

It transforms raw data into **trusted data**, giving systems the confidence to act safely.

IoTIVP-Verify = **Trust engine for IoT.**

