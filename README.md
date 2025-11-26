<p align="center">
  <img src="https://img.shields.io/badge/Protocol-IoTIVP%20Verify-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Engine-Integrity%20Score%20v2.0-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Security-Tamper%20Detection-red?style=for-the-badge"/>
</p>

# 🔍 IoTIVP-Verify v1.5  
### **Integrity Scoring Engine (0–100)**

IoTIVP-Verify evaluates IoTIVP-Core packets to determine:

- 🔒 Valid / Invalid  
- 📊 Integrity Score (0–100)  
- 🚩 Flags (hash mismatch, replay, anomalies, etc.)  
- 🔎 Behavior-level insights  

---

# 📈 Integrity Score Formula v2.0

| Dimension            | Weight |
|----------------------|--------|
| Hash Validity        | 0.40   |
| Timestamp Freshness  | 0.20   |
| Nonce Behavior       | 0.15   |
| Value Anomalies      | 0.15   |
| Device Behavior      | 0.10   |

If hash fails → **score = 0 immediately.**

---

# 🔧 Python Example

```python
from iotivp_verify import verify_packet, VerifyConfig

cfg = VerifyConfig(max_age_seconds=60)

result = verify_packet(
    packet_json,
    secret=b"demo-secret",
    cfg=cfg
)

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

# 🧩 What Verify Checks

- ✔ Hash correctness  
- ✔ Timestamp expiration  
- ✔ Nonce replay detection  
- ✔ Field anomaly detection  
- ✔ Device behavior deviation  

---

**IoTIVP-Verify converts raw sensor data into **trusted intelligence**.**
