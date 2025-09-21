# YARA Rules for Chime Insighter

A curated collection of YARA rules gathered, designed for use with **Chime Insighter** to detect. Note, malwares/ & virus/ are from public Internet sources.

- 🔍 **Information Leakage** (e.g., API keys, credentials, secrets)
- 🦠 **Malware Signatures**
- ☣️ **Viruses & Exploits**

These rules enhance Insighter’s static and dynamic analysis capabilities by providing pattern-based detection for sensitive data exposure and known malicious code.

---

## 📁 Structure


License & Attribution
Most of these rules are collected from open Internet sources (GitHub, YARA repositories, threat intel feeds, etc.).
All rules remain under their original licenses.

Before commercial or redistribution use, please:

✅ Review each rule’s header for license & attribution requirements
✅ Comply with original author’s terms (many are MIT/BSD, some require credit)
✅ Do not claim ownership of third-party rules
ℹ️ This repository does not modify or relicense any rule — it is a collection for convenience and integration. 

Contribute
Found a useful public YARA rule? Submit a PR or open an Issue!

→ We prioritize rules with clear licenses and real-world detection value.

📌 Note
This rule set is not exhaustive. For enterprise use, consider:

Adding organization-specific rules in custom/
Integrating commercial threat feeds
Enabling Insighter’s ML-based anomaly detection for zero-day coverage