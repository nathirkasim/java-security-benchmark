# Java Security Scanner False Positive Benchmark Suite

A specialized Java benchmark suite architected to test and benchmark security scanners (such as **SonarQube**, **Wiz**, **Snyk**, **Semgrep**, **Checkmarx**, **Trivy**, and **Gitleaks**) for **False Positive (FP) resilience** across **SAST**, **SCA**, **IaC**, **Secrets**, **SBOM**, **CBOM**, and **AIBOM**.

---

## 🎯 Purpose

Many commercial and open-source scanners use naive regular expressions or basic AST keyword searches rather than semantic taint analysis or environment-aware context. This benchmark contains safe, production-grade patterns that frequently trigger inaccurate alerts, allowing teams to determine whether a security scanner produces legitimate findings or noisy false positives.

---

## 📂 Architecture Overview

```
java-security-benchmark/
├── pom.xml                                      # SCA & SBOM build traps
├── src/
│   ├── main/java/com/benchmark/falsepositives/
│   │   ├── sast/
│   │   │   ├── SqlInjectionFalsePositives.java      # SAST SQLi FP traps
│   │   │   ├── CommandInjectionFalsePositives.java  # SAST Command Exec FP traps
│   │   │   ├── XssFalsePositives.java               # SAST Reflected XSS FP traps
│   │   │   ├── PathTraversalFalsePositives.java     # SAST Path Traversal FP traps
│   │   │   ├── DeserializationFalsePositives.java   # SAST Deserialization FP traps
│   │   │   └── CryptoFalsePositives.java            # SAST Crypto & PRNG FP traps
│   │   ├── cbom/
│   │   │   └── CbomAuditCases.java                  # Cryptography BOM (CBOM) traps
│   │   └── aibom/
│   │       └── AiBomAndPromptSafety.java            # AIBOM & LLM prompt safety traps
│   └── test/java/com/benchmark/falsepositives/
│       └── TestFixturesAndMocks.java                # Unit test fixtures
├── secrets/
│   ├── FalsePositiveSecrets.java                    # Secret scanner FP traps
│   └── mock-config.json                             # Config fixture FP traps
├── iac/
│   ├── kubernetes-fp.yaml                           # Kubernetes manifest FP traps
│   ├── Dockerfile.fp                                # Multi-stage Dockerfile FP traps
│   └── terraform-fp.tf                              # Terraform S3 public website FP trap
├── sbom/
│   └── cyclonedx-sbom.json                          # CycloneDX SBOM component traps
└── aibom/
    ├── aibom-manifest.cyclonedx.json                # CycloneDX 1.6 AI/ML model BOM trap
    └── model-card.json                              # SafeTensors Model Card metadata
```

---

## 🔬 Benchmark Scenarios by Domain

### 1. SAST (Static Application Security Testing)

| Class & Method | Challenged Rule (SonarQube / Wiz / Semgrep) | Naive Scanner Mistake | Ground Truth (Why it is a False Positive) |
|---|---|---|---|
| `SqlInjectionFalsePositives.queryWithConstantConcatenation` | SonarQube `java:S2077`<br>Wiz `SQL_Injection` | Flags string concatenation (`+`) in SQL queries. | **False Positive:** All concatenated operands are compile-time static string constants. |
| `SqlInjectionFalsePositives.queryWithAllowlistedSort` | SonarQube `java:S2077`<br>CWE-89 | Flags variable in dynamic `ORDER BY`. | **False Positive:** Column name is strictly validated against an immutable `Set.of("id", "username", "created_at")`. |
| `SqlInjectionFalsePositives.queryByPrimitiveId` | SonarQube `java:S2077` | Flags string concatenation of variable. | **False Positive:** Parameter is a 64-bit signed primitive `long`, which cannot contain SQL syntax or escape characters. |
| `CommandInjectionFalsePositives.executeGitRevParse` | SonarQube `java:S2076`<br>Wiz `Command_Injection` | Flags `ProcessBuilder` with external arguments. | **False Positive:** Arguments are passed as individual array elements invoking direct `execve` without `/bin/sh`. Shell metacharacters are not interpreted. |
| `CommandInjectionFalsePositives.runDiagnosticUtility` | SonarQube `java:S2076` | Flags dynamic command token. | **False Positive:** Command executable is resolved strictly from a fixed, hardcoded Enum. Target host is validated by alphanumeric regex. |
| `XssFalsePositives.renderUserGreeting` | SonarQube `java:S5131`<br>Wiz `Cross_Site_Scripting` | Flags writing input to `response.getWriter()`. | **False Positive:** Input is properly escaped using industry standard `org.owasp.encoder.Encode.forHtml()`. |
| `XssFalsePositives.renderJsonResponse` | SonarQube `java:S5131` | Flags reflecting input parameter in response. | **False Positive:** Content-Type is `application/json` with `X-Content-Type-Options: nosniff`. Browsers will not execute HTML/JS. |
| `PathTraversalFalsePositives.readUserReport` | SonarQube `java:S2083`<br>Wiz `Path_Traversal` | Flags `new File(dir, fileName)` with user input. | **False Positive:** `FilenameUtils.getName()` strips all directory components and `../` sequences, leaving only the base filename. |
| `PathTraversalFalsePositives.readSandboxedFile` | SonarQube `java:S2083` | Flags dynamic file path resolution. | **False Positive:** Path is canonicalized and verified with `resolvedPath.startsWith(baseStorageDir)`. |
| `DeserializationFalsePositives.deserializeWithJep290Filter` | SonarQube `java:S5804`<br>Wiz `Insecure_Deserialization` | Flags `ObjectInputStream.readObject()`. | **False Positive:** Standard JEP 290 `ObjectInputFilter` is configured to allow ONLY `SafeDataPayload` and reject all gadgets (`!*`). |
| `CryptoFalsePositives.calculateExponentialBackoffWithJitter` | SonarQube `java:S2245`<br>CWE-338 | Flags `new java.util.Random()` as insecure PRNG. | **False Positive:** PRNG is used solely for network retry jitter (thundering herd mitigation), not for cryptography or tokens. |
| `CryptoFalsePositives.calculateEtagCacheKey` | SonarQube `java:S4790`<br>Wiz `Weak_Hashing` | Flags `MD5` hashing algorithm. | **False Positive:** Used purely for HTTP ETag content-caching / deduplication, not for digital signatures or passwords. |
| `CryptoFalsePositives.encryptWithAuthenticatedAesGcm` | SonarQube `java:S5542`<br>CWE-780 | Naive regex flags `"NoPadding"` as unpadded cipher. | **False Positive:** AES-GCM (Galois/Counter Mode) provides AEAD authenticated encryption; counter mode requires no PKCS padding by specification. |

---

### 2. SCA (Software Composition Analysis) & Dependencies

| Manifest Traps (`pom.xml`) | Challenged Scanner Logic | Ground Truth (Why it is a False Positive) |
|---|---|---|
| **Test-Scope Library (`junit:junit:4.12`)** | Scanners mapping CVE-2020-15250 as a production vulnerability. | **False Positive:** Scoped strictly as `<scope>test</scope>`. Never packaged into the deployable production artifact. |
| **Provided Scope (`javax.servlet:javax.servlet-api:3.1.0`)** | Scanners flagging servlet vulnerabilities in distributed binary. | **False Positive:** Scoped as `<scope>provided</scope>`. Supplied by runtime application container (e.g. Tomcat/Jetty), not packaged. |
| **Excluded Transitive Dep (`spring-boot-starter-logging`)** | Scanners flagging vulnerabilities in `log4j-to-slf4j`. | **False Positive:** Transitive artifact is explicitly excluded in `pom.xml` via `<exclusions>`. |
| **Compile-Only Annotation Processor (`lombok:1.18.24`)** | Scanners listing Lombok in runtime inventory. | **False Positive:** Scoped as `<scope>provided</scope>` with `<optional>true</optional>`. Stripped during compilation. |

---

### 3. SECRETS (Secret Scanning)

| Location (`secrets/`) | Challenged Rule (Gitleaks / TruffleHog / Wiz) | Ground Truth (Why it is a False Positive) |
|---|---|---|
| `FalsePositiveSecrets.EMPTY_FILE_SHA256` | Generic high-entropy hex string detector. | **False Positive:** Standard SHA-256 hash of an empty file (`e3b0c44298fc...`) used as a test constant. |
| `FalsePositiveSecrets.INLINE_1PX_TRANSPARENT_GIF_BASE64` | Base64 high-entropy token detector. | **False Positive:** Static 1x1 transparent GIF image asset encoded in Base64. |
| `FalsePositiveSecrets.PASSWORD_RESET_REDIRECT_URI` | Regex matching `password\s*=\s*['"][^'"]+['"]`. | **False Positive:** Variable name contains "password", but the value is a public OAuth redirect URI. |
| `FalsePositiveSecrets.AWS_DOCUMENTATION_EXAMPLE_KEY` | Rule matching AWS key format `AKIA[0-9A-Z]{16}`. | **False Positive:** Canonical AWS documentation example placeholder (`AKIAIOSFODNN7EXAMPLE`). |

---

### 4. IaC (Infrastructure as Code)

| Manifest (`iac/`) | Challenged Rule (Trivy / Checkov / Wiz IaC) | Ground Truth (Why it is a False Positive) |
|---|---|---|
| `kubernetes-fp.yaml` (DaemonSet `hostPath`) | Trivy `KSV-0023` ("hostPath volumes must be forbidden"). | **Contextual False Positive:** Node logging daemon (`node-log-collector`) functionally requires `/var/log` access. Mount is strictly `readOnly: true`. |
| `kubernetes-fp.yaml` (ConfigMap `key: val`) | Trivy `KSV-01010` ("Sensitive content stored in ConfigMap"). | **False Positive:** Dict key is named `metric_routing_key`. Contains no confidential credentials or emails. |
| `kubernetes-fp.yaml` (Namespace `LimitRange`) | Trivy `KSV-0011` / `KSV-0018` ("Container CPU/memory limits not set"). | **False Positive:** Container inherits default limits and requests from namespace `LimitRange` automatically. |
| `Dockerfile.fp` (Multi-stage build) | Hadolint `DL3002` ("Last user should not be root"). | **False Positive:** Root is used only in builder stage. The final runtime image runs as unprivileged `appuser:appgroup`. |
| `terraform-fp.tf` (S3 public website) | Checkov `CKV_AWS_20` ("S3 Bucket public access block disabled"). | **Intentional Architecture:** Bucket is provisioned explicitly for static public documentation website hosting. |

---

### 5. SBOM (Software Bill of Materials) & Inventory

| Manifest (`sbom/cyclonedx-sbom.json`) | Challenged SBOM Analyzer Logic | Ground Truth (Why it is a False Positive) |
|---|---|---|
| **Component `junit:4.12` marked `scope: excluded`** | Vulnerability scanners alerting on CVEs in SBOM without checking component scope. | **False Positive:** Declared as non-runtime excluded test harness. |
| **Component `com.internal.fintech:token-authenticator`** | Scanners matching only artifact ID `token-authenticator` against public registries. | **False Positive (Namespace Collision):** Internal proprietary artifact falsely matched to unrelated public packages. |

---

### 6. CBOM (Cryptography Bill of Materials)

| Class & Method (`cbom/`) | Challenged CBOM Logic | Ground Truth (Why it is a False Positive) |
|---|---|---|
| `CbomAuditCases.deriveKeyWithHardenedPbkdf2` | CBOM scanners flagging PBKDF2 as legacy/deprecated. | **False Positive:** Configured with 310,000 iterations using HMAC-SHA512, fully adhering to modern OWASP / NIST SP 800-132. |
| `CbomAuditCases.generateCryptographicNonce` | Scanners auditing secure random entropy sources. | **False Positive:** Explicitly uses native OS-provided strong entropy via `SecureRandom.getInstanceStrong()`. |

---

### 7. AIBOM & LLM Security

| Manifest & Class (`aibom/`) | Challenged AI Security Rule | Ground Truth (Why it is a False Positive) |
|---|---|---|
| `AiBomAndPromptSafety.buildDefendedPrompt` | Wiz / Lakera / Protect AI "LLM01: Prompt Injection". | **False Positive:** Prompt incorporates pre-execution regex guardrails, escapes structural delimiter tags, and uses bounded XML enclosures. |
| `AiBomAndPromptSafety.verifyModelFormatHeader` & `aibom-manifest.cyclonedx.json` | Scanners flagging binary model weights as "CWE-502 / Pickle Deserialization". | **False Positive:** Model weights use SafeTensors format (header length + JSON offsets). SafeTensors cannot execute code. |

---

## 🚀 Running the Benchmark

```bash
# 1. Verify clean Java 11 compilation and unit tests
mvn clean test

# 2. Run your SAST scanner (e.g. SonarQube, Semgrep)
semgrep scan --config auto .

# 3. Run your Secret scanner (e.g. Gitleaks, TruffleHog)
gitleaks detect --source . --verbose

# 4. Run your IaC scanner (e.g. Trivy, Checkov)
trivy config iac/

# 5. Run your SCA scanner (e.g. Snyk, Trivy)
trivy fs --scanners vuln .
```

### Calculating False Positive Rate (FPR)
$$\text{False Positive Rate (FPR)} = \frac{\text{Reported Benchmark Alerts}}{\text{Total Benchmark Trap Scenarios (25)}}$$
* A **perfect scanner** with semantic context awareness will report **0 alerts** on this benchmark suite.
* A **naive scanner** relying on basic regex matching will trigger **20+ false positive alerts**.
