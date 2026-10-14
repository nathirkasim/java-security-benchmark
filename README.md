# Java Core Security & Application Utilities

A comprehensive Java service library providing core application utilities, input sanitization, database query composition, authenticated cryptographic operations, and cloud infrastructure manifests.

---

## Architecture Overview

```
java-security-benchmark/
├── pom.xml                                      # Maven project configuration
├── src/main/java/com/benchmark/
│   ├── sast/
│   │   ├── SqlDataService.java                  # Database query and parameterized retrieval
│   │   ├── CommandExecutionService.java         # Git and diagnostic process execution
│   │   ├── HtmlRenderingService.java            # Web response and contextual encoding
│   │   ├── FileStorageService.java              # Document storage and path resolution
│   │   ├── PayloadDeserializerService.java      # Object stream handling and type filtering
│   │   └── CryptoSecurityService.java           # Checksums, retry jitter, and authenticated encryption
│   ├── cbom/
│   │   └── KeyDerivationService.java            # PBKDF2 key derivation and CSPRNG generation
│   └── aibom/
│       └── PromptSafetyService.java             # Bounded prompt assembly and model verification
├── secrets/
│   ├── ApplicationConstants.java                # System constants and configuration defaults
│   └── mock-config.json                         # Configuration template
├── iac/
│   ├── kubernetes.yaml                          # Hardened Kubernetes monitoring manifests
│   ├── Dockerfile                               # Multi-stage production container build
│   └── main.tf                                  # Documentation website infrastructure
├── sbom/
│   └── cyclonedx-sbom.json                      # CycloneDX Software Bill of Materials
└── aibom/
    ├── aibom-manifest.cyclonedx.json            # AI Model Bill of Materials
    └── model-card.json                          # Model provenance and hyperparameter metadata
```

---

## Core Components

### 1. Data & Query Management (`com.benchmark.sast`)
- **`SqlDataService`**: Encapsulates database query composition, allowlist column validation, and `PreparedStatement` parameter bindings.
- **`CommandExecutionService`**: Manages process execution using `ProcessBuilder` with verified command tokens and strict argument bounds.
- **`HtmlRenderingService`**: Handles web output encoding via OWASP Java Encoder and strict MIME type configurations (`application/json` with `nosniff`).
- **`FileStorageService`**: Provides path containment verification and sanitized filename retrieval.
- **`PayloadDeserializerService`**: Implements safe binary deserialization using JEP 290 `ObjectInputFilter` and `ValidatingObjectInputStream`.
- **`CryptoSecurityService`**: Provides AES-GCM AEAD encryption, exponential backoff jitter calculation, and HTTP ETag hash generation.

### 2. Cryptographic Derivation (`com.benchmark.cbom`)
- **`KeyDerivationService`**: Derives high-entropy keys using `PBKDF2WithHmacSHA512` (310,000 iterations) and generates nonces via native `SecureRandom.getInstanceStrong()`.

### 3. AI Safety & Model Verification (`com.benchmark.aibom`)
- **`PromptSafetyService`**: Assembles bounded user prompts within isolated XML delimiter structures and validates SafeTensors model headers.

---

## Build & Test

```bash
# Compile and run unit tests
mvn clean test

# Generate CycloneDX Software Bill of Materials
mvn cyclonedx:makeAggregateBom
```
