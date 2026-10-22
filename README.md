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

### 4. AWS CodeArtifact Private Packages (`com.benchmark.security`)
- **`security-audit-logger`**: Enterprise security audit logger providing CRLF log injection neutralization (CWE-117), structured JSON serialization, and in-memory event tracking.
- **`security-token-validator`**: Cryptographic token signing and constant-time HMAC-SHA256 signature verification service (CWE-208 protection against timing attacks).
- **`PrivatePackageIntegrationService`**: Production integration bridging secure token issuance/validation with real-time audit event logging.

---

## AWS CodeArtifact Setup & Publishing

To create the AWS CodeArtifact domain/repository and publish the private packages:

```bash
# Automated setup and deployment of private packages using AWS CLI & Maven
./scripts/setup-and-publish-artifacts.sh
```

### Manual AWS CLI Commands

```bash
# 1. Create domain and repository
aws codeartifact create-domain --domain benchmark-domain --region us-east-1
aws codeartifact create-repository --domain benchmark-domain --repository benchmark-repo --region us-east-1

# 2. Retrieve endpoint and authorization token
REPO_ENDPOINT=$(aws codeartifact get-repository-endpoint \
    --domain benchmark-domain --repository benchmark-repo --format maven --region us-east-1 --query repositoryEndpoint --output text)
CODEARTIFACT_AUTH_TOKEN=$(aws codeartifact get-authorization-token \
    --domain benchmark-domain --region us-east-1 --query authorizationToken --output text)

# 3. List published packages in CodeArtifact
aws codeartifact list-packages --domain benchmark-domain --repository benchmark-repo --region us-east-1
```

---

## Build & Test

```bash
# Fetch authorization token and compile/test against AWS CodeArtifact packages
export CODEARTIFACT_AUTH_TOKEN=$(aws codeartifact get-authorization-token --domain benchmark-domain --region us-east-1 --query authorizationToken --output text)
mvn clean test

# Generate CycloneDX Software Bill of Materials
mvn cyclonedx:makeAggregateBom
```
