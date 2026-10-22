#!/usr/bin/env bash
set -euo pipefail

DOMAIN="benchmark-domain"
REPO="benchmark-repo"
REGION="us-east-1"
ACCOUNT_ID="589498925148"
VERSION="1.1.0"

echo "=========================================================="
echo " AWS CodeArtifact Setup & Vulnerable Package Publishing"
echo "=========================================================="

# 1. Verify AWS Identity
echo "[1/7] Verifying AWS Identity..."
aws sts get-caller-identity --region "$REGION"

# 2. Ensure CodeArtifact Domain exists
echo "[2/7] Checking CodeArtifact Domain '${DOMAIN}'..."
if ! aws codeartifact describe-domain --domain "$DOMAIN" --region "$REGION" >/dev/null 2>&1; then
    echo "Creating domain '${DOMAIN}'..."
    aws codeartifact create-domain --domain "$DOMAIN" --region "$REGION"
else
    echo "Domain '${DOMAIN}' is active."
fi

# 3. Ensure CodeArtifact Repository exists
echo "[3/7] Checking CodeArtifact Repository '${REPO}'..."
if ! aws codeartifact describe-repository --domain "$DOMAIN" --repository "$REPO" --region "$REGION" >/dev/null 2>&1; then
    echo "Creating repository '${REPO}' in domain '${DOMAIN}'..."
    aws codeartifact create-repository --domain "$DOMAIN" --repository "$REPO" \
        --description "Private repository for security benchmark packages" --region "$REGION"
else
    echo "Repository '${REPO}' is active."
fi

# 4. Get Repository Endpoint and Authorization Token
echo "[4/7] Retrieving CodeArtifact Endpoint and Authorization Token..."
REPO_ENDPOINT=$(aws codeartifact get-repository-endpoint \
    --domain "$DOMAIN" \
    --domain-owner "$ACCOUNT_ID" \
    --repository "$REPO" \
    --format maven \
    --region "$REGION" \
    --query repositoryEndpoint \
    --output text)

echo "Repository Endpoint: ${REPO_ENDPOINT}"

CODEARTIFACT_AUTH_TOKEN=$(aws codeartifact get-authorization-token \
    --domain "$DOMAIN" \
    --domain-owner "$ACCOUNT_ID" \
    --region "$REGION" \
    --query authorizationToken \
    --output text)

export CODEARTIFACT_AUTH_TOKEN

# 5. Configure ~/.m2/settings.xml for Maven Authentication
echo "[5/7] Configuring ~/.m2/settings.xml for CodeArtifact repository authentication..."
mkdir -p ~/.m2
cat << EOF > ~/.m2/settings.xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                              https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    <server>
      <id>benchmark-codeartifact</id>
      <username>aws</username>
      <password>\${env.CODEARTIFACT_AUTH_TOKEN}</password>
    </server>
  </servers>
</settings>
EOF

# 6. Build and Deploy Packages
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[6/7] Building and Publishing Private Maven Packages to CodeArtifact (version ${VERSION})..."

# Package 1: security-audit-logger
echo "Building security-audit-logger ${VERSION}..."
(cd "${WORKSPACE_ROOT}/packages/security-audit-logger" && mvn clean package -DskipTests)

echo "Deploying security-audit-logger:${VERSION} to CodeArtifact..."
mvn -s ~/.m2/settings.xml deploy:deploy-file \
    -Dfile="${WORKSPACE_ROOT}/packages/security-audit-logger/target/security-audit-logger-${VERSION}.jar" \
    -DpomFile="${WORKSPACE_ROOT}/packages/security-audit-logger/pom.xml" \
    -DrepositoryId=benchmark-codeartifact \
    -Durl="${REPO_ENDPOINT}"

# Package 2: security-token-validator
echo "Building security-token-validator ${VERSION}..."
(cd "${WORKSPACE_ROOT}/packages/security-token-validator" && mvn clean package -DskipTests)

echo "Deploying security-token-validator:${VERSION} to CodeArtifact..."
mvn -s ~/.m2/settings.xml deploy:deploy-file \
    -Dfile="${WORKSPACE_ROOT}/packages/security-token-validator/target/security-token-validator-${VERSION}.jar" \
    -DpomFile="${WORKSPACE_ROOT}/packages/security-token-validator/pom.xml" \
    -DrepositoryId=benchmark-codeartifact \
    -Durl="${REPO_ENDPOINT}"

# Publish generic package assets using AWS CLI publish-package-version
echo "Publishing generic assets via AWS CLI publish-package-version..."
AUDIT_SHA256=$(sha256sum "${WORKSPACE_ROOT}/packages/security-audit-logger/target/security-audit-logger-${VERSION}.jar" | awk '{print $1}')
aws codeartifact publish-package-version \
    --domain "$DOMAIN" \
    --repository "$REPO" \
    --format generic \
    --namespace "com.benchmark.security" \
    --package "security-audit-bundle" \
    --package-version "${VERSION}" \
    --asset-content "${WORKSPACE_ROOT}/packages/security-audit-logger/target/security-audit-logger-${VERSION}.jar" \
    --asset-name "security-audit-logger-${VERSION}.jar" \
    --asset-sha256 "$AUDIT_SHA256" \
    --region "$REGION" >/dev/null

TOKEN_SHA256=$(sha256sum "${WORKSPACE_ROOT}/packages/security-token-validator/target/security-token-validator-${VERSION}.jar" | awk '{print $1}')
aws codeartifact publish-package-version \
    --domain "$DOMAIN" \
    --repository "$REPO" \
    --format generic \
    --namespace "com.benchmark.security" \
    --package "security-token-bundle" \
    --package-version "${VERSION}" \
    --asset-content "${WORKSPACE_ROOT}/packages/security-token-validator/target/security-token-validator-${VERSION}.jar" \
    --asset-name "security-token-validator-${VERSION}.jar" \
    --asset-sha256 "$TOKEN_SHA256" \
    --region "$REGION" >/dev/null

# 7. List Published Packages in CodeArtifact
echo "[7/7] Verifying Published Packages in CodeArtifact..."
aws codeartifact list-packages --domain "$DOMAIN" --repository "$REPO" --region "$REGION"

echo "=========================================================="
echo " Successfully published version ${VERSION} to AWS CodeArtifact!"
echo "=========================================================="
