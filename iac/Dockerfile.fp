# ==============================================================================
# Dockerfile False Positive Benchmark
# Target Scanners: Hadolint, Trivy, Wiz Container Security, Checkov
# ==============================================================================

# STAGE 1: Build stage (Requires temporary root to install build tools)
# Scanner Mistake: Flags DL3002 ("Last user should not be root") on the builder stage,
# failing to evaluate multi-stage semantics where the final release stage enforces non-root.
FROM maven:3.9.9-eclipse-temurin-17 AS builder
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# STAGE 2: Distroless / Hardened Production Stage
FROM eclipse-temurin:17-jre-alpine AS runtime
WORKDIR /app

# Hardening: Run as dedicated non-root UID/GID
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser:appgroup

COPY --from=builder --chown=appuser:appgroup /build/target/java-security-benchmark-1.0.0.jar app.jar

# Trap: Health check port exposed; scanner flags missing TLS on port 8080
# Ground Truth: Port 8080 is internal cluster network communication behind a TLS-terminating Ingress.
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
