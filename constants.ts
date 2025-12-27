import { ModuleItem, SDLCPhase } from './types';
import { Shield, Box, Server, Activity } from 'lucide-react';

export const NEWS_SYSTEM_INSTRUCTION = `
You are a Cyber Threat Intelligence Analyst for Container Environments.
Your goal is to provide a brief, high-impact "Live Security Update" for a specific topic.
Focus on:
1. Recent high-profile CVEs (within the last 12-18 months) related to the topic.
2. Emerging tools or shifts in industry standards (e.g., new CIS benchmarks, deprecations in K8s).
3. Real-world incidents or "In the Wild" attacks relevant to this domain.
Keep it concise, news-oriented, and actionable. Use bullet points.
`;

export const DEFAULT_GIT_CONFIG = {
  token: '',
  owner: '',
  repo: '',
  path: 'container-security-progress.json',
  branch: 'main'
};

const CURRICULUM_EN: ModuleItem[] = [
  {
    id: 'base-images',
    title: 'Minimal & Distroless Images',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Reducing attack surface with Alpine, Wolfi, and Distroless.',
    staticContent: `
### The "Good Way" to Manage Base Images

Security starts with the base image. The "Good Way" is to **decouple the Build environment from the Runtime environment**. Reducing the attack surface isn't just about size; it's about removing tools that attackers use (shells, package managers, network tools).

#### 1. The "Good Time": Build vs Runtime

*   **Build Time**: You need compilers (\`gcc\`, \`go\`), build tools (\`make\`, \`maven\`, \`npm\`), and header files. These are **heavy** and **dangerous** in production.
*   **Runtime**: You only need your compiled binary (or bytecode) and the OS dependencies (glibc/musl). You do *not* need a shell (\`/bin/bash\`), package manager (\`apt\`, \`apk\`), or \`curl\`.

#### 2. The Golden Rule: Multi-Stage Builds

Never ship your build tools to production. Use multi-stage builds to strictly separate these two phases in a single Dockerfile.

\`\`\`dockerfile
# --- Stage 1: Build (The "Factory") ---
# We use a fat image with all necessary tools
FROM golang:1.21 AS builder
WORKDIR /src
COPY . .
# We build a static binary (self-contained)
RUN CGO_ENABLED=0 go build -o my-app main.go

# --- Stage 2: Runtime (The "Product") ---
# We use Distroless: No shell, no package manager, just the app
FROM gcr.io/distroless/static-debian12
COPY --from=builder /src/my-app /
# Security: Always run as non-root (Distroless provides this user)
USER nonroot:nonroot
CMD ["/my-app"]
\`\`\`

#### 3. Choosing the Right Flavor (Wolfi vs Distroless vs Alpine)

| Type | Best For | Pros | Cons |
| :--- | :--- | :--- | :--- |
| **Distroless** (Google) | Go, Rust, Java, Python | Zero bloat, **No Shell** (Max Security). | Hard to debug (requires \`kubectl debug\`). |
| **Wolfi** (Chainguard) | Modern Cloud Native | **Zero CVE** focus, granular packages, SBOM native. | Newer ecosystem, different package repo. |
| **Alpine** | Node.js, PHP, General | Tiny (~5MB), has \`apk\` and \`sh\`. | Uses \`musl\` libc (can cause DNS/Performance issues). |
| **Debian Slim** | Legacy Apps | Maximum compatibility (glibc). | Still contains \`apt\`/\`dpkg\` (larger attack surface). |

#### 4. Managing Vulnerabilities (The "Zero CVE" Goal)

*   **The Problem**: Old stable images (Debian 11) rarely update packages, leading to "noise" from unpatched, low-severity CVEs.
*   **The Solution**: Use **Wolfi** (or Chainguard Images). It is an "undistro" designed specifically for containers that releases daily updates, aiming for **Zero CVEs** by default, making your scanners green and alerts meaningful.
    `,
    newsContext: 'Docker Hardened Images (DHI) release, SLSA Level 3 adoption, and the shift towards distroless/hardened base images by default.',
    securityTip: 'Update: Use **Docker Scout** (GA Dec 2023) to analyze base images. It provides deeper insights than traditional scanners by correlating CVEs with your specific application usage.'
  },
  {
    id: 'secure-architecture',
    title: 'Secure Architecture',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Threat modeling, isolation, and Zero Trust principles.',
    staticContent: `
### Secure by Design

Security cannot be "bolted on" at the end. It must be architected from the start using **Zero Trust** principles.

#### Key Architectural Patterns

1.  **Namespace Isolation**: Treat Namespaces as soft tenancy boundaries. Use \`ResourceQuotas\` and \`LimitRanges\` to prevent noisy neighbor attacks.
2.  **Least Privilege**: Apps should only talk to necessary services. Assume the network is hostile.
3.  **Identity Awareness**: Use Workload Identity (OIDC) instead of long-lived static credentials.

#### STRIDE Threat Modeling for Containers

*   **S**poofing: Can a rogue pod impersonate a legitimate service? (Solution: mTLS)
*   **T**ampering: Can the container image be modified? (Solution: Immutable tags & Signing)
*   **R**epudiation: Are logs persistent? (Solution: Centralized logging)
*   **I**nformation Disclosure: Are secrets exposed? (Solution: External Secrets/Vault)
*   **D**enial of Service: Can one pod crash the node? (Solution: Limits & Requests)
*   **E**levation of Privilege: Can a container escape to host? (Solution: no-new-privs, non-root)
    `,
    newsContext: 'New architectural patterns in Kubernetes 1.29+, updates to "Zero Trust" definitions by NIST/CISA regarding containers.',
    securityTip: 'Architecture Tip: Design for **Isolation**. Kubernetes 1.28+ introduced native support for SidecarContainers, ensuring security sidecars start *before* your main application.'
  },
  {
    id: 'metadata-testing-design',
    title: 'Metadata & Testing Strategy',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Labeling standards, non-regression, and security gates.',
    staticContent: `
### Designing for Governance & Verification

Before writing code, establish the "Contract" for your containers. This includes how they are identified (Labels) and how their security is verified (Testing Strategy).

#### 1. Kubernetes Labeling Standards
Labels are the primary grouping mechanism in K8s. A consistent taxonomy is vital for Network Policies, Reporting, and Automation.

**Recommended Standard Labels (kubernetes.io):**
\`\`\`yaml
metadata:
  labels:
    app.kubernetes.io/name: my-app
    app.kubernetes.io/instance: my-app-prod
    app.kubernetes.io/version: "1.2.0"
    app.kubernetes.io/component: database
    app.kubernetes.io/part-of: billing-system
    app.kubernetes.io/managed-by: helm
\`\`\`

**Security Labels:**
*   \`data-classification: restricted\` (Used by Policy engines to enforce encryption).
*   \`compliance: pci-dss\` (triggers specific audit logs).
*   \`owner: team-security\` (Contact point for incidents).

#### 2. Security Testing Strategy
Security testing must be automated to prevent **Regression** (re-introducing fixed vulnerabilities).

| Test Type | Phase | Tool Example | Goal |
| :--- | :--- | :--- | :--- |
| **Linting** | Design/Dev | \`kube-linter\`, \`hadolint\` | Check YAML/Dockerfile syntax & best practices. |
| **Policy Unit Tests** | Design/Build | \`opa test\` | **Non-regression** for Policy-as-Code. Ensure a policy change doesn't accidentally allow root containers. |
| **SAST** | Build | \`semgrep\` | Find code flaws. |
| **DAST** | Staging | \`owasp-zap\` | Attack running app. |

#### 3. Designing Non-Regression
When a security bug is found:
1.  Fix the bug.
2.  Write a **Negative Test Case** (e.g., a "bad" manifest that *should* fail validation).
3.  Add it to the CI suite.
    `,
    newsContext: 'Updates to Kubernetes Recommended Labels, trends in "Policy Testing" (Rego unit testing), and best practices for non-regression in IaC.',
    securityTip: 'Governance: Enforce the presence of the `owner` label using an Admission Controller. If a pod crashes or triggers an alert, you immediately know who to page.'
  },
  {
    id: 'threat-modeling',
    title: 'Threat Modeling Fundamentals',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Deep dive into STRIDE and risk analysis.',
    staticContent: `
### Systematic Risk Analysis

Threat modeling is the process of identifying, enumerating, and prioritizing potential threats. We use the **STRIDE** methodology to systematically analyze container architectures.

#### STRIDE in Detail for Kubernetes

| Threat | Definition | Container Context | Mitigation |
| :--- | :--- | :--- | :--- |
| **S**poofing | Impersonating something or someone. | A rogue pod claims the IP of a DB service. | **mTLS** (Istio/Linkerd), Network Policies. |
| **T**ampering | Modifying data or code. | Injecting malware into a base image. | **Image Signing** (Cosign), Read-only Root FS. |
| **R**epudiation | Claiming not to have performed an action. | A developer \`kubectl delete\`s a deployment without logs. | **Audit Logs**, Remote logging (Fluentd/Splunk). |
| **I**nformation Disclosure | Exposing information to unauthorized users. | Leaking secrets in ENV vars or logs. | **External Secrets**, Encryption at Rest. |
| **D**enial of Service | Denying service to valid users. | A container consumes 100% CPU, starving others. | **Resource Quotas**, LimitRanges. |
| **E**levation of Privilege | Gaining capabilities without authorization. | Container escape to host (privilege escalation). | **Pod Security Standards** (Restricted), Seccomp. |

#### Data Flow Diagrams (DFD)
To apply STRIDE effectively, create a DFD of your cluster:
1.  **External Entities**: Users, CI/CD systems.
2.  **Processes**: Pods, Deployments, Operators.
3.  **Data Stores**: Persistent Volumes, ConfigMaps, Secrets, Databases.
4.  **Data Flows**: Network traffic (Ingress/Egress).
5.  **Trust Boundaries**: Namespace boundaries, Cluster perimeter.

*Apply STRIDE to every element crossing a Trust Boundary.*
    `,
    newsContext: 'Evolution of threat modeling tools (OWASP Threat Dragon), new automated threat modeling for cloud-native applications, and shifts in the threat landscape.',
    securityTip: 'Modeling Tip: When modeling AI/ML containers, explicitly add **Model Poisoning** (Tampering) and **Inference API Exhaustion** (DoS) to your STRIDE analysis.'
  },
  {
    id: 'data-compliance',
    title: 'Data Compliance & Sovereignty',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'GDPR, Data Residency patterns, and Encryption.',
    staticContent: `
### Privacy & Compliance by Design

For regulated industries (Finance, Healthcare, Gov), where code runs and where data lives is a legal requirement, not just technical.

#### Data Sovereignty Patterns (Node Affinity)
To ensure data never leaves a specific jurisdiction (e.g., "Germany Only" for GDPR), use **Node Affinity**.

\`\`\`yaml
apiVersion: v1
kind: Pod
metadata:
  name: gdpr-compliant-db
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: region
            operator: In
            values:
            - eu-central-1
\`\`\`

#### Encryption Standards
*   **At Rest**: Use KMS plugins to encrypt Secrets in etcd. Ensure Persistent Volumes (PVs) are encrypted by the storage provider.
*   **In Transit**: Enforce TLS 1.2+ everywhere. Use Service Mesh (Istio/Linkerd) to transparently upgrade TCP to mTLS.
    `,
    newsContext: 'Updates on GDPR fines related to cloud data, PCI-DSS v4.0 container requirements, and "Sovereign Cloud" architectural trends.',
    securityTip: 'Compliance: Use **Open Policy Agent (OPA)** to technically enforce residency. Deny Pod creation if the `nodeSelector` does not match the allowed region.'
  },
  {
    id: 'supply-chain',
    title: 'Supply Chain (SLSA)',
    phase: SDLCPhase.BUILD,
    shortDesc: 'Image signing, SBOMs, and the SLSA framework.',
    staticContent: `
### Securing the Software Supply Chain

An attacker doesn't need to hack your production server if they can hack your build server.

#### The SLSA Framework
**Supply-chain Levels for Software Artifacts (SLSA)** helps protect against tampering.
*   **Level 1**: Provenance exists (scripted build).
*   **Level 2**: Hosted build service + authenticated provenance.
*   **Level 3**: Hardened build platform (ephemeral environments).

#### Tools of the Trade
*   **SBOM (Software Bill of Materials)**: A list of ingredients. Tools: \`syft\`, \`trivy\`.
*   **Signing**: Cryptographically proving the author. Tools: \`cosign\`, \`notary\`.

\`\`\`bash
# Generating an SBOM
syft packages:alpine:latest -o json > sbom.json

# Signing an image with Cosign
cosign sign --key cosign.key my-registry/my-image:v1.0.0
\`\`\`
    `,
    newsContext: 'Recent supply chain attacks (like xz utils backdoor), updates to the SLSA specification, and adoption of SBOMs in government regulation.',
    securityTip: 'Tooling Update: Use `docker buildx build --attest type=provenance,mode=max` to automatically generate detailed **SLSA provenance** attestations attached to your image.'
  },
  {
    id: 'build-strategies',
    title: 'Secure Build Strategies',
    phase: SDLCPhase.BUILD,
    shortDesc: 'Safe CI/CD, secret avoidance, and deterministic builds.',
    staticContent: `
### Hardening the Build Process

The build environment is often highly privileged (access to secrets, registries, source code).

#### Best Practices

1.  **Avoid Secrets in Layers**: Never run \`COPY id_rsa .\` or \`ENV PASSWORD=...\`. Use build-time secret mounting.
2.  **Pin Base Images**: Do not use \`:latest\`. Use SHA256 digests for immutability.
    *   *Bad*: \`FROM node:latest\`
    *   *Good*: \`FROM node@sha256:4c2e...\`
3.  **Reproducible Builds**: Ensuring the same source code always produces the exact same binary bit-for-bit.

#### Secure Secret Mounting (BuildKit)
\`\`\`dockerfile
# Syntax to safely mount a secret that does not persist in the final image layer
RUN --mount=type=secret,id=mysecret \
    cat /run/secrets/mysecret && \
    ./script-requiring-secret.sh
\`\`\`
    `,
    newsContext: 'New features in Docker BuildKit, security risks in CI/CD pipelines (GitHub Actions runners), and "Leaky Vessels" vulnerabilities.',
    securityTip: 'Optimization: Consider **Docker Build Cloud** (released 2024) to ensure builds run in a consistent, ephemeral, and secure environment, avoiding "works on my machine" security drifts.'
  },
  {
    id: 'multi-stage-lifecycle',
    title: 'Multi-Stage Lifecycle',
    phase: SDLCPhase.BUILD,
    shortDesc: 'Unifying Dev, Test (Recette), and Prod in one Dockerfile.',
    staticContent: `
### One Dockerfile, Three Environments

Multi-stage builds are not just for shrinking images. They allow you to define your entire Software Development Life Cycle (SDLC) — **Dev, Test/Recette, and Prod** — within a single file.

#### 1. "Début" (Development Stage)
In the development stage, we need hot-reloading, debuggers, and full SDKs. We target this stage locally.

\`\`\`dockerfile
# Base Stage (Common dependencies)
FROM node:20-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Stage: Development
# Includes tools like nodemon and full devDependencies
FROM base AS dev
RUN npm install -g nodemon
COPY . .
CMD ["nodemon", "server.js"]
\`\`\`

#### 2. "Recette" (Testing Stage)
Before building the artifact, we run tests inside the container. If this stage fails, the image build stops.

\`\`\`dockerfile
# Stage: Tester (Recette)
FROM base AS tester
COPY . .
# Run linting and unit tests inside the build process
RUN npm run lint
RUN npm run test
\`\`\`

#### 3. "Déploiement" (Production Stage)
Finally, we create the lean, secure artifact. We copy *only* what is needed from previous stages.

\`\`\`dockerfile
# Stage: Production (Déploiement)
FROM gcr.io/distroless/nodejs20-debian11 AS prod
WORKDIR /app
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/package.json ./
COPY --from=base /app/server.js ./
CMD ["server.js"]
\`\`\`

#### Usage
*   **For Dev:** \`docker build --target dev -t myapp:dev .\`
*   **For CI/Recette:** \`docker build --target tester .\`
*   **For Prod:** \`docker build --target prod -t myapp:prod .\`
    `,
    newsContext: 'Adoption of "Hermetic Builds" where testing happens strictly inside containers to avoid "works on my machine" issues.',
    securityTip: 'Isolation: By running tests (Recette) in a separate stage, test secrets, test data, and test-runner code are never copied into the final Production image.'
  },
  {
    id: 'security-testing',
    title: 'Code & Dependency Scanning',
    phase: SDLCPhase.BUILD,
    shortDesc: 'SAST, SCA, and Image Vulnerability Testing.',
    staticContent: `
### Shift Left: Automated Security Testing

Detecting vulnerabilities during the Build phase is significantly cheaper and safer than finding them in Production.

#### 1. Static Application Security Testing (SAST)
**"White Box" Testing**: Analyzes source code for security flaws without running it.
*   **Detects**: SQL Injection, XSS, Buffer Overflows, Hardcoded Credentials.
*   **Tools**: SonarQube, CodeQL, Semgrep.

#### 2. Software Composition Analysis (SCA)
**"Supply Chain" Testing**: Analyzes open-source libraries and frameworks imported by your code.
*   **Detects**: Known CVEs in \`node_modules\`, \`pip\`, \`go.mod\`.
*   **Tools**: Snyk, OWASP Dependency Check, Trivy.

#### 3. Container Image Scanning
Scans the compiled container image (Base OS + App Layers).

#### Real-World CI/CD Integration

**Scenario A: GitHub Actions with Trivy**
This workflow builds an image and fails the pipeline if **CRITICAL** vulnerabilities are found.

\`\`\`yaml
name: Build and Scan
on: [push]
jobs:
  build-secure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker Image
        run: docker build -t myapp:\${{ github.sha }} .

      - name: Run Trivy Vulnerability Scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:\${{ github.sha }}'
          format: 'table'
          # FAIL the build on Critical issues
          exit-code: '1'
          ignore-unfixed: true
          severity: 'CRITICAL,HIGH'
\`\`\`

**Scenario B: GitLab CI with Grype**
Using Anchore Grype to scan an image within a GitLab pipeline.

\`\`\`yaml
security_scan:
  stage: test
  image: docker:stable
  services:
    - docker:dind
  before_script:
    # Install Grype
    - apk add curl
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - docker build -t myapp:$CI_COMMIT_SHA .
    # Scan and FAIL on Critical severity
    - grype myapp:$CI_COMMIT_SHA --fail-on critical
\`\`\`
    `,
    newsContext: 'Rise of AI-powered SAST tools, new regulations requiring SCA analysis (SBOM usage), and "Reachability Analysis" in modern scanners.',
    securityTip: 'Optimisation: Use **Reachability Analysis** (available in tools like Snyk or Endor Labs). It distinguishes between a vulnerable library you *installed* vs. one you actually *call* in code, reducing noise by 80%.'
  },
  {
    id: 'deployment-config',
    title: 'Pod Security Standards',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'Enforcing Restricted/Baseline profiles via PSS/PSA.',
    staticContent: `
### Kubernetes Pod Security Standards (PSS)

Kubernetes has deprecated \`PodSecurityPolicies\` (PSP) in favor of the built-in **Pod Security Admission (PSA)** controller.

#### The Three Profiles
1.  **Privileged**: Unrestricted (Avoid using this).
2.  **Baseline**: Minimally restrictive policy which prevents known privilege escalations.
3.  **Restricted**: Heavily restricted, following current hardening best practices.

#### Enforcing via Namespace Labels
You can enforce these standards simply by labeling your namespace:

\`\`\`yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-secure-app
  labels:
    # Enforce the restricted standard
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    # Warn on baseline violations
    pod-security.kubernetes.io/warn: baseline
\`\`\`
    `,
    newsContext: 'Adoption rates of PSS "Restricted" profile, common pitfalls migrating from PSP, and updates in Kubernetes 1.30 regarding admission control.',
    securityTip: 'Hardening: Always set `automountServiceAccountToken: false` in your PodSpec unless the pod explicitly needs to talk to the Kubernetes API.'
  },
  {
    id: 'secrets-management',
    title: 'Secrets Management',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'External Secrets Operator, Vault, and CSI.',
    staticContent: `
### Managing Secrets at Scale

Native Kubernetes Secrets store data in \`etcd\` encoded in **base64**, which is not encryption. Anyone with API access can read them.

#### The "External" Pattern
Instead of storing secrets in Git (GitOps anti-pattern) or manually creating them, use an operator to sync from a dedicated Vault.

**External Secrets Operator (ESO)**:
1.  Connects to AWS Secrets Manager, Azure Key Vault, HashiCorp Vault.
2.  Polles for changes.
3.  Creates/Updates a native K8s \`Secret\` object for the pod to consume.

#### Best Practice: Volume Mounts
Mount secrets as files (tmpfs) rather than Environment Variables. Env vars can be leaked via crash dumps or \`proc\` file system.

### ConfigMaps vs Secrets

While often used together, they serve different purposes:

*   **ConfigMap**: Designed for non-sensitive configuration data (e.g., config files, environment variables). Stored in plain text in etcd.
*   **Secret**: Designed for sensitive data (e.g., passwords, OAuth tokens, SSH keys). Stored as base64-encoded strings in etcd.

#### Kubernetes Secrets Best Practices

1.  **Encryption at Rest**: By default, secrets are stored unencrypted in etcd. Enable **Encryption Configuration** in Kubernetes to encrypt secrets at rest using a provider (like a KMS plugin).
2.  **RBAC**: Restrict \`get\`, \`list\`, and \`watch\` permissions on Secrets. Only specific controllers or operators should have broad access.
3.  **Immutable Secrets**: Use \`immutable: true\` for stable secrets to protect against accidental updates and improve performance.

### GitOps & Secrets Management

In GitOps, the git repository is the source of truth. However, **never commit raw Kubernetes Secrets to Git**.

#### Strategy 1: Encrypted Secrets in Git
Tools like **Sealed Secrets** or **SOPS** allow you to store encrypted data in Git, which is decrypted only inside the cluster.

*   **Bitnami Sealed Secrets**: Uses asymmetric encryption. Developers encrypt with a public key (\`kubeseal\`), and the cluster controller decrypts with a private key. Safe to commit the \`SealedSecret\` CRD.
*   **Mozilla SOPS**: Encrypts YAML values using cloud KMS (AWS/GCP/Azure) or PGP. Integrates seamlessly with Flux and ArgoCD.

#### Strategy 2: Reference External Secrets (ESO)
Don't store the secret in Git at all. Store a reference (manifest) that points to the actual secret in a Vault.

*   Commit an \`ExternalSecret\` custom resource to Git.
*   It contains the *pointer* (e.g., "fetch secret \`db-pass\` from AWS Secrets Manager").
*   The operator fetches the value and creates the Kubernetes Secret.
*   *Result*: Git contains no sensitive data, only configuration.

\`\`\`yaml
# Example: ExternalSecret pointing to AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: db-secret-k8s # The K8s secret to be created
  data:
  - secretKey: password
    remoteRef:
      key: production/db/password
\`\`\`
    `,
    newsContext: 'Latest integrations for External Secrets Operator, new attacks targeting etcd encryption, and comparisons of Vault vs Cloud Provider Secret Managers.',
    securityTip: 'Rotation: Implement **automated secret rotation** in your Vault (AWS/HashiCorp). The External Secrets Operator can automatically pick up the new value and restart the Pods.'
  },
  {
    id: 'deployment-gates',
    title: 'Policy as Code (OPA)',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'Admission controllers and deployment gates.',
    staticContent: `
### Policy as Code: The Implementation Guide

Admission Controllers intercept requests to the Kubernetes API server *before* persistence. This is where we enforce the "Contract" defined in Design.

#### 1. The Matrix: Who, Where, When?

| Role | Action | Tool | Location |
| :--- | :--- | :--- | :--- |
| **Security Engineer** | Writes the Policy (Rego/YAML). | OPA / Kyverno | **Git Repository** (Policy Repo) |
| **Platform Engineer** | Installs the Controller & Enforces Policy. | Helm / ArgocD | **K8s Cluster** (Admission Controller) |
| **Developer** | Checks violations locally/CI. | Conftest / Kyverno CLI | **CI Pipeline** (Shift Left) |

#### 2. Step-by-Step Implementation

**Step 1: Define the Policy (The Contract)**
Policies should be treated as code. They live in Git, are versioned, and reviewed.
*   *Example (Rego)*: "All images must come from \`registry.corp.com\`".

\`\`\`rego
# policy/image_registry.rego
package kubernetes.admission
deny[msg] {
  input.request.kind.kind == "Pod"
  image := input.request.object.spec.containers[_].image
  not startswith(image, "registry.corp.com/")
  msg := sprintf("Image '%v' is from an untrusted registry.", [image])
}
\`\`\`

**Step 2: Test in CI (The Soft Gate)**
Do not wait for deployment to fail. Fail the build in CI/CD using \`conftest\` (for OPA) or \`kyverno apply\` (for Kyverno).

\`\`\`bash
# .gitlab-ci.yml
policy_check:
  stage: test
  image: openpolicyagent/conftest
  script:
    - conftest test --policy policy/ deployment.yaml
\`\`\`

**Step 3: Audit in Cluster (The Dry Run)**
Deploy the policy to Kubernetes in **Warn/Audit** mode first.
*   **OPA Gatekeeper**: Set \`enforcementAction: dryrun\`.
*   **Kyverno**: Set \`validationFailureAction: Audit\`.
*   *Goal*: Monitor logs for a week to see what *would* break. Fix existing violations.

**Step 4: Enforce (The Hard Gate)**
Once logs are clean, switch to **Enforce/Deny**. Now, any non-compliant deployment is rejected by the API Server.

#### 3. Common Policies to Implement

*   **Disallow Root**: Enforce \`runAsNonRoot: true\`.
*   **Require Probes**: Ensure Liveness/Readiness probes exist.
*   **Ownership Labels**: Mandate \`team\` or \`cost-center\` labels.

#### Recommendation: The Safe Rollout
**Never enforce a blocking policy on Day 1.**
1.  **Week 1**: Deploy Policy in \`Audit\` mode.
2.  **Week 2**: Review Splunk/Datadog logs for violations. Contact teams to fix configs.
3.  **Week 3**: Switch to \`Enforce\` mode.
    `,
    newsContext: 'Updates to OPA/Gatekeeper (v3+), the rise of Kyverno, and shifting validation left to the CI pipeline vs the cluster.',
    securityTip: 'Workflow: Use **chain-bench** (by Aquasec) in your pipeline to audit your software supply chain stack against CIS Software Supply Chain benchmarks.'
  },
  {
    id: 'network-policies',
    title: 'Network Segmentation (East-West)',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'Securing traffic flow in OpenShift with Microsegmentation.',
    staticContent: `
### OpenShift Network Policies: The Cluster Firewall

By default, OpenShift (like stock Kubernetes) utilizes a **flat network** model. This means every Pod can communicate with every other Pod in the cluster, across all projects (namespaces), unless isolated by the CNI.

#### 🛑 The Risk: Unchecked East-West Traffic
"East-West" traffic refers to communication *inside* the cluster (Service-to-Service).
*   **Bad Practice**: A flat network where the \`Frontend\` can talk directly to the \`Database\`, but also to the \`Payment-Service\` and the \`Admin-Dashboard\`.
*   **Attack Scenario**: If the Frontend is compromised (e.g., via Log4Shell), the attacker has a direct line to probe the database or internal admin panels.

*(See the interactive visualization above)*

#### ✅ The Solution: Microsegmentation
We use \`NetworkPolicies\` to create a "Zero Trust" network inside the cluster.

**Step 1: The Default Deny (The "Firewall")**
Apply this policy to every Project (Namespace) to block all incoming traffic by default. This forces you to explicitly allow what is needed.

\`\`\`yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny-all
  namespace: my-project
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  # - Egress (Optional, but recommended for high security)
\`\`\`

**Step 2: Allow Specific Traffic (The "Hole")**
Allow *only* the Frontend to talk to the Backend, and *only* on port 8080.

\`\`\`yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-front-to-back
  namespace: my-project
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
\`\`\`

#### OpenShift Specifics (OVN-Kubernetes)
Modern OpenShift versions use **OVN-Kubernetes** as the default CNI.
*   **Performance**: OVN uses Open vSwitch, which is highly efficient for enforcing these ACLs.
*   **Visualization**: Use the **OpenShift Web Console > Topology** view. When you enable "Network Policy" overlay, you can visually see allowed traffic flows between components.
*   **Multi-Tenancy**: OpenShift offers a \`NetworkPolicy\` mode called \`MultiTenant\` (in older SDN) or strict isolation in OVN. Ensure your project isolation is enabled.
    `,
    newsContext: 'Adoption of Cilium and eBPF for networking in OpenShift, sidecar-less service meshes (Istio Ambient Mesh), and Gateway API security features.',
    securityTip: 'Performance: Utilize **Cilium** (available in OpenShift) with eBPF to enforce policies at the socket layer. This drops denied traffic before it even generates a packet.'
  },
  {
    id: 'observability-sidecars',
    title: 'Sidecars & Secure Debugging',
    phase: SDLCPhase.RUNTIME,
    shortDesc: 'Service Mesh patterns, Sidecars, and Ephemeral Containers.',
    staticContent: `
### Patterns for Observability & Debugging

In a "Secure by Design" environment, production containers are **immutable** and **minimal** (Distroless). They lack shells (\`/bin/sh\`), package managers, and debug tools. This makes them secure but hard to troubleshoot.

#### 1. The Sidecar Pattern (Implementation)
A sidecar is a secondary container in the same Pod. It shares the **Network Namespace** (localhost) and can share **Storage Volumes**.

**Example: Secure Log Shipping**
The application writes logs to a shared volume (never to stdout if sensitive, or strictly structured). The sidecar (Fluentd/Vector) reads, encrypts, and ships them.

\`\`\`yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-sidecar
spec:
  containers:
  # 1. Main Application
  - name: my-app
    image: my-app:1.0 (Distroless)
    volumeMounts:
    - name: logs
      mountPath: /var/log/app
  
  # 2. Sidecar (Log Shipper)
  - name: log-shipper
    image: fluentd:latest
    volumeMounts:
    - name: logs
      mountPath: /var/log/app
      readOnly: true # Security: Sidecar cannot tamper with logs
  
  volumes:
  - name: logs
    emptyDir: {}
\`\`\`

#### 2. Debugging Distroless with Ephemeral Containers
Since you cannot run \`kubectl exec\` on a Distroless image (no shell), you must bring your own shell using **Ephemeral Containers**.

**Feature:** Allows you to add a container to a *running* Pod without restarting it.

**Step-by-Step Debugging:**

1.  **Inject the Debugger**: We attach a "Swiss Army Knife" image (like \`netshoot\`) to the target pod.
2.  **Target the Process Namespace**: Use \`--target\` to see the main container's processes (localhost).

\`\`\`bash
# The "Magic" Command
kubectl debug -it my-secure-pod \\
  --image=nicolaka/netshoot \\
  --target=main-app-container \\
  -- sh

# Inside the debug shell:
netstat -tulpn  # View ports open by the main app
ps aux          # View processes of the main app
tcpdump -i eth0 # Capture traffic
\`\`\`

#### 3. Profiling & Copying
Sometimes you need to analyze files (heap dumps) generated by the crashed app.

\`\`\`bash
# Create a copy of the pod with a debug container attached (for post-mortem)
kubectl debug my-pod -it --image=busybox --share-processes --copy-to=my-debugger-pod
\`\`\`

#### Security Implications
*   **RBAC**: Restrict the \`ephemeralcontainers\` subresource in Role/ClusterRole. Only senior SREs should have this permission.
*   **Policy**: Use Admission Controllers (Kyverno/OPA) to whitelist allowed debug images (e.g., allow \`netshoot\`, deny \`hacker-tool-kit\`).
    `,
    newsContext: 'Rise of "Sidecar-less" service meshes (Istio Ambient), security risks of over-privileged sidecars, and advancements in OpenTelemetry security.',
    securityTip: 'Trend: Sidecar-less meshes (like **Istio Ambient Mesh** or **Cilium Service Mesh**) are reducing attack surface by moving proxy logic to per-node secure agents.'
  },
  {
    id: 'multi-arch-security',
    title: 'Multi-OS & Kernel Isolation',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'gVisor, Kata Containers, and Windows nodes.',
    staticContent: `
### Breaking the Shared Kernel Model

Standard containers share the host Linux kernel. A kernel vulnerability (like Dirty Cow) allows container escape.

#### Sandboxed Containers
For high-risk workloads (running untrusted code), use stronger isolation:

*   **gVisor (Google)**: A userspace kernel shim. Intercepts syscalls. Adds overhead but great security.
*   **Kata Containers**: Runs each pod in a lightweight micro-VM. Hardware-level isolation.

#### Runtime Classes
You can define which isolation technology a pod uses via \`RuntimeClass\`.

\`\`\`yaml
apiVersion: v1
kind: Pod
metadata:
  name: untrusted-workload
spec:
  runtimeClassName: gvisor
  containers:
  - name: app
    image: python-script-executor
\`\`\`
    `,
    newsContext: 'Performance improvements in Kata Containers v3, new WASM (WebAssembly) security models, and Windows container isolation updates.',
    securityTip: 'Recommendation: For running untrusted code (e.g., customer scripts), standard namespaces are insufficient. Mandatory use of **gVisor** or **Kata Containers** is recommended.'
  },
  {
    id: 'runtime-security',
    title: 'Runtime Security (Falco)',
    phase: SDLCPhase.RUNTIME,
    shortDesc: 'Behavioral analysis and anomaly detection.',
    staticContent: `
### Detecting the "Unknown Unknowns"

Static scanning finds vulnerabilities (CVEs). Runtime security finds **attacks** currently happening.

#### Falco & eBPF
Falco monitors kernel system calls in real-time. It can alert on suspicious behavior that static analysis misses.

**Typical Alerts:**
*   A shell (\`bash\`) spawned in a production container.
*   Modification of \`/etc/passwd\`.
*   Outbound connection to a crypto-mining pool IP.
*   Reading sensitive files (certificates/keys).

#### Response
Automated response (via tools like Falco Sidekick) can immediately kill a compromised pod or cordon the node for forensics.
    `,
    newsContext: 'New Falco rules for K8s attacks, evolution of eBPF for security observability, and Tetragon (Cilium) runtime enforcement features.',
    securityTip: 'Enforcement: **Tetragon** (by Isovalent) uses eBPF to transparently enforce runtime policies, capable of killing a process *before* a malicious syscall completes.'
  },
  {
    id: 'confidential-computing',
    title: 'Confidential Computing',
    phase: SDLCPhase.RUNTIME,
    shortDesc: 'Hardware-based protection (TEEs/SGX/SEV).',
    staticContent: `
### Protecting Data in Use

We encrypt data at rest (Disk) and in transit (TLS). But data in RAM is usually cleartext. **Confidential Computing** solves this.

#### Trusted Execution Environments (TEEs)
Hardware features like **Intel SGX**, **AMD SEV**, or **TDX** allow creating "Enclaves".
*   The host OS / Hypervisor cannot read the enclave's memory.
*   Cloud admins cannot read the memory.

#### Use Cases
*   Multi-party computation (banks sharing fraud data without revealing customers).
*   Running AI models on sensitive healthcare data.
*   Key Management Systems (KMS).
    `,
    newsContext: 'Major Cloud Providers (Azure/AWS/GCP) expanding Confidential Computing offerings (Confidential GKE), and attestation services updates.',
    securityTip: 'Adoption: Azure and GCP now offer **Confidential Nodes** for GKE/AKS. Enable this for financial or healthcare workloads to protect data in memory from host compromises.'
  },
];

const CURRICULUM_FR: ModuleItem[] = [
  {
    id: 'base-images',
    title: 'Images Minimales & Distroless',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Réduire la surface d\'attaque avec Alpine, Wolfi et Distroless.',
    staticContent: `
### La "Bonne Façon" de Gérer les Images de Base

La sécurité commence par l'image de base. La "Bonne Façon" est de **découpler l'environnement de Build de l'environnement Runtime**. Réduire la surface d'attaque ne concerne pas seulement la taille; il s'agit de supprimer les outils que les attaquants utilisent (shells, gestionnaires de paquets, curl).

#### 1. Le "Bon Moment": Build vs Runtime

*   **Build Time**: Vous avez besoin de compilateurs (\`gcc\`, \`go\`), d'outils de build (\`make\`, \`maven\`), et de headers. Ils sont **lourds** et **dangereux** en production.
*   **Runtime**: Vous n'avez besoin que de votre binaire (ou bytecode) et des dépendances OS (glibc/musl). Vous n'avez *pas* besoin d'un shell (\`/bin/bash\`), d'un gestionnaire de paquets (\`apt\`, \`apk\`) ou de \`curl\`.

#### 2. La Règle d'Or: Builds Multi-Stage

Ne livrez jamais vos outils de build en production. Utilisez les builds multi-stage pour séparer strictement ces deux phases dans un seul Dockerfile.

\`\`\`dockerfile
# --- Stage 1: Build (L'Usine) ---
# Image complète avec tous les outils nécessaires
FROM golang:1.21 AS builder
WORKDIR /src
COPY . .
# On compile un binaire statique
RUN CGO_ENABLED=0 go build -o my-app main.go

# --- Stage 2: Runtime (Le Produit) ---
# On utilise Distroless: Pas de shell, pas de package manager
FROM gcr.io/distroless/static-debian12
COPY --from=builder /src/my-app /
# Sécurité: Toujours tourner en non-root
USER nonroot:nonroot
CMD ["/my-app"]
\`\`\`

#### 3. Choisir la Bonne Saveur (Wolfi vs Distroless vs Alpine)

| Type | Idéal Pour | Avantages | Inconvénients |
| :--- | :--- | :--- | :--- |
| **Distroless** (Google) | Go, Rust, Java, Python | Zéro bloat, **Pas de Shell** (Sécurité Max). | Difficile à debugger (nécessite \`kubectl debug\`). |
| **Wolfi** (Chainguard) | Cloud Native Moderne | Focus **Zéro CVE**, paquets granulaires, SBOM natif. | Écosystème plus récent. |
| **Alpine** | Node.js, PHP, General | Minuscule (~5MB), a \`apk\` et \`sh\`. | Utilise \`musl\` libc (problèmes DNS/Perf possibles). |
| **Debian Slim** | Apps Legacy | Compatibilité maximale (glibc). | Contient encore \`apt\`/\`dpkg\` (surface d'attaque). |

#### 4. Gérer les Vulnérabilités (Objectif "Zéro CVE")

*   **Le Problème**: Les images stables classiques (Debian 11) mettent rarement à jour les paquets, créant du "bruit" avec des CVEs non corrigées de basse sévérité.
*   **La Solution**: Utilisez **Wolfi** (ou Chainguard Images). C'est une "undistro" conçue pour les conteneurs qui vise le **Zéro CVE** par défaut grâce à des mises à jour quotidiennes.
    `,
    newsContext: 'Sortie des Docker Hardened Images (DHI), adoption de SLSA Niveau 3 et transition vers des images de base distroless/durcies par défaut.',
    securityTip: 'Mise à jour: Utilisez **Docker Scout** (GA Dec 2023) pour analyser vos images de base. Il offre une analyse plus fine que les scanners traditionnels en corrélant les CVEs avec l\'utilisation réelle dans votre application.'
  },
  {
    id: 'secure-architecture',
    title: 'Architecture Sécurisée',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Threat modeling, isolation et principes Zero Trust.',
    staticContent: `
### Secure by Design

La sécurité ne peut pas être "ajoutée" à la fin. Elle doit être architecturée dès le départ en utilisant les principes du **Zero Trust**.

#### Patterns d'Architecture Clés

1.  **Isolation par Namespace**: Traitez les Namespaces comme des frontières de location (soft tenancy). Utilisez \`ResourceQuotas\` et \`LimitRanges\` pour éviter les attaques de type "noisy neighbor".
2.  **Moindre Privilège**: Les apps ne doivent parler qu'aux services nécessaires. Supposez que le réseau est hostile.
3.  **Identité**: Utilisez Workload Identity (OIDC) au lieu de credentials statiques longue durée.

#### Threat Modeling STRIDE pour Conteneurs

*   **S**poofing (Usurpation): Un pod malveillant peut-il se faire passer pour un service légitime ? (Solution: mTLS)
*   **T**ampering (Modification): L'image du conteneur peut-elle être modifiée ? (Solution: Tags Immuables & Signing)
*   **R**epudiation (Répudiation): Les logs sont-ils persistants ? (Solution: Logging Centralisé)
*   **I**nformation Disclosure (Divulgation): Les secrets sont-ils exposés ? (Solution: External Secrets/Vault)
*   **D**enial of Service (Déni de Service): Un pod peut-il crasher le nœud ? (Solution: Limits & Requests)
*   **E**levation of Privilege (Élévation): Un conteneur peut-il s'échapper vers l'hôte ? (Solution: no-new-privs, non-root)
    `,
    newsContext: 'Nouveaux patterns architecturaux dans Kubernetes 1.29+, mises à jour des définitions "Zero Trust" par le NIST/CISA concernant les conteneurs.',
    securityTip: 'Astuce Architecture: Designez pour l\'**Isolation**. Kubernetes 1.28+ a introduit le support natif des SidecarContainers, garantissant que les sidecars de sécurité démarrent *avant* votre application principale.'
  },
  {
    id: 'metadata-testing-design',
    title: 'Métadonnées & Stratégie de Test',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Standards de labeling, non-régression et security gates.',
    staticContent: `
### Designer pour la Gouvernance & la Vérification

Avant d'écrire du code, établissez le "Contrat" pour vos conteneurs. Cela inclut leur identification (Labels) et la vérification de leur sécurité (Stratégie de Test).

#### 1. Standards de Labeling Kubernetes
Les labels sont le mécanisme principal de regroupement dans K8s. Une taxonomie cohérente est vitale pour les Network Policies, le Reporting et l'Automatisation.

**Labels Standards Recommandés (kubernetes.io):**
\`\`\`yaml
metadata:
  labels:
    app.kubernetes.io/name: my-app
    app.kubernetes.io/instance: my-app-prod
    app.kubernetes.io/version: "1.2.0"
    app.kubernetes.io/component: database
    app.kubernetes.io/part-of: billing-system
    app.kubernetes.io/managed-by: helm
\`\`\`

**Labels de Sécurité:**
*   \`data-classification: restricted\` (Utilisé par les moteurs de Policy pour forcer le chiffrement).
*   \`compliance: pci-dss\` (déclenche des logs d'audit spécifiques).
*   \`owner: team-security\` (Point de contact pour les incidents).

#### 2. Stratégie de Test de Sécurité
Les tests de sécurité doivent être automatisés pour prévenir la **Régression** (réintroduction de vulnérabilités corrigées).

| Type de Test | Phase | Exemple d'Outil | Objectif |
| :--- | :--- | :--- | :--- |
| **Linting** | Design/Dev | \`kube-linter\`, \`hadolint\` | Vérifier la syntaxe YAML/Dockerfile & best practices. |
| **Policy Unit Tests** | Design/Build | \`opa test\` | **Non-régression** pour le Policy-as-Code. S'assurer qu'un changement de politique n'autorise pas accidentellement les conteneurs root. |
| **SAST** | Build | \`semgrep\` | Trouver les failles dans le code. |
| **DAST** | Staging | \`owasp-zap\` | Attaquer l'application en cours d'exécution. |

#### 3. Designer la Non-Régression
Lorsqu'un bug de sécurité est trouvé :
1.  Corrigez le bug.
2.  Écrivez un **Cas de Test Négatif** (ex: un "mauvais" manifeste qui *devrait* échouer à la validation).
3.  Ajoutez-le à la suite CI.
    `,
    newsContext: 'Mises à jour des Labels Recommandés Kubernetes, tendances dans le "Policy Testing" (tests unitaires Rego), et best practices pour la non-régression dans l\'IaC.',
    securityTip: 'Gouvernance: Forcez la présence du label `owner` via un Admission Controller. Si un pod crash ou déclenche une alerte, vous savez immédiatement qui contacter.'
  },
  {
    id: 'threat-modeling',
    title: 'Fondamentaux Threat Modeling',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Analyse approfondie STRIDE et risques.',
    staticContent: `
### Analyse Systématique des Risques

Le threat modeling est le processus d'identification, d'énumération et de priorisation des menaces potentielles. Nous utilisons la méthodologie **STRIDE** pour analyser systématiquement les architectures de conteneurs.

#### STRIDE en Détail pour Kubernetes

| Menace | Définition | Contexte Conteneur | Mitigation |
| :--- | :--- | :--- | :--- |
| **S**poofing | Usurper une identité. | Un pod voyou réclame l'IP d'un service DB. | **mTLS** (Istio/Linkerd), Network Policies. |
| **T**ampering | Modifier des données ou du code. | Injection de malware dans une image de base. | **Image Signing** (Cosign), Read-only Root FS. |
| **R**epudiation | Nier avoir effectué une action. | Un développeur fait un \`kubectl delete\` sans logs. | **Audit Logs**, Remote logging (Fluentd/Splunk). |
| **I**nformation Disclosure | Exposer des infos non autorisées. | Fuite de secrets dans les variables d'env ou les logs. | **External Secrets**, Chiffrement "At Rest". |
| **D**enial of Service | Déni de service. | Un conteneur consomme 100% du CPU. | **Resource Quotas**, LimitRanges. |
| **E**levation of Privilege | Gain de capacités non autorisées. | Évasion de conteneur vers l'hôte. | **Pod Security Standards** (Restricted), Seccomp. |

#### Diagrammes de Flux de Données (DFD)
Pour appliquer STRIDE efficacement, créez un DFD de votre cluster :
1.  **Entités Externes**: Utilisateurs, systèmes CI/CD.
2.  **Processus**: Pods, Deployments, Operators.
3.  **Data Stores**: Persistent Volumes, ConfigMaps, Secrets, Bases de données.
4.  **Flux de Données**: Trafic réseau (Ingress/Egress).
5.  **Frontières de Confiance**: Frontières de Namespace, périmètre du Cluster.

*Appliquez STRIDE à chaque élément traversant une Frontière de Confiance.*
    `,
    newsContext: 'Évolution des outils de threat modeling (OWASP Threat Dragon), nouveau threat modeling automatisé pour les applications cloud-native, et changements dans le paysage des menaces.',
    securityTip: 'Conseil Modeling: Lors de la modélisation de conteneurs AI/ML, ajoutez explicitement **Model Poisoning** (Tampering) et **Inference API Exhaustion** (DoS) à votre analyse STRIDE.'
  },
  {
    id: 'data-compliance',
    title: 'Conformité & Souveraineté des Données',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'GDPR, patterns de Résidence des données et Chiffrement.',
    staticContent: `
### Confidentialité & Conformité by Design

Pour les industries régulées (Finance, Santé, Gouv), où le code s'exécute et où les données vivent est une exigence légale, pas seulement technique.

#### Patterns de Souveraineté des Données (Node Affinity)
Pour garantir que les données ne quittent jamais une juridiction spécifique (ex: "Allemagne Uniquement" pour GDPR), utilisez la **Node Affinity**.

\`\`\`yaml
apiVersion: v1
kind: Pod
metadata:
  name: gdpr-compliant-db
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: region
            operator: In
            values:
            - eu-central-1
\`\`\`

#### Standards de Chiffrement
*   **At Rest**: Utilisez des plugins KMS pour chiffrer les Secrets dans etcd. Assurez-vous que les Persistent Volumes (PVs) sont chiffrés par le fournisseur de stockage.
*   **In Transit**: Forcez TLS 1.2+ partout. Utilisez un Service Mesh (Istio/Linkerd) pour upgrader de façon transparente le TCP en mTLS.
    `,
    newsContext: 'Mises à jour sur les amendes GDPR liées aux données cloud, exigences conteneurs PCI-DSS v4.0, et tendances architecturales "Sovereign Cloud".',
    securityTip: 'Conformité: Utilisez **Open Policy Agent (OPA)** pour forcer techniquement la résidence. Bloquez la création de Pod si le `nodeSelector` ne correspond pas à la région autorisée.'
  },
  {
    id: 'supply-chain',
    title: 'Supply Chain (SLSA)',
    phase: SDLCPhase.BUILD,
    shortDesc: 'Signature d\'image, SBOMs et le framework SLSA.',
    staticContent: `
### Sécuriser la Supply Chain Logicielle

Un attaquant n'a pas besoin de pirater votre serveur de production s'il peut pirater votre serveur de build.

#### Le Framework SLSA
**Supply-chain Levels for Software Artifacts (SLSA)** aide à protéger contre la falsification.
*   **Niveau 1**: La provenance existe (build scripté).
*   **Niveau 2**: Service de build hébergé + provenance authentifiée.
*   **Niveau 3**: Plateforme de build durcie (environnements éphémères).

#### Les Outils du Métier
*   **SBOM (Software Bill of Materials)**: Une liste d'ingrédients. Outils: \`syft\`, \`trivy\`.
*   **Signing**: Prouver cryptographiquement l'auteur. Outils: \`cosign\`, \`notary\`.

\`\`\`bash
# Générer un SBOM
syft packages:alpine:latest -o json > sbom.json

# Signer une image avec Cosign
cosign sign --key cosign.key my-registry/my-image:v1.0.0
\`\`\`
    `,
    newsContext: 'Attaques récentes sur la supply chain (comme la backdoor xz utils), mises à jour de la spécification SLSA, et adoption des SBOMs dans la régulation gouvernementale.',
    securityTip: 'Outillage: Utilisez `docker buildx build --attest type=provenance,mode=max` pour générer automatiquement des attestations de **provenance SLSA** détaillées attachées à votre image.'
  },
  {
    id: 'build-strategies',
    title: 'Stratégies de Build Sécurisées',
    phase: SDLCPhase.BUILD,
    shortDesc: 'CI/CD sûr, évitement des secrets et builds déterministes.',
    staticContent: `
### Durcir le Processus de Build

L'environnement de build est souvent hautement privilégié (accès aux secrets, registres, code source).

#### Best Practices

1.  **Éviter les Secrets dans les Layers**: Ne jamais faire \`COPY id_rsa .\` ou \`ENV PASSWORD=...\`. Utilisez le montage de secrets au build-time.
2.  **Pinner les Images de Base**: N'utilisez pas \`:latest\`. Utilisez les digests SHA256 pour l'immuabilité.
    *   *Mauvais*: \`FROM node:latest\`
    *   *Bon*: \`FROM node@sha256:4c2e...\`
3.  **Builds Reproductibles**: S'assurer que le même code source produit toujours exactement le même binaire bit-pour-bit.

#### Montage de Secret Sécurisé (BuildKit)
\`\`\`dockerfile
# Syntaxe pour monter un secret en toute sécurité sans persistance dans l'image finale
RUN --mount=type=secret,id=mysecret \
    cat /run/secrets/mysecret && \
    ./script-requiring-secret.sh
\`\`\`
    `,
    newsContext: 'Nouvelles fonctionnalités dans Docker BuildKit, risques de sécurité dans les pipelines CI/CD (GitHub Actions runners), et vulnérabilités "Leaky Vessels".',
    securityTip: 'Optimisation: Considérez **Docker Build Cloud** (sorti en 2024) pour assurer que les builds s\'exécutent dans un environnement cohérent, éphémère et sécurisé, évitant les dérives de sécurité "ça marche sur ma machine".'
  },
  {
    id: 'multi-stage-lifecycle',
    title: 'Cycle de Vie Multi-Stage',
    phase: SDLCPhase.BUILD,
    shortDesc: 'Unifier Dev, Test (Recette) et Prod dans un seul Dockerfile.',
    staticContent: `
### Un Dockerfile, Trois Environnements

Les builds multi-stage ne servent pas seulement à réduire la taille des images. Ils vous permettent de définir tout votre Cycle de Vie de Développement Logiciel (SDLC) — **Dev, Test/Recette, et Prod** — dans un seul fichier.

#### 1. "Début" (Stage de Développement)
Dans le stage de développement, nous avons besoin du hot-reloading, de debuggers et de SDKs complets. Nous ciblons ce stage localement.

\`\`\`dockerfile
# Base Stage (Dépendances communes)
FROM node:20-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Stage: Development
# Inclut des outils comme nodemon et les devDependencies complètes
FROM base AS dev
RUN npm install -g nodemon
COPY . .
CMD ["nodemon", "server.js"]
\`\`\`

#### 2. "Recette" (Stage de Test)
Avant de construire l'artefact, nous exécutons les tests *dans* le conteneur. Si ce stage échoue, le build de l'image s'arrête.

\`\`\`dockerfile
# Stage: Tester (Recette)
FROM base AS tester
COPY . .
# Exécuter le linting et les tests unitaires dans le processus de build
RUN npm run lint
RUN npm run test
\`\`\`

#### 3. "Déploiement" (Stage de Production)
Enfin, nous créons l'artefact léger et sécurisé. Nous ne copions *que* ce qui est nécessaire depuis les stages précédents.

\`\`\`dockerfile
# Stage: Production (Déploiement)
FROM gcr.io/distroless/nodejs20-debian11 AS prod
WORKDIR /app
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/package.json ./
COPY --from=base /app/server.js ./
CMD ["server.js"]
\`\`\`

#### Utilisation
*   **Pour le Dev:** \`docker build --target dev -t myapp:dev .\`
*   **Pour la CI/Recette:** \`docker build --target tester .\`
*   **Pour la Prod:** \`docker build --target prod -t myapp:prod .\`
    `,
    newsContext: 'Adoption des "Hermetic Builds" où les tests se passent strictement dans les conteneurs pour éviter les problèmes "works on my machine".',
    securityTip: 'Isolation: En exécutant les tests (Recette) dans un stage séparé, les secrets de test, les données de test et le code du test-runner ne sont jamais copiés dans l\'image de Production finale.'
  },
  {
    id: 'security-testing',
    title: 'Scan de Code & Dépendances',
    phase: SDLCPhase.BUILD,
    shortDesc: 'SAST, SCA et Test de Vulnérabilité d\'Image.',
    staticContent: `
### Shift Left: Tests de Sécurité Automatisés

Détecter les vulnérabilités pendant la phase de Build est significativement moins cher et plus sûr que de les trouver en Production.

#### 1. Static Application Security Testing (SAST)
**Test "Boîte Blanche"**: Analyse le code source pour trouver des failles de sécurité sans l'exécuter.
*   **Détecte**: Injections SQL, XSS, Buffer Overflows, Identifiants codés en dur.
*   **Outils**: SonarQube, CodeQL, Semgrep.

#### 2. Software Composition Analysis (SCA)
**Test "Supply Chain"**: Analyse les librairies open-source et frameworks importés par votre code.
*   **Détecte**: CVEs connues dans \`node_modules\`, \`pip\`, \`go.mod\`.
*   **Outils**: Snyk, OWASP Dependency Check, Trivy.

#### 3. Container Image Scanning
Scanne l'image conteneur compilée (OS de base + Layers applicatifs).

#### Intégration CI/CD Réelle

**Scénario A: GitHub Actions avec Trivy**
Ce workflow construit une image et fait échouer le pipeline si des vulnérabilités **CRITICAL** sont trouvées.

\`\`\`yaml
name: Build and Scan
on: [push]
jobs:
  build-secure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker Image
        run: docker build -t myapp:\${{ github.sha }} .

      - name: Run Trivy Vulnerability Scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:\${{ github.sha }}'
          format: 'table'
          # FAIL le build sur les problèmes Critiques
          exit-code: '1'
          ignore-unfixed: true
          severity: 'CRITICAL,HIGH'
\`\`\`

**Scénario B: GitLab CI avec Grype**
Utilisation d'Anchore Grype pour scanner une image dans un pipeline GitLab.

\`\`\`yaml
security_scan:
  stage: test
  image: docker:stable
  services:
    - docker:dind
  before_script:
    # Installer Grype
    - apk add curl
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - docker build -t myapp:$CI_COMMIT_SHA .
    # Scanner et FAIL sur sévérité Critique
    - grype myapp:$CI_COMMIT_SHA --fail-on critical
\`\`\`
    `,
    newsContext: 'Montée des outils SAST pilotés par IA, nouvelles régulations exigeant l\'analyse SCA (usage SBOM), et "Reachability Analysis" dans les scanners modernes.',
    securityTip: 'Optimisation: Utilisez la **Reachability Analysis** (disponible dans des outils comme Snyk ou Endor Labs). Elle distingue une librairie vulnérable que vous avez *installée* d\'une que vous *appelez* réellement dans le code, réduisant le bruit de 80%.'
  },
  {
    id: 'deployment-config',
    title: 'Pod Security Standards',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'Application des profils Restricted/Baseline via PSS/PSA.',
    staticContent: `
### Kubernetes Pod Security Standards (PSS)

Kubernetes a déprécié les \`PodSecurityPolicies\` (PSP) en faveur du contrôleur intégré **Pod Security Admission (PSA)**.

#### Les Trois Profils
1.  **Privileged**: Non restreint (Évitez de l'utiliser).
2.  **Baseline**: Politique minimalement restrictive qui empêche les escalades de privilèges connues.
3.  **Restricted**: Hautement restreint, suivant les meilleures pratiques de durcissement actuelles.

#### Application via Labels de Namespace
Vous pouvez appliquer ces standards simplement en labellisant votre namespace :

\`\`\`yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-secure-app
  labels:
    # Forcer le standard restricted
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    # Avertir sur les violations baseline
    pod-security.kubernetes.io/warn: baseline
\`\`\`
    `,
    newsContext: 'Taux d\'adoption du profil PSS "Restricted", pièges communs lors de la migration depuis PSP, et mises à jour dans Kubernetes 1.30 concernant l\'admission control.',
    securityTip: 'Durcissement: Définissez toujours `automountServiceAccountToken: false` dans votre PodSpec à moins que le pod n\'ait explicitement besoin de parler à l\'API Kubernetes.'
  },
  {
    id: 'secrets-management',
    title: 'Gestion des Secrets',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'External Secrets Operator, Vault et CSI.',
    staticContent: `
### Gérer les Secrets à l'Échelle

Les Secrets Kubernetes natifs stockent les données dans \`etcd\` encodées en **base64**, ce qui n'est pas du chiffrement. Quiconque a accès à l'API peut les lire.

#### Le Pattern "External"
Au lieu de stocker les secrets dans Git (anti-pattern GitOps) ou de les créer manuellement, utilisez un opérateur pour synchroniser depuis un Vault dédié.

**External Secrets Operator (ESO)**:
1.  Se connecte à AWS Secrets Manager, Azure Key Vault, HashiCorp Vault.
2.  Sonde les changements.
3.  Crée/Met à jour un objet \`Secret\` K8s natif pour que le pod le consomme.

#### Best Practice: Montages de Volume
Montez les secrets comme des fichiers (tmpfs) plutôt que comme Variables d'Environnement. Les variables d'env peuvent fuiter via les crash dumps ou le système de fichiers \`proc\`.

### ConfigMaps vs Secrets

Bien que souvent utilisés ensemble, ils servent des objectifs différents :

*   **ConfigMap**: Conçu pour les données de configuration non sensibles (ex: fichiers de config, variables d'env). Stocké en texte clair dans etcd.
*   **Secret**: Conçu pour les données sensibles (ex: mots de passe, tokens OAuth, clés SSH). Stocké en chaînes encodées base64 dans etcd.

#### Best Practices Secrets Kubernetes

1.  **Chiffrement At Rest**: Par défaut, les secrets sont stockés non chiffrés dans etcd. Activez l'**Encryption Configuration** dans Kubernetes pour chiffrer les secrets au repos en utilisant un provider (comme un plugin KMS).
2.  **RBAC**: Restreignez les permissions \`get\`, \`list\`, et \`watch\` sur les Secrets. Seuls des contrôleurs ou opérateurs spécifiques devraient avoir un accès large.
3.  **Secrets Immuables**: Utilisez \`immutable: true\` pour les secrets stables afin de protéger contre les mises à jour accidentelles et améliorer la performance.

### GitOps & Gestion des Secrets

En GitOps, le dépôt git est la source de vérité. Cependant, **ne committez jamais de Secrets Kubernetes bruts dans Git**.

#### Stratégie 1: Secrets Chiffrés dans Git
Des outils comme **Sealed Secrets** ou **SOPS** vous permettent de stocker des données chiffrées dans Git, qui ne sont déchiffrées qu'à l'intérieur du cluster.

*   **Bitnami Sealed Secrets**: Utilise le chiffrement asymétrique. Les développeurs chiffrent avec une clé publique (\`kubeseal\`), et le contrôleur du cluster déchiffre avec une clé privée. Sûr à committer (le CRD \`SealedSecret\`).
*   **Mozilla SOPS**: Chiffre les valeurs YAML en utilisant un Cloud KMS (AWS/GCP/Azure) ou PGP. S'intègre parfaitement avec Flux et ArgoCD.

#### Stratégie 2: Référencer des External Secrets (ESO)
Ne stockez pas le secret dans Git du tout. Stockez une référence (manifeste) qui pointe vers le vrai secret dans un Vault.

*   Committez une ressource custom \`ExternalSecret\` dans Git.
*   Elle contient le *pointeur* (ex: "récupérer le secret \`db-pass\` depuis AWS Secrets Manager").
*   L'opérateur récupère la valeur et crée le Secret Kubernetes.
*   *Résultat*: Git ne contient aucune donnée sensible, seulement de la configuration.

\`\`\`yaml
# Exemple: ExternalSecret pointant vers AWS Secrets Manager
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: db-secret-k8s # Le secret K8s à créer
  data:
  - secretKey: password
    remoteRef:
      key: production/db/password
\`\`\`
    `,
    newsContext: 'Dernières intégrations pour External Secrets Operator, nouvelles attaques ciblant le chiffrement etcd, et comparaisons Vault vs Cloud Provider Secret Managers.',
    securityTip: 'Rotation: Implémentez la **rotation automatique des secrets** dans votre Vault (AWS/HashiCorp). L\'External Secrets Operator peut automatiquement récupérer la nouvelle valeur et redémarrer les Pods.'
  },
  {
    id: 'deployment-gates',
    title: 'Policy as Code (OPA)',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'Admission controllers et deployment gates.',
    staticContent: `
### Policy as Code: Le Guide d'Implémentation

Les Admission Controllers interceptent les requêtes vers l'API Kubernetes *avant* la persistance. C'est ici que nous appliquons le "Contrat" défini lors du Design.

#### 1. La Matrice : Qui, Où, Quand ?

| Rôle | Action | Outil | Localisation |
| :--- | :--- | :--- | :--- |
| **Ingénieur Sécurité** | Rédige la Politique (Rego/YAML). | OPA / Kyverno | **Git Repository** (Policy Repo) |
| **Ingénieur Plateforme** | Installe le Contrôleur & Applique. | Helm / ArgocD | **Cluster K8s** (Admission Controller) |
| **Développeur** | Vérifie les violations en local/CI. | Conftest / Kyverno CLI | **Pipeline CI** (Shift Left) |

#### 2. Implémentation Pas-à-Pas

**Étape 1: Définir la Politique (Le Contrat)**
Les politiques doivent être traitées comme du code. Elles vivent dans Git, sont versionnées et revues.
*   *Exemple (Rego)*: "Toutes les images doivent venir de \`registry.corp.com\`".

\`\`\`rego
# policy/image_registry.rego
package kubernetes.admission
deny[msg] {
  input.request.kind.kind == "Pod"
  image := input.request.object.spec.containers[_].image
  not startswith(image, "registry.corp.com/")
  msg := sprintf("Image '%v' vient d'un registre non approuvé.", [image])
}
\`\`\`

**Étape 2: Tester dans la CI (Le Soft Gate)**
N'attendez pas que le déploiement échoue. Faites échouer le build dans la CI/CD avec \`conftest\` (pour OPA) ou \`kyverno apply\`.

\`\`\`bash
# .gitlab-ci.yml
policy_check:
  stage: test
  image: openpolicyagent/conftest
  script:
    - conftest test --policy policy/ deployment.yaml
\`\`\`

**Étape 3: Auditer dans le Cluster (Le Dry Run)**
Déployez la politique dans Kubernetes en mode **Warn/Audit** d'abord.
*   **OPA Gatekeeper**: Définir \`enforcementAction: dryrun\`.
*   **Kyverno**: Définir \`validationFailureAction: Audit\`.
*   *But*: Surveiller les logs pendant une semaine pour voir ce qui *casserait*. Corriger les violations existantes.

**Étape 4: Enforce (Le Hard Gate)**
Une fois les logs propres, passez en mode **Enforce/Deny**. Maintenant, tout déploiement non conforme est rejeté par l'API Server.

#### 3. Politiques Communes à Implémenter

*   **Disallow Root**: Forcer \`runAsNonRoot: true\`.
*   **Require Probes**: S'assurer que les sondes Liveness/Readiness existent.
*   **Ownership Labels**: Rendre obligatoires les labels \`team\` ou \`cost-center\`.

#### Recommandation: Le Déploiement Sûr
**N'activez jamais une politique bloquante au Jour 1.**
1.  **Semaine 1**: Déployer en mode \`Audit\`.
2.  **Semaine 2**: Revue des logs (Splunk/Datadog). Contacter les équipes pour corriger.
3.  **Semaine 3**: Passer en mode \`Enforce\`.
    `,
    newsContext: 'Mises à jour OPA/Gatekeeper (v3+), montée de Kyverno, et déplacement de la validation vers la gauche (CI pipeline) vs le cluster.',
    securityTip: 'Workflow: Utilisez **chain-bench** (par Aquasec) dans votre pipeline pour auditer votre stack software supply chain contre les benchmarks CIS Software Supply Chain.'
  },
  {
    id: 'network-policies',
    title: 'Segmentation Réseau (Est-Ouest)',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'Sécuriser les flux OpenShift avec la Microsegmentation.',
    staticContent: `
### OpenShift Network Policies: Le Firewall du Cluster

Par défaut, OpenShift (comme Kubernetes stock) utilise un modèle de **réseau plat**. Cela signifie que chaque Pod peut communiquer avec tous les autres Pods du cluster, à travers tous les projets (namespaces), à moins d'être isolé par le CNI.

#### 🛑 Le Risque: Trafic Est-Ouest Non Contrôlé
Le trafic "Est-Ouest" fait référence à la communication *à l'intérieur* du cluster (Service-à-Service).
*   **Mauvaise Pratique**: Un réseau plat où le \`Frontend\` can parler directement à la \`Database\`, mais aussi au \`Payment-Service\` et à l'\`Admin-Dashboard\`.
*   **Scénario d'Attaque**: Si le Frontend est compromis (ex: via Log4Shell), l'attaquant a une ligne directe pour sonder la base de données ou les panneaux d'admin internes.

*(Voir la visualisation interactive ci-dessus)*

#### ✅ La Solution: Microsegmentation
Nous utilisons les \`NetworkPolicies\` pour créer un réseau "Zero Trust" à l'intérieur du cluster.

**Étape 1: Le Default Deny (Le "Pare-feu")**
Appliquez cette politique à chaque Projet (Namespace) pour bloquer tout le trafic entrant par défaut. Cela vous force à autoriser explicitement ce qui est nécessaire.

\`\`\`yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny-all
  namespace: my-project
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  # - Egress (Optionnel, mais recommandé pour haute sécurité)
\`\`\`

**Étape 2: Autoriser le Trafic Spécifique (Le "Trou")**
N'autorisez *que* le Frontend à parler au Backend, et *uniquement* sur le port 8080.

\`\`\`yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-front-to-back
  namespace: my-project
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
\`\`\`

#### Spécificités OpenShift (OVN-Kubernetes)
Les versions modernes d'OpenShift utilisent **OVN-Kubernetes** comme CNI par défaut.
*   **Performance**: OVN utilise Open vSwitch, qui est hautement efficace pour appliquer ces ACLs.
*   **Visualisation**: Utilisez la vue **OpenShift Web Console > Topology**. Quand vous activez l'overlay "Network Policy", vous pouvez voir visuellement les flux de trafic autorisés entre les composants.
*   **Multi-Tenancy**: OpenShift offre un mode \`NetworkPolicy\` appelé \`MultiTenant\` (dans l'ancien SDN) ou une isolation stricte dans OVN. Assurez-vous que l'isolation de projet est activée.
    `,
    newsContext: 'Adoption de Cilium et eBPF pour le networking dans OpenShift, service meshes sidecar-less (Istio Ambient Mesh), et fonctionnalités de sécurité Gateway API.',
    securityTip: 'Performance: Utilisez **Cilium** (disponible dans OpenShift) avec eBPF pour appliquer les politiques au niveau socket. Cela rejette le trafic refusé avant même qu\'il ne génère un paquet.'
  },
  {
    id: 'observability-sidecars',
    title: 'Sidecars & Debugging Sécurisé',
    phase: SDLCPhase.RUNTIME,
    shortDesc: 'Patterns Service Mesh, Sidecars et Conteneurs Éphémères.',
    staticContent: `
### Patterns pour l'Observabilité & le Debugging

Dans un environnement "Secure by Design", les conteneurs de production sont **immuables** et **minimaux** (Distroless). Ils n'ont pas de shell (\`/bin/sh\`), pas de gestionnaires de paquets, et pas d'outils de debug. Cela les rend sûrs mais difficiles à dépanner.

#### 1. Le Pattern Sidecar (Implémentation)
Un sidecar est un conteneur secondaire dans le même Pod. Il partage le **Namespace Réseau** (localhost) et peut partager des **Volumes de Stockage**.

**Exemple: Log Shipping Sécurisé**
L'application écrit des logs dans un volume partagé. Le sidecar (Fluentd/Vector) les lit, les chiffre et les expédie.

\`\`\`yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-sidecar
spec:
  containers:
  # 1. Application Principale
  - name: my-app
    image: my-app:1.0 (Distroless)
    volumeMounts:
    - name: logs
      mountPath: /var/log/app
  
  # 2. Sidecar (Log Shipper)
  - name: log-shipper
    image: fluentd:latest
    volumeMounts:
    - name: logs
      mountPath: /var/log/app
      readOnly: true # Sécurité: Le sidecar ne peut pas altérer les logs
  
  volumes:
  - name: logs
    emptyDir: {}
\`\`\`

#### 2. Debugger du Distroless avec les Conteneurs Éphémères
Puisque vous ne pouvez pas faire de \`kubectl exec\` sur une image Distroless (pas de shell), vous devez apporter votre propre shell avec les **Conteneurs Éphémères**.

**Fonctionnalité:** Permet d'ajouter un conteneur à un Pod *en cours d'exécution* sans le redémarrer.

**Pas-à-Pas:**

1.  **Injecter le Debugger**: On attache une image "Couteau Suisse" (comme \`netshoot\`) au pod cible.
2.  **Cibler le Process Namespace**: Utilisez \`--target\` pour voir les processus du conteneur principal (localhost).

\`\`\`bash
# La Commande "Magique"
kubectl debug -it my-secure-pod \\
  --image=nicolaka/netshoot \\
  --target=main-app-container \\
  -- sh

# Dans le shell de debug :
netstat -tulpn  # Voir les ports ouverts par l'app principale
ps aux          # Voir les processus de l'app principale
tcpdump -i eth0 # Capturer le trafic
\`\`\`

#### 3. Profiling & Copie
Parfois, vous devez analyser des fichiers (heap dumps) générés par l'app crashée.

\`\`\`bash
# Créer une copie du pod avec un conteneur de debug attaché (pour post-mortem)
kubectl debug my-pod -it --image=busybox --share-processes --copy-to=my-debugger-pod
\`\`\`

#### Implications de Sécurité
*   **RBAC**: Restreignez la sous-ressource \`ephemeralcontainers\` dans les Role/ClusterRole. Seuls les SRE seniors devraient avoir cette permission.
*   **Politique**: Utilisez des Admission Controllers pour whitelister les images de debug autorisées (ex: autoriser \`netshoot\`, bloquer \`hacker-tool-kit\`).
    `,
    newsContext: 'Montée des service meshes "Sidecar-less" (Istio Ambient), risques de sécurité des sidecars sur-privilégiés, et avancées dans la sécurité OpenTelemetry.',
    securityTip: 'Tendance: Les maillages sans sidecar (comme **Istio Ambient Mesh** ou **Cilium Service Mesh**) réduisent la surface d\'attaque en déplaçant la logique proxy vers des agents sécurisés par nœud.'
  },
  {
    id: 'multi-arch-security',
    title: 'Isolation Multi-OS & Kernel',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'gVisor, Kata Containers et nœuds Windows.',
    staticContent: `
### Briser le Modèle de Noyau Partagé

Les conteneurs standards partagent le noyau Linux de l'hôte. Une vulnérabilité noyau (comme Dirty Cow) permet l'évasion de conteneur.

#### Conteneurs Sandboxés
Pour les workloads à haut risque (exécutant du code non approuvé), utilisez une isolation plus forte :

*   **gVisor (Google)**: Un shim noyau en userspace. Intercepte les syscalls. Ajoute de l'overhead mais une grande sécurité.
*   **Kata Containers**: Exécute chaque pod dans une micro-VM légère. Isolation au niveau matériel.

#### Runtime Classes
Vous pouvez définir quelle technologie d'isolation un pod utilise via \`RuntimeClass\`.

\`\`\`yaml
apiVersion: v1
kind: Pod
metadata:
  name: untrusted-workload
spec:
  runtimeClassName: gvisor
  containers:
  - name: app
    image: python-script-executor
\`\`\`
    `,
    newsContext: 'Améliorations de performance dans Kata Containers v3, nouveaux modèles de sécurité WASM (WebAssembly), et mises à jour de l\'isolation des conteneurs Windows.',
    securityTip: 'Recommandation: Pour exécuter du code non approuvé (ex: scripts clients), les namespaces standards sont insuffisants. L\'utilisation obligatoire de **gVisor** ou **Kata Containers** est recommandée.'
  },
  {
    id: 'runtime-security',
    title: 'Sécurité Runtime (Falco)',
    phase: SDLCPhase.RUNTIME,
    shortDesc: 'Analyse comportementale et détection d\'anomalies.',
    staticContent: `
### Détecter les "Inconnues Inconnues"

Le scan statique trouve les vulnérabilités (CVEs). La sécurité runtime trouve les **attaques** qui se produisent actuellement.

#### Falco & eBPF
Falco surveille les appels système du noyau en temps réel. Il peut alerter sur un comportement suspect que l'analyse statique manque.

**Alertes Typiques:**
*   Un shell (\`bash\`) lancé dans un conteneur de production.
*   Modification de \`/etc/passwd\`.
*   Connexion sortante vers une IP de pool de crypto-mining.
*   Lecture de fichiers sensibles (certificats/clés).

#### Réponse
La réponse automatisée (via des outils comme Falco Sidekick) peut immédiatement tuer un pod compromis ou isoler (cordon) le nœud pour l'analyse forensique.
    `,
    newsContext: 'Nouvelles règles Falco pour les attaques K8s, évolution d\'eBPF pour l\'observabilité sécurité, et fonctionnalités d\'application runtime Tetragon (Cilium).',
    securityTip: 'Application: **Tetragon** (par Isovalent) uses eBPF pour appliquer de manière transparente des politiques runtime, capable de tuer un processus *avant* qu\'un syscall malveillant ne se termine.'
  },
  {
    id: 'confidential-computing',
    title: 'Confidential Computing',
    phase: SDLCPhase.RUNTIME,
    shortDesc: 'Protection matérielle (TEEs/SGX/SEV).',
    staticContent: `
### Protéger les Données "In Use"

Nous chiffrons les données au repos (Disque) et en transit (TLS). Mais les données en RAM sont généralement en clair. Le **Confidential Computing** résout cela.

#### Trusted Execution Environments (TEEs)
Les fonctionnalités matérielles comme **Intel SGX**, **AMD SEV**, ou **TDX** permettent de créer des "Enclaves".
*   L'OS hôte / Hyperviseur ne peut pas lire la mémoire de l'enclave.
*   Les admins Cloud ne peuvent pas lire la mémoire.

#### Cas d'Usage
*   Calcul multi-partie (banques partageant des données de fraude sans révéler les clients).
*   Exécution de modèles IA sur des données de santé sensibles.
*   Systèmes de Gestion de Clés (KMS).
    `,
    newsContext: 'Les principaux fournisseurs Cloud (Azure/AWS/GCP) étendent les offres de Confidential Computing (Confidential GKE), et mises à jour des services d\'attestation.',
    securityTip: 'Adoption: Azure et GCP offrent maintenant des **Nœuds Confidentiels** pour GKE/AKS. Activez-le pour les workloads financiers ou de santé pour protéger les données en mémoire des compromissions de l\'hôte.'
  },
];

export const ICONS: Record<string, any> = {
  [SDLCPhase.DESIGN]: Shield,
  [SDLCPhase.BUILD]: Box,
  [SDLCPhase.DEPLOY]: Server,
  [SDLCPhase.RUNTIME]: Activity,
};

export const getCurriculum = (lang: string): ModuleItem[] => {
  return lang === 'fr' ? CURRICULUM_FR : CURRICULUM_EN;
};