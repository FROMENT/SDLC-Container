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

export const CURRICULUM: ModuleItem[] = [
  {
    id: 'base-images',
    title: 'Minimal & Distroless Images',
    phase: SDLCPhase.DESIGN,
    shortDesc: 'Reducing attack surface with Alpine, Wolfi, and Distroless.',
    staticContent: `
### The Importance of Minimal Base Images

The container base image is the foundation of your security posture. Standard OS images (like \`ubuntu:latest\` or \`node:latest\`) contain package managers, shells, and system libraries that are unnecessary for your application but useful for attackers.

#### Comparison: Standard vs. Minimal

| Feature | Standard (Debian/Ubuntu) | Minimal (Alpine) | Distroless (Google) |
| :--- | :--- | :--- | :--- |
| **Size** | > 100MB | ~5MB | ~20MB |
| **Package Mgr** | apt/dpkg | apk | None |
| **Shell** | Bash/Sh | Sh | None |
| **CVE Count** | High | Low | Lowest |

#### Implementation Example

Using a multi-stage build to deploy a Go application on a generic static container:

\`\`\`dockerfile
# Build Stage
FROM golang:1.21 as builder
WORKDIR /app
COPY . .
RUN go build -o myapp main.go

# Runtime Stage (Distroless)
FROM gcr.io/distroless/static-debian11
COPY --from=builder /app/myapp /
CMD ["/myapp"]
\`\`\`
    `,
    newsContext: 'Recent vulnerabilities in standard base images (glibc, openssl), updates to Wolfi OS, and trends in "chainguard" images.',
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
*   **Red Hat OpenShift**: Integrated scanning with Red Hat Quay (Clair).
*   **Tools**: Trivy, Grype, Docker Scout.

#### Pipeline Integration Example
A typical secure pipeline structure:

\`\`\`yaml
stages:
  - build
  - test
  - scan

sast_check:
  stage: test
  script:
    - semgrep --config=p/security-audit .

sca_check:
  stage: test
  script:
    - trivy fs --security-checks vuln,secret .

container_scan:
  stage: scan
  script:
    # Fail pipeline if Critical vulnerabilities are found
    - trivy image --exit-code 1 --severity CRITICAL my-image:latest
\`\`\`
    `,
    newsContext: 'Rise of AI-powered SAST tools, new regulations requiring SCA analysis (SBOM usage), and "Reachability Analysis" in modern scanners.',
    securityTip: 'Optimization: Use **Reachability Analysis** (available in tools like Snyk or Endor Labs). It distinguishes between a vulnerable library you *installed* vs. one you actually *call* in code, reducing noise by 80%.'
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
### The Deployment Gatekeeper

Admission Controllers intercept requests to the Kubernetes API server *before* persistence of the object, but *after* the request is authenticated and authorized.

#### OPA Gatekeeper vs Kyverno
*   **OPA Gatekeeper**: Uses **Rego**, a specialized query language. Extremely powerful and flexible.
*   **Kyverno**: Uses Kubernetes Native Policy (YAML). Easier to learn for K8s admins, but slightly less flexible than Rego.

#### 1. Disallow Root Containers (Rego)
This policy ensures no container runs as User ID 0 (root), mitigating container escape risks.

\`\`\`rego
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container '%v' must set runAsNonRoot to true.", [container.name])
}
\`\`\`

#### 2. Enforce Image Provenance (Trusted Registry)
Ensure all images come from your trusted internal registry (e.g., \`registry.corp.com\`) to prevent pulling malicious public images.

\`\`\`rego
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  container := input.request.object.spec.containers[_]
  not startswith(container.image, "registry.corp.com/")
  msg := sprintf("Image '%v' comes from an untrusted registry.", [container.image])
}
\`\`\`

#### 3. Require Ownership Labels
Mandate labels like \`cost-center\` or \`team\` for all Deployments to ensure accountability.

\`\`\`rego
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Deployment"
  not input.request.object.metadata.labels["team"]
  msg := "Deployments must have a 'team' label."
}
\`\`\`

#### Shift Left: Testing with Conftest
Don't wait for the cluster to reject you. Test policies in your CI/CD pipeline using \`conftest\`.

\`\`\`bash
# Run in CI before helm install
conftest test -p policies/ deployment.yaml
\`\`\`
    `,
    newsContext: 'Updates to OPA/Gatekeeper (v3+), the rise of Kyverno, and shifting validation left to the CI pipeline vs the cluster.',
    securityTip: 'Workflow: Use **chain-bench** (by Aquasec) in your pipeline to audit your software supply chain stack against CIS Software Supply Chain benchmarks.'
  },
  {
    id: 'network-policies',
    title: 'Network Segmentation',
    phase: SDLCPhase.DEPLOY,
    shortDesc: 'Microsegmentation using CNI plugins.',
    staticContent: `
### Network Policies: The Cluster Firewall

By default, in Kubernetes, **all pods can talk to all other pods**, across all namespaces. This is a massive security risk (flat network).

#### The "Default Deny" Stance
The first step in securing a namespace should be applying a "Deny All" policy.

\`\`\`yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
\`\`\`

#### CNI Capabilities
Standard \`NetworkPolicies\` are layer 3/4 (IP/Port). Advanced CNIs like **Cilium** allow Layer 7 filtering (HTTP methods, DNS names) and provide visual maps of traffic flows.
    `,
    newsContext: 'Adoption of Cilium and eBPF for networking, sidecar-less service meshes (Istio Ambient Mesh), and Gateway API security features.',
    securityTip: 'Performance: Utilize **Cilium** with eBPF to enforce policies at the socket layer. This drops denied traffic before it even generates a packet, saving resources.'
  },
  {
    id: 'observability-sidecars',
    title: 'Sidecars & Secure Debugging',
    phase: SDLCPhase.RUNTIME,
    shortDesc: 'Service Mesh patterns, Sidecars, and Ephemeral Containers.',
    staticContent: `
### Patterns for Observability & Debugging

In modern Kubernetes, we avoid installing debug tools (curl, netcat) in production images to keep them minimal. So how do we debug?

#### The Sidecar Pattern
A helper container running alongside your main application in the same Pod. They share the same network (localhost) and storage.
*   **Uses**: Log shipping (Fluentd), Network proxy (Envoy/Istio), Database proxy (Cloud SQL Auth).
*   **Security**: Sidecars inject observability (Tracing/Metrics) without modifying application code.

#### Secure Debugging: Ephemeral Containers
Never SSH into nodes. Use **Ephemeral Containers** to inject debug tools into a running pod temporarily.

\`\`\`bash
# Instead of: ssh user@node
# Use:
kubectl debug -it my-pod --image=nicolaka/netshoot --target=app-container
\`\`\`
This creates a temporary container with network tools attached to the target process namespace, which vanishes when you exit.
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

export const ICONS: Record<string, any> = {
  [SDLCPhase.DESIGN]: Shield,
  [SDLCPhase.BUILD]: Box,
  [SDLCPhase.DEPLOY]: Server,
  [SDLCPhase.RUNTIME]: Activity,
};