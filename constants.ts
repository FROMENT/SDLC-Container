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
    newsContext: 'Recent vulnerabilities in standard base images (glibc, openssl), updates to Wolfi OS, and trends in "chainguard" images.'
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
    newsContext: 'New architectural patterns in Kubernetes 1.29+, updates to "Zero Trust" definitions by NIST/CISA regarding containers.'
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
    newsContext: 'Updates on GDPR fines related to cloud data, PCI-DSS v4.0 container requirements, and "Sovereign Cloud" architectural trends.'
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
    newsContext: 'Recent supply chain attacks (like xz utils backdoor), updates to the SLSA specification, and adoption of SBOMs in government regulation.'
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
    newsContext: 'New features in Docker BuildKit, security risks in CI/CD pipelines (GitHub Actions runners), and "Leaky Vessels" vulnerabilities.'
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
    newsContext: 'Adoption rates of PSS "Restricted" profile, common pitfalls migrating from PSP, and updates in Kubernetes 1.30 regarding admission control.'
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
    newsContext: 'Latest integrations for External Secrets Operator, new attacks targeting etcd encryption, and comparisons of Vault vs Cloud Provider Secret Managers.'
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
    newsContext: 'Updates to OPA/Gatekeeper (v3+), the rise of Kyverno, and shifting validation left to the CI pipeline vs the cluster.'
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
    newsContext: 'Adoption of Cilium and eBPF for networking, sidecar-less service meshes (Istio Ambient Mesh), and Gateway API security features.'
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
    newsContext: 'Rise of "Sidecar-less" service meshes (Istio Ambient), security risks of over-privileged sidecars, and advancements in OpenTelemetry security.'
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
    newsContext: 'Performance improvements in Kata Containers v3, new WASM (WebAssembly) security models, and Windows container isolation updates.'
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
    newsContext: 'New Falco rules for K8s attacks, evolution of eBPF for security observability, and Tetragon (Cilium) runtime enforcement features.'
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
    newsContext: 'Major Cloud Providers (Azure/AWS/GCP) expanding Confidential Computing offerings (Confidential GKE), and attestation services updates.'
  },
];

export const ICONS: Record<string, any> = {
  [SDLCPhase.DESIGN]: Shield,
  [SDLCPhase.BUILD]: Box,
  [SDLCPhase.DEPLOY]: Server,
  [SDLCPhase.RUNTIME]: Activity,
};