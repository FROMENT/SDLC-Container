# KubeSecOps: Secure Container Lifecycle Guide

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![React](https://img.shields.io/badge/React-18-61dafb.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)
![AI Powered](https://img.shields.io/badge/AI-Gemini-orange.svg)

**KubeSecOps** is an interactive, "Secure by Design" educational platform tailored for DevOps engineers, SREs, and Security Architects working with **Red Hat OpenShift** and **Kubernetes**.

Unlike static documentation, this application uses AI, interactive visualizations, and gamification to bridge the gap between high-level security compliance and low-level implementation.

## 🎯 Objective

To transform security from a "Compliance Gate" into a "Quality Attribute". 

We believe that:
1.  **Security must be baked in**, not bolted on (Shift Left).
2.  **Developers need tools**, not just policies.
3.  **The Supply Chain is the new perimeter**.

## 🥁 The Rhythm (Methodology)

The guide follows the chronological life of a containerized application:

1.  **DESIGN (The Architect)**: Threat modeling (STRIDE), Base Image strategy (Distroless/Wolfi), and Labeling Governance.
2.  **BUILD (The Factory)**: CI Pipelines, Supply Chain security (SLSA, SBOMs), and Artifact Signing.
3.  **DEPLOY (The Gatekeeper)**: Admission Controllers (OPA/Kyverno), Secrets Management (Vault/CSI), and Network Segmentation.
4.  **RUN (The Watchtower)**: Runtime Security (Falco/Tetragon), Observability, and Incident Response.

## ✨ Key Features

*   **🧠 AI-Powered Intelligence**: Uses **Google Gemini** to fetch real-time "Security News" and context-aware CVE updates for every module.
*   **🤖 Interactive Assistants**:
    *   **Chat Assistant**: Ask questions about K8s security concepts.
    *   **STRIDE Generator**: Input your architecture, get an automated threat model.
    *   **Policy Wizard**: visually generate Kyverno/OPA policies without writing YAML.
*   **🎨 Visual Learning**: Interactive diagrams for Network Policies (East-West traffic) and Admission Gates.
*   **☁️ Cloud Sync**: Persist your learning progress across devices using your own **GitHub** repository as a secure backend.
*   **🌍 Bilingual**: Full support for **English** and **French**.

## 🛠️ Tech Stack

*   **Frontend**: React 18, TypeScript, Tailwind CSS.
*   **AI**: Google Generative AI SDK (Gemini).
*   **Backend Services**: 
    *   **Supabase** (for community reviews).
    *   **GitHub API** (for user progress sync).
*   **Icons**: Lucide React.

## 🚀 Getting Started

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Set up environment variables (Create a `.env` file):
    ```env
    # Required for AI features
    API_KEY=your_google_gemini_api_key
    ```
4.  Run the development server:
    ```bash
    npm start
    ```

## 🤝 Contributing

This guide is designed to evolve. If you find a gap in the curriculum or want to add a new visualization:

1.  Fork the repo.
2.  Create your feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a Pull Request.

## ☕ Support

If this project helped you secure your cluster, consider [Buying me a Ramen](https://ko-fi.com/newspace?donate=true)!

---
*Built with ❤️ for the DevSecOps community.*
