import React from 'react';
import { Terminal, Shield, Workflow, AlertOctagon, Lightbulb, Fingerprint, Coffee, Heart } from 'lucide-react';
import { FeedbackSection } from './FeedbackSection';

interface Props {
  onBack: () => void;
  translate: (key: string) => string;
}

export const AboutPage: React.FC<Props> = ({ onBack, translate }) => {
  return (
    <div className="max-w-4xl mx-auto px-4 py-8 animate-fade-in text-gray-900 dark:text-gray-200">
      
      {/* Header */}
      <div className="mb-12 text-center">
        <h1 className="text-4xl font-bold mb-4">About <span className="text-sec-red">Container Security</span> Guide</h1>
        <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
          The interactive roadmap to demystifying DevSecOps on OpenShift & Kubernetes.
        </p>
      </div>

      <div className="space-y-12">
        
        {/* 1. The Objective */}
        <section className="bg-white dark:bg-card-bg border border-gray-300 dark:border-gray-700 rounded-2xl p-8 shadow-sm">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
            <Terminal className="w-6 h-6 text-blue-500" />
            The Objective: Shift Smart, Not Just Left
          </h2>
          <div className="prose dark:prose-invert max-w-none text-gray-700 dark:text-gray-300">
            <p>
              The primary goal of this application is to <strong>transform security from a blocker into an enabler</strong>.
              Too often, "Security" is seen as a PDF checklist or a "Gate" at the end of a project. 
              This guide proves that security is actually a set of architectural patterns that make your application 
              more robust, observable, and maintainable.
            </p>
            <p>
              We aim to bridge the gap between:
            </p>
            <ul className="grid md:grid-cols-2 gap-4 list-none pl-0 mt-4">
              <li className="flex items-center gap-2 bg-gray-50 dark:bg-gray-800/50 p-3 rounded-lg border border-gray-200 dark:border-gray-700">
                <Shield className="w-5 h-5 text-sec-red" />
                <span><strong>The CISO:</strong> Who worries about compliance & risk.</span>
              </li>
              <li className="flex items-center gap-2 bg-gray-50 dark:bg-gray-800/50 p-3 rounded-lg border border-gray-200 dark:border-gray-700">
                <Workflow className="w-5 h-5 text-blue-500" />
                <span><strong>The Developer:</strong> Who wants to ship code fast.</span>
              </li>
            </ul>
          </div>
        </section>

        {/* 2. The Rhythm (Methodology) */}
        <section className="bg-gradient-to-br from-gray-900 to-black text-white rounded-2xl p-8 shadow-xl border border-gray-700">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-2 text-white">
            <Fingerprint className="w-6 h-6 text-sec-red" />
            The Rhythm of the Guide
          </h2>
          <p className="mb-6 text-gray-300">
            Security follows the natural lifecycle of a container. We structured the app to follow this chronological rhythm:
          </p>
          
          <div className="grid sm:grid-cols-4 gap-4">
            <div className="bg-white/10 p-4 rounded-xl border border-white/10 backdrop-blur-sm">
              <div className="text-sec-red font-bold text-lg mb-1">01. DESIGN</div>
              <p className="text-xs text-gray-300">Before code exists. Threat Modeling, Base Image selection, and Labeling strategies.</p>
            </div>
            <div className="bg-white/10 p-4 rounded-xl border border-white/10 backdrop-blur-sm">
              <div className="text-blue-400 font-bold text-lg mb-1">02. BUILD</div>
              <p className="text-xs text-gray-300">The Factory. CI pipelines, SBOM generation, Signing, and vulnerability scanning.</p>
            </div>
            <div className="bg-white/10 p-4 rounded-xl border border-white/10 backdrop-blur-sm">
              <div className="text-orange-400 font-bold text-lg mb-1">03. DEPLOY</div>
              <p className="text-xs text-gray-300">The Gatekeeper. Admission Controllers (OPA/Kyverno), Secrets, and Network Policies.</p>
            </div>
            <div className="bg-white/10 p-4 rounded-xl border border-white/10 backdrop-blur-sm">
              <div className="text-green-400 font-bold text-lg mb-1">04. RUN</div>
              <p className="text-xs text-gray-300">Live production. Runtime detection (Falco), Drift detection, and Incident Response.</p>
            </div>
          </div>
        </section>

        {/* 3. Value Proposition / Features */}
        <section className="bg-white dark:bg-card-bg border border-gray-300 dark:border-gray-700 rounded-2xl p-8 shadow-sm">
            <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
            <Lightbulb className="w-6 h-6 text-yellow-500" />
            Why this guide is unique
            </h2>
            <div className="grid md:grid-cols-2 gap-6">
                <div>
                    <h3 className="font-bold text-gray-900 dark:text-white mb-2">Live AI Intelligence</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Static docs get outdated. We use <strong>Google Gemini</strong> to fetch the latest CVEs and security news relevant to each specific module in real-time.
                    </p>
                </div>
                <div>
                    <h3 className="font-bold text-gray-900 dark:text-white mb-2">Interactive Tooling</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        We don't just explain; we demonstrate. Use the <strong>Policy Wizard</strong> to generate YAML or the <strong>STRIDE AI</strong> to model threats for your specific architecture.
                    </p>
                </div>
                <div>
                    <h3 className="font-bold text-gray-900 dark:text-white mb-2">Visual Learning</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Complex concepts like "Microsegmentation" or "Admission Gates" are visualized with interactive diagrams to build mental models faster.
                    </p>
                </div>
                <div>
                    <h3 className="font-bold text-gray-900 dark:text-white mb-2">Persistence & Sync</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Your progress is saved securely. Sync your learning journey across devices using your own GitHub repository as a backend.
                    </p>
                </div>
            </div>
        </section>

        {/* 4. Support */}
        <section className="bg-yellow-50 dark:bg-yellow-900/10 border border-yellow-200 dark:border-yellow-800/30 rounded-2xl p-8 text-center">
            <div className="flex justify-center mb-4">
                <div className="p-3 bg-yellow-100 dark:bg-yellow-900/30 rounded-full">
                    <Heart className="w-8 h-8 text-yellow-600 dark:text-yellow-500" />
                </div>
            </div>
            <h2 className="text-2xl font-bold mb-3 text-yellow-800 dark:text-yellow-500">Support the Project</h2>
            <p className="text-gray-700 dark:text-gray-300 max-w-lg mx-auto mb-6">
                This content is free and open source. If it helped you secure your clusters or pass an audit, consider buying me a ramen to keep the updates coming!
            </p>
            <a 
                href="https://ko-fi.com/newspace?donate=true"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-6 py-3 bg-yellow-500 hover:bg-yellow-600 text-white font-bold rounded-full transition-transform hover:scale-105 shadow-md"
            >
                <Coffee className="w-5 h-5" />
                Buy me a Ramen
            </a>
        </section>

        {/* 5. Reviews via Supabase */}
        <FeedbackSection />

      </div>

      <div className="mt-12 text-center">
        <button 
          onClick={onBack}
          className="px-6 py-3 bg-gray-200 dark:bg-gray-800 hover:bg-gray-300 dark:hover:bg-gray-700 rounded-lg font-semibold transition text-gray-800 dark:text-white"
        >
          Back to Dashboard
        </button>
      </div>
    </div>
  );
};