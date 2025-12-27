import React from 'react';
import { Terminal, Shield, Workflow, AlertOctagon, Lightbulb, GitMerge, Fingerprint } from 'lucide-react';
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
          An interactive platform designed to bridge the gap between DevOps agility and Security rigor.
        </p>
      </div>

      <div className="space-y-12">
        
        {/* 1. Resume du contenu */}
        <section className="bg-white dark:bg-card-bg border border-gray-300 dark:border-gray-700 rounded-2xl p-8 shadow-sm">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
            <Terminal className="w-6 h-6 text-blue-500" />
            Executive Summary
          </h2>
          <div className="prose dark:prose-invert max-w-none text-gray-700 dark:text-gray-300">
            <p>
              This application serves as a comprehensive "Secure Software Development Life Cycle" (SSDLC) guide tailored for 
              <strong> Red Hat OpenShift </strong> and Kubernetes environments. It provides actionable guidance to harden 
              your supply chain from the first line of code to runtime execution.
            </p>
            <ul className="grid md:grid-cols-2 gap-4 list-none pl-0 mt-4">
              <li className="flex items-start gap-2 bg-gray-50 dark:bg-gray-800/50 p-3 rounded-lg">
                <Shield className="w-5 h-5 text-sec-red mt-0.5" />
                <span><strong>Holistic Approach:</strong> Covers Design, Build, Deploy, and Runtime phases.</span>
              </li>
              <li className="flex items-start gap-2 bg-gray-50 dark:bg-gray-800/50 p-3 rounded-lg">
                <Workflow className="w-5 h-5 text-sec-red mt-0.5" />
                <span><strong>East-West Protection:</strong> Dedicated focus on OpenShift Network Policies and microsegmentation.</span>
              </li>
              <li className="flex items-start gap-2 bg-gray-50 dark:bg-gray-800/50 p-3 rounded-lg">
                <Lightbulb className="w-5 h-5 text-sec-red mt-0.5" />
                <span><strong>AI Integration:</strong> Uses Google Gemini for real-time security news and threat analysis.</span>
              </li>
              <li className="flex items-start gap-2 bg-gray-50 dark:bg-gray-800/50 p-3 rounded-lg">
                <GitMerge className="w-5 h-5 text-sec-red mt-0.5" />
                <span><strong>Persistence:</strong> Syncs your learning progress via GitHub API.</span>
              </li>
            </ul>
          </div>
        </section>

        {/* 2. Philosophy Check: "Passer la sécurité" */}
        <section className="relative overflow-hidden bg-gradient-to-br from-sec-red/90 to-red-900 rounded-2xl p-8 text-white shadow-lg">
          <div className="absolute top-0 right-0 w-64 h-64 bg-white/10 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2"></div>
          
          <div className="relative z-10">
            <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <AlertOctagon className="w-7 h-7" />
              Stop Saying "Passer la Sécurité"
            </h2>
            <div className="space-y-4 text-red-50 font-medium text-lg leading-relaxed">
              <p>
                I am constantly surprised that in {new Date().getFullYear()}, we still hear the phrase 
                <em> "Il faut qu'on passe la sécurité" </em> (We need to pass security).
              </p>
              <p className="p-4 bg-black/20 rounded-lg border-l-4 border-white italic">
                Security is not a checkpoint, a toll booth, or a "gate" you trick to get your code into production. 
                It is a quality attribute of your software, just like performance or reliability.
              </p>
              <p>
                When you say "pass security," you imply it's an obstacle. This mindset leads to 
                vulnerabilities. You don't "pass" stability; you build stable software. 
                We must build <strong>Secure by Design</strong> software.
              </p>
            </div>
          </div>
        </section>

        {/* 3. Analysis & Incoming Improvements */}
        <section className="bg-white dark:bg-card-bg border border-gray-300 dark:border-gray-700 rounded-2xl p-8 shadow-sm">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
            <Fingerprint className="w-6 h-6 text-purple-500" />
            Analysis & Improvement Roadmap
          </h2>
          
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-lg font-bold text-gray-500 dark:text-gray-400 uppercase tracking-widest mb-4">Current Gaps</h3>
              <ul className="space-y-3">
                <li className="flex gap-3 items-start text-sm">
                  <span className="text-red-500 font-bold">•</span>
                  <span><strong>Static Policy Generation:</strong> Users learn about OPA/Kyverno but have to write YAML manually.</span>
                </li>
                <li className="flex gap-3 items-start text-sm">
                  <span className="text-red-500 font-bold">•</span>
                  <span><strong>Limited Hands-on Labs:</strong> The app explains concepts but lacks an embedded terminal for actual `kubectl` commands.</span>
                </li>
                <li className="flex gap-3 items-start text-sm">
                  <span className="text-red-500 font-bold">•</span>
                  <span><strong>Supply Chain Visualization:</strong> We mention SBOMs, but we don't visualize the dependency graph.</span>
                </li>
              </ul>
            </div>

            <div>
              <h3 className="text-lg font-bold text-sec-red uppercase tracking-widest mb-4">Incoming Improvements (Secure by Design)</h3>
              <div className="space-y-4">
                <div className="bg-gray-50 dark:bg-gray-800/50 p-4 rounded-lg border-l-4 border-purple-500">
                  <h4 className="font-bold text-gray-900 dark:text-white">1. Policy-as-Code Wizard</h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    A visual generator that creates `ClusterPolicy` (Kyverno) or Rego (OPA) rules based on user-selected checkboxes (e.g., "Disallow Root", "Require Probes").
                  </p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-800/50 p-4 rounded-lg border-l-4 border-blue-500">
                  <h4 className="font-bold text-gray-900 dark:text-white">2. Automated Dependency Graph</h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    Upload a `package.json` or `go.mod`, and the app will visualize the attack surface and highlight vulnerable transitive dependencies using OSV.dev API.
                  </p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-800/50 p-4 rounded-lg border-l-4 border-green-500">
                  <h4 className="font-bold text-gray-900 dark:text-white">3. "Invisible Security" Mode</h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    Demonstrating eBPF (Tetragon) profiles that enforce security at the kernel level, requiring zero code changes from developers.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 4. Reviews via Supabase */}
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