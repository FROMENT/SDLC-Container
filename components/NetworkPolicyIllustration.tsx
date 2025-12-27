import React, { useState } from 'react';
import { Globe, Database, ShieldAlert, Lock, ArrowRight, Server, Layout, AlertTriangle, CheckCircle } from 'lucide-react';

interface Props {
  translate?: (key: string) => string;
}

export const NetworkPolicyIllustration: React.FC<Props> = ({ translate }) => {
  const [mode, setMode] = useState<'flat' | 'segmented'>('flat');
  const t = translate || ((k: string) => k);

  const isFlat = mode === 'flat';

  return (
    <div className="w-full max-w-3xl mx-auto my-8 p-6 bg-white dark:bg-black/20 border border-gray-300 dark:border-gray-700 rounded-xl shadow-sm animate-fade-in">
      
      {/* Header / Controls */}
      <div className="flex flex-col sm:flex-row items-center justify-between mb-8 gap-4">
        <div>
          <h3 className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <Layout className="w-5 h-5 text-sec-red" />
            {t('Network Traffic Visualization')}
          </h3>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {isFlat ? t('Current: Flat Network (Insecure)') : t('Current: Microsegmentation (Zero Trust)')}
          </p>
        </div>
        
        <div className="flex bg-gray-100 dark:bg-gray-800 p-1 rounded-lg border border-gray-200 dark:border-gray-700">
          <button
            onClick={() => setMode('flat')}
            className={`px-4 py-2 text-xs font-bold rounded-md transition-all ${
              isFlat 
                ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 shadow-sm' 
                : 'text-gray-500 hover:text-gray-700 dark:text-gray-400'
            }`}
          >
            {t('Flat Network')}
          </button>
          <button
            onClick={() => setMode('segmented')}
            className={`px-4 py-2 text-xs font-bold rounded-md transition-all ${
              !isFlat 
                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 shadow-sm' 
                : 'text-gray-500 hover:text-gray-700 dark:text-gray-400'
            }`}
          >
            {t('Microsegmentation')}
          </button>
        </div>
      </div>

      {/* Diagram Area */}
      <div className="relative h-[300px] w-full bg-gray-50 dark:bg-gray-900/50 rounded-lg border border-gray-200 dark:border-gray-800 p-4 overflow-hidden">
        
        {/* Background Grid */}
        <div className="absolute inset-0 opacity-10" style={{ backgroundImage: 'radial-gradient(#999 1px, transparent 1px)', backgroundSize: '20px 20px' }}></div>

        {/* Nodes */}
        <div className="absolute top-1/2 left-10 -translate-y-1/2 z-20 flex flex-col items-center">
            <div className={`p-3 rounded-xl border-2 shadow-lg transition-colors ${
                isFlat ? 'bg-red-50 border-red-200' : 'bg-blue-50 border-blue-200'
            }`}>
                <Globe className="w-8 h-8 text-blue-600" />
            </div>
            <span className="mt-2 text-xs font-bold bg-white dark:bg-black px-2 py-0.5 rounded border border-gray-200 dark:border-gray-700 shadow-sm">Frontend</span>
        </div>

        <div className="absolute top-10 right-10 z-20 flex flex-col items-center">
            <div className="p-3 bg-white dark:bg-gray-800 rounded-xl border-2 border-gray-200 dark:border-gray-700 shadow-lg">
                <Server className="w-8 h-8 text-indigo-600" />
            </div>
             <span className="mt-2 text-xs font-bold bg-white dark:bg-black px-2 py-0.5 rounded border border-gray-200 dark:border-gray-700 shadow-sm">Backend</span>
        </div>

        <div className="absolute bottom-10 right-32 z-20 flex flex-col items-center">
            <div className="p-3 bg-white dark:bg-gray-800 rounded-xl border-2 border-gray-200 dark:border-gray-700 shadow-lg">
                <Database className="w-8 h-8 text-orange-600" />
            </div>
             <span className="mt-2 text-xs font-bold bg-white dark:bg-black px-2 py-0.5 rounded border border-gray-200 dark:border-gray-700 shadow-sm">Database</span>
        </div>

        <div className="absolute bottom-10 right-10 z-20 flex flex-col items-center">
             <div className="p-3 bg-white dark:bg-gray-800 rounded-xl border-2 border-gray-200 dark:border-gray-700 shadow-lg">
                <ShieldAlert className="w-8 h-8 text-red-600" />
            </div>
             <span className="mt-2 text-xs font-bold bg-white dark:bg-black px-2 py-0.5 rounded border border-gray-200 dark:border-gray-700 shadow-sm">Internal Admin</span>
        </div>


        {/* Connecting Lines (SVG Overlay) */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none z-10">
            <defs>
                <marker id="arrowhead-red" markerWidth="10" markerHeight="7" refX="28" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#ef4444" />
                </marker>
                <marker id="arrowhead-green" markerWidth="10" markerHeight="7" refX="28" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#22c55e" />
                </marker>
                 <marker id="arrowhead-blocked" markerWidth="10" markerHeight="7" refX="25" refY="3.5" orient="auto">
                    <circle cx="5" cy="3.5" r="3" fill="#9ca3af" />
                </marker>
            </defs>

            {/* Path 1: Frontend -> Backend (Always Allowed) */}
            <path 
                d="M 80 150 C 150 150, 250 80, 500 60" 
                fill="none" 
                stroke="#22c55e" 
                strokeWidth="2" 
                strokeDasharray="5,5"
                markerEnd="url(#arrowhead-green)"
                className="animate-[dash_1s_linear_infinite]"
            />

            {/* Path 2: Frontend -> Database */}
            {isFlat ? (
                 <path 
                    d="M 80 150 C 150 150, 250 250, 550 250" 
                    fill="none" 
                    stroke="#ef4444" 
                    strokeWidth="2" 
                    markerEnd="url(#arrowhead-red)"
                    className="opacity-50"
                />
            ) : (
                <g>
                    <path 
                        d="M 80 150 C 150 150, 250 250, 450 250" 
                        fill="none" 
                        stroke="#ef4444" 
                        strokeWidth="2" 
                        strokeDasharray="2,4"
                        className="opacity-30"
                    />
                    <circle cx="450" cy="250" r="12" fill="#ef4444" className="animate-pulse" />
                    <text x="444" y="254" fill="white" fontSize="10" fontWeight="bold">X</text>
                </g>
            )}

            {/* Path 3: Frontend -> Admin */}
            {isFlat ? (
                 <path 
                    d="M 80 150 C 150 150, 300 300, 680 250" 
                    fill="none" 
                    stroke="#ef4444" 
                    strokeWidth="2" 
                    markerEnd="url(#arrowhead-red)"
                    className="opacity-50"
                />
            ) : (
                 <g>
                     <path 
                        d="M 80 150 C 150 150, 300 300, 580 260" 
                        fill="none" 
                        stroke="#ef4444" 
                        strokeWidth="2" 
                        strokeDasharray="2,4"
                        className="opacity-30"
                    />
                    <circle cx="580" cy="260" r="12" fill="#ef4444" className="animate-pulse" />
                    <text x="574" y="264" fill="white" fontSize="10" fontWeight="bold">X</text>
                </g>
            )}

        </svg>

        {/* Legend Overlay */}
        <div className="absolute top-4 left-4 bg-white/90 dark:bg-black/80 p-2 rounded-lg border border-gray-200 dark:border-gray-800 text-[10px] shadow-sm">
            <div className="flex items-center gap-2 mb-1">
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
                <span className="text-gray-700 dark:text-gray-300">Allowed Traffic (TCP 8080)</span>
            </div>
            <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500"></span>
                <span className="text-gray-700 dark:text-gray-300">Blocked / Unauthorized</span>
            </div>
        </div>

      </div>

      <div className={`mt-4 p-4 rounded-lg border ${
          isFlat ? 'bg-red-50 border-red-200 dark:bg-red-900/10 dark:border-red-900/30' : 'bg-green-50 border-green-200 dark:bg-green-900/10 dark:border-green-900/30'
      }`}>
          <div className="flex items-start gap-3">
              {isFlat ? <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" /> : <Lock className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />}
              <div>
                  <h4 className={`text-sm font-bold ${isFlat ? 'text-red-800 dark:text-red-400' : 'text-green-800 dark:text-green-400'}`}>
                      {isFlat ? t('Security Alert: Lateral Movement Possible') : t('Policy Enforced: Zero Trust')}
                  </h4>
                  <p className="text-xs mt-1 text-gray-700 dark:text-gray-300">
                      {isFlat 
                        ? t('In a flat network, if the Frontend is compromised, the attacker can directly access the Database and Admin panel.') 
                        : t('Network Policies block all traffic by default. Only specific, allowed connections (Frontend -> Backend) are permitted.')}
                  </p>
              </div>
          </div>
      </div>
    </div>
  );
};