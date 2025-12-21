import React, { useState } from 'react';
import { ShieldCheck, AlertTriangle, Ban, CheckCircle } from 'lucide-react';

export const SecurityGateIllustration: React.FC = () => {
  const [status, setStatus] = useState<'idle' | 'pass' | 'warn' | 'block'>('idle');

  return (
    <div className="bg-gray-900 p-6 rounded-xl border border-gray-700 mb-8 shadow-inner animate-fade-in">
      <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
        <ShieldCheck className="text-sec-red" />
        Deployment Gate Simulator
      </h3>
      
      {/* Controls */}
      <div className="flex flex-wrap gap-3 mb-10 justify-center">
        <button 
          onClick={() => setStatus('pass')}
          className={`px-4 py-2 text-xs font-bold uppercase tracking-wider rounded transition-all
            ${status === 'pass' ? 'bg-green-600 text-white shadow-lg shadow-green-900/50' : 'bg-green-900/20 text-green-400 border border-green-800 hover:bg-green-900/40'}
          `}
        >
          Scenario 1: Compliant
        </button>
        <button 
          onClick={() => setStatus('warn')}
          className={`px-4 py-2 text-xs font-bold uppercase tracking-wider rounded transition-all
            ${status === 'warn' ? 'bg-yellow-600 text-white shadow-lg shadow-yellow-900/50' : 'bg-yellow-900/20 text-yellow-400 border border-yellow-800 hover:bg-yellow-900/40'}
          `}
        >
          Scenario 2: Warning
        </button>
        <button 
          onClick={() => setStatus('block')}
          className={`px-4 py-2 text-xs font-bold uppercase tracking-wider rounded transition-all
            ${status === 'block' ? 'bg-red-600 text-white shadow-lg shadow-red-900/50' : 'bg-red-900/20 text-red-400 border border-red-800 hover:bg-red-900/40'}
          `}
        >
          Scenario 3: Stop Gate
        </button>
      </div>

      {/* Visualization */}
      <div className="relative flex items-center justify-between gap-2 md:gap-4 px-2 md:px-8">
        
        {/* Step 1: CI Pipeline */}
        <div className={`
          flex flex-col items-center p-4 rounded-lg border-2 transition-all duration-500 w-24 md:w-32 text-center z-10
          ${status === 'idle' ? 'border-gray-700 bg-gray-800' : 'border-blue-500 bg-blue-900/20 text-white shadow-[0_0_15px_rgba(59,130,246,0.2)]'}
        `}>
          <span className="text-[10px] uppercase font-bold tracking-widest text-gray-400 mb-2">Build</span>
          <div className="w-10 h-10 md:w-12 md:h-12 bg-blue-600 rounded flex items-center justify-center">
            <span className="text-xl font-bold">CI</span>
          </div>
        </div>

        {/* Connector 1 */}
        <div className="flex-1 h-1 bg-gray-700 relative overflow-hidden rounded">
           {status !== 'idle' && (
             <div className="absolute inset-0 bg-blue-500 animate-[shimmer_1.5s_infinite]" />
           )}
        </div>

        {/* Step 2: The Gate */}
        <div className="relative z-10 flex flex-col items-center">
           <div className={`
             w-20 h-20 md:w-28 md:h-28 rounded-full border-4 flex items-center justify-center bg-gray-900 transition-all duration-500
             ${status === 'idle' ? 'border-gray-700' : ''}
             ${status === 'pass' ? 'border-green-500 shadow-[0_0_30px_rgba(34,197,94,0.4)] scale-110' : ''}
             ${status === 'warn' ? 'border-yellow-500 shadow-[0_0_30px_rgba(234,179,8,0.4)] scale-110' : ''}
             ${status === 'block' ? 'border-red-500 shadow-[0_0_30px_rgba(239,68,68,0.4)] scale-110' : ''}
           `}>
              {status === 'idle' && <ShieldCheck className="w-8 h-8 md:w-12 md:h-12 text-gray-700" />}
              {status === 'pass' && <CheckCircle className="w-10 h-10 md:w-14 md:h-14 text-green-500 animate-pulse" />}
              {status === 'warn' && <AlertTriangle className="w-10 h-10 md:w-14 md:h-14 text-yellow-500 animate-pulse" />}
              {status === 'block' && <Ban className="w-10 h-10 md:w-14 md:h-14 text-red-500 animate-pulse" />}
           </div>
           <div className={`mt-3 text-xs md:text-sm font-bold uppercase tracking-widest
             ${status === 'pass' ? 'text-green-500' : ''}
             ${status === 'warn' ? 'text-yellow-500' : ''}
             ${status === 'block' ? 'text-red-500' : ''}
             ${status === 'idle' ? 'text-gray-500' : ''}
           `}>Security Gate</div>
        </div>

        {/* Connector 2 */}
         <div className="flex-1 h-1 bg-gray-700 relative overflow-hidden rounded">
           {(status === 'pass' || status === 'warn') && <div className={`absolute inset-0 animate-[shimmer_1.5s_infinite] ${status === 'pass' ? 'bg-green-500' : 'bg-yellow-500'}`} />}
           {status === 'block' && <div className="absolute left-0 w-1/2 h-full bg-gradient-to-r from-red-500 to-transparent opacity-50" />}
        </div>

        {/* Step 3: Cluster */}
        <div className={`
          flex flex-col items-center p-4 rounded-lg border-2 transition-all duration-500 w-24 md:w-32 text-center z-10
          ${status === 'idle' ? 'border-gray-700 bg-gray-800 opacity-30' : ''}
          ${status === 'pass' ? 'border-green-500 bg-green-900/20 text-white shadow-[0_0_15px_rgba(34,197,94,0.2)]' : ''}
          ${status === 'warn' ? 'border-yellow-500 bg-yellow-900/20 text-white shadow-[0_0_15px_rgba(234,179,8,0.2)]' : ''}
          ${status === 'block' ? 'border-red-900/30 bg-red-900/10 opacity-50 grayscale' : ''}
        `}>
          <span className="text-[10px] uppercase font-bold tracking-widest text-gray-400 mb-2">Cluster</span>
          <div className="w-10 h-10 md:w-12 md:h-12 bg-gray-800 rounded flex items-center justify-center border border-gray-600">
             <div className="grid grid-cols-2 gap-1">
               <div className={`w-2 h-2 md:w-3 md:h-3 rounded-full ${status === 'pass' || status === 'warn' ? 'bg-green-400 shadow-[0_0_5px_rgba(74,222,128,1)]' : 'bg-gray-700'}`} />
               <div className={`w-2 h-2 md:w-3 md:h-3 rounded-full ${status === 'pass' || status === 'warn' ? 'bg-green-400 shadow-[0_0_5px_rgba(74,222,128,1)]' : 'bg-gray-700'}`} />
               <div className={`w-2 h-2 md:w-3 md:h-3 rounded-full ${status === 'pass' || status === 'warn' ? 'bg-green-400 shadow-[0_0_5px_rgba(74,222,128,1)]' : 'bg-gray-700'}`} />
               <div className={`w-2 h-2 md:w-3 md:h-3 rounded-full ${status === 'pass' || status === 'warn' ? 'bg-green-400 shadow-[0_0_5px_rgba(74,222,128,1)]' : 'bg-gray-700'}`} />
             </div>
          </div>
        </div>
      </div>

      {/* Outcome Text */}
      <div className="mt-8 mx-auto max-w-lg p-4 bg-black/40 rounded-lg border border-gray-700/50 text-center min-h-[80px] flex items-center justify-center transition-all duration-300">
        {status === 'idle' && <span className="text-gray-500 italic">Select a scenario above to test the baseline control gate.</span>}
        {status === 'pass' && (
          <div>
            <div className="text-green-400 font-bold text-lg mb-1">Baseline Met</div>
            <div className="text-gray-400 text-sm">All security checks passed. Deployment automatically promoted to production.</div>
          </div>
        )}
        {status === 'warn' && (
          <div>
             <div className="text-yellow-400 font-bold text-lg mb-1">Warning Gate (Audit Mode)</div>
             <div className="text-gray-400 text-sm">Baseline violation detected. Deployment proceeds, but alerts are sent to the security team.</div>
          </div>
        )}
        {status === 'block' && (
          <div>
            <div className="text-red-400 font-bold text-lg mb-1">Stop Gate Enforced</div>
            <div className="text-gray-400 text-sm">Critical violation detected. Pipeline halted. <span className="text-red-400">Deployment rejected.</span></div>
          </div>
        )}
      </div>
    </div>
  );
};