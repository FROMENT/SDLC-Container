import React, { useState } from 'react';
import { Shield, AlertTriangle, Ban, Check, ChevronRight } from 'lucide-react';

export const SecurityGateIllustration: React.FC = () => {
  const [status, setStatus] = useState<'idle' | 'pass' | 'warn' | 'block'>('idle');

  return (
    <div className="font-mono text-sm border border-gray-300 dark:border-gray-700 p-4 mb-6 bg-transparent animate-fade-in max-w-2xl mx-auto">
      <div className="flex items-center justify-between mb-4 border-b border-gray-200 dark:border-gray-800 pb-2">
        <h3 className="uppercase tracking-widest text-xs font-bold text-gray-500 dark:text-gray-400">Gate.Logic</h3>
        <div className="flex gap-1">
             <button onClick={() => setStatus('pass')} className={`w-3 h-3 border ${status === 'pass' ? 'bg-green-500 border-green-500' : 'border-green-500/50 hover:bg-green-500/20'}`}></button>
             <button onClick={() => setStatus('warn')} className={`w-3 h-3 border ${status === 'warn' ? 'bg-yellow-500 border-yellow-500' : 'border-yellow-500/50 hover:bg-yellow-500/20'}`}></button>
             <button onClick={() => setStatus('block')} className={`w-3 h-3 border ${status === 'block' ? 'bg-red-500 border-red-500' : 'border-red-500/50 hover:bg-red-500/20'}`}></button>
        </div>
      </div>

      <div className="flex items-center justify-between relative py-4">
        {/* Background Line */}
        <div className="absolute top-1/2 left-0 w-full h-px bg-gray-300 dark:bg-gray-800 -z-10"></div>

        {/* Node 1: CI */}
        <div className={`w-12 h-12 border flex items-center justify-center bg-white dark:bg-black transition-colors duration-300
            ${status !== 'idle' ? 'border-blue-500 text-blue-500' : 'border-gray-300 dark:border-gray-700 text-gray-400'}
        `}>
            <span className="font-bold">CI</span>
        </div>

        {/* Flow Animation */}
        <ChevronRight className={`w-4 h-4 text-gray-400 ${status !== 'idle' ? 'text-blue-500 animate-[shimmer_1s_infinite]' : ''}`} />

        {/* Node 2: Gate */}
        <div className={`w-16 h-16 border-2 flex items-center justify-center bg-white dark:bg-black transition-all duration-300 z-10
            ${status === 'idle' ? 'border-gray-300 dark:border-gray-700' : ''}
            ${status === 'pass' ? 'border-green-500 shadow-[0_0_10px_rgba(34,197,94,0.3)]' : ''}
            ${status === 'warn' ? 'border-yellow-500 shadow-[0_0_10px_rgba(234,179,8,0.3)]' : ''}
            ${status === 'block' ? 'border-red-500 shadow-[0_0_10px_rgba(239,68,68,0.3)]' : ''}
        `}>
            {status === 'idle' && <Shield className="w-6 h-6 text-gray-300 dark:text-gray-700" />}
            {status === 'pass' && <Check className="w-8 h-8 text-green-500" />}
            {status === 'warn' && <AlertTriangle className="w-8 h-8 text-yellow-500" />}
            {status === 'block' && <Ban className="w-8 h-8 text-red-500" />}
        </div>

        {/* Flow Animation */}
        <ChevronRight className={`w-4 h-4 text-gray-400 ${status === 'pass' || status === 'warn' ? 'text-blue-500 animate-[shimmer_1s_infinite]' : ''}`} />

        {/* Node 3: Cluster */}
        <div className={`w-12 h-12 border flex items-center justify-center bg-white dark:bg-black transition-colors duration-300
             ${status === 'pass' || status === 'warn' ? 'border-green-500 text-green-500' : ''}
             ${status === 'block' ? 'border-gray-300 dark:border-gray-700 opacity-50' : ''}
             ${status === 'idle' ? 'border-gray-300 dark:border-gray-700 text-gray-400' : ''}
        `}>
            <span className="font-bold">K8s</span>
        </div>
      </div>

      <div className="mt-4 text-center">
         <span className={`text-xs uppercase tracking-widest 
            ${status === 'pass' ? 'text-green-600 dark:text-green-400' : ''}
            ${status === 'warn' ? 'text-yellow-600 dark:text-yellow-400' : ''}
            ${status === 'block' ? 'text-red-600 dark:text-red-400' : ''}
            ${status === 'idle' ? 'text-gray-400' : ''}
         `}>
            {status === 'idle' ? 'WAITING FOR INPUT...' : 
             status === 'pass' ? '>> ADMISSION GRANTED' : 
             status === 'warn' ? '>> WARNING: AUDIT LOGGED' : 
             '>> ADMISSION DENIED'}
         </span>
      </div>
    </div>
  );
};