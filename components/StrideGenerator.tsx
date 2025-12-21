import React, { useState } from 'react';
import { ShieldAlert, Zap, Loader2, FileCode } from 'lucide-react';
import { generateStrideAnalysis } from '../services/geminiService';
import { MarkdownRenderer } from './MarkdownRenderer';

export const StrideGenerator: React.FC = () => {
  const [input, setInput] = useState('');
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleGenerate = async () => {
    if (!input.trim()) return;
    setLoading(true);
    const result = await generateStrideAnalysis(input);
    setAnalysis(result);
    setLoading(false);
  };

  return (
    <div className="bg-gradient-to-br from-gray-900 to-gray-800 border border-gray-700 rounded-xl p-6 mb-8 shadow-2xl relative overflow-hidden animate-fade-in group">
      {/* Decorative background element */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-sec-red/5 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 pointer-events-none"></div>

      <div className="flex items-center gap-3 mb-6 relative z-10">
        <div className="p-3 bg-sec-red/20 rounded-lg border border-sec-red/30">
           <ShieldAlert className="w-6 h-6 text-sec-red" />
        </div>
        <div>
          <h3 className="text-xl font-bold text-white">AI STRIDE Threat Modeler</h3>
          <p className="text-xs text-gray-400">Automated Threat Analysis Engine</p>
        </div>
      </div>
      
      <div className="space-y-4 relative z-10">
        <div className="bg-black/40 rounded-lg p-4 border border-gray-700/50">
            <label className="block text-sm font-medium text-gray-300 mb-2 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-blue-400" />
                Describe Architecture Pattern
            </label>
            <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder='e.g., "A Node.js microservice reading from a public S3 bucket and writing to a protected Postgres database in a separate namespace."'
            className="w-full h-28 bg-dark-bg/80 border border-gray-600 rounded-lg p-3 text-gray-200 text-sm focus:border-sec-red focus:ring-1 focus:ring-sec-red focus:outline-none transition-all resize-none placeholder-gray-600 font-mono"
            />
        </div>
        
        <div className="flex justify-end">
            <button
            onClick={handleGenerate}
            disabled={loading || !input.trim()}
            className="bg-sec-red hover:bg-red-700 text-white px-6 py-2.5 rounded-lg font-bold text-sm tracking-wide flex items-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(238,0,0,0.4)] hover:shadow-[0_0_25px_rgba(238,0,0,0.6)]"
            >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4 fill-white" />}
            {loading ? 'ANALYZING THREATS...' : 'GENERATE STRIDE MODEL'}
            </button>
        </div>
      </div>

      {analysis && (
        <div className="mt-8 pt-6 border-t border-gray-700/50 animate-fade-in-up relative z-10">
          <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-bold text-white">Analysis Report</h4>
              <span className="text-xs font-mono text-green-400 px-2 py-1 bg-green-900/20 rounded border border-green-900/30">STATUS: COMPLETE</span>
          </div>
          <div className="bg-black/30 rounded-xl p-5 border border-gray-700 overflow-hidden">
             <MarkdownRenderer content={analysis} />
          </div>
        </div>
      )}
    </div>
  );
};