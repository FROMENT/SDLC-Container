import React, { useState, useEffect } from 'react';
import { Github, Save, Download, Upload, X, CheckCircle, AlertCircle, Loader2, ShieldAlert, Trash2, Lock } from 'lucide-react';
import { GitHubConfig } from '../services/githubService';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  config: GitHubConfig;
  onSaveConfig: (config: GitHubConfig) => void;
  onPush: () => Promise<void>;
  onPull: () => Promise<void>;
  translate: (key: string) => string;
}

export const GitHubSyncModal: React.FC<Props> = ({ 
  isOpen, onClose, config, onSaveConfig, onPush, onPull, translate 
}) => {
  const [localConfig, setLocalConfig] = useState<GitHubConfig>(config);
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');

  // Reset local config when modal opens
  useEffect(() => {
    if (isOpen) {
      setLocalConfig(config);
      setStatus('idle');
      setMessage('');
    }
  }, [isOpen, config]);

  const handleChange = (field: keyof GitHubConfig, value: string) => {
    setLocalConfig(prev => ({ ...prev, [field]: value }));
  };

  const handleSaveConfig = () => {
    onSaveConfig(localConfig);
    setStatus('success');
    setMessage('Configuration saved securely.');
    setTimeout(() => setStatus('idle'), 2000);
  };

  const handleClearToken = () => {
    const newConfig = { ...localConfig, token: '' };
    setLocalConfig(newConfig);
    onSaveConfig(newConfig);
    setStatus('success');
    setMessage('Token removed from secure storage.');
    setTimeout(() => setStatus('idle'), 2000);
  }

  const wrapAction = async (action: () => Promise<void>, successMsg: string) => {
    setStatus('loading');
    setMessage('Processing...');
    try {
      await action();
      setStatus('success');
      setMessage(successMsg);
    } catch (e: any) {
      setStatus('error');
      setMessage(e.message || 'Operation failed');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="bg-white dark:bg-card-bg w-full max-w-md rounded-2xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="bg-gray-900 text-white p-4 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Github className="w-5 h-5" />
            <h3 className="font-bold">GitHub Sync Storage</h3>
          </div>
          <button onClick={onClose} className="hover:bg-white/20 p-1 rounded-full transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          
          <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg text-xs text-blue-800 dark:text-blue-300 border border-blue-200 dark:border-blue-800/50">
             {translate('Sync your progress (Modules, Views, Settings) to a GitHub repository to use across devices.')}
          </div>

          <div className="space-y-4">
            <div>
              <div className="flex justify-between items-center mb-1">
                <label className="block text-xs font-bold uppercase text-gray-500">Personal Access Token (PAT)</label>
                {localConfig.token && (
                  <button onClick={handleClearToken} className="text-[10px] text-red-500 hover:text-red-700 flex items-center gap-1">
                    <Trash2 className="w-3 h-3" /> Clear Token
                  </button>
                )}
              </div>
              <div className="relative">
                <input 
                  type="password" 
                  value={localConfig.token}
                  onChange={e => handleChange('token', e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxx"
                  className="w-full bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 pl-8 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none"
                />
                <Lock className="w-3 h-3 text-gray-400 absolute left-3 top-3" />
              </div>
              <p className="text-[10px] text-gray-500 mt-1">
                Required Scope: <strong>repo</strong> (Classic).
              </p>
            </div>

            {/* Security Notice */}
            <div className="flex items-start gap-2 p-3 bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-800/30 rounded-lg">
               <ShieldAlert className="w-4 h-4 text-green-600 dark:text-green-500 flex-shrink-0 mt-0.5" />
               <p className="text-[10px] text-green-800 dark:text-green-400 leading-tight">
                 <strong>Secure Storage:</strong> Your token is now encrypted/obfuscated before being saved to this device. It is safe from casual inspection.
               </p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold uppercase text-gray-500 mb-1">Owner</label>
                <input 
                  type="text" 
                  value={localConfig.owner}
                  onChange={e => handleChange('owner', e.target.value)}
                  placeholder="username"
                  className="w-full bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-bold uppercase text-gray-500 mb-1">Repo Name</label>
                <input 
                  type="text" 
                  value={localConfig.repo}
                  onChange={e => handleChange('repo', e.target.value)}
                  placeholder="my-data"
                  className="w-full bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold uppercase text-gray-500 mb-1">File Path</label>
              <input 
                type="text" 
                value={localConfig.path}
                onChange={e => handleChange('path', e.target.value)}
                placeholder="container-security-data.json"
                className="w-full bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none"
              />
            </div>
            
            <button 
              onClick={handleSaveConfig}
              className="w-full py-2 bg-gray-200 dark:bg-gray-800 hover:bg-gray-300 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg flex items-center justify-center gap-2 text-sm font-semibold transition"
            >
              <Save className="w-4 h-4" /> Save Configuration
            </button>
          </div>

          <hr className="border-gray-200 dark:border-gray-700" />

          <div className="grid grid-cols-2 gap-4">
             <button 
                onClick={() => wrapAction(onPush, 'Data successfully pushed to GitHub!')}
                disabled={!localConfig.token || status === 'loading'}
                className="flex flex-col items-center justify-center gap-2 p-4 rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-700 hover:border-sec-red dark:hover:border-sec-red hover:bg-red-50 dark:hover:bg-red-900/10 transition group"
             >
                <Upload className="w-6 h-6 text-gray-400 group-hover:text-sec-red" />
                <span className="text-sm font-bold text-gray-600 dark:text-gray-400 group-hover:text-sec-red">PUSH (Save)</span>
             </button>

             <button 
                onClick={() => wrapAction(onPull, 'Data restored from GitHub!')}
                disabled={!localConfig.token || status === 'loading'}
                className="flex flex-col items-center justify-center gap-2 p-4 rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-700 hover:border-blue-500 dark:hover:border-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900/10 transition group"
             >
                <Download className="w-6 h-6 text-gray-400 group-hover:text-blue-500" />
                <span className="text-sm font-bold text-gray-600 dark:text-gray-400 group-hover:text-blue-500">PULL (Load)</span>
             </button>
          </div>

          {/* Status Bar */}
          {status !== 'idle' && (
            <div className={`flex items-center gap-3 p-3 rounded-lg text-sm animate-fade-in
                ${status === 'loading' ? 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300' : ''}
                ${status === 'success' ? 'bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400' : ''}
                ${status === 'error' ? 'bg-red-100 dark:bg-red-900/20 text-red-700 dark:text-red-400' : ''}
            `}>
                {status === 'loading' && <Loader2 className="w-4 h-4 animate-spin" />}
                {status === 'success' && <CheckCircle className="w-4 h-4" />}
                {status === 'error' && <AlertCircle className="w-4 h-4" />}
                <span className="font-medium">{message}</span>
            </div>
          )}

        </div>
      </div>
    </div>
  );
};