import React from 'react';
import { SDLCPhase } from '../types';
import { Shield, Box, Server, Activity, ArrowRight } from 'lucide-react';

interface Props {
  currentPhase: SDLCPhase | null;
  onSelectPhase: (phase: SDLCPhase) => void;
  translate?: (key: string) => string;
}

const PipelineVisualizer: React.FC<Props> = ({ currentPhase, onSelectPhase, translate }) => {
  const t = translate || ((k: string) => k);

  const phases = [
    { id: SDLCPhase.DESIGN, icon: Shield, label: t('Design') },
    { id: SDLCPhase.BUILD, icon: Box, label: t('Build') },
    { id: SDLCPhase.DEPLOY, icon: Server, label: t('Deploy') },
    { id: SDLCPhase.RUNTIME, icon: Activity, label: t('Run') },
  ];

  return (
    <div className="w-full py-8 px-4 transition-colors duration-300 bg-white border-b border-gray-300 dark:bg-dark-bg dark:border-gray-800">
      <div className="max-w-5xl mx-auto">
        <h3 className="mb-6 text-sm font-bold text-center uppercase tracking-wider text-gray-600 dark:text-gray-400">
          {t('Secure Container Lifecycle')}
        </h3>
        <div className="flex flex-col items-center justify-center gap-4 md:flex-row relative">
          
          {phases.map((phase, idx) => {
             const Icon = phase.icon;
             const isActive = currentPhase === phase.id;
             
             return (
               <React.Fragment key={phase.id}>
                 <button
                   onClick={() => onSelectPhase(phase.id)}
                   className={`
                     relative group flex flex-col items-center p-4 rounded-xl transition-all duration-300
                     w-full md:w-32 z-10 border
                     ${isActive 
                       ? 'bg-red-50 dark:bg-gradient-to-br dark:from-red-900/50 dark:to-red-900/10 border-red-500 shadow-md dark:shadow-[0_0_15px_rgba(238,0,0,0.3)]' 
                       : 'bg-white dark:bg-card-bg border-gray-300 dark:border-gray-700 hover:border-gray-400 dark:hover:border-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800'}
                   `}
                 >
                   <Icon 
                     className={`w-8 h-8 mb-2 transition-colors ${isActive ? 'text-sec-red dark:text-red-500' : 'text-gray-500 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-white'}`} 
                   />
                   <span className={`text-sm font-bold ${isActive ? 'text-sec-red dark:text-white' : 'text-gray-700 dark:text-gray-400 group-hover:text-gray-900 dark:group-hover:text-gray-200'}`}>
                     {phase.label}
                   </span>
                   
                   {/* Active Indicator Dot */}
                   {isActive && (
                     <span className="absolute -bottom-2 w-1.5 h-1.5 bg-sec-red dark:bg-red-500 rounded-full animate-pulse" />
                   )}
                 </button>
                 
                 {/* Arrow Connector (hide on last item) */}
                 {idx < phases.length - 1 && (
                   <div className="hidden text-gray-400 md:flex dark:text-gray-600">
                     <ArrowRight className="w-6 h-6" />
                   </div>
                 )}
                 {/* Mobile Arrow Connector */}
                 {idx < phases.length - 1 && (
                   <div className="flex my-2 rotate-90 text-gray-400 md:hidden dark:text-gray-600">
                     <ArrowRight className="w-6 h-6" />
                   </div>
                 )}
               </React.Fragment>
             );
          })}
        </div>
      </div>
    </div>
  );
};

export default PipelineVisualizer;