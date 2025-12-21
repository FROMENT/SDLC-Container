import React from 'react';
import { SDLCPhase } from '../types';
import { Shield, Box, Server, Activity, ArrowRight } from 'lucide-react';

interface Props {
  currentPhase: SDLCPhase | null;
  onSelectPhase: (phase: SDLCPhase) => void;
}

const PipelineVisualizer: React.FC<Props> = ({ currentPhase, onSelectPhase }) => {
  const phases = [
    { id: SDLCPhase.DESIGN, icon: Shield, label: 'Design' },
    { id: SDLCPhase.BUILD, icon: Box, label: 'Build' },
    { id: SDLCPhase.DEPLOY, icon: Server, label: 'Deploy' },
    { id: SDLCPhase.RUNTIME, icon: Activity, label: 'Run' },
  ];

  return (
    <div className="w-full py-8 px-4 bg-dark-bg border-b border-gray-800">
      <div className="max-w-5xl mx-auto">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-6 text-center">
          Secure Container Lifecycle
        </h3>
        <div className="flex flex-col md:flex-row items-center justify-center gap-4 relative">
          
          {phases.map((phase, idx) => {
             const Icon = phase.icon;
             const isActive = currentPhase === phase.id;
             
             return (
               <React.Fragment key={phase.id}>
                 <button
                   onClick={() => onSelectPhase(phase.id)}
                   className={`
                     relative group flex flex-col items-center p-4 rounded-xl transition-all duration-300
                     w-full md:w-32 z-10
                     ${isActive 
                       ? 'bg-gradient-to-br from-red-900/50 to-red-900/10 border-red-500 shadow-[0_0_15px_rgba(238,0,0,0.3)] border' 
                       : 'bg-card-bg border border-gray-700 hover:border-gray-500 hover:bg-gray-800'}
                   `}
                 >
                   <Icon 
                     className={`w-8 h-8 mb-2 transition-colors ${isActive ? 'text-red-500' : 'text-gray-400 group-hover:text-white'}`} 
                   />
                   <span className={`text-sm font-medium ${isActive ? 'text-white' : 'text-gray-400 group-hover:text-gray-200'}`}>
                     {phase.label}
                   </span>
                   
                   {/* Active Indicator Dot */}
                   {isActive && (
                     <span className="absolute -bottom-2 w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" />
                   )}
                 </button>
                 
                 {/* Arrow Connector (hide on last item) */}
                 {idx < phases.length - 1 && (
                   <div className="hidden md:flex text-gray-600">
                     <ArrowRight className="w-6 h-6" />
                   </div>
                 )}
                 {/* Mobile Arrow Connector */}
                 {idx < phases.length - 1 && (
                   <div className="flex md:hidden text-gray-600 rotate-90 my-2">
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
