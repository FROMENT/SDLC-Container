import React, { useEffect, useState, useMemo } from 'react';
import { ShieldCheck, Activity, Lock, Box, FileCode, Server, Radar } from 'lucide-react';
import { SDLCPhase } from '../types';

interface Props {
  phase: SDLCPhase;
  translate?: (key: string) => string;
}

export const CyberScanner: React.FC<Props> = ({ phase, translate }) => {
  const [currentMonthName, setCurrentMonthName] = useState('');
  const [monthIndex, setMonthIndex] = useState(0);
  
  useEffect(() => {
    const date = new Date();
    setCurrentMonthName(date.toLocaleString('default', { month: 'long' }).toUpperCase());
    setMonthIndex(date.getMonth());
  }, []);

  const t = translate || ((k: string) => k);

  // Configuration map for each phase
  const config = {
    [SDLCPhase.DESIGN]: {
      title: 'ARCH',
      color: 'text-blue-600 dark:text-cyan-400',
      stroke: 'stroke-blue-600 dark:stroke-cyan-400',
      icon: FileCode,
      status: 'OK'
    },
    [SDLCPhase.BUILD]: {
      title: 'IMG',
      color: 'text-yellow-600 dark:text-yellow-400',
      stroke: 'stroke-yellow-600 dark:stroke-yellow-400',
      icon: Box,
      status: '0'
    },
    [SDLCPhase.DEPLOY]: {
      title: 'GATE',
      color: 'text-orange-600 dark:text-orange-500',
      stroke: 'stroke-orange-600 dark:stroke-orange-500',
      icon: Server,
      status: 'ACT'
    },
    [SDLCPhase.RUNTIME]: {
      title: 'SYS',
      color: 'text-red-600 dark:text-red-500',
      stroke: 'stroke-red-600 dark:stroke-red-500',
      icon: Activity,
      status: 'SEC'
    }
  }[phase] || {
    title: 'SCAN',
    color: 'text-gray-500 dark:text-gray-400',
    stroke: 'stroke-gray-500 dark:stroke-gray-400',
    icon: ShieldCheck,
    status: 'IDLE'
  };

  // Procedural Geometry Generation based on Month
  const wireframe = useMemo(() => {
    // 3 to 8 sides based on month
    // Month 0 (Jan) -> 3 sides
    // Month 11 (Dec) -> 8 sides (wrapping logic if needed, here we just mod)
    const sides = 3 + (monthIndex % 6); 
    const center = 50;
    const radius = 30;
    
    // Calculate vertices for a regular polygon
    const vertices = [];
    for (let i = 0; i < sides; i++) {
        const angle = (i * 2 * Math.PI) / sides - (Math.PI / 2); // Start at top
        vertices.push({
            x: center + radius * Math.cos(angle),
            y: center + radius * Math.sin(angle)
        });
    }

    // Create path data connecting vertices
    const pathD = vertices.map((v, i) => 
        `${i === 0 ? 'M' : 'L'} ${v.x.toFixed(1)} ${v.y.toFixed(1)}`
    ).join(' ') + ' Z';

    // Create inner connections (wireframe look)
    const innerLines = vertices.map(v => 
        `M ${center} ${center} L ${v.x.toFixed(1)} ${v.y.toFixed(1)}`
    ).join(' ');

    return { pathD, innerLines, sides };
  }, [monthIndex]);

  return (
    <div className="mt-8 border border-gray-300 dark:border-gray-800 bg-white dark:bg-black p-3 max-w-[200px] mx-auto transition-colors duration-300">
        
        {/* Header - Wireframe Style */}
        <div className="flex justify-between items-center border-b border-gray-200 dark:border-gray-800 pb-2 mb-2">
            <span className="text-[10px] font-mono tracking-widest text-gray-500 dark:text-gray-400">{config.title}.EXE</span>
            <span className="text-[8px] font-mono text-gray-400 dark:text-gray-600">{currentMonthName}</span>
        </div>

        {/* Viewport */}
        <div className="relative aspect-square w-full bg-gray-50 dark:bg-gray-900 overflow-hidden border border-gray-200 dark:border-gray-800 flex items-center justify-center">
            
            {/* Retro Grid Background */}
            <div className="absolute inset-0" 
                 style={{ 
                    backgroundImage: 'linear-gradient(rgba(100,100,100,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(100,100,100,0.1) 1px, transparent 1px)',
                    backgroundSize: '10px 10px'
                 }}>
            </div>

            {/* Procedural Rotating Wireframe */}
            <svg viewBox="0 0 100 100" className="w-full h-full animate-[spin_10s_linear_infinite]">
                {/* Main Polygon */}
                <path 
                    d={wireframe.pathD} 
                    fill="none" 
                    className={`${config.stroke} opacity-80`}
                    strokeWidth="1"
                    vectorEffect="non-scaling-stroke"
                />
                
                {/* Inner Spokes */}
                <path 
                    d={wireframe.innerLines} 
                    stroke="currentColor" 
                    className={`${config.color} opacity-30`}
                    strokeWidth="0.5"
                    vectorEffect="non-scaling-stroke"
                />

                {/* Pulsing Nodes at vertices */}
                {/* Note: We can't map inside SVG easily without re-calculating points, so we rely on the paths */}
            </svg>
            
            {/* Overlay Scanline */}
            <div className="absolute inset-0 bg-gradient-to-b from-transparent via-current to-transparent opacity-5 animate-scan pointer-events-none text-white dark:text-green-400 h-[20%]"></div>
        </div>

        {/* Footer Stats */}
        <div className="mt-2 flex justify-between items-center font-mono text-[9px]">
            <div className="flex flex-col">
                <span className="text-gray-400">POLY.COUNT</span>
                <span className={`font-bold ${config.color}`}>{wireframe.sides}</span>
            </div>
            <div className="flex flex-col text-right">
                <span className="text-gray-400">STATUS</span>
                <span className={`font-bold ${config.color} animate-pulse`}>{config.status}</span>
            </div>
        </div>

    </div>
  );
};