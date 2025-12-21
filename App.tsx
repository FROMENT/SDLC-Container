import React, { useState, useEffect } from 'react';
import { SDLCPhase, ModuleItem, NewsContentState } from './types';
import { CURRICULUM, ICONS } from './constants';
import { generateNewsUpdate } from './services/geminiService';
import PipelineVisualizer from './components/PipelineVisualizer';
import { MarkdownRenderer } from './components/MarkdownRenderer';
import { ChatAssistant } from './components/ChatAssistant';
import { SecurityGateIllustration } from './components/SecurityGateIllustration';
import { ShieldAlert, Info, Menu, ChevronRight, Container, Radio, Sparkles } from 'lucide-react';

const App: React.FC = () => {
  const [activePhase, setActivePhase] = useState<SDLCPhase>(SDLCPhase.DESIGN);
  const [activeModuleId, setActiveModuleId] = useState<string>(CURRICULUM[0].id);
  
  // Separate state for news updates
  const [newsContent, setNewsContent] = useState<NewsContentState>({});
  const [isNewsLoading, setIsNewsLoading] = useState<boolean>(false);
  
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Filter modules by active phase
  const phaseModules = CURRICULUM.filter(m => m.phase === activePhase);
  const activeModule = CURRICULUM.find(m => m.id === activeModuleId);

  // Load news content when module changes
  useEffect(() => {
    const loadNews = async () => {
      if (!activeModule) return;
      
      // Return if already cached
      if (newsContent[activeModule.id]) return;

      setIsNewsLoading(true);
      const update = await generateNewsUpdate(activeModule.newsContext, activeModule.title);
      setNewsContent(prev => ({
        ...prev,
        [activeModule.id]: update
      }));
      setIsNewsLoading(false);
    };

    loadNews();
  }, [activeModuleId, activeModule, newsContent]);

  // Handle phase change
  const handlePhaseChange = (phase: SDLCPhase) => {
    setActivePhase(phase);
    // Find first module of this phase
    const firstModule = CURRICULUM.find(m => m.phase === phase);
    if (firstModule) {
      setActiveModuleId(firstModule.id);
    }
  };

  const ActiveIcon = ICONS[activePhase] || Info;

  return (
    <div className="min-h-screen bg-dark-bg flex flex-col text-gray-200">
      
      {/* Navbar */}
      <header className="bg-sec-black border-b border-gray-800 sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="bg-sec-red p-1.5 rounded">
                <Container className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white tracking-tight">
                  Container <span className="text-sec-red">Security</span>
                </h1>
                <p className="text-xs text-gray-400 -mt-1">DevSecOps & K8s Best Practices</p>
              </div>
            </div>
            
            <div className="hidden md:block">
              <span className="text-sm text-gray-400 bg-gray-900 px-3 py-1 rounded-full border border-gray-700 flex items-center gap-2">
                <Sparkles className="w-3 h-3 text-yellow-500" />
                AI-Powered News
              </span>
            </div>

            <button 
              className="md:hidden text-gray-400 hover:text-white"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              <Menu className="w-6 h-6" />
            </button>
          </div>
        </div>
      </header>

      {/* Pipeline Visualization */}
      <PipelineVisualizer 
        currentPhase={activePhase} 
        onSelectPhase={handlePhaseChange} 
      />

      <div className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col md:flex-row gap-8">
        
        {/* Sidebar / Module List */}
        <aside className={`
            md:w-64 flex-shrink-0 
            ${mobileMenuOpen ? 'block' : 'hidden'} md:block
          `}>
          <div className="sticky top-24">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">
              {activePhase} Modules
            </h3>
            <div className="space-y-2">
              {phaseModules.map(module => (
                <button
                  key={module.id}
                  onClick={() => {
                    setActiveModuleId(module.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`
                    w-full text-left px-4 py-3 rounded-lg transition-all duration-200 flex items-center justify-between group
                    ${activeModuleId === module.id 
                      ? 'bg-gray-800 text-white border-l-4 border-sec-red shadow-md' 
                      : 'hover:bg-gray-800/50 text-gray-400 hover:text-gray-200'}
                  `}
                >
                  <span className="text-sm font-medium">{module.title}</span>
                  {activeModuleId === module.id && <ChevronRight className="w-4 h-4 text-sec-red" />}
                </button>
              ))}
            </div>

            <div className="mt-8 p-4 bg-gray-900 rounded-xl border border-gray-800">
              <div className="flex items-center gap-2 text-yellow-500 mb-2">
                <ShieldAlert className="w-5 h-5" />
                <span className="font-bold text-sm">Security Tip</span>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">
                Always apply the principle of least privilege. Containers should essentially never run as root in production.
              </p>
            </div>
          </div>
        </aside>

        {/* Main Content Area */}
        <main className="flex-1 min-w-0 flex flex-col gap-8">
           
           {/* Static Content Section */}
           {activeModule && (
             <div className="bg-card-bg rounded-2xl border border-gray-800 p-6 md:p-8 shadow-2xl animate-fade-in">
               <div className="flex items-center gap-4 mb-8 border-b border-gray-700 pb-6">
                 <div className="p-3 bg-gray-900 rounded-lg">
                   <ActiveIcon className="w-8 h-8 text-sec-red" />
                 </div>
                 <div>
                   <h2 className="text-3xl font-bold text-white">
                     {activeModule.title}
                   </h2>
                   <p className="text-gray-400 mt-1">
                     {activeModule.shortDesc}
                   </p>
                 </div>
               </div>
               
               {/* Interactive Illustrations */}
               {activeModuleId === 'deployment-gates' && <SecurityGateIllustration />}

               {/* Render Static Markdown */}
               <div className="prose prose-invert max-w-none">
                 <MarkdownRenderer content={activeModule.staticContent} />
               </div>
             </div>
           )}

           {/* Dynamic News Section */}
           <div className="bg-gradient-to-br from-gray-900 to-black rounded-2xl border border-gray-800 p-6 md:p-8 shadow-lg relative overflow-hidden">
              <div className="absolute top-0 left-0 w-1 h-full bg-blue-500"></div>
              
              <div className="flex items-center gap-3 mb-6">
                 <Radio className={`w-5 h-5 text-blue-400 ${isNewsLoading ? 'animate-pulse' : ''}`} />
                 <h3 className="text-lg font-bold text-blue-100">Live Security Intelligence</h3>
                 {isNewsLoading && <span className="text-xs text-blue-400/70 animate-pulse">Fetching latest updates...</span>}
              </div>

              {isNewsLoading ? (
                 <div className="space-y-3 animate-pulse">
                   <div className="h-4 bg-gray-800 rounded w-3/4"></div>
                   <div className="h-4 bg-gray-800 rounded w-1/2"></div>
                   <div className="h-4 bg-gray-800 rounded w-5/6"></div>
                 </div>
              ) : (
                 <div className="prose prose-sm prose-invert max-w-none text-gray-300">
                    <MarkdownRenderer content={newsContent[activeModuleId] || 'No updates available.'} />
                 </div>
              )}
           </div>

        </main>
      </div>

      <ChatAssistant />
      
      {/* Footer */}
      <footer className="bg-sec-black border-t border-gray-800 py-8 mt-12">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-500 text-sm">
          <p>© {new Date().getFullYear()} Container Security Guide. Powered by Google Gemini.</p>
        </div>
      </footer>
    </div>
  );
};

export default App;