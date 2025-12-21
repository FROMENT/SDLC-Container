import React, { useState, useEffect } from 'react';
import { SDLCPhase, ModuleItem, NewsContentState } from './types';
import { CURRICULUM, ICONS } from './constants';
import { generateNewsUpdate } from './services/geminiService';
import PipelineVisualizer from './components/PipelineVisualizer';
import { MarkdownRenderer } from './components/MarkdownRenderer';
import { ChatAssistant } from './components/ChatAssistant';
import { SecurityGateIllustration } from './components/SecurityGateIllustration';
import { CyberScanner } from './components/CyberScanner';
import { StrideGenerator } from './components/StrideGenerator';
import { SettingsMenu, ThemeMode, LangMode } from './components/SettingsMenu';
import { ShieldAlert, Info, Menu, ChevronRight, Container, Radio, Sparkles, ShoppingBag, ExternalLink, Eye } from 'lucide-react';

const App: React.FC = () => {
  // --- Persistent State Initialization Helpers ---
  const getStoredItem = <T,>(key: string, defaultVal: T): T => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : defaultVal;
    } catch (error) {
      console.warn(`Error reading localStorage key "${key}":`, error);
      return defaultVal;
    }
  };

  const usePersistentState = <T,>(key: string, defaultValue: T): [T, React.Dispatch<React.SetStateAction<T>>] => {
    const [state, setState] = useState<T>(() => getStoredItem(key, defaultValue));
    useEffect(() => {
      window.localStorage.setItem(key, JSON.stringify(state));
    }, [key, state]);
    return [state, setState];
  };

  // --- State Management ---
  const [activePhase, setActivePhase] = usePersistentState<SDLCPhase>('app_activePhase', SDLCPhase.DESIGN);
  const [activeModuleId, setActiveModuleId] = usePersistentState<string>('app_activeModuleId', CURRICULUM[0].id);
  const [viewCounts, setViewCounts] = usePersistentState<Record<string, number>>('app_viewCounts', {});
  
  // Theme & Language State
  const [theme, setTheme] = usePersistentState<ThemeMode>('app_theme', 'dark');
  const [lang, setLang] = usePersistentState<LangMode>('app_lang', 'en');

  // Separate state for news updates (Not persisted to ensure freshness)
  const [newsContent, setNewsContent] = useState<NewsContentState>({});
  const [isNewsLoading, setIsNewsLoading] = useState<boolean>(false);
  
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // --- Theme Effect ---
  useEffect(() => {
    const root = window.document.documentElement;
    root.classList.remove('light', 'dark');

    if (theme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      root.classList.add(systemTheme);
    } else {
      root.classList.add(theme);
    }
  }, [theme]);

  // --- View Counter Effect ---
  useEffect(() => {
    if (activeModuleId) {
      setViewCounts(prev => ({
        ...prev,
        [activeModuleId]: (prev[activeModuleId] || 0) + 1
      }));
    }
  }, [activeModuleId]); // Intentionally not including setViewCounts to avoid loops, though stable ref

  // --- Translation Helper (UI Shell Only) ---
  const t = (key: string): string => {
    if (lang === 'en') return key;

    // Check system language
    const sysLang = navigator.language.split('-')[0];
    
    // Simple dictionary for non-technical UI terms
    const dict: Record<string, Record<string, string>> = {
      fr: {
        'AI-Powered News': 'Actualités IA',
        'Live Security Intelligence': 'Veille Sécurité en Temps Réel',
        'Fetching latest updates...': 'Recherche des mises à jour...',
        'No updates available.': 'Aucune mise à jour disponible.',
        'DevSecOps & K8s Best Practices': 'Bonnes Pratiques DevSecOps & K8s',
        'Security Pro Tip': 'Conseil de Sécurité',
        'Modules': 'Modules',
        'Secure Container Lifecycle': 'Cycle de vie des conteneurs',
        'Design': 'Conception',
        'Build': 'Construction',
        'Deploy': 'Déploiement',
        'Run': 'Exécution',
        'Copyright': 'Guide de Sécurité des Conteneurs.',
        'Shop Merch': 'Boutique',
        'Get the Kitten Tee': 'T-Shirt Chat Japonais',
        'Views': 'Vues'
      },
      es: {
        'AI-Powered News': 'Noticias IA',
        'Modules': 'Módulos',
        'Security Pro Tip': 'Consejo de Seguridad',
        'Views': 'Vistas'
      }
    };

    if (dict[sysLang] && dict[sysLang][key]) {
      return dict[sysLang][key];
    }
    return key;
  };

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
    <div className="min-h-screen flex flex-col transition-colors duration-300 bg-gray-100 text-gray-900 dark:bg-dark-bg dark:text-gray-200">
      
      {/* Navbar */}
      <header className="sticky top-0 z-30 transition-colors duration-300 bg-white border-b border-gray-300 dark:bg-sec-black dark:border-gray-800 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="p-1.5 rounded bg-sec-red">
                <Container className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight text-gray-900 dark:text-white">
                  Container <span className="text-sec-red">Security</span>
                </h1>
                <p className="text-xs -mt-1 text-gray-600 dark:text-gray-400">{t('DevSecOps & K8s Best Practices')}</p>
              </div>
            </div>
            
            <div className="hidden md:flex items-center gap-4">
              
              {/* Etsy Promo Link */}
              <a 
                href="https://www.etsy.com/fr/listing/4324702523/minimalist-japanese-kitten-t-shirt-stay?ref=shop_home_active_11&logging_key=1d0299ec772988e82dfecfc5abb10b2f3dbdafca%3A4324702523"
                target="_blank"
                rel="noopener noreferrer"
                className="group flex items-center gap-3 pr-4 border-r border-gray-300 dark:border-gray-700 hover:opacity-100 transition-opacity"
              >
                <div className="relative w-9 h-9 rounded-md overflow-hidden border border-gray-200 dark:border-gray-600 shadow-sm">
                  <img 
                    src="https://images.unsplash.com/photo-1574158622682-e40e69881006?w=100&h=100&fit=crop&q=80" 
                    alt="Kitten T-Shirt" 
                    className="object-cover w-full h-full transition-transform duration-300 group-hover:scale-110"
                  />
                </div>
                <div className="flex flex-col">
                  <span className="text-[10px] font-bold uppercase text-gray-400 group-hover:text-sec-red transition-colors flex items-center gap-1">
                    {t('Shop Merch')} <ExternalLink className="w-2 h-2" />
                  </span>
                  <span className="text-xs font-semibold text-gray-700 dark:text-gray-200">
                    {t('Get the Kitten Tee')}
                  </span>
                </div>
              </a>

              <span className="flex items-center gap-2 px-3 py-1 text-sm rounded-full border bg-gray-100 border-gray-300 text-gray-700 dark:bg-gray-900 dark:border-gray-700 dark:text-gray-400 font-medium">
                <Sparkles className="w-3 h-3 text-yellow-600 dark:text-yellow-500" />
                {t('AI-Powered News')}
              </span>
              
              <div className="h-6 w-px bg-gray-300 dark:bg-gray-700 mx-2"></div>
              
              <SettingsMenu 
                currentTheme={theme} 
                onThemeChange={setTheme}
                currentLang={lang}
                onLangChange={setLang}
              />
            </div>

            <button 
              className="md:hidden text-gray-700 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
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
        translate={t}
      />

      <div className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col md:flex-row gap-8">
        
        {/* Sidebar / Module List */}
        <aside className={`
            md:w-64 flex-shrink-0 
            ${mobileMenuOpen ? 'block' : 'hidden'} md:block
          `}>
          <div className="sticky top-24">
            <h3 className="mb-4 text-xs font-bold uppercase tracking-wider text-gray-600 dark:text-gray-500">
              {activePhase} {t('Modules')}
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
                      ? 'bg-white dark:bg-gray-800 text-gray-900 dark:text-white border-l-4 border-sec-red shadow-md dark:shadow-none ring-1 ring-gray-200 dark:ring-0' 
                      : 'hover:bg-gray-200 dark:hover:bg-gray-800/50 text-gray-700 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'}
                  `}
                >
                  <div className="flex flex-col">
                    <span className="text-sm font-medium">{module.title}</span>
                    <span className="text-[10px] text-gray-400 flex items-center gap-1 mt-1">
                      <Eye className="w-3 h-3" /> {viewCounts[module.id] || 0}
                    </span>
                  </div>
                  {activeModuleId === module.id && <ChevronRight className="w-4 h-4 text-sec-red" />}
                </button>
              ))}
            </div>

            {/* Futuristic Scanner Widget */}
            <CyberScanner phase={activePhase} translate={t} />

          </div>
        </aside>

        {/* Main Content Area */}
        <main className="flex-1 min-w-0 flex flex-col gap-8">
           
           {/* Static Content Section */}
           {activeModule && (
             <div className="p-6 transition-all duration-300 shadow-lg rounded-2xl md:p-8 animate-fade-in bg-white border border-gray-300 dark:bg-card-bg dark:border-gray-800">
               <div className="flex items-center justify-between mb-6 pb-6 border-b border-gray-200 dark:border-gray-700">
                 <div className="flex items-center gap-4">
                    <div className="p-3 rounded-lg bg-gray-100 dark:bg-gray-900">
                      <ActiveIcon className="w-8 h-8 text-sec-red" />
                    </div>
                    <div>
                      <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
                        {activeModule.title}
                      </h2>
                      <p className="mt-1 text-gray-700 dark:text-gray-400 font-medium">
                        {activeModule.shortDesc}
                      </p>
                    </div>
                 </div>
                 
                 {/* Counter Display */}
                 <div className="hidden sm:flex flex-col items-end text-gray-400">
                    <span className="text-xs uppercase tracking-wider">{t('Views')}</span>
                    <span className="text-2xl font-mono font-bold text-sec-red">{viewCounts[activeModule.id] || 1}</span>
                 </div>
               </div>
               
               {/* Dynamic Security Tip */}
               <div className="flex flex-col items-start gap-4 p-4 mb-8 border rounded-xl md:flex-row bg-yellow-50 border-yellow-300 dark:bg-yellow-900/10 dark:border-yellow-800/50">
                  <div className="flex-shrink-0 p-2 rounded-lg bg-yellow-100 dark:bg-yellow-500/10">
                    <ShieldAlert className="w-6 h-6 text-yellow-700 dark:text-yellow-500" />
                  </div>
                  <div>
                    <h4 className="mb-1 text-sm font-bold uppercase tracking-wider text-yellow-800 dark:text-yellow-500">
                      {t('Security Pro Tip')}
                    </h4>
                    <div className="text-sm leading-relaxed text-gray-900 dark:text-gray-300 font-medium">
                       <MarkdownRenderer content={activeModule.securityTip} />
                    </div>
                  </div>
               </div>

               {/* Interactive Illustrations */}
               {activeModuleId === 'deployment-gates' && <SecurityGateIllustration />}
               {activeModuleId === 'threat-modeling' && <StrideGenerator />}

               {/* Render Static Markdown */}
               <div className="prose max-w-none prose-gray dark:prose-invert text-gray-900 dark:text-gray-300">
                 <MarkdownRenderer content={activeModule.staticContent} />
               </div>
             </div>
           )}

           {/* Dynamic News Section */}
           <div className="relative p-6 overflow-hidden border shadow-lg rounded-2xl md:p-8 bg-white border-gray-300 dark:bg-card-bg dark:border-gray-800 transition-colors duration-300">
              <div className="absolute top-0 left-0 w-1 h-full bg-blue-600 dark:bg-blue-500"></div>
              
              <div className="flex items-center gap-3 mb-6">
                 <Radio className={`w-5 h-5 text-blue-700 dark:text-blue-400 ${isNewsLoading ? 'animate-pulse' : ''}`} />
                 <h3 className="text-lg font-bold text-gray-900 dark:text-white">{t('Live Security Intelligence')}</h3>
                 {isNewsLoading && <span className="text-xs animate-pulse text-blue-700 dark:text-blue-400/70">{t('Fetching latest updates...')}</span>}
              </div>

              {isNewsLoading ? (
                 <div className="space-y-3 animate-pulse">
                   <div className="w-3/4 h-4 rounded bg-gray-200 dark:bg-gray-800"></div>
                   <div className="w-1/2 h-4 rounded bg-gray-200 dark:bg-gray-800"></div>
                   <div className="w-5/6 h-4 rounded bg-gray-200 dark:bg-gray-800"></div>
                 </div>
              ) : (
                 <div className="prose prose-sm max-w-none prose-gray dark:prose-invert text-gray-900 dark:text-gray-300">
                    <MarkdownRenderer content={newsContent[activeModuleId] || t('No updates available.')} />
                 </div>
              )}
           </div>

        </main>
      </div>

      <ChatAssistant />
      
      {/* Footer */}
      <footer className="py-8 mt-12 transition-colors border-t bg-white border-gray-300 dark:bg-sec-black dark:border-gray-800">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-600 dark:text-gray-500 text-sm">
          <p>© {new Date().getFullYear()} {t('Copyright')} Pascal augmented by Google Gemini.</p>
        </div>
      </footer>
    </div>
  );
};

export default App;