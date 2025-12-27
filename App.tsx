import React, { useState, useEffect } from 'react';
import { SDLCPhase, ModuleItem, NewsContentState } from './types';
import { getCurriculum, ICONS, DEFAULT_GIT_CONFIG } from './constants';
import { generateNewsUpdate } from './services/geminiService';
import { GitHubConfig, AppState, saveToGitHub, loadFromGitHub } from './services/githubService';
import { secureStorage } from './services/secureStorage';
import PipelineVisualizer from './components/PipelineVisualizer';
import { MarkdownRenderer } from './components/MarkdownRenderer';
import { ChatAssistant } from './components/ChatAssistant';
import { SecurityGateIllustration } from './components/SecurityGateIllustration';
import { NetworkPolicyIllustration } from './components/NetworkPolicyIllustration';
import { PolicyWizard } from './components/PolicyWizard';
import { CyberScanner } from './components/CyberScanner';
import { StrideGenerator } from './components/StrideGenerator';
import { SettingsMenu, ThemeMode, LangMode } from './components/SettingsMenu';
import { GitHubSyncModal } from './components/GitHubSyncModal';
import { AboutPage } from './components/AboutPage';
import { ShieldAlert, Info, Menu, ChevronRight, Container, Radio, Sparkles, ShoppingBag, ExternalLink, Eye, Cloud, Info as InfoIcon } from 'lucide-react';

type ViewMode = 'app' | 'about';

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

  // --- Secure State Helper for GitHub Config ---
  const useSecureState = <T,>(key: string, defaultValue: T): [T, React.Dispatch<React.SetStateAction<T>>] => {
      const [state, setState] = useState<T>(() => secureStorage.getItem(key, defaultValue));
      useEffect(() => {
          secureStorage.setItem(key, state);
      }, [key, state]);
      return [state, setState];
  };

  // --- State Management ---
  const [activePhase, setActivePhase] = usePersistentState<SDLCPhase>('app_activePhase', SDLCPhase.DESIGN);
  // We store ID, not the object, so we can switch langs easily
  // Note: CURRICULUM ids must be identical in both langs
  const [activeModuleId, setActiveModuleId] = usePersistentState<string>('app_activeModuleId', 'base-images');
  
  // View Counts is now managed via API, not local persistence (though state is kept for UI)
  const [viewCounts, setViewCounts] = useState<Record<string, number>>({});
  
  const [currentView, setCurrentView] = useState<ViewMode>('app');

  // Theme & Language State
  const [theme, setTheme] = usePersistentState<ThemeMode>('app_theme', 'dark');
  const [lang, setLang] = usePersistentState<LangMode>('app_lang', 'en');

  // Resolve actual language string (en or fr)
  const currentLangCode = lang === 'system' 
    ? (navigator.language.startsWith('fr') ? 'fr' : 'en') 
    : lang;

  // Get localized curriculum
  const CURRICULUM = getCurriculum(currentLangCode);

  // GitHub Sync State - Uses Secure Storage
  const [gitConfig, setGitConfig] = useSecureState<GitHubConfig>('app_gitConfig', {
    token: DEFAULT_GIT_CONFIG.token || '', 
    owner: DEFAULT_GIT_CONFIG.owner, 
    repo: DEFAULT_GIT_CONFIG.repo, 
    path: DEFAULT_GIT_CONFIG.path,
    branch: DEFAULT_GIT_CONFIG.branch
  });
  
  const [isSyncModalOpen, setIsSyncModalOpen] = useState(false);

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

  // --- View Counter Effect (Public API) ---
  useEffect(() => {
    if (activeModuleId && currentView === 'app') {
      const fetchViewCount = async () => {
        try {
          // Namespace: Unique to this application demo
          const NAMESPACE = 'container-security-sdlc-demo-v1';
          const KEY = activeModuleId;
          
          // Call the public counter API (increments the count)
          const response = await fetch(`https://api.counterapi.dev/v1/${NAMESPACE}/${KEY}/up`);
          
          if (response.ok) {
            const data = await response.json();
            // Offset Logic: Start visually at 10
            // If API returns 1, we show 11.
            const offsetCount = (data.count || 0) + 10;
            
            setViewCounts(prev => ({
              ...prev,
              [activeModuleId]: offsetCount
            }));
          }
        } catch (error) {
          console.warn('Could not fetch view count from external API', error);
          // Fallback: Just increment local state conceptually or leave as is
        }
      };

      fetchViewCount();
    }
  }, [activeModuleId, currentView]); 

  // --- Translation Helper (UI Shell Only) ---
  const t = (key: string): string => {
    if (currentLangCode === 'en') return key;

    const dict: Record<string, string> = {
      // General
      'AI-Powered News': 'Actualités IA',
      'Live Security Intelligence': 'Veille Sécurité en Temps Réel',
      'Fetching latest updates...': 'Recherche des mises à jour...',
      'No updates available.': 'Aucune mise à jour disponible.',
      'DevSecOps & K8s Best Practices': 'Bonnes Pratiques DevSecOps & K8s',
      'Security Pro Tip': 'Conseil de Sécurité',
      'Modules': 'Modules',
      'Views': 'Vues',
      'Copyright': 'Guide de Sécurité des Conteneurs.',
      
      // Phases
      'Secure Container Lifecycle': 'Cycle de vie des conteneurs',
      'Design': 'Conception',
      'Build': 'Build', // "Build" is common in FR tech
      'Deploy': 'Déploiement',
      'Run': 'Runtime', // "Runtime" is common in FR tech
      
      // Phase Enum (Manual mapping because enum keys are English)
      'Design & Base Images': 'Design & Images de Base',
      'Build & Registry': 'Build & Registre',
      'Deployment & Config': 'Déploiement & Config',
      'Runtime & Monitoring': 'Runtime & Monitoring',

      // Merch
      'Shop Merch': 'Boutique',
      'Get the Kitten Tee': 'T-Shirt Chat Japonais',

      // About Page
      'About Container Security Guide': 'À propos du Guide de Sécurité',
      'Executive Summary': 'Résumé Exécutif',
      'Stop Saying "Passer la Sécurité"': 'Arrêtez de dire "Passer la Sécurité"',
      'Analysis & Improvement Roadmap': 'Analyse & Roadmap',
      'Current Gaps': 'Lacunes Actuelles',
      'Incoming Improvements (Secure by Design)': 'Améliorations à Venir (Secure by Design)',
      'Back to Dashboard': 'Retour au Tableau de Bord',
      'An interactive platform designed to bridge the gap between DevOps agility and Security rigor.': 'Une plateforme interactive conçue pour combler le fossé entre l\'agilité DevOps et la rigueur de la Sécurité.',
      'This application serves as a comprehensive "Secure Software Development Life Cycle" (SSDLC) guide tailored for': 'Cette application sert de guide complet "Secure Software Development Life Cycle" (SSDLC) adapté pour',
      'and Kubernetes environments. It provides actionable guidance to harden your supply chain from the first line of code to runtime execution.': 'et les environnements Kubernetes. Elle fournit des conseils exploitables pour durcir votre supply chain de la première ligne de code à l\'exécution runtime.',
      'Holistic Approach:': 'Approche Holistique :',
      'Covers Design, Build, Deploy, and Runtime phases.': 'Couvre les phases de Design, Build, Déploiement et Runtime.',
      'East-West Protection:': 'Protection Est-Ouest :',
      'Dedicated focus on OpenShift Network Policies and microsegmentation.': 'Focus dédié sur les Network Policies OpenShift et la microsegmentation.',
      'AI Integration:': 'Intégration IA :',
      'Uses Google Gemini for real-time security news and threat analysis.': 'Utilise Google Gemini pour les actualités de sécurité en temps réel et l\'analyse de menaces.',
      'Persistence:': 'Persistance :',
      'Syncs your learning progress via GitHub API.': 'Synchronise votre progression via l\'API GitHub.',
      'I am constantly surprised that in': 'Je suis constamment surpris qu\'en',
      ', we still hear the phrase': ', nous entendons encore la phrase',
      '(We need to pass security).': '(Il faut qu\'on passe la sécurité).',
      'Security is not a checkpoint, a toll booth, or a "gate" you trick to get your code into production.': 'La sécurité n\'est pas un point de contrôle, un péage ou une "porte" que vous trompez pour mettre votre code en production.',
      'It is a quality attribute of your software, just like performance or reliability.': 'C\'est un attribut de qualité de votre logiciel, tout comme la performance ou la fiabilité.',
      'When you say "pass security," you imply it\'s an obstacle. This mindset leads to vulnerabilities. You don\'t "pass" stability; you build stable software.': 'Quand vous dites "passer la sécurité", vous impliquez que c\'est un obstacle. Cet état d\'esprit mène aux vulnérabilités. Vous ne "passez" pas la stabilité; vous construisez des logiciels stables.',
      'We must build': 'Nous devons construire des logiciels',
      'software.': '.',
      'Static Policy Generation:': 'Génération de Politique Statique :',
      'Users learn about OPA/Kyverno but have to write YAML manually.': 'Les utilisateurs apprennent OPA/Kyverno mais doivent écrire le YAML manuellement.',
      'Limited Hands-on Labs:': 'Labs Pratiques Limités :',
      'The app explains concepts but lacks an embedded terminal for actual `kubectl` commands.': 'L\'app explique les concepts mais manque d\'un terminal intégré pour les vraies commandes `kubectl`.',
      'Supply Chain Visualization:': 'Visualisation Supply Chain :',
      'We mention SBOMs, but we don\'t visualize the dependency graph.': 'Nous mentionnons les SBOMs, mais nous ne visualisons pas le graphe de dépendance.',
      'Policy-as-Code Wizard': 'Assistant Policy-as-Code',
      'A visual generator that creates `ClusterPolicy` (Kyverno) or Rego (OPA) rules based on user-selected checkboxes (e.g., "Disallow Root", "Require Probes").': 'Un générateur visuel qui crée des règles `ClusterPolicy` (Kyverno) ou Rego (OPA) basées sur des cases à cocher (ex: "Interdire Root", "Exiger Probes").',
      'Automated Dependency Graph': 'Graphe de Dépendance Automatisé',
      'Upload a `package.json` or `go.mod`, and the app will visualize the attack surface and highlight vulnerable transitive dependencies using OSV.dev API.': 'Uploadez un `package.json` ou `go.mod`, et l\'app visualisera la surface d\'attaque et surlignera les dépendances transitives vulnérables via l\'API OSV.dev.',
      '"Invisible Security" Mode': 'Mode "Sécurité Invisible"',
      'Demonstrating eBPF (Tetragon) profiles that enforce security at the kernel level, requiring zero code changes from developers.': 'Démonstration de profils eBPF (Tetragon) qui appliquent la sécurité au niveau noyau, ne nécessitant aucun changement de code des développeurs.',

      // Feedback
      'Community Feedback': 'Retours de la Communauté',
      'Leave a Review': 'Laisser un Avis',
      'Name': 'Nom',
      'Rating': 'Note',
      'Comment': 'Commentaire',
      'Submit Review': 'Envoyer l\'Avis',
      'Please fill in all fields.': 'Veuillez remplir tous les champs.',
      'Failed to submit review.': 'Échec de l\'envoi de l\'avis.',
      'No reviews yet. Be the first!': 'Aucun avis pour l\'instant. Soyez le premier !',
      'Unable to load reviews.': 'Impossible de charger les avis.',
      "Check if 'reviews' table exists in Supabase.": "Vérifiez si la table 'reviews' existe dans Supabase.",

      // Settings
      'Settings': 'Paramètres',
      'Theme': 'Thème',
      'Language': 'Langue',
      'Light (High Contrast)': 'Clair (Haut Contraste)',
      'Dark': 'Sombre',
      'System': 'Système',
      'System / Regional': 'Système / Régional',
      'English (Default)': 'Anglais (Défaut)',

      // GitHub Sync
      'GitHub Sync Storage': 'Stockage Sync GitHub',
      'Sync your progress (Modules, Views, Settings) to a GitHub repository to use across devices.': 'Synchronisez votre progression (Modules, Vues, Paramètres) vers un dépôt GitHub pour l\'utiliser sur tous vos appareils.',
      'Personal Access Token (PAT)': 'Personal Access Token (PAT)',
      'Clear Token': 'Effacer le Token',
      'Required Scope': 'Scope Requis',
      'Secure Storage': 'Stockage Sécurisé',
      'Your token is now encrypted/obfuscated before being saved to this device. It is safe from casual inspection.': 'Votre token est maintenant chiffré/obfusqué avant d\'être sauvegardé sur cet appareil. Il est protégé contre l\'inspection occasionnelle.',
      'Owner': 'Propriétaire',
      'Repo Name': 'Nom du Dépôt',
      'File Path': 'Chemin du Fichier',
      'Save Configuration': 'Sauvegarder la Configuration',
      'PUSH (Save)': 'PUSH (Sauver)',
      'PULL (Load)': 'PULL (Charger)',
      'Processing...': 'Traitement...',
      'Configuration saved securely.': 'Configuration sauvegardée de manière sécurisée.',
      'Token removed from secure storage.': 'Token supprimé du stockage sécurisé.',
      'Data successfully pushed to GitHub!': 'Données poussées avec succès vers GitHub !',
      'Data restored from GitHub!': 'Données restaurées depuis GitHub !',
      'Operation failed': 'Échec de l\'opération',

      // Network Policy Illustration
      'Network Traffic Visualization': 'Visualisation du Trafic Réseau',
      'Current: Flat Network (Insecure)': 'Actuel : Réseau Plat (Non Sécurisé)',
      'Current: Microsegmentation (Zero Trust)': 'Actuel : Microsegmentation (Zero Trust)',
      'Flat Network': 'Réseau Plat',
      'Microsegmentation': 'Microsegmentation',
      'Security Alert: Lateral Movement Possible': 'Alerte Sécurité : Mouvement Latéral Possible',
      'Policy Enforced: Zero Trust': 'Politique Appliquée : Zero Trust',
      'In a flat network, if the Frontend is compromised, the attacker can directly access the Database and Admin panel.': 'Dans un réseau plat, si le Frontend est compromis, l\'attaquant peut accéder directement à la Base de Données et au panneau Admin.',
      'Network Policies block all traffic by default. Only specific, allowed connections (Frontend -> Backend) are permitted.': 'Les Network Policies bloquent tout le trafic par défaut. Seules les connexions spécifiques autorisées (Frontend -> Backend) sont permises.',
    };

    return dict[key] || key;
  };

  // --- Git Sync Handlers ---
  const handleGitPush = async () => {
    const appData: AppState = {
      activePhase,
      activeModuleId,
      viewCounts,
      theme,
      lang: lang as string,
      lastUpdated: Date.now()
    };
    await saveToGitHub(gitConfig, appData);
  };

  const handleGitPull = async () => {
    const data = await loadFromGitHub(gitConfig);
    if (data) {
      if (data.activePhase) setActivePhase(data.activePhase as SDLCPhase);
      if (data.activeModuleId) setActiveModuleId(data.activeModuleId);
      if (data.viewCounts) setViewCounts(data.viewCounts);
      if (data.theme) setTheme(data.theme as ThemeMode);
      if (data.lang) setLang(data.lang as LangMode);
    }
  };

  // Filter modules by active phase
  // Note: activePhase enum values are "Design & Base Images", etc. We must translate them for display but use raw for filter.
  // Wait, the CURRICULUM objects have `phase` property matching the Enum.
  const phaseModules = CURRICULUM.filter(m => m.phase === activePhase);
  const activeModule = CURRICULUM.find(m => m.id === activeModuleId);

  // Load news content when module changes
  useEffect(() => {
    const loadNews = async () => {
      if (!activeModule || currentView !== 'app') return;
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
  }, [activeModuleId, activeModule, newsContent, currentView]);

  // Handle phase change
  const handlePhaseChange = (phase: SDLCPhase) => {
    setActivePhase(phase);
    // Find the first module in this phase from the CURRENT curriculum
    const firstModule = CURRICULUM.find(m => m.phase === phase);
    if (firstModule) {
      setActiveModuleId(firstModule.id);
    }
  };

  const ActiveIcon = ICONS[activePhase] || Info;

  return (
    <div className="min-h-screen flex flex-col transition-colors duration-300 bg-gray-100 text-gray-900 dark:bg-dark-bg dark:text-gray-200">
      
      {/* Git Modal */}
      <GitHubSyncModal 
        isOpen={isSyncModalOpen}
        onClose={() => setIsSyncModalOpen(false)}
        config={gitConfig}
        onSaveConfig={setGitConfig}
        onPush={handleGitPush}
        onPull={handleGitPull}
        translate={t}
      />

      {/* Navbar */}
      <header className="sticky top-0 z-30 transition-colors duration-300 bg-white border-b border-gray-300 dark:bg-sec-black dark:border-gray-800 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div 
              className="flex items-center gap-3 cursor-pointer" 
              onClick={() => setCurrentView('app')}
            >
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
              
              <button 
                onClick={() => setCurrentView('about')}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-colors border border-transparent
                  ${currentView === 'about' ? 'bg-gray-200 dark:bg-gray-800 text-sec-red' : 'hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-700 dark:text-gray-300'}
                `}
                title={t('About Container Security Guide')}
              >
                <InfoIcon className="w-4 h-4" />
              </button>

              <button 
                onClick={() => setIsSyncModalOpen(true)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 transition-colors border border-gray-200 dark:border-gray-700"
                title={t('GitHub Sync Storage')}
              >
                <Cloud className="w-4 h-4" />
              </button>

              <SettingsMenu 
                currentTheme={theme} 
                onThemeChange={setTheme}
                currentLang={lang}
                onLangChange={setLang}
                translate={t}
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

      {currentView === 'about' ? (
        <AboutPage onBack={() => setCurrentView('app')} translate={t} />
      ) : (
        <>
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
                  {t(activePhase)} {t('Modules')}
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
                          <Eye className="w-3 h-3" /> {viewCounts[module.id] || 10}
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
                        <span className="text-2xl font-mono font-bold text-sec-red">{viewCounts[activeModule.id] || 10}</span>
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
                  {activeModuleId === 'deployment-gates' && (
                    <>
                      <SecurityGateIllustration />
                      <PolicyWizard />
                    </>
                  )}
                  {activeModuleId === 'threat-modeling' && <StrideGenerator />}
                  {activeModuleId === 'network-policies' && <NetworkPolicyIllustration translate={t} />}

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
        </>
      )}

      <ChatAssistant lang={currentLangCode} />
      
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