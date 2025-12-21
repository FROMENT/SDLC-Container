import React, { useState, useRef, useEffect } from 'react';
import { Sun, Moon, Monitor, Globe, ChevronDown, Check, Languages } from 'lucide-react';

export type ThemeMode = 'dark' | 'light' | 'system';
export type LangMode = 'en' | 'system';

interface Props {
  currentTheme: ThemeMode;
  onThemeChange: (theme: ThemeMode) => void;
  currentLang: LangMode;
  onLangChange: (lang: LangMode) => void;
}

export const SettingsMenu: React.FC<Props> = ({ currentTheme, onThemeChange, currentLang, onLangChange }) => {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const getThemeIcon = () => {
    switch (currentTheme) {
      case 'dark': return <Moon className="w-4 h-4" />;
      case 'light': return <Sun className="w-4 h-4" />;
      case 'system': return <Monitor className="w-4 h-4" />;
    }
  };

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 transition-colors border border-gray-200 dark:border-gray-700"
      >
        {getThemeIcon()}
        <span className="hidden sm:inline text-xs font-medium uppercase tracking-wider">Settings</span>
        <ChevronDown className={`w-3 h-3 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-56 rounded-xl bg-white dark:bg-card-bg border border-gray-200 dark:border-gray-700 shadow-xl z-50 overflow-hidden animate-fade-in">
          
          {/* Theme Section */}
          <div className="p-2 border-b border-gray-100 dark:border-gray-800">
            <div className="px-2 py-1.5 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Theme
            </div>
            <div className="space-y-1">
              {[
                { id: 'light', icon: Sun, label: 'Light (High Contrast)' },
                { id: 'dark', icon: Moon, label: 'Dark' },
                { id: 'system', icon: Monitor, label: 'System' }
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    onThemeChange(item.id as ThemeMode);
                    // Don't close immediately for better UX
                  }}
                  className={`w-full flex items-center justify-between px-2 py-2 text-sm rounded-lg transition-colors
                    ${currentTheme === item.id 
                      ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400' 
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'}
                  `}
                >
                  <div className="flex items-center gap-3">
                    <item.icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </div>
                  {currentTheme === item.id && <Check className="w-3 h-3" />}
                </button>
              ))}
            </div>
          </div>

          {/* Language Section */}
          <div className="p-2">
            <div className="px-2 py-1.5 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Language
            </div>
             <div className="space-y-1">
              <button
                  onClick={() => onLangChange('en')}
                  className={`w-full flex items-center justify-between px-2 py-2 text-sm rounded-lg transition-colors
                    ${currentLang === 'en' 
                      ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400' 
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'}
                  `}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-bold border border-current rounded px-1">EN</span>
                    <span>English (Default)</span>
                  </div>
                  {currentLang === 'en' && <Check className="w-3 h-3" />}
                </button>
                <button
                  onClick={() => onLangChange('system')}
                  className={`w-full flex items-center justify-between px-2 py-2 text-sm rounded-lg transition-colors
                    ${currentLang === 'system' 
                      ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400' 
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'}
                  `}
                >
                  <div className="flex items-center gap-3">
                     <Globe className="w-4 h-4" />
                    <span>System / Regional</span>
                  </div>
                  {currentLang === 'system' && <Check className="w-3 h-3" />}
                </button>
            </div>
          </div>

        </div>
      )}
    </div>
  );
};