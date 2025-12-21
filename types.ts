export enum SDLCPhase {
  DESIGN = 'Design & Base Images',
  BUILD = 'Build & Registry',
  DEPLOY = 'Deployment & Config',
  RUNTIME = 'Runtime & Monitoring'
}

export interface ModuleItem {
  id: string;
  title: string;
  phase: SDLCPhase;
  shortDesc: string;
  staticContent: string; // Core educational content (Static)
  newsContext: string;   // Context for AI to generate news (Dynamic)
  securityTip: string;   // Specific security tip for this module
}

export interface ChatMessage {
  role: 'user' | 'model';
  text: string;
  timestamp: number;
}

export interface NewsContentState {
  [moduleId: string]: string;
}