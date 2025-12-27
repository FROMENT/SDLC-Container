import { createClient } from '@supabase/supabase-js';

// Specific Project URL and Anon Key
const SUPABASE_URL = 'https://plsuhpgvfsmhhcztvtby.supabase.co/';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable__bCGPRyx83rbi1-dfb8wsg_8PVeZ8l6';

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

export interface Review {
  id?: number;
  created_at?: string;
  site_name: string; // Mandatory per schema
  rating: number;
  title: string;     // Mandatory per schema
  comment: string;
  name: string;
  alias?: string;
  email?: string;
}