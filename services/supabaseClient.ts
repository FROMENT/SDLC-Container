import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://plsuhpgvfsmhhcztvtby.supabase.co';
const SUPABASE_KEY = 'sb_publishable__bCGPRyx83rbi1-dfb8wsg_8PVeZ8l6';

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

export interface Review {
  id?: number;
  name: string;
  rating: number;
  comment: string;
  created_at?: string;
}
