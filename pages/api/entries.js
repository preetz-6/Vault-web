import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const { data, error } = await supabase
    .from('vault_entries')
    .select('id, encrypted, category, updated_at')
    .order('updated_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.status(200).json({ entries: data });
}
