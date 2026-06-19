const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  "https://nublqmgwcjtbldavyvyn.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im51YmxxbWd3Y2p0YmxkYXZ5dnluIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODE3NTAxNTUsImV4cCI6MjA5NzMyNjE1NX0.lWbWoPLsQeM5qN1gXRbauaNIPirIytExtgPuDZWdZMw"
);

async function check() {
  const { data, error } = await supabase.from('vault_entries').select('*');
  console.log('Error:', error);
  console.log('Data count:', data ? data.length : 0);
  console.log('Data:', JSON.stringify(data, null, 2));
}

check();
