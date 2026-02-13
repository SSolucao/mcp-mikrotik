// Debug helper for Portainer API routing.
// Usage:
// PORTAINER_URL=https://portainer.example.com PORTAINER_USERNAME=... PORTAINER_PASSWORD=... node scripts/portainer_probe.mjs

const base = process.env.PORTAINER_URL;
const user = process.env.PORTAINER_USERNAME;
const pass = process.env.PORTAINER_PASSWORD;

if (!base || !user || !pass) {
  console.error('Missing PORTAINER_URL/PORTAINER_USERNAME/PORTAINER_PASSWORD');
  process.exit(2);
}

async function req(path, method = 'GET', body) {
  const auth = await fetch(base + '/api/auth', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ Username: user, Password: pass }),
  });
  const aj = await auth.json();
  const jwt = aj.jwt;

  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${jwt}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  console.log(`\n### ${method} ${path} => ${res.status} ${res.statusText}`);
  console.log(text.slice(0, 800));
}

await req('/api/endpoints');
await req('/api/stacks');
