import { readFile } from 'node:fs/promises';

const PORTAINER_URL = process.env.PORTAINER_URL ?? 'https://portainer.supersolucao.com.br';
const USERNAME = process.env.PORTAINER_USERNAME;
const PASSWORD = process.env.PORTAINER_PASSWORD;

const STACK_NAME = process.env.PORTAINER_STACK_NAME ?? 'mcp-mikrotik';
const ENDPOINT_ID = process.env.PORTAINER_ENDPOINT_ID ? Number(process.env.PORTAINER_ENDPOINT_ID) : undefined;

const MIKROTIK_MCP_AUTH_TOKEN = process.env.MIKROTIK_MCP_AUTH_TOKEN;

if (!USERNAME || !PASSWORD) {
  console.error('Missing PORTAINER_USERNAME or PORTAINER_PASSWORD');
  process.exit(2);
}
if (!MIKROTIK_MCP_AUTH_TOKEN) {
  console.error('Missing MIKROTIK_MCP_AUTH_TOKEN');
  process.exit(2);
}

function url(path) {
  return new URL(path, PORTAINER_URL).toString();
}

async function portainerFetch(path, { method = 'GET', jwt, json } = {}) {
  const headers = {};
  if (jwt) headers['Authorization'] = `Bearer ${jwt}`;
  if (json !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(url(path), {
    method,
    headers,
    body: json !== undefined ? JSON.stringify(json) : undefined,
  });

  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const msg = typeof data === 'string' ? data : JSON.stringify(data);
    throw new Error(`Portainer API ${method} ${path} failed: ${res.status} ${res.statusText} ${msg}`);
  }
  return data;
}

async function main() {
  const auth = await portainerFetch('/api/auth', {
    method: 'POST',
    json: { Username: USERNAME, Password: PASSWORD },
  });

  const jwt = auth?.jwt;
  if (!jwt) throw new Error('No jwt returned from /api/auth');

  const endpoints = await portainerFetch('/api/endpoints', { jwt });
  if (!Array.isArray(endpoints) || endpoints.length === 0) {
    throw new Error('No endpoints returned by /api/endpoints');
  }

  const endpointId = ENDPOINT_ID ?? endpoints[0].Id;
  if (!endpointId) throw new Error('Could not resolve endpointId');

  const swarm = await portainerFetch(`/api/endpoints/${endpointId}/docker/swarm`, { jwt });
  const swarmId = swarm?.ID;
  if (!swarmId) throw new Error('Could not resolve SwarmID from /docker/swarm');

  let stackFile = await readFile(new URL('../deploy/stack.yml', import.meta.url), 'utf-8');
  stackFile = stackFile.replace(
    'MIKROTIK_MCP_AUTH_TOKEN=troque_por_um_token_forte',
    `MIKROTIK_MCP_AUTH_TOKEN=${MIKROTIK_MCP_AUTH_TOKEN}`,
  );

  const stacks = await portainerFetch('/api/stacks', { jwt });
  const existing = Array.isArray(stacks)
    ? stacks.find((s) => (s?.Name ?? '').toLowerCase() === STACK_NAME.toLowerCase())
    : undefined;

  if (existing?.Id) {
    await portainerFetch(`/api/stacks/${existing.Id}?endpointId=${endpointId}`, {
      method: 'PUT',
      jwt,
      json: {
        StackFileContent: stackFile,
        Env: existing.Env ?? [],
        Prune: true,
      },
    });

    console.log(JSON.stringify({ action: 'updated', stackId: existing.Id, endpointId, swarmId }, null, 2));
    return;
  }

  const created = await portainerFetch(`/api/stacks/create/swarm/string?endpointId=${endpointId}`, {
    method: 'POST',
    jwt,
    json: {
      Name: STACK_NAME,
      SwarmID: swarmId,
      StackFileContent: stackFile,
      Env: [],
    },
  });

  console.log(JSON.stringify({ action: 'created', created, endpointId, swarmId }, null, 2));
}

main().catch((err) => {
  console.error(err?.stack || String(err));
  process.exit(1);
});
