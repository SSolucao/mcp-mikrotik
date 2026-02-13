import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const MCP_URL = process.env.MCP_URL ?? 'https://mcpmikrotik.supersolucao.com.br/mcp';
const MCP_TOKEN = process.env.MCP_TOKEN;

const MT_HOST = process.env.MT_HOST;
const MT_PORT = process.env.MT_PORT ? Number(process.env.MT_PORT) : 8728;
const MT_USER = process.env.MT_USER;
const MT_PASS = process.env.MT_PASS;

if (!MCP_TOKEN) {
  console.error('Missing MCP_TOKEN');
  process.exit(2);
}
if (!MT_HOST || !MT_USER || !MT_PASS) {
  console.error('Missing MT_HOST/MT_USER/MT_PASS');
  process.exit(2);
}

function parseToolText(result) {
  const text = result?.content?.find((c) => c?.type === 'text')?.text;
  if (!text) throw new Error('No text content from tool');
  return JSON.parse(text);
}

async function main() {
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), {
    requestInit: {
      headers: {
        Authorization: `Bearer ${MCP_TOKEN}`,
      },
    },
  });

  const client = new Client({ name: 'mcp-mikrotik-smoke', version: '0.0.0' });
  await client.connect(transport);

  const ident = await client.callTool({
    name: 'mikrotik__run',
    arguments: {
      conn: { host: MT_HOST, port: MT_PORT, user: MT_USER, password: MT_PASS, timeoutMs: 15000 },
      command: '/system/identity/print',
    },
  });

  const res = await client.callTool({
    name: 'mikrotik__run',
    arguments: {
      conn: { host: MT_HOST, port: MT_PORT, user: MT_USER, password: MT_PASS, timeoutMs: 15000 },
      command: '/system/resource/print',
    },
  });

  const identData = parseToolText(ident);
  const resData = parseToolText(res);

  const identityName = identData?.result?.[0]?.name ?? null;
  const version = resData?.result?.[0]?.version ?? null;

  console.log(JSON.stringify({ identityName, version, rawIdentity: identData, rawResource: resData }, null, 2));

  await client.close();
}

main().catch((err) => {
  console.error(err?.stack || String(err));
  process.exit(1);
});
