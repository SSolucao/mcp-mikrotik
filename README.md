# MCP MikroTik

Servidor MCP para executar comandos via RouterOS API (MikroTik).

## Multi-tenant (dinamico por agente)

Este MCP e **multi-tenant**: `host/porta/usuario/senha` sao enviados no input de cada tool.

## Transporte MCP (HTTP remoto)

Variaveis:

- `MIKROTIK_MCP_TRANSPORT`: `http` (padrao) ou `stdio`
- `MIKROTIK_MCP_HOST`: bind host (padrao `0.0.0.0`)
- `MIKROTIK_MCP_PORT`: porta (padrao `3333`)
- `MIKROTIK_MCP_PATH`: path MCP (padrao `/mcp`)
- `MIKROTIK_MCP_AUTH_TOKEN`: token obrigatorio no modo HTTP

Healthcheck:

- `GET /healthz` => `ok`

Auth esperado:

```http
Authorization: Bearer <MIKROTIK_MCP_AUTH_TOKEN>
```

## Tools

### `mikrotik__run` (modo livre)

Executa qualquer comando RouterOS API (pode retornar payload grande).

Input:

```json
{
  "conn": {
    "host": "10.0.0.1",
    "port": 8728,
    "user": "admin",
    "password": "senha",
    "timeoutMs": 45000
  },
  "command": "/system/resource/print",
  "words": []
}
```

Observacao: `words` sao as "palavras" cruas do protocolo API (ex.: `=.proplist=...`, `=numbers=*1`, `=disabled=yes`, `?=chain=input`).

### `mikrotik__print` (economia de tokens)

Helper para `/<resource>/print` com:

- `proplist` para limitar campos
- `where`/`queryWords` para filtrar
- `maxItems` para truncar o retorno

### Listagens prontas (token-friendly)

- `mikrotik__firewall_filter_list`
- `mikrotik__firewall_mangle_list`
- `mikrotik__firewall_nat_list`

### Info do sistema

- `mikrotik__system_identity_get`
- `mikrotik__system_resource_get`

### `mikrotik__examples`

Retorna exemplos prontos de payload.

## Dev

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
npm start
```

## Deploy (Portainer/Swarm + Traefik)

Template: `deploy/stack.yml`.
