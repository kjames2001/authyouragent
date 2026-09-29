#!/usr/bin/env node
/**
 * authyouragent-mcp - Node wrapper that launches the Python MCP server.
 *
 * This is a thin shim: it checks for the Python `authyouragent-mcp` command
 * and spawns it as a child process, passing stdin/stdout through for
 * JSON-RPC communication. Node-based MCP clients (Cursor, Windsurf, etc.)
 * can install this via `npx authyouragent-mcp` or `npm i -g authyouragent-mcp`.
 *
 * Requirements: Python 3.9+ and `pip install "authyouragent[mcp]"` must be
 * run first. This wrapper does not bundle Python.
 */

const { spawn } = require('child_process');

const cmd = process.platform === 'win32' ? 'authyouragent-mcp.exe' : 'authyouragent-mcp';

const child = spawn(cmd, [], {
  stdio: ['inherit', 'inherit', 'inherit'],
  env: process.env,
});

child.on('error', (err) => {
  if (err.code === 'ENOENT') {
    process.stderr.write(
      '\nauthyouragent-mcp: Python command not found.\n' +
      'Install it first: pip install "authyouragent[mcp]"\n' +
      'See https://authyouragent.com/docs/agents for details.\n\n'
    );
    process.exit(1);
  }
  process.stderr.write(`authyouragent-mcp: ${err.message}\n`);
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code || 0);
});