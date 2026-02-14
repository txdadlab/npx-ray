/**
 * MCP configuration scanner for npx-ray.
 *
 * Scans known editor/tool configuration files for MCP (Model Context Protocol)
 * server entries that use npm packages. Discovers servers from Claude Desktop,
 * Cursor, VS Code, Claude Code, and Windsurf configurations.
 */

import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { McpServerEntry } from './types.js';

/**
 * Commands that indicate an npm-based MCP server.
 */
const NPM_COMMANDS = new Set(['npx', 'npx.exe', 'bunx', 'node']);

/**
 * Argument flags that should be skipped when searching for the package name.
 * These are npx/bunx flags that precede the actual package specifier.
 */
const SKIP_FLAGS = new Set(['-y', '--yes', '-p', '--package', '-q', '--quiet']);

/**
 * Get the list of MCP configuration file paths to check,
 * based on the current platform.
 */
function getConfigPaths(): Array<{ path: string; label: string }> {
  const home = homedir();
  const platform = process.platform;
  const paths: Array<{ path: string; label: string }> = [];

  // Claude Desktop
  if (platform === 'darwin') {
    paths.push({
      path: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      label: 'Claude Desktop',
    });
  } else if (platform === 'win32') {
    const appData = process.env.APPDATA || join(home, 'AppData', 'Roaming');
    paths.push({
      path: join(appData, 'Claude', 'claude_desktop_config.json'),
      label: 'Claude Desktop',
    });
  } else {
    // Linux
    paths.push({
      path: join(home, '.config', 'claude_desktop', 'claude_desktop_config.json'),
      label: 'Claude Desktop',
    });
  }

  // Cursor
  paths.push({
    path: join(home, '.cursor', 'mcp.json'),
    label: 'Cursor',
  });

  // VS Code (user-level)
  paths.push({
    path: join(home, '.vscode', 'mcp.json'),
    label: 'VS Code',
  });

  // Claude Code
  paths.push({
    path: join(home, '.claude.json'),
    label: 'Claude Code',
  });

  // Windsurf
  paths.push({
    path: join(home, '.windsurf', 'mcp.json'),
    label: 'Windsurf',
  });
  paths.push({
    path: join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    label: 'Windsurf (Codeium)',
  });

  return paths;
}

/**
 * Safely read and parse a JSON file.
 *
 * @returns Parsed JSON object, or `null` if the file doesn't exist or is invalid.
 */
async function readJsonFile(filePath: string): Promise<Record<string, unknown> | null> {
  try {
    const content = await readFile(filePath, 'utf-8');
    return JSON.parse(content) as Record<string, unknown>;
  } catch {
    // File doesn't exist, is unreadable, or contains invalid JSON — skip silently
    return null;
  }
}

/**
 * Extract the npm package name from a command's argument list.
 *
 * For `npx -y @anthropic-ai/mcp-server`, this returns `@anthropic-ai/mcp-server`.
 * For `node ./server.js`, this returns `undefined` (not an npm package).
 *
 * @param command - The command (e.g., "npx", "node").
 * @param args    - The argument list.
 * @returns The npm package specifier, or `undefined` if not npm-based.
 */
function extractNpmPackage(command: string, args: string[]): string | undefined {
  const baseCommand = command.replace(/\.exe$/, '');

  if (!NPM_COMMANDS.has(baseCommand)) {
    return undefined;
  }

  // For `node`, the first arg is typically a script path, not an npm package
  if (baseCommand === 'node') {
    return undefined;
  }

  // For npx/bunx, find the first non-flag argument
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    // Skip known flags
    if (SKIP_FLAGS.has(arg)) {
      // If this flag takes a value (e.g., --package <name>), skip the next arg too
      if (arg === '-p' || arg === '--package') {
        i++;
      }
      continue;
    }

    // Skip any other flags (start with -)
    if (arg.startsWith('-')) {
      continue;
    }

    // This is the package specifier
    return arg;
  }

  return undefined;
}

/**
 * Check whether a package specifier includes a pinned version.
 *
 * Examples:
 *   - `@anthropic-ai/mcp-server@1.2.3`  -> true
 *   - `@anthropic-ai/mcp-server@latest`  -> false (tag, not a pin)
 *   - `@anthropic-ai/mcp-server`         -> false
 *   - `my-server@^2.0.0`                 -> true (range, but at least constrained)
 *   - `my-server`                         -> false
 */
function isVersionPinned(packageSpecifier: string): boolean {
  // For scoped packages: @scope/name@version
  if (packageSpecifier.startsWith('@')) {
    const lastAt = packageSpecifier.lastIndexOf('@');
    if (lastAt <= 0) {
      // No version specifier (only the scope @)
      return false;
    }
    const version = packageSpecifier.slice(lastAt + 1);
    return version !== '' && version !== 'latest' && version !== 'next';
  }

  // For unscoped packages: name@version
  const atIndex = packageSpecifier.indexOf('@');
  if (atIndex === -1) {
    return false;
  }
  const version = packageSpecifier.slice(atIndex + 1);
  return version !== '' && version !== 'latest' && version !== 'next';
}

/**
 * Parse MCP server entries from a configuration object.
 *
 * Looks for the `mcpServers` key, which maps server names to their
 * configuration (command, args, env).
 *
 * @param config     - Parsed JSON configuration object.
 * @param configFile - Path to the config file (for reporting).
 * @returns Array of MCP server entries found in this config.
 */
function parseServers(
  config: Record<string, unknown>,
  configFile: string,
): McpServerEntry[] {
  const servers: McpServerEntry[] = [];

  const mcpServers = config.mcpServers as Record<string, unknown> | undefined;
  if (!mcpServers || typeof mcpServers !== 'object') {
    return servers;
  }

  for (const [name, value] of Object.entries(mcpServers)) {
    if (!value || typeof value !== 'object') {
      continue;
    }

    const entry = value as Record<string, unknown>;
    const command = (entry.command as string) || '';
    const args = (Array.isArray(entry.args) ? entry.args : []) as string[];

    const npmPackage = extractNpmPackage(command, args);
    const versionPinned = npmPackage ? isVersionPinned(npmPackage) : false;

    servers.push({
      name,
      command,
      args,
      configFile,
      npmPackage,
      versionPinned,
    });
  }

  return servers;
}

/**
 * Scan all known MCP configuration files for server entries.
 *
 * Checks Claude Desktop, Cursor, VS Code, Claude Code, and Windsurf
 * configuration files for MCP server definitions. Missing or unreadable
 * config files are silently skipped.
 *
 * @returns Array of all discovered MCP server entries.
 */
export async function scanMcpConfigs(): Promise<McpServerEntry[]> {
  const configPaths = getConfigPaths();
  const allServers: McpServerEntry[] = [];

  // Read all config files in parallel
  const results = await Promise.all(
    configPaths.map(async ({ path, label }) => {
      const config = await readJsonFile(path);
      if (!config) {
        return [];
      }
      return parseServers(config, `${path} (${label})`);
    }),
  );

  for (const servers of results) {
    allServers.push(...servers);
  }

  return allServers;
}
