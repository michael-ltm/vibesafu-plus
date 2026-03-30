#!/usr/bin/env node

/**
 * vibesafu CLI - Claude Code Security Guard
 *
 * Commands:
 *   install   - Install hook to ~/.claude/settings.json
 *   uninstall - Remove hook from settings
 *   check     - Run security check (stdin: PermissionRequest JSON)
 *   config    - Configure API key and settings
 */

import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { install, uninstall } from './cli/install.js';
import { config } from './cli/config.js';
import { rules } from './cli/rules.js';
import { runHook } from './hook.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf-8'));

const COMMANDS = ['install', 'uninstall', 'check', 'config', 'rules'] as const;
type Command = (typeof COMMANDS)[number];

async function main(): Promise<void> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    strict: false,
    options: {
      version: { type: 'boolean', short: 'v' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  if (values.version) {
    console.log(pkg.version);
    return;
  }

  const command = positionals[0] as Command | undefined;

  if (values.help || !command || !COMMANDS.includes(command)) {
    console.error('vibesafu-plus - Claude Code Security Guard (Interactive)');
    console.error('');
    console.error(`Usage: vibesafu-plus <${COMMANDS.join('|')}>`);
    console.error('');
    console.error('Commands:');
    console.error('  install   - Install security hook to Claude Code');
    console.error('  uninstall - Remove security hook');
    console.error('  check     - Run security check (stdin: PermissionRequest JSON)');
    console.error('  config    - Configure API key and settings');
    console.error('  rules     - View/manage auto-approve and alert rules');
    process.exit(1);
  }

  switch (command) {
    case 'install':
      await install();
      break;
    case 'uninstall':
      await uninstall();
      break;
    case 'check':
      await runHook();
      break;
    case 'config':
      await config();
      break;
    case 'rules':
      await rules(positionals.slice(1));
      break;
  }
}

main().catch((error: Error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
