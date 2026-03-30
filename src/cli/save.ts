/**
 * CLI Save Command
 * Save auto-approve rules for commands (project-level or global)
 *
 * Usage:
 *   vibesafu-plus save --project "npm install"
 *   vibesafu-plus save --global "git push"
 *   vibesafu-plus save --project --pattern "^npm\\s+install" --desc "NPM installs"
 */

import { saveProjectRule, saveGlobalRule, generatePattern } from '../utils/dialog.js';

export async function save(args: string[]): Promise<void> {
  const isProject = args.includes('--project') || args.includes('-p');
  const isGlobal = args.includes('--global') || args.includes('-g');

  if (!isProject && !isGlobal) {
    console.error('Usage:');
    console.error('  vibesafu-plus save --project "command"    # Always allow in this project');
    console.error('  vibesafu-plus save --global  "command"    # Always allow everywhere');
    console.error('');
    console.error('Options:');
    console.error('  --project, -p   Save to .vibesafu-rules.json in current directory');
    console.error('  --global,  -g   Save to ~/.vibesafu/config.json');
    console.error('  --pattern       Use a custom regex pattern instead of auto-generating');
    console.error('  --desc          Custom description for the rule');
    console.error('');
    console.error('Examples:');
    console.error('  vibesafu-plus save -p "npm install"');
    console.error('  vibesafu-plus save -g "git push"');
    console.error('  vibesafu-plus save -g --pattern "^docker\\\\s+build" --desc "Docker builds"');
    process.exit(1);
  }

  // Extract command (first non-flag argument after "save")
  const flagsToSkip = new Set(['--project', '-p', '--global', '-g', '--pattern', '--desc']);
  let command = '';
  let customPattern = '';
  let customDesc = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--pattern' && i + 1 < args.length) {
      customPattern = args[++i];
    } else if (args[i] === '--desc' && i + 1 < args.length) {
      customDesc = args[++i];
    } else if (!flagsToSkip.has(args[i]) && !command) {
      command = args[i];
    }
  }

  if (!command && !customPattern) {
    console.error('Error: Please provide a command or --pattern');
    console.error('Example: vibesafu-plus save --project "npm install lodash"');
    process.exit(1);
  }

  // Show what pattern will be saved
  const pattern = customPattern || generatePattern(command);
  const desc = customDesc || `Auto-approved: ${command.slice(0, 80)}`;

  console.log(`Pattern: ${pattern}`);
  console.log(`Description: ${desc}`);
  console.log('');

  if (isProject) {
    await saveProjectRule(process.cwd(), command || pattern, desc);
  } else {
    await saveGlobalRule(command || pattern, desc);
  }
}
