/**
 * CLI Rules Command
 * View and manage auto-approve/alert rules
 */

import { readConfig, writeConfig } from './config.js';
import { loadProjectRules } from '../utils/dialog.js';

/**
 * Display all rules with their status
 */
export async function rules(args: string[]): Promise<void> {
  const config = await readConfig();

  if (args.includes('--init')) {
    // Write current config (with defaults) to disk for easy editing
    await writeConfig(config);
    console.log('Default config with all rules written to ~/.vibesafu/config.json');
    console.log('Edit the file to customize your rules.');
    return;
  }

  console.log('vibesafu-plus Rules');
  console.log('===================');
  console.log('');
  console.log(`Mode: ${config.autoDeny ? 'Auto-Deny (original)' : 'Interactive Alert (recommended)'}`);
  console.log('');

  // Auto-approve rules
  console.log('\x1b[32m--- Auto-Approve Rules ---\x1b[0m');
  console.log('Commands matching these patterns are automatically allowed.\n');
  if (config.rules.autoApprove.length === 0) {
    console.log('  (none configured)');
  } else {
    for (const rule of config.rules.autoApprove) {
      const status = rule.enabled ? '\x1b[32m[ON] \x1b[0m' : '\x1b[90m[OFF]\x1b[0m';
      console.log(`  ${status} ${rule.description}`);
      console.log(`        Pattern: ${rule.pattern}`);
    }
  }
  console.log('');

  // Alert-and-ask rules
  console.log('\x1b[33m--- Alert-And-Ask Rules ---\x1b[0m');
  console.log('Commands matching these patterns trigger a notification + user prompt.\n');
  if (config.rules.alertAndAsk.length === 0) {
    console.log('  (none configured)');
  } else {
    for (const rule of config.rules.alertAndAsk) {
      const status = rule.enabled ? '\x1b[33m[ON] \x1b[0m' : '\x1b[90m[OFF]\x1b[0m';
      console.log(`  ${status} ${rule.description}`);
      console.log(`        Pattern: ${rule.pattern}`);
    }
  }
  console.log('');

  // Custom patterns (legacy)
  if (config.customPatterns.allow.length > 0 || config.customPatterns.block.length > 0) {
    console.log('\x1b[36m--- Legacy Custom Patterns ---\x1b[0m');
    if (config.customPatterns.allow.length > 0) {
      console.log('  Allow:', config.customPatterns.allow.join(', '));
    }
    if (config.customPatterns.block.length > 0) {
      console.log('  Block:', config.customPatterns.block.join(', '));
    }
    console.log('');
  }

  // MCP tools
  if (config.allowedMCPTools.length > 0) {
    console.log('\x1b[36m--- Allowed MCP Tools ---\x1b[0m');
    for (const tool of config.allowedMCPTools) {
      console.log(`  ${tool}`);
    }
    console.log('');
  }

  // Project-level rules
  const cwd = process.cwd();
  const projectRules = await loadProjectRules(cwd);
  if (projectRules.length > 0) {
    console.log('\x1b[35m--- Project Rules (.vibesafu-rules.json) ---\x1b[0m');
    console.log(`Location: ${cwd}/.vibesafu-rules.json\n`);
    for (const rule of projectRules) {
      const status = rule.enabled ? '\x1b[35m[ON] \x1b[0m' : '\x1b[90m[OFF]\x1b[0m';
      console.log(`  ${status} ${rule.description}`);
      console.log(`        Pattern: ${rule.pattern}`);
    }
    console.log('');
  }

  console.log('To edit global rules: ~/.vibesafu/config.json');
  console.log('To edit project rules: .vibesafu-rules.json (in project root)');
  console.log('To regenerate defaults: vibesafu-plus rules --init');
}
