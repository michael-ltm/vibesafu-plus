/**
 * Rule persistence and pattern generation for vibesafu-plus
 *
 * Design: Hooks are non-interactive (stdin JSON → stdout JSON).
 * All interactive features (save rules) are done via separate CLI commands,
 * not inside the hook process. This ensures compatibility with all environments
 * and future Claude Code upgrades.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { RuleEntry } from '../types.js';

/**
 * Generate a regex pattern from a command for saving as a rule.
 */
export function generatePattern(command: string): string {
  const trimmed = command.trim();
  const parts = trimmed.split(/\s+/);
  const binary = parts[0];

  const toolsWithSubcommands = ['git', 'npm', 'pnpm', 'yarn', 'pip', 'cargo', 'docker', 'kubectl', 'brew'];
  if (toolsWithSubcommands.includes(binary) && parts.length > 1) {
    const sub = parts[1];
    return `^${escapeRegex(binary)}\\s+${escapeRegex(sub)}`;
  }

  if (parts.length <= 3) {
    return `^${escapeRegex(trimmed)}$`;
  }

  const prefix = parts.slice(0, 3).join('\\s+');
  return `^${prefix}`;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─── Rule Persistence ──────────────────────────────────────────────────────────

const GLOBAL_CONFIG_DIR = join(homedir(), '.vibesafu');
const GLOBAL_CONFIG_PATH = join(GLOBAL_CONFIG_DIR, 'config.json');
const PROJECT_RULES_FILE = '.vibesafu-rules.json';

interface ProjectRules {
  autoApprove: RuleEntry[];
}

/**
 * Save a rule to the project-level config ({cwd}/.vibesafu-rules.json)
 */
export async function saveProjectRule(cwd: string, command: string, description?: string): Promise<void> {
  const filePath = join(cwd, PROJECT_RULES_FILE);
  let rules: ProjectRules = { autoApprove: [] };

  try {
    const content = await readFile(filePath, 'utf-8');
    rules = JSON.parse(content);
  } catch {
    // File doesn't exist yet
  }

  const pattern = generatePattern(command);
  if (rules.autoApprove.some(r => r.pattern === pattern)) {
    console.log(`Rule already exists: ${pattern}`);
    return;
  }

  rules.autoApprove.push({
    pattern,
    description: description ?? `Auto-approved: ${command.slice(0, 80)}`,
    enabled: true,
  });

  await writeFile(filePath, JSON.stringify(rules, null, 2));
  console.log(`\x1b[32m✓ Project rule saved to ${filePath}\x1b[0m`);
  console.log(`  Pattern: ${pattern}`);
}

/**
 * Save a rule to the global config (~/.vibesafu/config.json)
 */
export async function saveGlobalRule(command: string, description?: string): Promise<void> {
  await mkdir(GLOBAL_CONFIG_DIR, { recursive: true });

  let config: Record<string, unknown> = {};
  try {
    const content = await readFile(GLOBAL_CONFIG_PATH, 'utf-8');
    config = JSON.parse(content);
  } catch {
    // File doesn't exist yet
  }

  if (!config.rules || typeof config.rules !== 'object') {
    config.rules = { autoApprove: [], alertAndAsk: [] };
  }
  const rules = config.rules as { autoApprove: RuleEntry[]; alertAndAsk: RuleEntry[] };
  if (!Array.isArray(rules.autoApprove)) {
    rules.autoApprove = [];
  }

  const pattern = generatePattern(command);
  if (rules.autoApprove.some(r => r.pattern === pattern)) {
    console.log(`Rule already exists: ${pattern}`);
    return;
  }

  rules.autoApprove.push({
    pattern,
    description: description ?? `Auto-approved: ${command.slice(0, 80)}`,
    enabled: true,
  });

  await writeFile(GLOBAL_CONFIG_PATH, JSON.stringify(config, null, 2));
  console.log(`\x1b[32m✓ Global rule saved to ${GLOBAL_CONFIG_PATH}\x1b[0m`);
  console.log(`  Pattern: ${pattern}`);
}

/**
 * Load project-level rules from {cwd}/.vibesafu-rules.json
 */
export async function loadProjectRules(cwd: string): Promise<RuleEntry[]> {
  try {
    const filePath = join(cwd, PROJECT_RULES_FILE);
    const content = await readFile(filePath, 'utf-8');
    const rules: ProjectRules = JSON.parse(content);
    return Array.isArray(rules.autoApprove) ? rules.autoApprove : [];
  } catch {
    return [];
  }
}
