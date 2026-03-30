/**
 * Interactive macOS Dialog for security decisions
 * Shows native dialog with Allow Once / Always Allow / Deny options
 */

import { execSync } from 'node:child_process';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import type { RuleEntry } from '../types.js';

export type DialogResult =
  | { action: 'allow' }
  | { action: 'deny' }
  | { action: 'always-allow-project' }
  | { action: 'always-allow-global' };

/**
 * Escape a string for use inside AppleScript double quotes
 */
function escapeAppleScript(str: string): string {
  return str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Generate a regex pattern from a command for saving as a rule.
 * Extracts the command structure (binary + subcommand) to create a useful pattern.
 */
export function generatePattern(command: string): string {
  const trimmed = command.trim();

  // Extract binary and first argument/subcommand
  const parts = trimmed.split(/\s+/);
  const binary = parts[0];

  // For common tools, create patterns based on the binary + subcommand
  const toolsWithSubcommands = ['git', 'npm', 'pnpm', 'yarn', 'pip', 'cargo', 'docker', 'kubectl', 'brew'];
  if (toolsWithSubcommands.includes(binary) && parts.length > 1) {
    const sub = parts[1];
    // e.g., "npm install" → "^npm\\s+install"
    return `^${escapeRegex(binary)}\\s+${escapeRegex(sub)}`;
  }

  // For simple commands, match the full command more precisely
  if (parts.length <= 3) {
    return `^${escapeRegex(trimmed)}$`;
  }

  // For complex commands, match the binary + first few tokens
  const prefix = parts.slice(0, 3).join('\\s+');
  return `^${prefix}`;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Show a native macOS dialog for security decisions.
 * Returns the user's choice.
 *
 * Falls back to 'ask' behavior on non-macOS or if dialog fails.
 */
export function showSecurityDialog(
  reason: string,
  command: string,
  source: string,
): DialogResult | null {
  if (platform() !== 'darwin') {
    return null; // Non-macOS: fall back to 'ask' behavior
  }

  const commandPreview = command.length > 120 ? command.slice(0, 117) + '...' : command;
  const dialogText = escapeAppleScript(
    `[${source}] ${reason}\n\nCommand: ${commandPreview}`
  );

  try {
    // Step 1: Allow Once / Always Allow / Deny
    const step1Script =
      `display dialog "${dialogText}" ` +
      `buttons {"Deny", "Allow Once", "Always Allow..."} ` +
      `default button "Allow Once" ` +
      `with title "vibesafu-plus: Security Alert" ` +
      `with icon caution ` +
      `giving up after 300`;

    const step1Result = execSync(`osascript -e '${step1Script}'`, {
      timeout: 305000,
      encoding: 'utf-8',
    }).trim();

    if (step1Result.includes('gave up:true')) {
      return { action: 'deny' }; // Timeout = deny
    }

    if (step1Result.includes('Deny')) {
      return { action: 'deny' };
    }

    if (step1Result.includes('Allow Once')) {
      return { action: 'allow' };
    }

    // Step 2: "Always Allow..." → choose scope
    const step2Script =
      `display dialog "Save this as an auto-approve rule?\\n\\nPattern: ${escapeAppleScript(generatePattern(command))}" ` +
      `buttons {"Cancel", "This Project Only", "All Projects (Global)"} ` +
      `default button "This Project Only" ` +
      `with title "vibesafu-plus: Save Rule" ` +
      `with icon note`;

    const step2Result = execSync(`osascript -e '${step2Script}'`, {
      timeout: 60000,
      encoding: 'utf-8',
    }).trim();

    if (step2Result.includes('All Projects')) {
      return { action: 'always-allow-global' };
    }

    if (step2Result.includes('This Project')) {
      return { action: 'always-allow-project' };
    }

    // Cancel → treat as allow once
    return { action: 'allow' };
  } catch {
    // Dialog cancelled (Cmd+.) or error → fall back to null
    return null;
  }
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
export async function saveProjectRule(cwd: string, command: string, reason: string): Promise<void> {
  const filePath = join(cwd, PROJECT_RULES_FILE);
  let rules: ProjectRules = { autoApprove: [] };

  try {
    const content = await readFile(filePath, 'utf-8');
    rules = JSON.parse(content);
  } catch {
    // File doesn't exist yet, use default
  }

  const pattern = generatePattern(command);

  // Don't add duplicate patterns
  if (rules.autoApprove.some(r => r.pattern === pattern)) {
    return;
  }

  rules.autoApprove.push({
    pattern,
    description: `Auto-approved: ${reason.slice(0, 80)}`,
    enabled: true,
  });

  await writeFile(filePath, JSON.stringify(rules, null, 2));
  process.stderr.write(`\x1b[32m[vibesafu-plus] Rule saved to ${filePath}\x1b[0m\n`);
}

/**
 * Save a rule to the global config (~/.vibesafu/config.json)
 */
export async function saveGlobalRule(command: string, reason: string): Promise<void> {
  await mkdir(GLOBAL_CONFIG_DIR, { recursive: true });

  let config: Record<string, unknown> = {};
  try {
    const content = await readFile(GLOBAL_CONFIG_PATH, 'utf-8');
    config = JSON.parse(content);
  } catch {
    // File doesn't exist yet
  }

  // Ensure rules.autoApprove exists
  if (!config.rules || typeof config.rules !== 'object') {
    config.rules = { autoApprove: [], alertAndAsk: [] };
  }
  const rules = config.rules as { autoApprove: RuleEntry[]; alertAndAsk: RuleEntry[] };
  if (!Array.isArray(rules.autoApprove)) {
    rules.autoApprove = [];
  }

  const pattern = generatePattern(command);

  // Don't add duplicate patterns
  if (rules.autoApprove.some(r => r.pattern === pattern)) {
    return;
  }

  rules.autoApprove.push({
    pattern,
    description: `Auto-approved: ${reason.slice(0, 80)}`,
    enabled: true,
  });

  await writeFile(GLOBAL_CONFIG_PATH, JSON.stringify(config, null, 2));
  process.stderr.write(`\x1b[32m[vibesafu-plus] Rule saved to ${GLOBAL_CONFIG_PATH}\x1b[0m\n`);
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
