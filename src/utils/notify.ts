/**
 * macOS Notification + Sound Alert
 * Sends system notifications when risky commands need user attention
 */

import { exec } from 'node:child_process';
import { platform } from 'node:os';

/**
 * Send a macOS notification with sound alert
 */
export function sendAlert(title: string, message: string): void {
  const os = platform();

  // Sanitize for shell
  const safeTitle = title.replace(/["`$\\]/g, '').slice(0, 100);
  const safeMsg = message.replace(/["`$\\]/g, '').replace(/\n/g, ' ').slice(0, 200);

  if (os === 'darwin') {
    // macOS: use osascript for notification with sound
    const script = `display notification "${safeMsg}" with title "${safeTitle}" sound name "Funk"`;
    exec(`osascript -e '${script}'`, () => {});

    // Also play an additional alert sound for urgency
    exec('afplay /System/Library/Sounds/Funk.aiff 2>/dev/null &', () => {});
  } else if (os === 'linux') {
    // Linux: try notify-send
    exec(`notify-send "${safeTitle}" "${safeMsg}" 2>/dev/null`, () => {});
    // Terminal bell
    process.stderr.write('\x07');
  } else {
    // Fallback: terminal bell
    process.stderr.write('\x07');
  }

  // Always write a visible stderr warning with color
  process.stderr.write(
    `\n\x1b[1;33m` +
    `╔══════════════════════════════════════════════════════════════╗\n` +
    `║  ⚠️  SECURITY ALERT - ACTION REQUIRED                       ║\n` +
    `╠══════════════════════════════════════════════════════════════╣\n` +
    `║  ${safeTitle.padEnd(58)} ║\n` +
    `║  ${safeMsg.slice(0, 58).padEnd(58)} ║\n` +
    `║                                                              ║\n` +
    `║  → Go to Claude Code and click "Allow" or "Deny"            ║\n` +
    `╚══════════════════════════════════════════════════════════════╝\n` +
    `\x1b[0m\n`
  );
}
