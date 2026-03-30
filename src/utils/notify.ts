/**
 * Terminal notification - sound alert via bell
 * Used as fallback when /dev/tty is not available
 */

/**
 * Send a terminal bell + stderr warning
 */
export function sendAlert(title: string, message: string): void {
  const safeTitle = title.slice(0, 100);
  const safeMsg = message.replace(/\n/g, ' ').slice(0, 200);

  // Terminal bell
  process.stderr.write('\x07');

  process.stderr.write(
    `\n\x1b[1;33m` +
    `╔══════════════════════════════════════════════════════════════╗\n` +
    `║  ⚠  SECURITY ALERT - ACTION REQUIRED                       ║\n` +
    `╠══════════════════════════════════════════════════════════════╣\n` +
    `║  ${safeTitle.padEnd(58)} ║\n` +
    `║  ${safeMsg.slice(0, 58).padEnd(58)} ║\n` +
    `║                                                              ║\n` +
    `║  → Go to Claude Code and click "Allow" or "Deny"            ║\n` +
    `╚══════════════════════════════════════════════════════════════╝\n` +
    `\x1b[0m\n`
  );
}
