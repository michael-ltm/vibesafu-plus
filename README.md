# vibesafu-plus

**Enhanced Claude Code security guard with interactive alerts**

Forked from [vibesafu](https://github.com/kevin-hs-sohn/vibesafu) - adds interactive notification alerts instead of auto-deny, plus customizable rules.

## Key Differences from vibesafu

| Feature | vibesafu | vibesafu-plus |
|---------|----------|---------------|
| Risky commands | Auto-deny after 7s timeout | macOS notification + sound + user decides |
| Rules | Config patterns only | Visual rules with descriptions |
| Alerts | Terminal only | System notification + sound + terminal |
| Mode | Auto-deny only | Interactive (default) or auto-deny (configurable) |

## Quick Start

```bash
# Install globally
npm install -g vibesafu-plus

# Install the hook
vibesafu-plus install

# Configure API key (optional but recommended)
vibesafu-plus config

# View/customize rules
vibesafu-plus rules

# Restart Claude Code
claude
```

## How It Works

1. **Auto-approve** safe commands (git status, ls, cat, etc.) - no interruption
2. **Alert + Ask** for risky commands - sends macOS notification with sound, shows warning in Claude Code, and lets YOU decide (Allow or Deny)
3. **Pattern + LLM analysis** for complex commands - multi-layer security check

When a risky command is detected:
- macOS notification pops up with sound alert
- Terminal shows a colored warning box
- Claude Code shows the permission dialog
- You click "Allow" or "Deny" - no auto-deny timeout

## Configuration

Config file: `~/.vibesafu/config.json`

```bash
# Interactive setup
vibesafu-plus config

# View all rules
vibesafu-plus rules

# Generate default config for editing
vibesafu-plus rules --init
```

### Example Config

```json
{
  "anthropic": {
    "apiKey": "sk-ant-..."
  },
  "models": {
    "triage": "claude-haiku-4-20250514",
    "review": "claude-sonnet-4-20250514"
  },
  "autoDeny": false,
  "rules": {
    "autoApprove": [
      {
        "pattern": "^git\\s+(status|log|diff|show|branch|tag)",
        "description": "Read-only git commands",
        "enabled": true
      },
      {
        "pattern": "^ls\\b",
        "description": "List directory contents",
        "enabled": true
      }
    ],
    "alertAndAsk": [
      {
        "pattern": "rm\\s+-rf",
        "description": "Recursive force delete",
        "enabled": true
      },
      {
        "pattern": "curl.*\\|.*bash",
        "description": "Pipe remote script to shell",
        "enabled": true
      },
      {
        "pattern": "DROP\\s+TABLE",
        "description": "SQL table drop",
        "enabled": true
      }
    ]
  },
  "customPatterns": {
    "allow": [],
    "block": []
  },
  "allowedMCPTools": [
    "mcp__memory__*"
  ],
  "trustedDomains": []
}
```

### Config Options

| Field | Description | Default |
|-------|-------------|---------|
| `autoDeny` | Use original auto-deny behavior instead of interactive alerts | `false` |
| `rules.autoApprove` | Commands to auto-approve (with descriptions) | Common safe commands |
| `rules.alertAndAsk` | Commands that trigger notification + user prompt | Common risky patterns |
| `customPatterns.allow` | Legacy: regex patterns to auto-approve | `[]` |
| `customPatterns.block` | Legacy: regex patterns to block/alert | `[]` |
| `allowedMCPTools` | MCP tools to auto-approve (supports wildcards) | `[]` |
| `trustedDomains` | Additional trusted domains for network requests | `[]` |

### Rule Format

Each rule has three fields:

```json
{
  "pattern": "^npm\\s+install",
  "description": "NPM package installation",
  "enabled": true
}
```

- **pattern**: Regex to match against the command (case-insensitive)
- **description**: Human-readable explanation shown in alerts and `rules` output
- **enabled**: Toggle rules on/off without deleting them

## Commands

```bash
vibesafu-plus install     # Install hook to Claude Code
vibesafu-plus uninstall   # Remove hook
vibesafu-plus config      # Configure API key and settings
vibesafu-plus rules       # View all rules and their status
vibesafu-plus rules --init # Write default config to disk for editing
vibesafu-plus check       # Run security check (used by hook)
```

## Security Layers

Same multi-layer defense as vibesafu:

1. **Instant allow** - Safe patterns (git read-only) skip all checks
2. **Custom rules** - Your configured auto-approve and alert rules
3. **Pattern detection** - Reverse shells, data exfil, crypto mining, etc.
4. **Checkpoint detection** - Package installs, script execution, env access
5. **Trusted domains** - Known-safe domains for network requests (not scripts)
6. **LLM triage** (Haiku) - Fast first-pass classification
7. **LLM review** (Sonnet) - Deep analysis for escalated cases
8. **Prompt injection defense** - Sanitization + post-validation

## Migrating from vibesafu

```bash
# Uninstall vibesafu
npm uninstall -g vibesafu

# Install vibesafu-plus
npm install -g vibesafu-plus
vibesafu-plus install

# Your existing ~/.vibesafu/config.json will be used automatically
# New fields (autoDeny, rules) get sensible defaults
```

## Credits

Based on [vibesafu](https://github.com/kevin-hs-sohn/vibesafu) by kevin-hs-sohn. All original security patterns, LLM analysis, and prompt injection defense are preserved.

## License

MIT
