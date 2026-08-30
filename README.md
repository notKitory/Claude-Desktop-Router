# Claude Desktop Custom Gateway Setup

A cross-platform Python script that routes Claude Desktop to any custom Anthropic-compatible API endpoint (e.g., Kimi, OpenRouter, local LLM) — **no Ollama required**.

It can also **patch the app bundle itself** so that non-Anthropic model names (`gpt`, `gemini`, `glm`, …) are accepted everywhere: in model discovery, in Settings, and in the Cowork workspace.

## How It Works

Claude Desktop has an undocumented "enterprise gateway" (3P) mode. When activated, it routes all inference through a custom API endpoint instead of `api.anthropic.com`. This script creates the minimal config files that activate this mode and point it at your gateway.

For non-Anthropic gateways, the script uses the `inferenceModels` config field to bypass model discovery and present your gateway's model as an Anthropic-compatible one.

### Optional: App Bundle Patch

Claude Desktop hard-codes a **banword regex** of competitor model names:

```
ark-code | astron | command-r | deepseek | doubao | gemini | gemma | glm | gpt | grok |
hermes | hy3 | kimi | lfm | ling | llama | longcat | mimo | minimax | mistral |
mixtral | moonshot | nemotron | openai | phi- | qianfan | qwen | tc-code | unic |
yi- | stepfun | step-3 | seed- | bytedance | hunyuan | granite | amazon.nova | nova- |
devstral | ministral | ernie | codex | arcee | trinity | abab | phi<N> | k2. | m2. |
jamba | arctic | solar | mercury | zamba | kat-coder | ds- | dpsk
```

Any custom model name containing one of these words — or not looking like an Anthropic model — is rejected in several independent places. `--patch-model-names` neutralizes all of them:

| # | Layer | Where | Fix |
|---|-------|-------|-----|
| 1 | Model-name validators (main process) | `app.asar` → `.vite/build/*.js` | Validator functions rewritten to `return!0` / probe to `return!1` |
| 2 | Model discovery, server context & thinking switches | `app.asar` → `.vite/build/*.js` | Merges duplicate models with effort suffixes into single base models, enables thinking switchers with server-supported effort levels, and dynamically sets 1M-context variants for models with server context >= 1M |
| 3 | Prompt caching for custom models | `app.asar` → `.vite/build/*.js` | Enables prompt caching with dynamic boundary partitioning and shortname identity mappings for custom gateway models |
| 4 | Per-file ASAR integrity | asar header (`"integrity"` entries) | SHA256 hash + 4 MiB block hashes recomputed |
| 5 | Header integrity | `Info.plist` → `ElectronAsarIntegrity` (macOS) | Header SHA256 updated |
| 6 | Settings-UI validators (renderer) | `Resources/ion-dist/assets/v1/*.js` | Same validator rewrite (inverted form) |
| 7 | Cowork VM start gate | `app.asar` | Refusal on non-`supported` probe result removed; `vm-support-probe.json` caches seeded with `virtSupport: supported` |

On macOS the script then re-signs the bundle ad-hoc **with embedded entitlements** (`com.apple.security.virtualization`, JIT, …) and hardened runtime enabled — otherwise macOS refuses to launch the modified app and Virtualization.framework refuses to create the workspace VM.

All edits are byte-length preserving (hex-for-hex substitutions, space padding), so archive offsets stay valid and no repacking is required. Pure Python stdlib — works on macOS, Windows and Linux.

## Prerequisites

- Python 3.7+
- Claude Desktop installed
- A gateway that supports:
  - `GET /v1/models` — for model discovery
  - `POST /v1/messages` — Anthropic Messages API format (streaming)

## Quick Start

### Interactive Mode

```bash
python setup-claude-gateway.py
```

The script will:
1. Auto-detect your OS and locate the Claude-3p config directory
2. Back up your existing config
3. Ask for your gateway Base URL, API Key, and Anthropic Model ID
4. Optionally offer to patch the app bundle (foreign model names)
5. Write the config files
6. Tell you to restart Claude Desktop

### Non-Interactive Mode (AI Assistants / CI)

```bash
python setup-claude-gateway.py \
  --base-url https://api.kimi.com/coding/ \
  --api-key sk-xxxxxxxxx \
  --model-id claude-sonnet-4-5 \
  --patch-model-names
```

After restart, your gateway's model should appear in the Claude Desktop model picker with the Anthropic model ID you specified.

### Updating Claude Desktop & Re-patching

Because patched apps cannot use Electron's built-in Squirrel auto-updater (due to signature mismatch), you can update Claude Desktop directly using:

```bash
python setup-claude-gateway.py --update
```

This checks Anthropic's official update feed for the latest version, downloads and installs it, and automatically re-applies all model name & VM gate patches in one step. Use `--force` to reinstall/re-patch even if already at the latest version.

### App Bundle Only

Patch without touching the gateway config (e.g., after a Claude Desktop auto-update):

```bash
python setup-claude-gateway.py --patch-model-names
```

Fully quit Claude first (tray icon → Quit). Idempotent: safe to re-run any time.

### Diagnostics

```bash
python setup-claude-gateway.py --status
```

Shows every layer at a glance:

```
Model-name validators & discovery
  banword check:        patched ✓
  VM start gate:        patched ✓
  discovery & thinking: patched ✓
  prompt caching:       patched ✓
  settings UI:          patched ✓
Integrity
  Info.plist header hash: in sync ✓
  signature:              0x10002(adhoc,runtime); virtualization entitlement: yes ✓
VM probe cache
  Claude: virtSupport=supported, key=fresh ✓
Backup
  .../app.asar.bak: present (38219841 bytes)
```

## Choosing a Model ID

With the app bundle patched you are **not limited to Anthropic-looking IDs anymore** — `gpt-4o`, `gemini-2.0-flash`, `deepseek-chat`, etc. are accepted and displayed as-is.

Without the patch, Claude Desktop validates model IDs from custom gateways and only accepts Anthropic-shaped names:

| What you want | `--model-id` value |
|---------------|-------------------|
| Claude 4 Sonnet | `claude-sonnet-4-5` |
| Claude 3.5 Sonnet | `claude-3-5-sonnet-20241022` |
| Claude 3 Opus | `claude-3-opus-20240229` |

The model ID determines how Claude Desktop labels and treats the model (context limit, capabilities, etc.). The actual API calls are forwarded to your gateway unchanged.

## Supported Platforms

| Platform | Config Path | App Bundle |
|----------|-------------|------------|
| Windows (legacy) | `%LOCALAPPDATA%\Claude-3p\configLibrary\` | `%LOCALAPPDATA%\AnthropicClaude\app-*\resources\app.asar` |
| Windows (MSIX/Store) | `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude-3p\configLibrary\` | not writable — use the EXE installer build |
| macOS | `~/Library/Application Support/Claude-3p/configLibrary/` | `/Applications/Claude.app/Contents/Resources/app.asar` |
| Linux | `~/.config/Claude-3p/configLibrary/` | `/opt/Claude`, `/usr/lib/claude-desktop`, snap, … |

The script auto-detects your OS and uses the correct paths, or pass `--asar-path` explicitly.

## Manual Setup (No Script)

If you prefer to do it manually — or you're asking an AI assistant to do it for you — follow these steps:

### Step 1: Locate the config directory

Find your OS-specific `Claude-3p/` path from the table above. Create it if it doesn't exist.

### Step 2: Create the deployment mode flag

Create or edit:

```
Claude-3p/claude_desktop_config.json
```

If the file already exists, **preserve all existing fields** and only add/ensure:

```json
{
  "deploymentMode": "3p"
}
```

If the file does not exist, create it with just:

```json
{ "deploymentMode": "3p" }
```

### Step 3: Create the gateway config

Create the `configLibrary` directory inside `Claude-3p/`, then create:

```
configLibrary/00000000-0000-4000-8000-000000000114.json
```

Write:

```json
{
  "inferenceProvider": "gateway",
  "inferenceCredentialKind": "static",
  "inferenceGatewayApiKey": "YOUR_API_KEY",
  "inferenceGatewayAuthScheme": "bearer",
  "inferenceGatewayBaseUrl": "https://your-gateway.com/",
  "inferenceModels": [
    {
      "name": "claude-sonnet-4-5",
      "labelOverride": "claude-sonnet-4-5"
    }
  ]
}
```

### Step 4: Create the config registry

Create:

```
configLibrary/_meta.json
```

Write:

```json
{
  "appliedId": "00000000-0000-4000-8000-000000000114",
  "entries": [
    {
      "id": "00000000-0000-4000-8000-000000000114",
      "name": "claude-sonnet-4-5"
    }
  ]
}
```

### Step 5: Restart Claude Desktop

Fully quit (tray icon → Quit), then relaunch.

## Reverting

### Gateway config only

```bash
python setup-claude-gateway.py --restore
```

Or manually: remove `"deploymentMode": "3p"` from `Claude-3p/claude_desktop_config.json` and delete the `Claude-3p/configLibrary/` directory.

### App bundle patch

```bash
python setup-claude-gateway.py --unpatch-app
```

Restores the original `app.asar` and renderer files from the backup created on first patch, then re-signs the bundle.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Claude crashes at launch with `ASAR Integrity Violation` | Outdated patch that didn't recompute header/file hashes | Re-run `--patch-model-names` with this version; `--unpatch-app` restores the original |
| `Integrity check failed for asar archive entry '<header>'` | Info.plist header hash out of sync | Same — current script syncs it automatically |
| *"Failed to start Claude's workspace… installation appears to be invalid"* | Cowork VM start gate / stale probe cache | Re-run `--patch-model-names` (patches the gate and seeds `vm-support-probe.json`) |
| `VZErrorDomain Code=2 … have no permission "com.apple.security.virtualization"` | Bundle was re-signed without entitlements | Re-run `--patch-model-names` — resigning now embeds entitlements + hardened runtime |
| *"Doesn't look like an Anthropic model…"* when adding a model in Settings | Renderer copy of the validator not patched | Re-run `--patch-model-names` (patches ion-dist too) |
| Foreign models stopped working after a Claude update | Auto-update replaced `app.asar`, wiping all patches | Re-run `--patch-model-names`; check `--status` |

Run `--status` first whenever something misbehaves — it tells you exactly which layer regressed.

## Limitations

- Claude Desktop's embedded Claude Code may cap context at 200k tokens for unknown models, even if your gateway reports a larger `context_length`. This is a client-side hardcoded limit.
- Web search, billing, and other Anthropic-cloud-only features are unavailable in third-party mode.
- Claude Desktop auto-updates replace `app.asar` (and may ship new validation logic). Re-run `--patch-model-names` after each update; if the internal layout changed too much, the script will tell you and change nothing.
- On macOS the patched bundle is ad-hoc signed. It runs fine locally but is no longer notarized — don't re-distribute it.

## License

MIT
