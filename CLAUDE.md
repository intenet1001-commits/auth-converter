# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an Electron-based desktop application that functions as a JSON viewer with specialized features for managing MCP (Model Context Protocol) server configurations and Google OAuth authentication for workspace services.

**Primary Functions:**
- JSON file viewing and parsing with copy functionality
- MCP server configuration merging and management
- Google OAuth authentication for workspace MCP servers
- Claude Config (.claude.json) and Claude Desktop Config management
- Extension-to-MCP conversion for Claude Desktop Extensions

## Commands

### Development
```bash
npm install           # Install dependencies
npm start            # Run Electron app in development mode
npm run dev          # Alias for npm start
npm run web          # Run web-only version (Express server on port 3000)
```

### Building
```bash
npm run build        # Build for current platform
npm run build:mac    # Build macOS DMG/zip
npm run build:win    # Build Windows installer/portable
npm run build:linux  # Build Linux AppImage/deb
```

Built artifacts are output to `dist/` directory.

## Architecture

### Multi-Process Architecture

The app uses Electron's multi-process model:

1. **Main Process** (`main.js`):
   - Manages Electron BrowserWindow lifecycle
   - Spawns Express server as child process
   - Handles file associations (JSON files can open directly)
   - Implements IPC handlers for Claude Config operations
   - Coordinates OAuth workflows

2. **Renderer Process** (`public/index.html`):
   - Loads from `http://localhost:3000` (served by Express)
   - Vanilla JavaScript frontend with tab-based UI
   - Communicates with main process via contextBridge API

3. **Server Process** (`server.js`):
   - Express server running on port 3000
   - Provides REST API endpoints for JSON parsing, MCP merging, OAuth flows
   - Handles file I/O for configs and authentication tokens

### Key Components

**Preload Script** (`preload.js`):
- Uses contextBridge to expose safe IPC methods to renderer
- Provides `window.electronAPI` interface
- Methods include: `loadClaudeConfig`, `saveClaudeConfig`, `buildApp`, `openExternal`

**Server Routes** (`server.js`):
- `/api/parse` - Parse JSON from text input
- `/api/upload` - Upload and parse JSON file
- `/api/merge-mcp` - Merge MCP server configurations with rename capability
- `/api/scan-extensions` - Scan Claude Desktop Extensions from `~/Library/Application Support/Claude/Claude Extensions`
- `/api/extension-to-mcp` - Convert extension manifest to MCP config format
- `/api/check-auth-status` - Check Google OAuth status for workspace servers
- `/api/start-auth` - Initiate OAuth flow
- `/api/save-client-secret` - Save OAuth client_secret.json files with auto port detection
- `/api/detect-port-from-extension` - Auto-detect OAuth port from client_secret.json
- `/api/get-oauth-port` - Get OAuth port for specific account
- `/oauth2callback` - OAuth callback endpoint

### Configuration File Locations

The app works with multiple configuration files:

1. **Claude Code Config**: `~/.claude.json`
   - Contains `projects` object with workspace-specific MCP servers
   - Structure: `projects[homeDir].mcpServers`

2. **Claude Desktop Config**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Desktop app MCP configuration
   - Top-level `mcpServers` object

3. **OAuth Credentials**:
   - Tokens: `~/.google_workspace_mcp/credentials/{email}.json` or `~/.mcp-workspace/token-{email}.json`
   - Client secrets: `~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_{accountId}/client_secret.json`
   - Port mapping: `~/.mcp-workspace/oauth_port_map.json`

4. **Extensions**: `~/Library/Application Support/Claude/Claude Extensions/`

### Google OAuth Flow

The app implements a complete OAuth2 flow for Google Workspace MCP servers:

1. Scans MCP servers for Google Workspace keywords (workspace, google, gmail, drive, sheets, docs, calendar)
2. Checks for existing authentication tokens
3. Generates OAuth URLs using client_secret.json files
4. Runs OAuth callback servers on multiple ports (8766, 8675, plus dynamic ports from oauth_port_map.json)
5. Exchanges authorization codes for access/refresh tokens
6. Saves tokens in workspace MCP format with expiry tracking
7. Supports token refresh when expired

**OAuth Port Management**:
- Detects OAuth redirect port from client_secret.json redirect_uris
- Saves port mappings to `oauth_port_map.json` for multi-account support
- Starts callback servers dynamically based on configured ports

### MCP Server Merging Logic

The `/api/merge-mcp` endpoint intelligently merges MCP configurations:
- Preserves existing server order
- Appends new servers at the end
- Supports server renaming via `serverNameMap` parameter
- Maintains structure compatibility (with or without `mcpServers` wrapper)

## Important Implementation Details

### File Association Handling

macOS file opening is handled via:
- `app.on('open-file')` event in main.js:212
- Command-line arguments for Windows/Linux in main.js:414
- Files opened before app ready are queued in `pendingFilePath`

### Config Merger Strategy

When merging Claude configs (main.js:293-331):
- Creates `.backup` file before saving
- Preserves all non-mcpServers fields in user config
- Only updates `projects[homeDir].mcpServers` or top-level `mcpServers`
- Logs server counts for debugging

### Security Considerations

- Context isolation enabled (`contextIsolation: true`)
- Node integration disabled in renderer
- All file system operations happen in main/server process
- OAuth tokens stored locally with client credentials
- Token refresh automatically handles expiry

## Common Development Patterns

### Adding New IPC Handlers

1. Add handler in main.js using `ipcMain.handle()`
2. Expose method in preload.js via `contextBridge.exposeInMainWorld()`
3. Call from renderer using `window.electronAPI.methodName()`

### Adding API Endpoints

Add Express routes in server.js following the pattern:
```javascript
app.post('/api/endpoint-name', async (req, res) => {
  try {
    // Logic
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});
```

### Debugging OAuth Issues

- Check console logs for port detection: "Using OAuth port X from..."
- Verify client_id in oauth_port_map.json matches client_secret.json
- Token format: workspace MCP uses `token` field, standard OAuth uses `access_token`
- Check both token locations: `.mcp-workspace` and `.google_workspace_mcp/credentials`

## Recent Updates (2025-11-12)

### OAuth UI/UX Improvements
1. **Browser Authentication Guidance**
   - Added warning messages explaining OAuth must happen in browser (not Electron app)
   - External link dialog now shows detailed OAuth flow explanation
   - Authentication status area shows helpful prompts when auth is needed

2. **Environment Variable Management**
   - Replaced `prompt()` with modern modal dialog for adding environment variables
   - Support for simultaneous key+value input with placeholders
   - Visual feedback on successful port detection

3. **Auto Port Detection Feature**
   - "🔍 포트 자동 감지" button automatically extracts port from client_secret.json
   - `/api/detect-port-from-extension` endpoint analyzes redirect_uris
   - Auto-adds WORKSPACE_MCP_PORT to .claude.json when saving client_secret

4. **Port Detection Bug Fixes**
   - Fixed email-specific client_secret matching (prioritizes accountId-specific directories)
   - Server now correctly maps intenet1→8766, intenet8821→8765
   - Eliminated false port mismatch warnings

5. **Desktop App OAuth Support**
   - Added support for "installed" (Desktop App) type OAuth clients
   - Handles dynamic ports with `http://localhost` redirect_uris
   - Works alongside "web" type OAuth clients
