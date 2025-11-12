# Troubleshooting Guide for AI Assistants

This document is designed for AI assistants (like Claude) to diagnose and fix common issues with Google Workspace MCP OAuth authentication and configuration.

## Table of Contents

1. [OAuth Authentication Errors](#oauth-authentication-errors)
2. [Port Configuration Issues](#port-configuration-issues)
3. [Token Management Problems](#token-management-problems)
4. [Extension Configuration Issues](#extension-configuration-issues)
5. [Debugging Workflow](#debugging-workflow)

---

## OAuth Authentication Errors

### Error: "invalid_client" / "Unauthorized"

**Symptom:**
```
Token exchange failed: { "error": "invalid_client", "error_description": "Unauthorized" }
```

**Root Causes:**
1. Client ID or client_secret in local file doesn't match Google Cloud Console
2. OAuth Client has been deleted or regenerated in Google Cloud Console
3. OAuth Client is disabled or suspended

**Diagnostic Steps:**

1. **Check client_secret.json file**
   ```bash
   cat ~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_{accountId}/client_secret.json
   ```
   Verify:
   - `client_id` value
   - `client_secret` value
   - `redirect_uris` array

2. **Check oauth_port_map.json**
   ```bash
   cat ~/.mcp-workspace/oauth_port_map.json
   ```
   Verify client_id exists and maps to correct port

3. **Check server logs**
   ```bash
   tail -100 /tmp/server-debug.log | grep "TOKEN EXCHANGE"
   ```
   Look for:
   - Client ID being used
   - Client secret (first/last chars)
   - Redirect URI
   - Response status code (401 = unauthorized)

**Resolution:**

**Option A: OAuth Client Still Exists (Just Need to Re-download)**
1. User must download fresh client_secret.json from Google Cloud Console
2. Upload it through the program:
   - "Extension 설치된 서버 설정" tab
   - Click "⚙️ 편집" for the Extension
   - Click "📁 client_secret.json 업로드"
   - Enable "자동으로 포트 추가" checkbox
   - Click "✅ 저장 및 설정 완료"

**Option B: OAuth Client Was Deleted (Need to Create New One)**
1. Guide user to create new OAuth Client in Google Cloud Console:
   ```
   1. Go to https://console.cloud.google.com
   2. Select project or create new one
   3. Navigate to "APIs & Services" > "Credentials"
   4. Click "CREATE CREDENTIALS" > "OAuth client ID"
   5. Choose application type:
      - "Web application" (recommended) OR
      - "Desktop app" (simpler but less flexible)
   6. For Web Application, add redirect URI:
      - http://localhost:8765/oauth2callback
      OR
      - http://localhost:8766/oauth2callback
      (Use unique port per account)
   7. Download client_secret.json
   ```

2. Follow Option A to upload new file

**Code Reference:**
- Token exchange logic: `server.js:1349-1500`
- Client secret loading: `server.js:1375-1404`

---

### Error: "redirect_uri_mismatch"

**Symptom:**
```
Error 400: redirect_uri_mismatch
The redirect URI in the request, http://localhost:8765/oauth2callback, does not match...
```

**Root Cause:**
The redirect_uri used in OAuth request doesn't match what's registered in Google Cloud Console.

**Diagnostic Steps:**

1. **Check client_secret.json redirect_uris**
   ```bash
   cat ~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_{accountId}/client_secret.json | python3 -c "import json, sys; data=json.load(sys.stdin); config=data.get('web') or data.get('installed'); print(config.get('redirect_uris'))"
   ```

2. **Check configured WORKSPACE_MCP_PORT**
   ```bash
   cat ~/.claude.json | python3 -m json.tool | grep -A 10 "workspace-mcp-"
   ```

3. **Check oauth_port_map.json**
   ```bash
   cat ~/.mcp-workspace/oauth_port_map.json
   ```

**Resolution:**

**For Web Application Type:**
1. Ensure Google Cloud Console redirect URIs match exactly:
   ```
   http://localhost:{port}/oauth2callback
   ```
   Where {port} is from WORKSPACE_MCP_PORT env variable

2. Update redirect URI in Google Cloud Console if needed:
   - Go to Credentials page
   - Click the OAuth 2.0 Client ID
   - Edit "Authorized redirect URIs"
   - Add: `http://localhost:{port}/oauth2callback`
   - Save

**For Desktop Application Type:**
1. Desktop apps use `http://localhost` as redirect_uri (no port)
2. Program automatically detects port from oauth_port_map.json
3. No changes needed in Google Cloud Console

**Code Reference:**
- OAuth URL generation: `server.js:1051-1058`
- Redirect URI construction: `server.js:1041-1044`

---

## Port Configuration Issues

### Issue: Port Mismatch Warning

**Symptom:**
```
⚠️ 포트 불일치 경고: 설정된 포트 8765가 client_secret.json의 포트 8766과 다릅니다
```

**Root Cause:**
The port in `WORKSPACE_MCP_PORT` environment variable doesn't match the port extracted from client_secret.json redirect_uri.

**Diagnostic Steps:**

1. **Check configured port in .claude.json**
   ```bash
   cat ~/.claude.json | python3 -c "
   import json, sys
   data = json.load(sys.stdin)
   servers = data['projects']['{homeDir}']['mcpServers']
   for name, config in servers.items():
       if 'workspace-mcp' in name.lower():
           port = config.get('env', {}).get('WORKSPACE_MCP_PORT', 'NOT SET')
           email = config.get('env', {}).get('USER_GOOGLE_EMAIL', 'NOT SET')
           print(f'{name}: port={port}, email={email}')
   "
   ```

2. **Check client_secret.json port**
   ```bash
   cat ~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_{accountId}/client_secret.json | python3 -c "import json, sys; data=json.load(sys.stdin); config=data.get('web') or data.get('installed'); uri=config['redirect_uris'][0]; import re; match=re.search(r':(\d+)/', uri); print(f'Port: {match.group(1) if match else \"N/A\"}')"
   ```

3. **Check oauth_port_map.json mapping**
   ```bash
   cat ~/.mcp-workspace/oauth_port_map.json
   ```

**Resolution:**

**Option 1: Auto-detect Port (Recommended)**
1. User clicks "🔍 포트 자동 감지" button in Extension edit dialog
2. Program extracts port from client_secret.json
3. Automatically updates WORKSPACE_MCP_PORT

**Option 2: Manual Fix**
1. User edits WORKSPACE_MCP_PORT in Extension settings
2. Enter correct port number (e.g., 8765 or 8766)
3. Save configuration

**Option 3: Fix client_secret.json (if wrong)**
1. Download new client_secret.json from Google Cloud Console
2. Ensure redirect_uri has correct port
3. Re-upload through program

**Code Reference:**
- Port detection: `server.js:754-844`
- Port mismatch check: `server.js:789-796`
- Auto-detect API: `server.js:504-599`

---

### Issue: Wrong Port Detected for Email Account

**Symptom:**
```
intenet8821@gmail.com is detecting port 8766 instead of 8765
```

**Root Cause:**
Server is scanning all client_secret directories and matching the first client_id found in oauth_port_map.json, instead of the email-specific one.

**Diagnostic Steps:**

1. **Check which client_secret directories exist**
   ```bash
   ls -la ~/Documents/GitHub/myproduct_v4/google_workspace_mcp/ | grep client_secret
   ```

2. **Check each client_secret's client_id**
   ```bash
   for dir in ~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_*/; do
       echo "Directory: $(basename $dir)"
       cat "$dir/client_secret.json" | python3 -c "import json, sys; data=json.load(sys.stdin); config=data.get('web') or data.get('installed'); print(f\"  Client ID: {config['client_id']}\")"
   done
   ```

3. **Check oauth_port_map.json**
   ```bash
   cat ~/.mcp-workspace/oauth_port_map.json | python3 -m json.tool
   ```

**Resolution:**

The fix is already implemented in server.js (as of 2025-11-12). The server now:
1. Extracts accountId from email (e.g., intenet8821@gmail.com → intenet8821)
2. Checks specific directory first: `client_secret_{accountId}/client_secret.json`
3. Falls back to scanning all directories only if specific one not found

If issue still occurs:
1. Restart server: `kill {server_pid} && node server.js`
2. Verify accountId matches directory name
3. Check server logs for port detection process

**Code Reference:**
- Email-specific port detection: `server.js:762-801`
- Fallback directory scanning: `server.js:804-839`

---

## Token Management Problems

### Issue: Token Expired / Needs Refresh

**Symptom:**
```
토큰이 만료됨
Refresh token 있음
자동 갱신 가능
```

**Root Cause:**
Access token has expired. Needs refresh using refresh_token.

**Diagnostic Steps:**

1. **Check token file**
   ```bash
   cat ~/.google_workspace_mcp/credentials/{email}.json | python3 -m json.tool
   ```
   Look for:
   - `expiry` field (ISO timestamp)
   - `refresh_token` field (should exist)
   - `token` field (access token)

2. **Check if refresh_token exists**
   ```bash
   cat ~/.google_workspace_mcp/credentials/{email}.json | python3 -c "import json, sys; data=json.load(sys.stdin); print('Has refresh_token:', 'refresh_token' in data)"
   ```

**Resolution:**

**If refresh_token exists:**
- Token will auto-refresh on next API call
- No user action needed
- Program handles this automatically

**If refresh_token missing:**
1. User must re-authenticate
2. Click "🔐 인증 시작" button
3. Complete OAuth flow in browser
4. Ensure `prompt=consent` parameter is used to get new refresh_token

**Code Reference:**
- Token expiry check: `server.js:856-899`
- Auto-refresh logic: Handled by workspace-mcp Extension itself

---

### Issue: No Token Found

**Symptom:**
```
인증되지 않음
이메일: user@gmail.com
토큰 경로: null
```

**Root Cause:**
No authentication token exists for this email account.

**Diagnostic Steps:**

1. **Check both token locations**
   ```bash
   # Location 1
   ls -la ~/.mcp-workspace/token-{email}.json

   # Location 2
   ls -la ~/.google_workspace_mcp/credentials/{email}.json
   ```

2. **Check .claude.json has correct email**
   ```bash
   cat ~/.claude.json | python3 -c "
   import json, sys
   data = json.load(sys.stdin)
   servers = data['projects']['{homeDir}']['mcpServers']
   for name, config in servers.items():
       if 'workspace-mcp' in name.lower():
           email = config.get('env', {}).get('USER_GOOGLE_EMAIL', 'NOT SET')
           print(f'{name}: {email}')
   "
   ```

**Resolution:**

1. Ensure USER_GOOGLE_EMAIL is set correctly in Extension config
2. Click "🔐 인증 시작" button
3. Complete OAuth flow in browser
4. Token will be saved to `~/.google_workspace_mcp/credentials/{email}.json`

**Code Reference:**
- Token path check: `server.js:846-877`
- Token locations checked: `server.js:851-872`

---

## Extension Configuration Issues

### Issue: Extension Not Showing in List

**Symptom:**
Extension installed in Claude Desktop but not appearing in program.

**Diagnostic Steps:**

1. **Check Extension directory**
   ```bash
   ls -la ~/Library/Application\ Support/Claude/Claude\ Extensions/
   ```

2. **Check manifest.json**
   ```bash
   cat ~/Library/Application\ Support/Claude/Claude\ Extensions/{extension_dir}/manifest.json
   ```
   Verify:
   - Valid JSON format
   - Has `name` field
   - Has `version` field

3. **Check scan API response**
   ```bash
   curl -s http://localhost:3000/api/scan-extensions | python3 -m json.tool
   ```

**Resolution:**

1. Ensure Extension manifest.json is valid
2. Restart program to re-scan Extensions
3. Check browser console for scan errors

**Code Reference:**
- Extension scanning: `server.js:220-280`

---

### Issue: Environment Variables Not Saving

**Symptom:**
User adds environment variables but they disappear after page refresh.

**Diagnostic Steps:**

1. **Check .claude.json was modified**
   ```bash
   ls -la ~/.claude.json
   cat ~/.claude.json | python3 -m json.tool | grep -A 5 "{serverName}"
   ```

2. **Check for file permission issues**
   ```bash
   ls -l ~/.claude.json
   # Should be writable by current user
   ```

3. **Check server logs**
   ```bash
   tail -50 /tmp/server-debug.log | grep "save.*extension"
   ```

**Resolution:**

1. Ensure .claude.json has write permissions
2. Click "✅ 저장 및 설정 완료" button (not just "저장")
3. Wait for success message before closing dialog
4. Restart Claude Code to reload configuration

**Code Reference:**
- Save Extension config: `server.js:300-370`

---

## Debugging Workflow

When user reports an authentication issue, follow this systematic approach:

### Step 1: Gather Information

```bash
# Check Extension configuration
cat ~/.claude.json | python3 -m json.tool | grep -A 20 "workspace-mcp"

# Check client_secret files
ls -la ~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_*/

# Check port mapping
cat ~/.mcp-workspace/oauth_port_map.json

# Check token files
ls -la ~/.google_workspace_mcp/credentials/

# Check server logs (if available)
tail -100 /tmp/server-debug.log
```

### Step 2: Verify OAuth Setup

1. **Email configured?**
   - Check USER_GOOGLE_EMAIL in Extension env

2. **client_secret uploaded?**
   - Check client_secret_{accountId} directory exists
   - Verify client_id matches oauth_port_map.json

3. **Port configured?**
   - Check WORKSPACE_MCP_PORT in Extension env
   - Verify it matches client_secret redirect_uri

### Step 3: Test Authentication Flow

1. **Start auth**
   - User clicks "🔐 인증 시작"
   - Check OAuth URL is generated correctly

2. **Complete in browser**
   - Check for redirect_uri_mismatch error
   - Check for invalid_client error

3. **Check token saved**
   - Verify token file exists after successful auth
   - Check expiry timestamp

### Step 4: Verify OAuth Callback Server

```bash
# Check which ports have callback servers running
lsof -i :8765
lsof -i :8766

# Check server.js logs for callback server startup
tail -100 /tmp/server-debug.log | grep "OAuth callback server"
```

### Step 5: Common Fix Patterns

**Pattern 1: Fresh Start**
```
1. Delete old token file
2. Re-upload client_secret.json
3. Auto-detect port
4. Save configuration
5. Re-authenticate
```

**Pattern 2: Port Mismatch**
```
1. Click "🔍 포트 자동 감지"
2. Verify correct port detected
3. Save configuration
4. Restart server if needed
5. Re-authenticate
```

**Pattern 3: Invalid Client**
```
1. Download fresh client_secret.json from Google Cloud Console
2. Verify OAuth Client is "Active" in Console
3. Upload new file through program
4. Auto-detect port
5. Save and re-authenticate
```

---

## File Locations Reference

Quick reference for AI assistants:

```bash
# Claude Code Configuration
~/.claude.json

# OAuth Port Mapping
~/.mcp-workspace/oauth_port_map.json

# Client Secrets (per account)
~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_{accountId}/client_secret.json

# Authentication Tokens
~/.google_workspace_mcp/credentials/{email}.json
~/.mcp-workspace/token-{email}.json

# Server Logs
/tmp/server-debug.log
/tmp/electron-app-*.log

# Claude Desktop Extensions
~/Library/Application Support/Claude/Claude Extensions/
```

---

## API Endpoints Reference

For AI assistants debugging via API:

```bash
# Check auth status
curl -X POST http://localhost:3000/api/check-auth-status \
  -H "Content-Type: application/json" \
  -d '{"mcpServers": {...}}'

# Start OAuth flow
curl -X POST http://localhost:3000/api/start-auth \
  -H "Content-Type: application/json" \
  -d '{"serverName": "workspace-mcp-intenet1-v2", "email": "intenet1@gmail.com"}'

# Auto-detect port
curl -X POST http://localhost:3000/api/detect-port-from-extension \
  -H "Content-Type: application/json" \
  -d '{"serverName": "workspace-mcp-intenet1-v2", "email": "intenet1@gmail.com"}'

# Scan extensions
curl http://localhost:3000/api/scan-extensions
```

---

## Recent Fixes (Changelog for AI)

### 2025-11-12
- Fixed port detection to prioritize email-specific client_secret directories
- Added support for "installed" (Desktop App) OAuth type
- Improved oauth_port_map.json management for multiple accounts
- Enhanced server logs with detailed debug information

### Known Limitations
- OAuth callback servers must be started manually for each port
- Token refresh handled by workspace-mcp Extension, not this program
- Google Cloud Console configuration must be done manually by user

---

## Emergency Commands

When all else fails:

```bash
# Nuclear option: Reset everything
rm ~/.claude.json.backup
rm ~/.google_workspace_mcp/credentials/*.json
rm ~/.mcp-workspace/oauth_port_map.json
rm ~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_*/client_secret.json

# Then guide user to set up from scratch

# Restart server
ps aux | grep "node.*server.js" | grep -v grep | awk '{print $2}' | xargs kill
cd "/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter"
node server.js > /tmp/server-debug.log 2>&1 &
```

Use these commands only as a last resort after documenting current state for debugging purposes.
