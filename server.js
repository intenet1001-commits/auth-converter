const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const os = require('os');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = './uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() === '.json') {
      cb(null, true);
    } else {
      cb(new Error('Only JSON files are allowed'));
    }
  }
});

// Helper function to find google_workspace_mcp directory dynamically
function findGoogleWorkspaceMcpDir() {
  const homeDir = os.homedir();
  const possiblePaths = [
    path.join(homeDir, 'Documents', 'GitHub', 'myproduct_v4', 'google_workspace_mcp'),
    path.join(homeDir, 'Documents', 'github', 'myproduct_v4', 'google_workspace_mcp'),
    path.join(homeDir, 'Documents', 'myproduct_v4', 'google_workspace_mcp'),
    path.join(homeDir, 'google_workspace_mcp'),
    path.join(homeDir, '.google_workspace_mcp'),
  ];

  for (const dirPath of possiblePaths) {
    if (fs.existsSync(dirPath)) {
      console.log(`✓ Found google_workspace_mcp at: ${dirPath}`);
      return dirPath;
    }
  }

  console.log('⚠️ google_workspace_mcp directory not found in common locations');
  return null;
}

// Helper function to find client_secret.json for a given account ID
function findClientSecretForAccount(accountId, baseDir) {
  if (!baseDir || !fs.existsSync(baseDir)) {
    console.log(`Base directory not found: ${baseDir}`);
    return null;
  }

  try {
    const dirs = fs.readdirSync(baseDir, { withFileTypes: true })
      .filter(dirent => dirent.isDirectory());

    // Try exact match patterns first
    const exactPatterns = [
      `client_secret_${accountId}`,
      `client_secret-${accountId}`,
      `${accountId}_client_secret`,
      `${accountId}-client_secret`
    ];

    for (const pattern of exactPatterns) {
      const dir = dirs.find(d => d.name === pattern);
      if (dir) {
        const secretPath = path.join(baseDir, dir.name, 'client_secret.json');
        if (fs.existsSync(secretPath)) {
          console.log(`✓ Found exact match client_secret at: ${secretPath}`);
          return secretPath;
        }
      }
    }

    // Try partial match (contains accountId)
    for (const dir of dirs) {
      if (dir.name.includes(accountId) && dir.name.includes('client_secret')) {
        const secretPath = path.join(baseDir, dir.name, 'client_secret.json');
        if (fs.existsSync(secretPath)) {
          console.log(`✓ Found partial match client_secret at: ${secretPath}`);
          return secretPath;
        }
      }
    }

    console.log(`❌ No client_secret found for account: ${accountId}`);
    return null;
  } catch (err) {
    console.error(`Error scanning directory ${baseDir}:`, err);
    return null;
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Parse JSON from text input
app.post('/api/parse', (req, res) => {
  try {
    const jsonData = typeof req.body.json === 'string'
      ? JSON.parse(req.body.json)
      : req.body.json;
    res.json({ success: true, data: jsonData });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Upload and parse JSON file
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    const fileContent = fs.readFileSync(req.file.path, 'utf8');
    const jsonData = JSON.parse(fileContent);

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json({ success: true, data: jsonData });
  } catch (error) {
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    res.status(400).json({ success: false, error: error.message });
  }
});

// Merge MCP servers
app.post('/api/merge-mcp', (req, res) => {
  try {
    const { existingConfig, newServers, serverNameMap } = req.body;

    if (!existingConfig || !newServers) {
      return res.status(400).json({
        success: false,
        error: 'existingConfig와 newServers가 필요합니다'
      });
    }

    // Parse JSON strings if needed
    const existing = typeof existingConfig === 'string'
      ? JSON.parse(existingConfig)
      : existingConfig;
    const newSrvs = typeof newServers === 'string'
      ? JSON.parse(newServers)
      : newServers;

    // Determine if we're working with mcpServers wrapper or direct servers
    let existingServers = existing.mcpServers || existing;
    let serversToAdd = newSrvs.mcpServers || newSrvs;

    // Apply server name mapping if provided
    if (serverNameMap && Object.keys(serverNameMap).length > 0) {
      const renamedServers = {};
      Object.keys(serversToAdd).forEach(oldName => {
        const newName = serverNameMap[oldName] || oldName;
        renamedServers[newName] = serversToAdd[oldName];
      });
      serversToAdd = renamedServers;
    }

    // Merge servers ensuring new servers are added at the end
    // This maintains the order: existing servers first, then new servers
    const mergedServers = { ...existingServers, ...serversToAdd };

    console.log('Existing server count:', Object.keys(existingServers).length);
    console.log('New servers being added:', Object.keys(serversToAdd));
    console.log('Total merged servers:', Object.keys(mergedServers).length);

    // Prepare result with same structure as input
    let result;
    if (existing.mcpServers) {
      result = { mcpServers: mergedServers };
    } else {
      result = mergedServers;
    }

    res.json({
      success: true,
      data: result,
      addedServers: Object.keys(serversToAdd),
      totalServers: Object.keys(mergedServers).length
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Scan Claude Desktop Extensions
app.get('/api/scan-extensions', (req, res) => {
  try {
    const homeDir = os.homedir();
    const extensionsPath = path.join(homeDir, 'Library', 'Application Support', 'Claude', 'Claude Extensions');

    console.log('Scanning extensions from:', extensionsPath);

    // Check if extensions directory exists
    if (!fs.existsSync(extensionsPath)) {
      return res.json({
        success: true,
        extensions: [],
        message: 'Extensions 폴더가 존재하지 않습니다'
      });
    }

    // Read all directories in extensions folder
    const entries = fs.readdirSync(extensionsPath, { withFileTypes: true });
    const extensionDirs = entries.filter(entry => entry.isDirectory() && !entry.name.startsWith('.'));

    const extensions = [];

    for (const dir of extensionDirs) {
      const extensionPath = path.join(extensionsPath, dir.name);
      const manifestPath = path.join(extensionPath, 'manifest.json');

      // Check if manifest.json exists
      if (fs.existsSync(manifestPath)) {
        try {
          const manifestContent = fs.readFileSync(manifestPath, 'utf8');
          const manifest = JSON.parse(manifestContent);

          // Extract key information
          const extension = {
            id: dir.name,
            name: manifest.name || dir.name,
            displayName: manifest.display_name || manifest.name || dir.name,
            version: manifest.version || 'unknown',
            description: manifest.description || '',
            author: manifest.author || {},
            path: extensionPath,
            server: manifest.server || null,
            tools: manifest.tools || [],
            userConfig: manifest.user_config || {}
          };

          extensions.push(extension);
        } catch (error) {
          console.error(`Error parsing manifest for ${dir.name}:`, error.message);
        }
      }
    }

    res.json({
      success: true,
      extensions: extensions,
      count: extensions.length
    });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Convert Extension to MCP Server config
app.post('/api/extension-to-mcp', (req, res) => {
  try {
    const { extension, shareCredentials, uploadedClientSecret } = req.body;

    if (!extension || !extension.server) {
      return res.status(400).json({
        success: false,
        error: 'Extension 정보가 유효하지 않습니다'
      });
    }

    const mcpConfig = extension.server.mcp_config;
    if (!mcpConfig) {
      return res.status(400).json({
        success: false,
        error: 'Extension에 MCP 설정이 없습니다'
      });
    }

    // Replace ${__dirname} with actual extension path
    const command = mcpConfig.command;
    const args = (mcpConfig.args || []).map(arg => {
      if (typeof arg === 'string') {
        return arg.replace(/\$\{__dirname\}/g, extension.path);
      }
      return arg;
    });

    // Process environment variables
    const env = {};
    if (mcpConfig.env) {
      Object.keys(mcpConfig.env).forEach(key => {
        const value = mcpConfig.env[key];
        // Skip template variables for now (user needs to configure them)
        if (typeof value === 'string' && !value.includes('${user_config.')) {
          env[key] = value;
        }
      });
    }

    // Add shared credentials directory if requested
    if (shareCredentials) {
      const homeDir = os.homedir();
      const sharedCredentialsDir = path.join(homeDir, '.google-workspace-mcp', 'credentials');

      // Add credential sharing environment variable
      env['GOOGLE_MCP_CREDENTIALS_DIR'] = sharedCredentialsDir;

      console.log('Credentials sharing enabled:', sharedCredentialsDir);
    }

    // Check if this is a workspace MCP server and auto-detect OAuth port
    const isWorkspaceMcp = extension.id && extension.id.includes('workspace-mcp');
    let detectedPort = null;
    let portSource = null; // Track where port was detected from

    if (isWorkspaceMcp) {
      // PRIORITY 1: Try to extract port from uploaded client_secret.json (if available)
      if (uploadedClientSecret) {
        try {
          const clientConfig = uploadedClientSecret.installed || uploadedClientSecret.web;
          if (clientConfig && clientConfig.redirect_uris && clientConfig.redirect_uris.length > 0) {
            const redirectUri = clientConfig.redirect_uris[0];
            const portMatch = redirectUri.match(/:(\d+)\//);
            if (portMatch) {
              detectedPort = parseInt(portMatch[1]);
              portSource = 'uploaded_client_secret';
              console.log(`✓ Port ${detectedPort} extracted from uploaded client_secret.json redirect_uri: ${redirectUri}`);

              // Add WORKSPACE_MCP_PORT to env
              env.WORKSPACE_MCP_PORT = String(detectedPort);
              env.WORKSPACE_MCP_BASE_URI = env.WORKSPACE_MCP_BASE_URI || 'http://localhost';
              env.OAUTHLIB_INSECURE_TRANSPORT = env.OAUTHLIB_INSECURE_TRANSPORT || 'true';
            }
          }
        } catch (err) {
          console.error('Error extracting port from uploaded client_secret:', err);
        }
      }

      // PRIORITY 2: Try to find port from oauth_port_map.json (fallback)
      if (!detectedPort) {
        const homeDir = os.homedir();
        const portMapPath = path.join(homeDir, '.mcp-workspace', 'oauth_port_map.json');

        if (fs.existsSync(portMapPath)) {
          try {
            const portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));

            // Extract USER_GOOGLE_EMAIL from env to find matching port
            const userEmail = env.USER_GOOGLE_EMAIL || env.user_google_email;

            if (userEmail) {
              // Look for client_secret.json for this email to get client_id
              const workspaceMcpDir = findGoogleWorkspaceMcpDir();

              if (workspaceMcpDir && fs.existsSync(workspaceMcpDir)) {
                const clientSecretDirs = fs.readdirSync(workspaceMcpDir, { withFileTypes: true })
                  .filter(dirent => dirent.isDirectory() && dirent.name.includes('client_secret'));

                for (const dir of clientSecretDirs) {
                  const secretPath = path.join(workspaceMcpDir, dir.name, 'client_secret.json');

                  if (fs.existsSync(secretPath)) {
                    const clientSecret = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
                    const clientConfig = clientSecret.installed || clientSecret.web;
                    const clientId = clientConfig.client_id;

                    if (portMap[clientId]) {
                      detectedPort = portMap[clientId];
                      portSource = 'oauth_port_map';
                      console.log(`Auto-detected OAuth port ${detectedPort} for ${userEmail} from port map`);

                      // Add WORKSPACE_MCP_PORT to env
                      env.WORKSPACE_MCP_PORT = String(detectedPort);
                      env.WORKSPACE_MCP_BASE_URI = env.WORKSPACE_MCP_BASE_URI || 'http://localhost';
                      env.OAUTHLIB_INSECURE_TRANSPORT = env.OAUTHLIB_INSECURE_TRANSPORT || 'true';
                      break;
                    }
                  }
                }
              }
            }
          } catch (err) {
            console.error('Error reading port map:', err);
          }
        }
      }
    }

    const mcpServerConfig = {
      command: command,
      args: args
    };

    // Only add env if there are non-empty values
    if (Object.keys(env).length > 0) {
      mcpServerConfig.env = env;
    }

    res.json({
      success: true,
      mcpConfig: mcpServerConfig,
      requiresUserConfig: Object.keys(extension.userConfig || {}).length > 0,
      userConfigFields: extension.userConfig || {},
      credentialsShared: shareCredentials || false,
      credentialsDir: shareCredentials ? env['GOOGLE_MCP_CREDENTIALS_DIR'] : null,
      detectedPort: detectedPort,
      portAutoConfigured: detectedPort !== null,
      portSource: portSource // 'uploaded_client_secret' or 'oauth_port_map' or null
    });

  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Save client secret file API
app.post('/api/save-client-secret', (req, res) => {
  try {
    const { clientSecretData, accountId, email, serverName, autoAddPort } = req.body;

    if (!clientSecretData || !accountId) {
      return res.status(400).json({
        success: false,
        error: 'clientSecretData와 accountId가 필요합니다'
      });
    }

    // Extract client_id and redirect_uris
    const clientConfig = clientSecretData.installed || clientSecretData.web;
    const client_id = clientConfig.client_id;
    const redirect_uris = clientConfig.redirect_uris || [];

    // Extract port from redirect_uris
    let detectedPort = null;
    for (const uri of redirect_uris) {
      const match = uri.match(/http:\/\/localhost:(\d+)/);
      if (match) {
        detectedPort = parseInt(match[1]);
        console.log(`Detected OAuth port ${detectedPort} from redirect_uri: ${uri}`);
        break;
      }
    }

    // Update port mapping configuration
    if (detectedPort && client_id) {
      const homeDir = os.homedir();
      const configDir = path.join(homeDir, '.mcp-workspace');
      const portMapPath = path.join(configDir, 'oauth_port_map.json');

      // Load existing port map or create new one
      let portMap = {};
      if (fs.existsSync(portMapPath)) {
        try {
          portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));
        } catch (err) {
          console.error('Error reading port map:', err);
        }
      }

      // Update port map
      portMap[client_id] = detectedPort;

      // Save port map
      if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true });
      }
      fs.writeFileSync(portMapPath, JSON.stringify(portMap, null, 2));

      console.log(`Updated port mapping: ${client_id} -> ${detectedPort}`);
    }

    // Create directory for client secrets
    const homeDir = os.homedir();
    let baseDir = findGoogleWorkspaceMcpDir();

    // If not found, create in default location
    if (!baseDir) {
      baseDir = path.join(homeDir, 'Documents', 'GitHub', 'myproduct_v4', 'google_workspace_mcp');
      console.log(`Creating new google_workspace_mcp directory at: ${baseDir}`);
    }

    const secretDir = path.join(baseDir, `client_secret_${accountId}`);

    if (!fs.existsSync(secretDir)) {
      fs.mkdirSync(secretDir, { recursive: true });
    }

    // Save the client secret file
    const secretPath = path.join(secretDir, 'client_secret.json');
    fs.writeFileSync(secretPath, JSON.stringify(clientSecretData, null, 2));

    console.log('Client secret saved to:', secretPath);

    // Auto-add port to .claude.json if requested and port detected
    let portAddedToConfig = false;
    if (autoAddPort && detectedPort && serverName) {
      try {
        const claudeConfigPath = path.join(homeDir, '.claude.json');

        if (fs.existsSync(claudeConfigPath)) {
          const claudeConfig = JSON.parse(fs.readFileSync(claudeConfigPath, 'utf8'));

          // Find the project entry
          const projects = claudeConfig.projects || {};
          const projectKey = Object.keys(projects).find(key =>
            key.match(/^\/Users\/[^\/]+$/) ||
            key.match(/^\/home\/[^\/]+$/) ||
            key.match(/^[A-Z]:\\Users\\[^\\]+$/)
          );

          if (projectKey && projects[projectKey] && projects[projectKey].mcpServers) {
            const server = projects[projectKey].mcpServers[serverName];

            if (server) {
              // Add or update WORKSPACE_MCP_PORT in env
              if (!server.env) {
                server.env = {};
              }

              server.env.WORKSPACE_MCP_PORT = String(detectedPort);

              // Also add related env vars if not present
              if (!server.env.WORKSPACE_MCP_BASE_URI) {
                server.env.WORKSPACE_MCP_BASE_URI = 'http://localhost';
              }
              if (!server.env.OAUTHLIB_INSECURE_TRANSPORT) {
                server.env.OAUTHLIB_INSECURE_TRANSPORT = 'true';
              }

              // Save updated config
              fs.writeFileSync(claudeConfigPath, JSON.stringify(claudeConfig, null, 2));

              console.log(`✅ Auto-added WORKSPACE_MCP_PORT=${detectedPort} to ${serverName} in .claude.json`);
              portAddedToConfig = true;
            } else {
              console.log(`⚠️ Server ${serverName} not found in .claude.json`);
            }
          } else {
            console.log('⚠️ No project entry found in .claude.json');
          }
        } else {
          console.log('⚠️ .claude.json not found');
        }
      } catch (error) {
        console.error('Error auto-adding port to .claude.json:', error);
        // Continue anyway, don't fail the entire request
      }
    }

    res.json({
      success: true,
      path: secretPath,
      detectedPort: detectedPort,
      client_id: client_id,
      portAddedToConfig: portAddedToConfig
    });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Detect OAuth port from existing Extension's client_secret.json
app.post('/api/detect-port-from-extension', (req, res) => {
  try {
    const { serverName, email } = req.body;

    console.log(`🔍 Detecting port for server: ${serverName}, email: ${email}`);

    // Try to find client_secret.json from various possible locations
    const homeDir = os.homedir();
    const possiblePaths = [];
    const workspaceMcpDir = findGoogleWorkspaceMcpDir();

    if (!workspaceMcpDir) {
      console.log('⚠️ google_workspace_mcp directory not found');
    }

    // 1. From server name (extract account identifier)
    if (serverName && workspaceMcpDir) {
      const match = serverName.match(/workspace-mcp-(.+?)(?:-v\d+)?$/);
      if (match) {
        const accountId = match[1];
        const foundPath = findClientSecretForAccount(accountId, workspaceMcpDir);
        if (foundPath) possiblePaths.push(foundPath);
      }
    }

    // 2. From email
    if (email && workspaceMcpDir) {
      const accountId = email.split('@')[0];
      const foundPath = findClientSecretForAccount(accountId, workspaceMcpDir);
      if (foundPath) possiblePaths.push(foundPath);
    }

    // 3. Try to find from .claude.json GOOGLE_CLIENT_SECRET_PATH
    const claudeConfigPath = path.join(homeDir, '.claude.json');
    if (fs.existsSync(claudeConfigPath)) {
      try {
        const claudeConfig = JSON.parse(fs.readFileSync(claudeConfigPath, 'utf8'));
        const projects = claudeConfig.projects || {};
        const projectKey = Object.keys(projects).find(key =>
          key.match(/^\/Users\/[^\/]+$/) ||
          key.match(/^\/home\/[^\/]+$/) ||
          key.match(/^[A-Z]:\\Users\\[^\\]+$/)
        );

        if (projectKey && projects[projectKey] && projects[projectKey].mcpServers) {
          const server = projects[projectKey].mcpServers[serverName];
          if (server && server.env && server.env.GOOGLE_CLIENT_SECRET_PATH) {
            possiblePaths.push(server.env.GOOGLE_CLIENT_SECRET_PATH);
          }
        }
      } catch (err) {
        console.error('Error reading .claude.json:', err);
      }
    }

    console.log('Possible client_secret paths:', possiblePaths);

    // Try each path
    for (const secretPath of possiblePaths) {
      if (fs.existsSync(secretPath)) {
        try {
          const clientSecretData = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
          const clientConfig = clientSecretData.installed || clientSecretData.web;

          if (clientConfig && clientConfig.redirect_uris) {
            // Extract port from redirect_uris
            for (const uri of clientConfig.redirect_uris) {
              const match = uri.match(/http:\/\/localhost:(\d+)/);
              if (match) {
                const detectedPort = parseInt(match[1]);
                console.log(`✅ Detected port ${detectedPort} from ${secretPath}`);

                return res.json({
                  success: true,
                  port: detectedPort,
                  source: secretPath
                });
              }
            }
          }
        } catch (err) {
          console.error(`Error reading ${secretPath}:`, err);
          continue;
        }
      }
    }

    // No port found
    return res.json({
      success: false,
      error: 'client_secret.json을 찾을 수 없거나 포트 정보가 없습니다.',
      searchedPaths: possiblePaths
    });

  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get OAuth port for a specific account from saved client_secret
app.post('/api/get-oauth-port', (req, res) => {
  try {
    const { accountId } = req.body;

    if (!accountId) {
      return res.status(400).json({
        success: false,
        error: 'accountId가 필요합니다'
      });
    }

    console.log(`🔍 Checking OAuth port for account: ${accountId}`);

    // Path to saved client_secret file
    const clientSecretPath = path.join(
      __dirname,
      '..',
      'google_workspace_mcp',
      `client_secret_${accountId}`,
      'client_secret.json'
    );

    console.log(`📁 Looking for client_secret at: ${clientSecretPath}`);

    if (!fs.existsSync(clientSecretPath)) {
      console.log(`❌ Client secret file not found for ${accountId}`);
      return res.json({
        success: false,
        error: 'Client secret 파일을 찾을 수 없습니다'
      });
    }

    // Read client_secret file
    const clientSecret = JSON.parse(fs.readFileSync(clientSecretPath, 'utf8'));
    const clientConfig = clientSecret.web || clientSecret.installed;

    if (!clientConfig || !clientConfig.client_id) {
      console.log(`❌ Invalid client_secret format for ${accountId}`);
      return res.json({
        success: false,
        error: 'Client secret 형식이 올바르지 않습니다'
      });
    }

    const clientId = clientConfig.client_id;
    console.log(`✓ Found client_id: ${clientId}`);

    // Try to get port from oauth_port_map.json
    const homeDir = os.homedir();
    const portMapPath = path.join(homeDir, '.mcp-workspace', 'oauth_port_map.json');

    if (fs.existsSync(portMapPath)) {
      const portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));

      if (portMap[clientId]) {
        const port = portMap[clientId];
        console.log(`✓ Found port ${port} for client_id ${clientId}`);
        return res.json({
          success: true,
          port: port,
          clientId: clientId,
          source: 'oauth_port_map'
        });
      }
    }

    // Fallback: Try to extract port from redirect_uri
    if (clientConfig.redirect_uris && clientConfig.redirect_uris.length > 0) {
      const redirectUri = clientConfig.redirect_uris[0];
      const portMatch = redirectUri.match(/:(\d+)\//);

      if (portMatch) {
        const port = parseInt(portMatch[1]);
        console.log(`✓ Extracted port ${port} from redirect_uri: ${redirectUri}`);
        return res.json({
          success: true,
          port: port,
          clientId: clientId,
          source: 'redirect_uri'
        });
      }
    }

    console.log(`❌ Could not determine port for ${accountId}`);
    return res.json({
      success: false,
      error: '포트를 확인할 수 없습니다'
    });

  } catch (error) {
    console.error('Error in get-oauth-port:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Check authentication status for MCP servers
app.post('/api/check-auth-status', async (req, res) => {
  try {
    const { mcpServers } = req.body;

    if (!mcpServers) {
      return res.status(400).json({
        success: false,
        error: 'mcpServers 정보가 필요합니다'
      });
    }

    const authStatus = {};
    const homeDir = os.homedir();

    // Keywords that indicate a server needs Google authentication
    const googleWorkspaceKeywords = ['workspace', 'google', 'gmail', 'drive', 'sheets', 'docs', 'calendar'];

    // Check each MCP server for authentication status
    for (const serverName of Object.keys(mcpServers)) {
      const server = mcpServers[serverName];

      console.log(`\n=== Checking server: ${serverName} ===`);
      console.log('Server config:', JSON.stringify(server, null, 2));

      // Check if this server needs Google authentication
      const needsGoogleAuth = googleWorkspaceKeywords.some(keyword =>
        serverName.toLowerCase().includes(keyword)
      );

      console.log(`Needs Google auth: ${needsGoogleAuth}`);

      // Only include servers that need Google authentication
      if (!needsGoogleAuth) {
        continue; // Skip this server
      }

      authStatus[serverName] = {
        authenticated: false,
        email: null,
        tokenPath: null,
        needsEmail: false,
        configuredPort: null,
        detectedPort: null,
        portMismatch: false
      };

      // Check if server has env variables for Google email (case-insensitive)
      const email = server.env && (server.env.user_google_email || server.env.USER_GOOGLE_EMAIL);

      // Check configured OAuth port
      const configuredPort = server.env && (server.env.WORKSPACE_MCP_PORT || server.env.PORT);
      if (configuredPort) {
        authStatus[serverName].configuredPort = parseInt(configuredPort);
        console.log(`Found configured port in env: ${configuredPort}`);
      }

      // Try to detect the OAuth port from oauth_port_map.json
      const portMapPath = path.join(homeDir, '.mcp-workspace', 'oauth_port_map.json');
      if (fs.existsSync(portMapPath)) {
        try {
          const portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));

          // Try to find matching client_secret.json for this email
          if (email) {
            // Extract account ID from email (e.g., intenet8821@gmail.com -> intenet8821)
            const accountId = email.split('@')[0];
            console.log(`Server: Looking for client_secret for account: ${accountId}`);

            // Find google_workspace_mcp directory dynamically
            const workspaceMcpDir = findGoogleWorkspaceMcpDir();

            if (!workspaceMcpDir) {
              console.log('⚠️ google_workspace_mcp directory not found, skipping port detection');
              continue;
            }

            // Use helper function to find client_secret for this account
            const specificSecretPath = findClientSecretForAccount(accountId, workspaceMcpDir);

            let foundPort = false;

            if (specificSecretPath) {
              try {
                console.log(`Server: Reading client_secret from ${specificSecretPath}`);
                const clientSecret = JSON.parse(fs.readFileSync(specificSecretPath, 'utf8'));
                const clientConfig = clientSecret.installed || clientSecret.web;
                const clientId = clientConfig.client_id;

                console.log(`Server: Client ID for ${email}: ${clientId}`);

                if (portMap[clientId]) {
                  authStatus[serverName].detectedPort = portMap[clientId];
                  console.log(`Server: Detected OAuth port ${portMap[clientId]} for ${email}`);
                  foundPort = true;

                  // Check for port mismatch
                  if (configuredPort && parseInt(configuredPort) !== portMap[clientId]) {
                    authStatus[serverName].portMismatch = true;
                    authStatus[serverName].portMismatchWarning = `Configured port ${configuredPort} doesn't match client_secret port ${portMap[clientId]}`;
                    console.log(`⚠️ Port mismatch detected for ${serverName}`);
                  } else if (!configuredPort) {
                    authStatus[serverName].needsPortConfig = true;
                    console.log(`⚠️ WORKSPACE_MCP_PORT not configured for ${serverName}`);
                  }
                }
              } catch (err) {
                console.error(`Error reading ${specificSecretPath}:`, err);
              }
            }

            // If not found, fall back to scanning all directories
            if (!foundPort) {
              console.log(`Server: Scanning all client_secret directories...`);
              try {
                const clientSecretDirs = fs.readdirSync(workspaceMcpDir, { withFileTypes: true })
                  .filter(dirent => dirent.isDirectory() && dirent.name.includes('client_secret'));

                for (const dir of clientSecretDirs) {
                  const secretPath = path.join(workspaceMcpDir, dir.name, 'client_secret.json');

                  if (fs.existsSync(secretPath)) {
                    const clientSecret = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
                    const clientConfig = clientSecret.installed || clientSecret.web;
                    const clientId = clientConfig.client_id;

                    if (portMap[clientId]) {
                      authStatus[serverName].detectedPort = portMap[clientId];
                      console.log(`Detected OAuth port ${portMap[clientId]} for ${email} from ${dir.name}`);

                      // Check for port mismatch
                      if (configuredPort && parseInt(configuredPort) !== portMap[clientId]) {
                        authStatus[serverName].portMismatch = true;
                        authStatus[serverName].portMismatchWarning = `Configured port ${configuredPort} doesn't match client_secret port ${portMap[clientId]}`;
                        console.log(`⚠️ Port mismatch detected for ${serverName}`);
                      } else if (!configuredPort) {
                        authStatus[serverName].needsPortConfig = true;
                        console.log(`⚠️ WORKSPACE_MCP_PORT not configured for ${serverName}`);
                      }
                      break;
                    }
                  }
                }
              } catch (err) {
                console.error(`Error scanning ${workspaceMcpDir}:`, err);
              }
            }
          }
        } catch (err) {
          console.error('Error reading port map:', err);
        }
      }

      if (email) {
        console.log(`Found email in env: ${email}`);
        authStatus[serverName].email = email;
        authStatus[serverName].needsEmail = false;

        // Check for token file in both possible locations
        const tokenDir1 = path.join(homeDir, '.mcp-workspace');
        const tokenPath1 = path.join(tokenDir1, `token-${email}.json`);

        const tokenDir2 = path.join(homeDir, '.google_workspace_mcp', 'credentials');
        const tokenPath2 = path.join(tokenDir2, `${email}.json`);

        console.log(`Checking token path 1: ${tokenPath1}`);
        console.log(`Token 1 exists: ${fs.existsSync(tokenPath1)}`);
        console.log(`Checking token path 2: ${tokenPath2}`);
        console.log(`Token 2 exists: ${fs.existsSync(tokenPath2)}`);

        let tokenPath = null;
        if (fs.existsSync(tokenPath1)) {
          tokenPath = tokenPath1;
        } else if (fs.existsSync(tokenPath2)) {
          tokenPath = tokenPath2;
        }

        if (tokenPath) {
          try {
            const tokenData = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
            // Check if token has required fields
            const hasAccessToken = tokenData.access_token || tokenData.token;
            const hasRefreshToken = tokenData.refresh_token;

            if (hasAccessToken || hasRefreshToken) {
              authStatus[serverName].tokenPath = tokenPath;

              // Check token expiry from file
              const expiry = tokenData.expiry;
              const isExpired = expiry && new Date(expiry) <= new Date();

              authStatus[serverName].tokenExpired = isExpired;
              authStatus[serverName].hasRefreshToken = !!hasRefreshToken;

              // Verify token with Google API (with timeout)
              let isTokenActuallyValid = false;
              if (hasAccessToken && !isExpired) {
                try {
                  const token = hasAccessToken;
                  const verifyUrl = `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${encodeURIComponent(token)}`;

                  const https = require('https');
                  const verifyResult = await Promise.race([
                    new Promise((resolve) => {
                      https.get(verifyUrl, (res) => {
                        let data = '';
                        res.on('data', (chunk) => data += chunk);
                        res.on('end', () => {
                          resolve(res.statusCode === 200);
                        });
                      }).on('error', () => {
                        resolve(false);
                      });
                    }),
                    new Promise((resolve) => setTimeout(() => resolve(false), 3000)) // 3초 타임아웃
                  ]);

                  isTokenActuallyValid = verifyResult;
                  console.log(`Token verification for ${email}: ${isTokenActuallyValid ? 'VALID' : 'INVALID/TIMEOUT'}`);
                } catch (err) {
                  console.error(`Error verifying token for ${email}:`, err);
                  isTokenActuallyValid = false;
                }
              }

              // Set authentication status
              if (isExpired || !isTokenActuallyValid) {
                // Token is expired or invalid
                authStatus[serverName].authenticated = false;
                if (hasRefreshToken) {
                  authStatus[serverName].canRefresh = true;
                  authStatus[serverName].needsReauth = true;
                  console.log(`⚠️ Token invalid/expired, needs re-auth for ${email}`);
                } else {
                  authStatus[serverName].canRefresh = false;
                  authStatus[serverName].needsReauth = true;
                  console.log(`⚠️ Token invalid and no refresh token for ${email}`);
                }
              } else {
                // Token is valid
                authStatus[serverName].authenticated = true;
                authStatus[serverName].canRefresh = false;
                authStatus[serverName].needsReauth = false;
                console.log(`✓ Token valid and verified for ${email}`);
              }
            }
          } catch (err) {
            console.error(`Error reading token for ${email}:`, err);
          }
        }
      } else {
        // Server needs Google auth but doesn't have email configured
        console.log(`No email found in env`);
        authStatus[serverName].needsEmail = true;
      }

      console.log(`Final status for ${serverName}:`, authStatus[serverName]);
    }

    res.json({
      success: true,
      authStatus
    });

  } catch (error) {
    console.error('Error checking auth status:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Start authentication for a specific account
app.post('/api/start-auth', (req, res) => {
  try {
    const { email, serverName } = req.body;

    if (!email || !serverName) {
      return res.status(400).json({
        success: false,
        error: 'email과 serverName이 필요합니다'
      });
    }

    // Find appropriate client_secret.json based on email
    const homeDir = os.homedir();
    const accountId = email.split('@')[0];

    // Try to find using helper function first
    const workspaceMcpDir = findGoogleWorkspaceMcpDir();
    let secretPath = null;

    if (workspaceMcpDir) {
      secretPath = findClientSecretForAccount(accountId, workspaceMcpDir);
      if (secretPath) {
        console.log(`Found client_secret for ${email} at: ${secretPath}`);
      }
    }

    // Fallback: try default locations
    if (!secretPath) {
      const fallbackPaths = [
        path.join(homeDir, '.mcp-workspace', 'client_secret.json'),
        path.join(homeDir, '.google_workspace_mcp', 'client_secret.json')
      ];

      for (const tryPath of fallbackPaths) {
        if (fs.existsSync(tryPath)) {
          secretPath = tryPath;
          console.log(`Found client_secret for ${email} at fallback: ${secretPath}`);
          break;
        }
      }
    }

    if (!secretPath) {
      return res.json({
        success: true,
        needsClientSecret: true,
        message: `${email}에 대한 client_secret.json을 찾을 수 없습니다`
      });
    }

    // Read client_secret.json and generate OAuth URL
    const clientSecret = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
    const { client_id, redirect_uris } = clientSecret.installed || clientSecret.web;

    // First try oauth_port_map.json
    let oauthPort = 8766; // default
    const portMapPath = path.join(homeDir, '.mcp-workspace', 'oauth_port_map.json');
    if (fs.existsSync(portMapPath)) {
      try {
        const portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));
        if (portMap[client_id]) {
          oauthPort = portMap[client_id];
          console.log(`Using port ${oauthPort} from oauth_port_map.json`);
        }
      } catch (err) {
        console.error('Error loading port map:', err);
      }
    }

    // Check if this is "installed" (Desktop App) or "web" type
    const isDesktopApp = !!clientSecret.installed;

    // Extract port from redirect_uris in client_secret.json (highest priority)
    if (redirect_uris && redirect_uris.length > 0) {
      for (const uri of redirect_uris) {
        const match = uri.match(/http:\/\/localhost:(\d+)/);
        if (match) {
          oauthPort = parseInt(match[1]);
          console.log(`Using port ${oauthPort} from client_secret redirect_uri: ${uri}`);
          break;
        }
      }
    }

    // For Desktop App (installed), use dynamic port in redirect_uri
    const redirectUri = isDesktopApp
      ? `http://localhost:${oauthPort}/oauth2callback`
      : `http://localhost:${oauthPort}/oauth2callback`;

    console.log(`Using OAuth port ${oauthPort} for ${email} (client_id: ${client_id})`);

    // Scopes for Google Workspace APIs
    const scopes = [
      'https://www.googleapis.com/auth/forms',
      'https://www.googleapis.com/auth/drive.readonly',
      'https://www.googleapis.com/auth/presentations.readonly',
      'https://www.googleapis.com/auth/spreadsheets.readonly'
    ];

    // Generate OAuth URL
    const authUrl = `https://accounts.google.com/o/oauth2/auth?` +
      `response_type=code&` +
      `client_id=${encodeURIComponent(client_id)}&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `scope=${encodeURIComponent(scopes.join(' '))}&` +
      `access_type=offline&` +
      `prompt=consent&` +
      `state=${encodeURIComponent(email)}`;

    res.json({
      success: true,
      authUrl: authUrl,
      email: email,
      serverName: serverName
    });

  } catch (error) {
    console.error('Error starting auth:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Exchange authorization code for tokens
app.post('/api/exchange-code', async (req, res) => {
  try {
    const { code, email, redirectUri } = req.body;

    if (!code || !email || !redirectUri) {
      return res.status(400).json({
        success: false,
        error: 'code, email, redirectUri가 필요합니다'
      });
    }

    const homeDir = os.homedir();
    const secretDir = path.join(homeDir, '.mcp-workspace');
    const secretPath = path.join(secretDir, 'client_secret.json');

    if (!fs.existsSync(secretPath)) {
      return res.json({
        success: false,
        error: 'client_secret.json을 찾을 수 없습니다'
      });
    }

    const clientSecret = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
    const { client_id, client_secret: secret } = clientSecret.installed || clientSecret.web;

    // Exchange code for tokens
    const tokenUrl = 'https://oauth2.googleapis.com/token';
    const params = new URLSearchParams({
      code: code,
      client_id: client_id,
      client_secret: secret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    });

    const https = require('https');
    const tokenData = await new Promise((resolve, reject) => {
      const postData = params.toString();
      const options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData)
        }
      };

      const req = https.request(tokenUrl, options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data));
          } else {
            reject(new Error(`Token exchange failed: ${data}`));
          }
        });
      });

      req.on('error', reject);
      req.write(postData);
      req.end();
    });

    // Save token file
    const tokenPath = path.join(secretDir, `token-${email}.json`);
    fs.writeFileSync(tokenPath, JSON.stringify(tokenData, null, 2));

    res.json({
      success: true,
      message: `${email} 계정의 인증이 완료되었습니다`,
      tokenPath: tokenPath
    });

  } catch (error) {
    console.error('Error exchanging code:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete authentication token for a specific account
app.post('/api/delete-auth', (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'email이 필요합니다'
      });
    }

    const homeDir = os.homedir();

    // Check both possible token locations
    const tokenPath1 = path.join(homeDir, '.mcp-workspace', `token-${email}.json`);
    const tokenPath2 = path.join(homeDir, '.google_workspace_mcp', 'credentials', `${email}.json`);

    let deleted = false;
    let deletedPaths = [];

    // Delete from first location
    if (fs.existsSync(tokenPath1)) {
      fs.unlinkSync(tokenPath1);
      deleted = true;
      deletedPaths.push(tokenPath1);
      console.log(`Deleted token from: ${tokenPath1}`);
    }

    // Delete from second location
    if (fs.existsSync(tokenPath2)) {
      fs.unlinkSync(tokenPath2);
      deleted = true;
      deletedPaths.push(tokenPath2);
      console.log(`Deleted token from: ${tokenPath2}`);
    }

    if (deleted) {
      res.json({
        success: true,
        message: `${email} 계정의 인증 토큰이 삭제되었습니다 (${deletedPaths.length}개 파일)`
      });
    } else {
      res.json({
        success: false,
        message: `${email} 계정의 인증 토큰을 찾을 수 없습니다`
      });
    }

  } catch (error) {
    console.error('Error deleting auth:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Helper function to refresh access token
async function refreshAccessToken(tokenData, tokenPath) {
  const https = require('https');
  const tokenUrl = 'https://oauth2.googleapis.com/token';

  const params = new URLSearchParams({
    client_id: tokenData.client_id,
    client_secret: tokenData.client_secret,
    refresh_token: tokenData.refresh_token,
    grant_type: 'refresh_token'
  });

  const newTokenData = await new Promise((resolve, reject) => {
    const postData = params.toString();
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = https.request(tokenUrl, options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(JSON.parse(data));
        } else {
          reject(new Error(`Token refresh failed: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });

  // Update token file with new access token
  tokenData.token = newTokenData.access_token;
  tokenData.expiry = new Date(Date.now() + newTokenData.expires_in * 1000).toISOString();
  fs.writeFileSync(tokenPath, JSON.stringify(tokenData, null, 2));

  return tokenData.token;
}

// Helper function to get valid access token
async function getValidAccessToken(tokenData, tokenPath) {
  // Support both token formats
  let accessToken = tokenData.access_token || tokenData.token;
  let expiry = tokenData.expiry;

  // Check if token is expired
  if (expiry && new Date(expiry) <= new Date()) {
    console.log('Token expired, refreshing...');
    accessToken = await refreshAccessToken(tokenData, tokenPath);
  }

  return accessToken;
}

// List Google Forms for a specific account
app.post('/api/list-forms', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'email이 필요합니다'
      });
    }

    const homeDir = os.homedir();

    // Check for token in both possible locations
    const tokenPath1 = path.join(homeDir, '.mcp-workspace', `token-${email}.json`);
    const tokenPath2 = path.join(homeDir, '.google_workspace_mcp', 'credentials', `${email}.json`);

    let tokenPath = null;
    if (fs.existsSync(tokenPath1)) {
      tokenPath = tokenPath1;
    } else if (fs.existsSync(tokenPath2)) {
      tokenPath = tokenPath2;
    }

    if (!tokenPath) {
      return res.json({
        success: false,
        error: `${email} 계정의 인증 토큰을 찾을 수 없습니다`
      });
    }

    const tokenData = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));

    // Get valid access token (refresh if needed)
    const accessToken = await getValidAccessToken(tokenData, tokenPath);

    // Use Google Drive API to search for Google Forms
    const https = require('https');

    const searchUrl = `https://www.googleapis.com/drive/v3/files?` +
      `q=mimeType='application/vnd.google-apps.form'&` +
      `fields=files(id,name,createdTime,modifiedTime,webViewLink)&` +
      `orderBy=modifiedTime desc`;

    const driveData = await new Promise((resolve, reject) => {
      const options = {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      };

      https.get(searchUrl, options, (response) => {
        let data = '';
        response.on('data', (chunk) => data += chunk);
        response.on('end', () => {
          if (response.statusCode === 200) {
            resolve(JSON.parse(data));
          } else {
            reject(new Error(`Drive API failed: ${data}`));
          }
        });
      }).on('error', reject);
    });

    res.json({
      success: true,
      forms: driveData.files || [],
      email: email
    });

  } catch (error) {
    console.error('Error listing forms:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// OAuth callback endpoint
app.get('/oauth2callback', async (req, res) => {
  try {
    const { code, state, oauth_port } = req.query;
    const email = state; // email is passed as state parameter

    if (!code || !email) {
      return res.status(400).send('Missing code or email parameter');
    }

    console.log(`Received OAuth callback for ${email} from port ${oauth_port}`);

    const homeDir = os.homedir();

    // Try to get client_id and client_secret from existing token file
    const credentialsDir = path.join(homeDir, '.google_workspace_mcp', 'credentials');
    const existingTokenPath = path.join(credentialsDir, `${email}.json`);

    let client_id, secret;

    if (fs.existsSync(existingTokenPath)) {
      // Use client credentials from existing token file
      const existingToken = JSON.parse(fs.readFileSync(existingTokenPath, 'utf8'));
      client_id = existingToken.client_id;
      secret = existingToken.client_secret;
      console.log(`Using client credentials from existing token file for ${email}`);
    } else {
      // Find appropriate client_secret.json based on email
      const accountId = email.split('@')[0];
      const workspaceMcpDir = findGoogleWorkspaceMcpDir();
      let secretPath = null;

      if (workspaceMcpDir) {
        secretPath = findClientSecretForAccount(accountId, workspaceMcpDir);
        if (secretPath) {
          console.log(`Found client_secret for ${email} at: ${secretPath}`);
        }
      }

      // Fallback: try default locations
      if (!secretPath) {
        const fallbackPaths = [
          path.join(homeDir, '.mcp-workspace', 'client_secret.json'),
          path.join(homeDir, '.google_workspace_mcp', 'client_secret.json')
        ];

        for (const tryPath of fallbackPaths) {
          if (fs.existsSync(tryPath)) {
            secretPath = tryPath;
            console.log(`Found client_secret for ${email} at fallback: ${secretPath}`);
            break;
          }
        }
      }

      if (!secretPath) {
        return res.status(400).send(`client_secret.json not found for ${email}`);
      }

      const clientSecret = JSON.parse(fs.readFileSync(secretPath, 'utf8'));
      client_id = (clientSecret.installed || clientSecret.web).client_id;
      secret = (clientSecret.installed || clientSecret.web).client_secret;
      console.log(`Using client credentials from ${secretPath}`);
    }

    // Use the oauth_port from query parameter if available, otherwise default to 8766
    const oauthPort = oauth_port ? parseInt(oauth_port) : 8766;

    // Exchange code for tokens
    const tokenUrl = 'https://oauth2.googleapis.com/token';
    const redirectUri = `http://localhost:${oauthPort}/oauth2callback`;

    console.log(`Using redirect_uri: ${redirectUri}`);

    const params = new URLSearchParams({
      code: code,
      client_id: client_id,
      client_secret: secret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    });

    // DEBUG: Log token exchange request details
    console.log('\n🔍 ===== TOKEN EXCHANGE REQUEST DEBUG =====');
    console.log('  tokenUrl:', tokenUrl);
    console.log('  client_id:', client_id);
    console.log('  client_secret:', secret ? `${secret.substring(0, 10)}...${secret.substring(secret.length - 5)}` : 'null');
    console.log('  redirect_uri:', redirectUri);
    console.log('  code (first 20 chars):', code ? code.substring(0, 20) + '...' : 'null');
    console.log('  grant_type:', 'authorization_code');
    console.log('🔍 =========================================\n');

    const https = require('https');
    const tokenData = await new Promise((resolve, reject) => {
      const postData = params.toString();
      console.log('🔍 POST data length:', postData.length);
      console.log('🔍 POST data (first 100 chars):', postData.substring(0, 100) + '...');
      const options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData)
        }
      };

      const reqHTTPS = https.request(tokenUrl, options, (resHTTPS) => {
        console.log('🔍 Response status code:', resHTTPS.statusCode);
        console.log('🔍 Response headers:', JSON.stringify(resHTTPS.headers, null, 2));
        let data = '';
        resHTTPS.on('data', (chunk) => data += chunk);
        resHTTPS.on('end', () => {
          console.log('🔍 Response body:', data);
          if (resHTTPS.statusCode === 200) {
            console.log('✅ Token exchange successful!');
            resolve(JSON.parse(data));
          } else {
            console.log('❌ Token exchange failed!');
            reject(new Error(`Token exchange failed: ${data}`));
          }
        });
      });

      reqHTTPS.on('error', reject);
      reqHTTPS.write(postData);
      reqHTTPS.end();
    });

    // Save token file in workspace MCP format
    // credentialsDir is already defined above, just reuse it
    if (!fs.existsSync(credentialsDir)) {
      fs.mkdirSync(credentialsDir, { recursive: true });
    }

    const tokenPath = path.join(credentialsDir, `${email}.json`);
    const tokenFileData = {
      token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      token_uri: tokenUrl,
      client_id: client_id,
      client_secret: secret,
      scopes: tokenData.scope ? tokenData.scope.split(' ') : [],
      expiry: new Date(Date.now() + tokenData.expires_in * 1000).toISOString()
    };

    fs.writeFileSync(tokenPath, JSON.stringify(tokenFileData, null, 2));

    console.log(`✓ Token saved for ${email} at ${tokenPath}`);

    // Send success page
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>인증 완료</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
          .success { color: #28a745; font-size: 24px; margin-bottom: 20px; }
          .info { color: #666; }
        </style>
      </head>
      <body>
        <div class="success">✓ 인증이 완료되었습니다!</div>
        <div class="info">
          <p>${email} 계정의 Google 인증이 성공적으로 완료되었습니다.</p>
          <p>이 창을 닫고 앱으로 돌아가서 "🔄 새로고침" 버튼을 눌러주세요.</p>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('Error in OAuth callback:', error);
    res.status(500).send(`인증 오류: ${error.message}`);
  }
});

// Get home directory
app.get('/api/get-home-dir', (req, res) => {
  try {
    const homeDir = os.homedir();
    res.json({
      success: true,
      homeDir: homeDir
    });
  } catch (error) {
    console.error('Error getting home directory:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Save Claude Code Config
app.post('/api/save-claude-code-config', (req, res) => {
  try {
    const { config } = req.body;

    if (!config) {
      return res.status(400).json({ success: false, error: 'Config data is required' });
    }

    // Save to ~/.claude.json
    const homeDir = os.homedir();
    const configPath = path.join(homeDir, '.claude.json');

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    res.json({
      success: true,
      message: 'Claude Code Config saved successfully',
      path: configPath
    });
  } catch (error) {
    console.error('Error saving Claude Code Config:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Save Claude Desktop Config
app.post('/api/save-claude-desktop-config', (req, res) => {
  try {
    const { config } = req.body;

    if (!config) {
      return res.status(400).json({ success: false, error: 'Config data is required' });
    }

    // Save to ~/Library/Application Support/Claude/claude_desktop_config.json
    const homeDir = os.homedir();
    const configPath = path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    res.json({
      success: true,
      message: 'Claude Desktop Config saved successfully',
      path: configPath
    });
  } catch (error) {
    console.error('Error saving Claude Desktop Config:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update environment variables for an MCP server
app.post('/api/update-server-env', (req, res) => {
  try {
    const { serverName, envVars, configType } = req.body;

    if (!serverName || !envVars) {
      return res.status(400).json({
        success: false,
        error: 'serverName과 envVars가 필요합니다'
      });
    }

    const homeDir = os.homedir();
    let configPath, config;

    // Determine which config to update
    if (configType === 'desktop') {
      // Claude Desktop config
      configPath = path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    } else {
      // Claude Code config (default)
      configPath = path.join(homeDir, '.claude.json');
    }

    if (!fs.existsSync(configPath)) {
      return res.status(404).json({
        success: false,
        error: '설정 파일을 찾을 수 없습니다: ' + configPath
      });
    }

    // Read existing config
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    // Find and update the server
    let serverConfig = null;
    if (configType === 'desktop') {
      // Desktop: mcpServers is at top level
      if (config.mcpServers && config.mcpServers[serverName]) {
        serverConfig = config.mcpServers[serverName];
      }
    } else {
      // Code: mcpServers is under projects[homeDir]
      if (config.projects && config.projects[homeDir] && config.projects[homeDir].mcpServers) {
        if (config.projects[homeDir].mcpServers[serverName]) {
          serverConfig = config.projects[homeDir].mcpServers[serverName];
        }
      }
    }

    if (!serverConfig) {
      return res.status(404).json({
        success: false,
        error: `서버 "${serverName}"을 찾을 수 없습니다`
      });
    }

    // Initialize env if doesn't exist
    if (!serverConfig.env) {
      serverConfig.env = {};
    }

    // Update or add environment variables
    Object.keys(envVars).forEach(key => {
      if (envVars[key] === null || envVars[key] === undefined || envVars[key] === '') {
        // Remove the variable if value is empty
        delete serverConfig.env[key];
      } else {
        // Add or update the variable
        serverConfig.env[key] = envVars[key];
      }
    });

    // Create backup
    const backupPath = configPath + '.backup';
    fs.writeFileSync(backupPath, fs.readFileSync(configPath));

    // Save updated config
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    console.log(`✓ Updated environment variables for ${serverName} in ${configPath}`);

    res.json({
      success: true,
      message: `환경 변수가 업데이트되었습니다`,
      serverName: serverName,
      updatedEnv: serverConfig.env,
      backupPath: backupPath
    });

  } catch (error) {
    console.error('Error updating server env:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Read documentation files
app.get('/api/docs/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    const allowedFiles = ['README.md', 'TROUBLESHOOTING.md', 'CLAUDE.md'];

    if (!allowedFiles.includes(filename)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid filename'
      });
    }

    const filePath = path.join(__dirname, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    const content = fs.readFileSync(filePath, 'utf8');

    res.json({
      success: true,
      filename: filename,
      content: content
    });

  } catch (error) {
    console.error('Error reading documentation:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  const isElectron = process.env.ELECTRON_MODE === 'true';

  if (isElectron) {
    console.log(`JSON Viewer server is running at http://localhost:${PORT}`);
  } else {
    console.log(`JSON Viewer is running at http://localhost:${PORT}`);
    console.log(`Open your browser and navigate to http://localhost:${PORT}`);
  }
});

// Start OAuth callback servers on multiple ports
// Load port mappings from oauth_port_map.json
const homeDir = os.homedir();
const portMapPath = path.join(homeDir, '.mcp-workspace', 'oauth_port_map.json');

let OAUTH_PORTS = [8766, 8675]; // Default ports

// Load dynamic ports from port map
if (fs.existsSync(portMapPath)) {
  try {
    const portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));
    const dynamicPorts = [...new Set(Object.values(portMap))]; // Get unique ports
    OAUTH_PORTS = [...new Set([...OAUTH_PORTS, ...dynamicPorts])]; // Merge with defaults
    console.log('OAuth callback servers will start on ports:', OAUTH_PORTS);
  } catch (err) {
    console.error('Error loading port map for OAuth servers:', err);
  }
}

OAUTH_PORTS.forEach(oauthPort => {
  const oauthApp = express();

  oauthApp.get('/oauth2callback', async (req, res) => {
    // Redirect to main server's callback endpoint with port info
    const queryString = new URLSearchParams(req.query).toString();
    res.redirect(`http://localhost:${PORT}/oauth2callback?${queryString}&oauth_port=${oauthPort}`);
  });

  oauthApp.listen(oauthPort, () => {
    console.log(`OAuth callback server is running at http://localhost:${oauthPort}`);
  }).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`Port ${oauthPort} is already in use, skipping...`);
    } else {
      console.error(`Error starting OAuth server on port ${oauthPort}:`, err);
    }
  });
});
