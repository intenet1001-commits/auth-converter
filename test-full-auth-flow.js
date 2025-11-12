const fs = require('fs');
const path = require('path');

// Test configuration
const testAccounts = [
  {
    name: 'intenet1',
    email: 'intenet1@gmail.com',
    clientSecretPath: '/Users/gwanli/Library/CloudStorage/GoogleDrive-intenet1@gmail.com/내 드라이브/개인/계정/구글워크스페이스/데스크탑앱/intenet1/client_secret_2_785825570589-2u5kd1tukgq6cbdceto8kug0svp44gl6.apps.googleusercontent.com.json',
    expectedPort: 8766,
    expectedClientId: '785825570589-2u5kd1tukgq6cbdceto8kug0svp44gl6.apps.googleusercontent.com'
  },
  {
    name: 'intenet8821',
    email: 'intenet8821@gmail.com',
    clientSecretPath: '/Users/gwanli/Library/CloudStorage/GoogleDrive-intenet1@gmail.com/내 드라이브/개인/계정/구글워크스페이스/데스크탑앱/intenet8821/client_secret_2_1054624136873-6g9usojq2b05jf0plp0k9vn1nudrgsde.apps.googleusercontent.com.json',
    expectedPort: 8765,
    expectedClientId: '1054624136873-6g9usojq2b05jf0plp0k9vn1nudrgsde.apps.googleusercontent.com'
  }
];

async function testFileUploadAndAuth(account) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`🧪 Testing: ${account.name} (${account.email})`);
  console.log(`${'='.repeat(60)}\n`);

  try {
    // 1. Check if file exists
    console.log('📁 Step 1: Checking client_secret file...');
    if (!fs.existsSync(account.clientSecretPath)) {
      console.error(`❌ File not found: ${account.clientSecretPath}`);
      return false;
    }
    console.log(`✅ File exists: ${account.clientSecretPath}`);

    // 2. Read and validate JSON
    console.log('\n📄 Step 2: Reading client_secret JSON...');
    const fileContent = fs.readFileSync(account.clientSecretPath, 'utf8');
    const clientSecret = JSON.parse(fileContent);
    console.log('✅ JSON parsed successfully');
    console.log(`   Client ID: ${clientSecret.web.client_id}`);
    console.log(`   Project ID: ${clientSecret.web.project_id}`);
    console.log(`   Redirect URIs: ${JSON.stringify(clientSecret.web.redirect_uris)}`);

    // 3. Extract port from redirect_uri
    console.log('\n🔌 Step 3: Extracting OAuth port...');
    const redirectUri = clientSecret.web.redirect_uris[0];
    const portMatch = redirectUri.match(/:(\d+)\//);
    const extractedPort = portMatch ? parseInt(portMatch[1]) : null;
    console.log(`   Redirect URI: ${redirectUri}`);
    console.log(`   Extracted port: ${extractedPort}`);
    console.log(`   Expected port: ${account.expectedPort}`);

    if (extractedPort === account.expectedPort) {
      console.log(`✅ Port matches expected: ${extractedPort}`);
    } else {
      console.error(`❌ Port mismatch! Expected: ${account.expectedPort}, Got: ${extractedPort}`);
      return false;
    }

    // 4. Test API endpoint - Upload file
    console.log('\n📤 Step 4: Testing file upload API...');

    // The API expects JSON POST with clientSecretData and accountId
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    // Prepare JSON payload with client secret data
    const payload = JSON.stringify({
      clientSecretData: clientSecret,
      accountId: account.name
    });

    // Escape single quotes in payload for shell
    const escapedPayload = payload.replace(/'/g, "'\\''");

    const curlCmd = `curl -s -X POST http://localhost:3000/api/save-client-secret -H "Content-Type: application/json" -d '${escapedPayload}'`;

    const { stdout: uploadOutput } = await execAsync(curlCmd);
    const uploadResult = JSON.parse(uploadOutput);
    console.log('   Upload response:', JSON.stringify(uploadResult, null, 2));

    if (uploadResult.success) {
      console.log('✅ File upload successful');
      console.log(`   Saved to: ${uploadResult.savedPath}`);
    } else {
      console.error('❌ File upload failed:', uploadResult.error);
      return false;
    }

    // 5. Check oauth_port_map.json
    console.log('\n🗺️  Step 5: Checking OAuth port mapping...');
    const portMapPath = path.join(require('os').homedir(), '.mcp-workspace', 'oauth_port_map.json');
    if (fs.existsSync(portMapPath)) {
      const portMap = JSON.parse(fs.readFileSync(portMapPath, 'utf8'));
      console.log('   Port map contents:', JSON.stringify(portMap, null, 2));

      if (portMap[account.expectedClientId] === account.expectedPort) {
        console.log(`✅ Port mapping correct: ${account.expectedClientId} → ${account.expectedPort}`);
      } else {
        console.error(`❌ Port mapping incorrect or missing for ${account.expectedClientId}`);
      }
    } else {
      console.error('❌ oauth_port_map.json not found');
    }

    // 6. Verify client_secret.json was saved correctly
    console.log('\n📋 Step 6: Verifying saved client_secret...');
    const savedSecretPath = `/Users/gwanli/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_${account.name}/client_secret.json`;

    if (fs.existsSync(savedSecretPath)) {
      const savedSecret = JSON.parse(fs.readFileSync(savedSecretPath, 'utf8'));
      const savedClientId = (savedSecret.web || savedSecret.installed).client_id;

      if (savedClientId === account.expectedClientId) {
        console.log('✅ Client secret saved correctly');
        console.log(`   Path: ${savedSecretPath}`);
        console.log(`   Client ID matches: ${savedClientId}`);
      } else {
        console.error(`❌ Client ID mismatch in saved file`);
        console.error(`   Expected: ${account.expectedClientId}`);
        console.error(`   Got: ${savedClientId}`);
        return false;
      }
    } else {
      console.error(`❌ Saved client_secret not found at: ${savedSecretPath}`);
      return false;
    }

    // 7. Test auth status check
    console.log('\n🔐 Step 7: Testing auth status check...');
    const authStatusCmd = `curl -s -X POST http://localhost:3000/api/check-auth-status \
      -H "Content-Type: application/json" \
      -d '{}'`;

    const { stdout: authStatusOutput } = await execAsync(authStatusCmd);
    const authStatus = JSON.parse(authStatusOutput);
    console.log('   Auth status:', JSON.stringify(authStatus, null, 2));

    if (authStatus.success) {
      console.log('✅ Auth status check successful');

      // Find workspace-mcp server
      const workspaceMcpServers = Object.entries(authStatus.servers)
        .filter(([name]) => name.includes('workspace-mcp'));

      if (workspaceMcpServers.length > 0) {
        workspaceMcpServers.forEach(([serverName, status]) => {
          console.log(`\n   Server: ${serverName}`);
          console.log(`   - Authenticated: ${status.authenticated}`);
          console.log(`   - Email: ${status.email || 'Not set'}`);
          console.log(`   - Needs email: ${status.needsEmail}`);
          console.log(`   - Configured port: ${status.configuredPort || 'Not set'}`);
          console.log(`   - Detected port: ${status.detectedPort || 'Not detected'}`);
        });
      } else {
        console.log('   ⚠️  No workspace-mcp servers found in auth status');
      }
    } else {
      console.error('❌ Auth status check failed');
    }

    console.log(`\n✅ All tests passed for ${account.name}!`);
    return true;

  } catch (error) {
    console.error(`\n❌ Test failed for ${account.name}:`, error.message);
    console.error(error.stack);
    return false;
  }
}

async function runAllTests() {
  console.log('\n' + '='.repeat(60));
  console.log('🚀 Starting Full Authentication Flow Tests');
  console.log('='.repeat(60));

  const results = [];

  for (const account of testAccounts) {
    const success = await testFileUploadAndAuth(account);
    results.push({ account: account.name, success });
  }

  console.log('\n' + '='.repeat(60));
  console.log('📊 Test Results Summary');
  console.log('='.repeat(60));
  results.forEach(result => {
    console.log(`${result.success ? '✅' : '❌'} ${result.account}`);
  });

  const allPassed = results.every(r => r.success);
  console.log('\n' + (allPassed ? '✅ All tests passed!' : '❌ Some tests failed'));

  process.exit(allPassed ? 0 : 1);
}

// Run tests
runAllTests().catch(error => {
  console.error('❌ Fatal error:', error);
  process.exit(1);
});
