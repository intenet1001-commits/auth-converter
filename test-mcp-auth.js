#!/usr/bin/env node

/**
 * MCP Authentication Diagnostic Tool
 *
 * This script tests workspace MCP server authentication by:
 * 1. Checking if token files exist and are valid
 * 2. Verifying token expiry and refresh capability
 * 3. Testing actual Google API calls with the tokens
 * 4. Simulating what Claude Code does when calling MCP tools
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');

// Configuration
const TEST_EMAIL = 'intenet8821@gmail.com';
const homeDir = os.homedir();

// Token file locations (check both possible paths)
const TOKEN_PATHS = [
  path.join(homeDir, '.google_workspace_mcp', 'credentials', `${TEST_EMAIL}.json`),
  path.join(homeDir, '.mcp-workspace', `token-${TEST_EMAIL}.json`)
];

// Colors for output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function success(message) {
  log(`✓ ${message}`, colors.green);
}

function error(message) {
  log(`✗ ${message}`, colors.red);
}

function warning(message) {
  log(`⚠ ${message}`, colors.yellow);
}

function info(message) {
  log(`ℹ ${message}`, colors.cyan);
}

function section(title) {
  log(`\n${colors.bold}=== ${title} ===${colors.reset}\n`);
}

// Load token file
function loadToken() {
  section('Step 1: Locating Token Files');

  for (const tokenPath of TOKEN_PATHS) {
    info(`Checking: ${tokenPath}`);

    if (fs.existsSync(tokenPath)) {
      success(`Found token file at: ${tokenPath}`);

      try {
        const tokenData = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
        info(`Token structure: ${Object.keys(tokenData).join(', ')}`);
        return { path: tokenPath, data: tokenData };
      } catch (err) {
        error(`Failed to parse token file: ${err.message}`);
      }
    }
  }

  error(`No token file found for ${TEST_EMAIL}`);
  return null;
}

// Check token expiry
function checkTokenExpiry(tokenData) {
  section('Step 2: Checking Token Expiry');

  const expiry = tokenData.expiry;
  if (!expiry) {
    warning('No expiry field found in token');
    return { expired: false, hasExpiry: false };
  }

  const expiryDate = new Date(expiry);
  const now = new Date();
  const isExpired = expiryDate <= now;

  info(`Token expiry: ${expiryDate.toISOString()}`);
  info(`Current time: ${now.toISOString()}`);

  if (isExpired) {
    error(`Token is EXPIRED (expired ${Math.floor((now - expiryDate) / 1000)} seconds ago)`);

    if (tokenData.refresh_token) {
      success('Refresh token available - can be refreshed');
      return { expired: true, hasExpiry: true, canRefresh: true };
    } else {
      error('No refresh token - re-authentication required');
      return { expired: true, hasExpiry: true, canRefresh: false };
    }
  } else {
    const remainingSeconds = Math.floor((expiryDate - now) / 1000);
    success(`Token is VALID (expires in ${remainingSeconds} seconds)`);
    return { expired: false, hasExpiry: true };
  }
}

// Verify token with Google API
async function verifyTokenWithGoogle(tokenData) {
  section('Step 3: Verifying Token with Google API');

  const accessToken = tokenData.access_token || tokenData.token;

  if (!accessToken) {
    error('No access token found in token data');
    return false;
  }

  info('Testing token with Google OAuth2 API...');

  const verifyUrl = `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${encodeURIComponent(accessToken)}`;

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      error('Token verification timed out after 5 seconds');
      resolve(false);
    }, 5000);

    https.get(verifyUrl, (res) => {
      clearTimeout(timeout);

      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 200) {
          const tokenInfo = JSON.parse(data);
          success('Token is VALID according to Google API');
          info(`Scopes: ${tokenInfo.scope}`);
          info(`Audience: ${tokenInfo.audience || 'N/A'}`);
          info(`Expires in: ${tokenInfo.expires_in} seconds`);
          resolve(true);
        } else {
          error(`Token is INVALID (HTTP ${res.statusCode})`);
          info(`Response: ${data}`);
          resolve(false);
        }
      });
    }).on('error', (err) => {
      clearTimeout(timeout);
      error(`Network error: ${err.message}`);
      resolve(false);
    });
  });
}

// Refresh access token
async function refreshAccessToken(tokenData, tokenPath) {
  section('Step 4: Refreshing Access Token');

  if (!tokenData.refresh_token) {
    error('No refresh token available');
    return null;
  }

  if (!tokenData.client_id || !tokenData.client_secret) {
    error('Missing client_id or client_secret in token file');
    return null;
  }

  info('Attempting to refresh access token...');

  const tokenUrl = 'https://oauth2.googleapis.com/token';
  const params = new URLSearchParams({
    client_id: tokenData.client_id,
    client_secret: tokenData.client_secret,
    refresh_token: tokenData.refresh_token,
    grant_type: 'refresh_token'
  });

  return new Promise((resolve) => {
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
          const newTokenData = JSON.parse(data);
          success('Token refreshed successfully');

          // Update token file
          tokenData.token = newTokenData.access_token;
          tokenData.expiry = new Date(Date.now() + newTokenData.expires_in * 1000).toISOString();

          fs.writeFileSync(tokenPath, JSON.stringify(tokenData, null, 2));
          success(`Updated token file: ${tokenPath}`);

          resolve(tokenData);
        } else {
          error(`Token refresh failed (HTTP ${res.statusCode})`);
          info(`Response: ${data}`);
          resolve(null);
        }
      });
    });

    req.on('error', (err) => {
      error(`Network error during refresh: ${err.message}`);
      resolve(null);
    });

    req.write(postData);
    req.end();
  });
}

// Test Google API call (Gmail example)
async function testGoogleApiCall(tokenData) {
  section('Step 5: Testing Actual Google API Call');

  const accessToken = tokenData.access_token || tokenData.token;

  if (!accessToken) {
    error('No access token available');
    return false;
  }

  info('Testing Gmail API (listing messages)...');

  const apiUrl = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1';

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      error('API call timed out after 10 seconds');
      resolve(false);
    }, 10000);

    const options = {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    };

    https.get(apiUrl, options, (res) => {
      clearTimeout(timeout);

      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 200) {
          success('Gmail API call successful!');
          const response = JSON.parse(data);
          info(`Found ${response.messages ? response.messages.length : 0} message(s)`);
          resolve(true);
        } else if (res.statusCode === 403) {
          error('Gmail API call failed - Insufficient permissions');
          info('Token may not have Gmail scope');
          resolve(false);
        } else if (res.statusCode === 401) {
          error('Gmail API call failed - Authentication error');
          info('Token is invalid or expired');
          resolve(false);
        } else {
          error(`Gmail API call failed (HTTP ${res.statusCode})`);
          info(`Response: ${data.substring(0, 200)}`);
          resolve(false);
        }
      });
    }).on('error', (err) => {
      clearTimeout(timeout);
      error(`Network error: ${err.message}`);
      resolve(false);
    });
  });
}

// Main test function
async function runDiagnostics() {
  log(`${colors.bold}${colors.cyan}MCP Authentication Diagnostic Tool${colors.reset}`);
  log(`Testing authentication for: ${TEST_EMAIL}\n`);

  // Step 1: Load token
  const tokenResult = loadToken();
  if (!tokenResult) {
    error('\nDiagnosis: Token file not found. Re-authentication required.');
    process.exit(1);
  }

  const { path: tokenPath, data: tokenData } = tokenResult;

  // Step 2: Check expiry
  const expiryResult = checkTokenExpiry(tokenData);

  let currentTokenData = tokenData;

  // Step 3: Verify with Google (only if not expired, or just to see the error)
  const isValidOnGoogle = await verifyTokenWithGoogle(tokenData);

  // Step 4: If expired and can refresh, try refreshing
  if (expiryResult.expired && expiryResult.canRefresh) {
    const refreshedToken = await refreshAccessToken(tokenData, tokenPath);
    if (refreshedToken) {
      currentTokenData = refreshedToken;
      info('Token has been refreshed, re-verifying...');
      await verifyTokenWithGoogle(currentTokenData);
    }
  }

  // Step 5: Test actual API call
  await testGoogleApiCall(currentTokenData);

  // Summary
  section('Diagnosis Summary');

  if (expiryResult.expired && !expiryResult.canRefresh) {
    error('PROBLEM: Token expired and cannot be refreshed');
    error('SOLUTION: Re-authenticate using the auth converter app');
  } else if (!isValidOnGoogle && !expiryResult.expired) {
    error('PROBLEM: Token appears valid but Google API rejects it');
    error('SOLUTION: Token may have been revoked. Re-authenticate required.');
  } else {
    success('Token is working correctly!');
    success('MCP server should be able to authenticate properly.');
  }

  log('');
}

// Run diagnostics
runDiagnostics().catch((err) => {
  error(`Unexpected error: ${err.message}`);
  console.error(err);
  process.exit(1);
});
