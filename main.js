const { app, BrowserWindow, Menu, dialog, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn, exec } = require('child_process');
const fs = require('fs');

let mainWindow;
let serverProcess;
let pendingFilePath = null; // 앱 시작 전에 열려는 파일 경로 저장

// JSON 파일 열기 함수
function openJsonFile(filePath) {
  if (!mainWindow) {
    pendingFilePath = filePath;
    return;
  }

  if (!fs.existsSync(filePath)) {
    dialog.showErrorBox('파일 오류', '파일을 찾을 수 없습니다: ' + filePath);
    return;
  }

  try {
    const fileContent = fs.readFileSync(filePath, 'utf8');
    JSON.parse(fileContent); // 유효성 검사

    // 파일 내용을 프론트엔드로 전송
    mainWindow.webContents.send('open-json-file', {
      path: filePath,
      content: fileContent
    });
  } catch (error) {
    dialog.showErrorBox('JSON 파싱 오류', '유효하지 않은 JSON 파일입니다: ' + error.message);
  }
}

// Express 서버 시작
function startServer() {
  return new Promise((resolve, reject) => {
    // 패키지된 앱에서는 fork를 사용, 개발 모드에서는 spawn 사용
    if (app.isPackaged) {
      // 패키지된 앱: fork 사용
      const { fork } = require('child_process');
      const serverPath = path.join(__dirname, 'server.js');

      console.log('Starting server (packaged mode):', serverPath);

      serverProcess = fork(serverPath, [], {
        env: { ...process.env, ELECTRON_MODE: 'true' },
        silent: true
      });

      if (serverProcess.stdout) {
        serverProcess.stdout.on('data', (data) => {
          console.log(`Server: ${data}`);
        });
      }

      if (serverProcess.stderr) {
        serverProcess.stderr.on('data', (data) => {
          console.error(`Server Error: ${data}`);
        });
      }

      serverProcess.on('error', (error) => {
        console.error('Failed to start server:', error);
        reject(error);
      });

      // 서버 시작 대기
      setTimeout(resolve, 2000);
    } else {
      // 개발 모드: spawn 사용
      serverProcess = spawn('node', [path.join(__dirname, 'server.js')], {
        env: { ...process.env, ELECTRON_MODE: 'true' }
      });

      serverProcess.stdout.on('data', (data) => {
        console.log(`Server: ${data}`);
        if (data.toString().includes('running at')) {
          resolve();
        }
      });

      serverProcess.stderr.on('data', (data) => {
        console.error(`Server Error: ${data}`);
      });

      serverProcess.on('error', (error) => {
        console.error('Failed to start server:', error);
        reject(error);
      });

      // 서버 시작 대기 시간
      setTimeout(resolve, 2000);
    }
  });
}

// 메인 윈도우 생성
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js')
    },
    show: false
  });

  // 메뉴바 설정
  const menu = Menu.buildFromTemplate([
    {
      label: 'File',
      submenu: [
        {
          label: 'Open JSON File',
          accelerator: 'CmdOrCtrl+O',
          click: () => {
            dialog.showOpenDialog(mainWindow, {
              properties: ['openFile'],
              filters: [
                { name: 'JSON Files', extensions: ['json'] }
              ]
            }).then(result => {
              if (!result.canceled && result.filePaths.length > 0) {
                openJsonFile(result.filePaths[0]);
              }
            });
          }
        },
        { type: 'separator' },
        {
          label: 'Quit',
          accelerator: 'CmdOrCtrl+Q',
          click: () => app.quit()
        }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo', label: 'Undo' },
        { role: 'redo', label: 'Redo' },
        { type: 'separator' },
        { role: 'cut', label: 'Cut' },
        { role: 'copy', label: 'Copy' },
        { role: 'paste', label: 'Paste' },
        { role: 'selectAll', label: 'Select All' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload', label: 'Reload' },
        { role: 'forceReload', label: 'Force Reload' },
        { role: 'toggleDevTools', label: 'Toggle Developer Tools' },
        { type: 'separator' },
        { role: 'resetZoom', label: 'Reset Zoom' },
        { role: 'zoomIn', label: 'Zoom In' },
        { role: 'zoomOut', label: 'Zoom Out' },
        { type: 'separator' },
        { role: 'togglefullscreen', label: 'Toggle Fullscreen' }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'About',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'About JSON Viewer by CS',
              message: 'JSON Viewer by CS',
              detail: 'Version 1.0\nRelease Date: 2025-11-04\n\nA powerful JSON viewer and MCP server configuration merger.\n\nFeatures:\n- JSON parsing and viewing\n- File upload support\n- MCP server merger with rename capability\n- Export to JSON and Markdown\n\nDeveloped by CS'
            });
          }
        }
      ]
    }
  ]);

  Menu.setApplicationMenu(menu);

  // 서버가 준비되면 로드
  mainWindow.loadURL('http://localhost:3000');

  // 윈도우가 준비되면 표시
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();

    // 대기 중인 파일이 있으면 열기
    if (pendingFilePath) {
      setTimeout(() => {
        openJsonFile(pendingFilePath);
        pendingFilePath = null;
      }, 500);
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// macOS에서 파일을 앱 아이콘에 드롭하거나 더블클릭으로 열 때
app.on('open-file', (event, filePath) => {
  event.preventDefault();

  if (filePath.endsWith('.json')) {
    if (mainWindow) {
      openJsonFile(filePath);
    } else {
      pendingFilePath = filePath;
    }
  }
});

// Claude Config IPC 핸들러
ipcMain.handle('load-claude-config', async (event) => {
  try {
    const os = require('os');
    const homeDir = os.homedir();
    const claudeConfigPath = path.join(homeDir, '.claude.json');

    console.log('Loading Claude config from:', claudeConfigPath);

    // Check if file exists
    if (!fs.existsSync(claudeConfigPath)) {
      return {
        success: false,
        error: 'Claude config 파일을 찾을 수 없습니다: ' + claudeConfigPath
      };
    }

    // Read file
    const fileContent = fs.readFileSync(claudeConfigPath, 'utf8');
    const configData = JSON.parse(fileContent);

    return {
      success: true,
      data: configData,
      path: claudeConfigPath
    };
  } catch (error) {
    console.error('Error loading Claude config:', error);
    return {
      success: false,
      error: error.message
    };
  }
});

ipcMain.handle('load-claude-desktop-config', async (event) => {
  try {
    const os = require('os');
    const homeDir = os.homedir();
    const desktopConfigPath = path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');

    console.log('Loading Claude Desktop config from:', desktopConfigPath);

    // Check if file exists
    if (!fs.existsSync(desktopConfigPath)) {
      return {
        success: false,
        error: 'Claude Desktop config 파일을 찾을 수 없습니다: ' + desktopConfigPath
      };
    }

    // Read file
    const fileContent = fs.readFileSync(desktopConfigPath, 'utf8');
    const configData = JSON.parse(fileContent);

    return {
      success: true,
      data: configData,
      path: desktopConfigPath
    };
  } catch (error) {
    console.error('Error loading Claude Desktop config:', error);
    return {
      success: false,
      error: error.message
    };
  }
});

ipcMain.handle('save-claude-config', async (event, { path: configPath, data }) => {
  try {
    console.log('=== Saving Claude config ===');
    console.log('Path:', configPath);
    console.log('Data keys:', Object.keys(data));

    // Check /Users/gwanli mcpServers in projects
    if (data.projects) {
      const homeDir = Object.keys(data.projects).find(key => key.startsWith('/Users/') || key.startsWith('/home/'));
      if (homeDir && data.projects[homeDir] && data.projects[homeDir].mcpServers) {
        console.log(`mcpServers in projects/${homeDir}:`, Object.keys(data.projects[homeDir].mcpServers));
        console.log(`Server count: ${Object.keys(data.projects[homeDir].mcpServers).length}`);
      }
    }

    // Create backup
    const backupPath = configPath + '.backup';
    if (fs.existsSync(configPath)) {
      fs.copyFileSync(configPath, backupPath);
      console.log('Backup created:', backupPath);
    }

    // Write file
    const jsonString = JSON.stringify(data, null, 2);
    fs.writeFileSync(configPath, jsonString, 'utf8');
    console.log('File saved successfully');

    return {
      success: true,
      message: 'Claude config가 성공적으로 저장되었습니다'
    };
  } catch (error) {
    console.error('Error saving Claude config:', error);
    return {
      success: false,
      error: error.message
    };
  }
});

// 외부 브라우저에서 URL 열기
ipcMain.handle('open-external', async (event, url) => {
  try {
    console.log('Opening external URL:', url);
    await shell.openExternal(url);
    return { success: true };
  } catch (error) {
    console.error('Error opening external URL:', error);
    return { success: false, error: error.message };
  }
});

// 빌드 IPC 핸들러
ipcMain.handle('build-app', async (event) => {
  return new Promise((resolve) => {
    // Check if running in development mode
    const isDev = !app.isPackaged;

    if (!isDev) {
      resolve({
        success: false,
        message: '빌드 기능은 개발 모드(npm start)에서만 사용할 수 있습니다. DMG로 설치된 앱에서는 사용할 수 없습니다.'
      });
      return;
    }

    // Verify that we're in the source directory
    const packageJsonPath = path.join(__dirname, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      resolve({
        success: false,
        message: '소스 코드 디렉토리를 찾을 수 없습니다. 개발 모드로 실행해주세요.'
      });
      return;
    }

    const buildProcess = exec('npm run build:mac', {
      cwd: __dirname,
      maxBuffer: 1024 * 1024 * 10 // 10MB buffer
    });

    // 빌드 시작 알림
    mainWindow.webContents.send('build-progress', {
      status: 'building',
      message: '빌드를 진행 중입니다... (몇 분 소요될 수 있습니다)'
    });

    buildProcess.stdout.on('data', (data) => {
      console.log(`Build: ${data}`);

      // 진행 상황 전송
      const output = data.toString();
      if (output.includes('building') || output.includes('packaging')) {
        mainWindow.webContents.send('build-progress', {
          status: 'building',
          message: '패키징 중...'
        });
      }
    });

    buildProcess.stderr.on('data', (data) => {
      console.error(`Build Error: ${data}`);
    });

    buildProcess.on('close', (code) => {
      if (code === 0) {
        const distPath = path.join(__dirname, 'dist');

        // dist 폴더 열기
        if (fs.existsSync(distPath)) {
          exec(`open "${distPath}"`);
        }

        resolve({
          success: true,
          message: '빌드가 완료되었습니다! dist 폴더에서 DMG 파일을 확인하세요.'
        });
      } else {
        resolve({
          success: false,
          message: `빌드 실패 (종료 코드: ${code}). 콘솔을 확인하세요.`
        });
      }
    });

    buildProcess.on('error', (error) => {
      console.error('Build process error:', error);
      resolve({
        success: false,
        message: '빌드 프로세스 시작 실패: ' + error.message
      });
    });
  });
});

// 앱 시작
app.whenReady().then(async () => {
  try {
    await startServer();
    createWindow();

    // 커맨드라인 인자로 파일 경로가 전달된 경우 (Windows/Linux)
    if (process.argv.length >= 2) {
      const filePath = process.argv[process.argv.length - 1];
      if (filePath.endsWith('.json') && fs.existsSync(filePath)) {
        pendingFilePath = filePath;
      }
    }
  } catch (error) {
    console.error('Failed to start application:', error);
    app.quit();
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// 모든 윈도우가 닫히면
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// 앱 종료 시 서버 프로세스도 종료
app.on('before-quit', () => {
  if (serverProcess) {
    serverProcess.kill();
  }
});

// 예상치 못한 에러 처리
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});
