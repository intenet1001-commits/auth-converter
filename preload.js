const { contextBridge, ipcRenderer } = require('electron');

// 안전한 API를 window 객체에 노출
contextBridge.exposeInMainWorld('electronAPI', {
  // 파일 열기 이벤트 리스너
  onOpenJsonFile: (callback) => {
    ipcRenderer.on('open-json-file', (event, data) => {
      callback(data);
    });
  },

  // 빌드 요청
  buildApp: () => {
    return ipcRenderer.invoke('build-app');
  },

  // 빌드 진행 상황 리스너
  onBuildProgress: (callback) => {
    ipcRenderer.on('build-progress', (event, data) => {
      callback(data);
    });
  },

  // Claude Config 불러오기
  loadClaudeConfig: () => {
    return ipcRenderer.invoke('load-claude-config');
  },

  // Claude Desktop Config 불러오기
  loadClaudeDesktopConfig: () => {
    return ipcRenderer.invoke('load-claude-desktop-config');
  },

  // Claude Config 저장
  saveClaudeConfig: (data) => {
    return ipcRenderer.invoke('save-claude-config', data);
  },

  // 외부 브라우저에서 URL 열기
  openExternal: (url) => {
    return ipcRenderer.invoke('open-external', url);
  }
});
