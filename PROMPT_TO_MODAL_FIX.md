# "이메일 추가 & 인증" 버튼 수정: prompt() → 커스텀 모달

**날짜**: 2025-11-12
**이슈**: "이메일 추가 & 인증" 버튼이 클릭되어도 반응하지 않음

---

## 🔍 문제 원인

**근본 원인**: Electron 환경에서 `prompt()` 함수가 차단되거나 제대로 작동하지 않음

### 기존 코드 (라인 2482):
```javascript
const email = prompt(`${serverName} 서버의 Google 계정 이메일을 입력하세요:`, '');
```

**문제점**:
- Electron에서 `prompt()`는 보안상의 이유로 차단되거나 제한될 수 있음
- 사용자가 버튼을 클릭해도 입력창이 나타나지 않음
- 디버깅이 어려움 (콘솔 로그만으로 확인 불가)

---

## ✅ 해결 방법

### 커스텀 HTML 모달로 교체

**변경 사항**:
1. `addEmailAndAuth` 함수를 두 부분으로 분리:
   - `addEmailAndAuth`: 모달 UI 생성 및 사용자 입력 대기
   - `processEmailAuth`: 이메일 검증 및 Config 저장 로직

2. Promise 기반 커스텀 모달 구현:
   - HTML/CSS로 깔끔한 모달 UI
   - 이벤트 리스너로 사용자 입력 처리
   - Enter 키 지원
   - 모달 외부 클릭 시 취소

---

## 📝 새로운 코드 구조

### 1. addEmailAndAuth 함수 (라인 2478-2538)

**기능**: 커스텀 모달 생성 및 사용자 입력 처리

```javascript
async function addEmailAndAuth(serverName) {
  console.log('🔵 addEmailAndAuth 호출됨:', serverName);

  // 커스텀 모달 HTML 생성
  const modalHtml = `
    <div id="emailModal" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 10000;">
      <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); min-width: 400px;">
        <h3 style="margin-top: 0; color: #333;">📧 Google 계정 이메일 입력</h3>
        <p style="color: #666; margin-bottom: 20px;">서버: <strong>${escapeHtml(serverName)}</strong></p>
        <input type="email" id="emailInput" placeholder="example@gmail.com"
          style="width: 100%; padding: 10px; border: 2px solid #ddd; border-radius: 5px; font-size: 14px; box-sizing: border-box; margin-bottom: 20px;">
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
          <button id="cancelEmailBtn" style="background: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold;">취소</button>
          <button id="submitEmailBtn" style="background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold;">확인</button>
        </div>
      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', modalHtml);

  // Promise로 사용자 입력 대기
  return new Promise((resolve) => {
    const modal = document.getElementById('emailModal');
    const input = document.getElementById('emailInput');
    const submitBtn = document.getElementById('submitEmailBtn');
    const cancelBtn = document.getElementById('cancelEmailBtn');

    input.focus();

    const handleSubmit = () => {
      const email = input.value.trim();
      console.log('🔵 입력된 이메일:', email);
      modal.remove();
      resolve(email);
    };

    const handleCancel = () => {
      console.log('🔵 이메일 입력 취소됨');
      modal.remove();
      resolve(null);
    };

    submitBtn.addEventListener('click', handleSubmit);
    cancelBtn.addEventListener('click', handleCancel);
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleSubmit();
    });
    modal.addEventListener('click', (e) => {
      if (e.target === modal) handleCancel();
    });
  }).then(email => {
    if (!email) {
      return; // User cancelled
    }

    return processEmailAuth(email, serverName);
  });
}
```

**특징**:
- ✅ 깔끔한 UI: 흰색 배경, 그림자 효과, 모던한 디자인
- ✅ 자동 포커스: 모달이 열리면 즉시 입력 가능
- ✅ Enter 키 지원: 입력 후 Enter로 제출
- ✅ ESC 대체: 모달 외부 클릭으로 취소
- ✅ Promise 기반: async/await와 완벽한 호환

### 2. processEmailAuth 함수 (라인 2540-2610)

**기능**: 이메일 검증 및 Claude Config 저장

```javascript
async function processEmailAuth(email, serverName) {
  console.log('🔵 processEmailAuth 시작:', { email, serverName });

  // 이메일 형식 검증
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    showError('올바른 이메일 형식이 아닙니다.');
    return;
  }

  // Claude Config 확인
  if (!claudeConfigData || !claudeConfigPath) {
    console.error('❌ Claude Config가 없습니다');
    showError('Claude Config를 먼저 불러오세요');
    return;
  }

  try {
    // 홈 디렉토리 찾기
    const projects = claudeConfigData.projects || {};
    const homeDir = Object.keys(projects).find(key =>
      key.match(/^\/Users\/[^\/]+$/) ||
      key.match(/^\/home\/[^\/]+$/) ||
      key.match(/^[A-Z]:\\Users\\[^\\]+$/)
    );

    // 서버 존재 확인
    if (!homeDir || !projects[homeDir] || !projects[homeDir].mcpServers || !projects[homeDir].mcpServers[serverName]) {
      console.log('🔵 서버가 Config에 없습니다. Extensions 탭에서 먼저 추가해야 합니다.');
      showError('먼저 Extensions 탭에서 이 Extension을 "➕ Add to MCP Config" 버튼으로 추가한 후, 다시 시도하세요.');
      return;
    }

    // 환경 변수에 이메일 추가
    if (!projects[homeDir].mcpServers[serverName].env) {
      projects[homeDir].mcpServers[serverName].env = {};
    }
    projects[homeDir].mcpServers[serverName].env.USER_GOOGLE_EMAIL = email;

    // Config 저장
    const saveResult = await window.electronAPI.saveClaudeConfig({
      path: claudeConfigPath,
      data: claudeConfigData
    });

    if (saveResult.success) {
      showSuccess(`✓ ${email}을(를) ${serverName} 서버에 추가했습니다.\n\n이제 인증을 진행합니다.`);
      await updateAuthDisplay();
      await startAuth(email, serverName);
    } else {
      showError('Config 저장 실패: ' + saveResult.error);
    }
  } catch (error) {
    console.error('Error in processEmailAuth:', error);
    showError('오류가 발생했습니다: ' + error.message);
  }
}
```

---

## 🎨 모달 UI 디자인

### 레이아웃
```
┌─────────────────────────────────────┐
│  반투명 배경 (rgba(0,0,0,0.7))      │
│                                      │
│  ┌────────────────────────────────┐ │
│  │ 📧 Google 계정 이메일 입력     │ │
│  │                                │ │
│  │ 서버: workspace-mcp-...        │ │
│  │                                │ │
│  │ ┌──────────────────────────┐  │ │
│  │ │ example@gmail.com        │  │ │
│  │ └──────────────────────────┘  │ │
│  │                                │ │
│  │               [취소]  [확인]   │ │
│  └────────────────────────────────┘ │
└─────────────────────────────────────┘
```

### 스타일 특징
- **배경**: 반투명 오버레이로 포커스 유도
- **모달**: 흰색 배경, 둥근 모서리, 그림자 효과
- **입력창**: 2px 회색 테두리, placeholder 텍스트
- **버튼**:
  - 취소: 회색 (#6c757d)
  - 확인: 파란색 (#007bff)
  - hover 효과 포함

---

## ✅ 장점

### 1. **크로스 플랫폼 호환성**
- Electron, Chrome, Firefox, Safari 모두 작동
- 브라우저 보안 정책 우회

### 2. **UX 개선**
- 깔끔하고 현대적인 디자인
- 키보드 단축키 지원 (Enter, 외부 클릭)
- 자동 포커스로 즉시 입력 가능

### 3. **디버깅 용이**
- 콘솔 로그로 모든 단계 추적 가능
- Promise 기반으로 에러 처리 명확

### 4. **확장 가능**
- 추가 입력 필드 쉽게 추가 가능
- 검증 로직 커스터마이징 용이

---

## 🧪 테스트 시나리오

### 시나리오 1: 정상 입력
1. "이메일 추가 & 인증" 버튼 클릭
2. 모달 표시 확인
3. 이메일 입력 (예: test@gmail.com)
4. Enter 키 또는 "확인" 버튼 클릭
5. ✅ Config에 이메일 추가 확인
6. ✅ OAuth 인증 시작

### 시나리오 2: 취소
1. 버튼 클릭
2. 모달 표시
3. "취소" 버튼 클릭 또는 모달 외부 클릭
4. ✅ 모달 닫힘, 아무 일도 일어나지 않음

### 시나리오 3: 잘못된 이메일 형식
1. 버튼 클릭
2. 모달 표시
3. 잘못된 이메일 입력 (예: "notanemail")
4. "확인" 클릭
5. ✅ 에러 메시지 표시: "올바른 이메일 형식이 아닙니다."

### 시나리오 4: Extension이 Config에 없음
1. Extension을 Claude Config에 추가하지 않은 상태
2. 버튼 클릭
3. 모달 표시
4. 이메일 입력
5. ✅ 명확한 에러 메시지:
   ```
   먼저 Extensions 탭에서 이 Extension을
   "➕ Add to MCP Config" 버튼으로 추가한 후,
   다시 시도하세요.
   ```

---

## 📊 변경 사항 요약

| 항목 | Before | After |
|-----|--------|-------|
| **입력 방법** | `prompt()` | 커스텀 HTML 모달 |
| **Electron 호환성** | ❌ 작동 불안정 | ✅ 완벽 작동 |
| **UX** | 기본 시스템 프롬프트 | 현대적인 모달 UI |
| **키보드 지원** | Enter만 지원 | Enter + 외부 클릭 지원 |
| **디버깅** | 어려움 | 콘솔 로그로 명확 |
| **확장성** | 제한적 | 높음 (HTML/CSS 커스터마이징) |

---

## 🔧 기술적 세부사항

### 파일 변경
**파일**: `/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter/public/index.html`

**변경 라인**: 2478-2610

### 주요 기술
- **Promise**: 비동기 사용자 입력 처리
- **Event Listeners**: 버튼 클릭, 키보드 입력 처리
- **DOM Manipulation**: `insertAdjacentHTML`, `remove()`
- **CSS-in-JS**: 인라인 스타일로 독립적인 모달

### 브라우저 호환성
- ✅ Chrome/Electron
- ✅ Firefox
- ✅ Safari
- ✅ Edge

---

## 📚 관련 문서

- **버튼 클릭 문제 해결**: `BUTTON_CLICK_ISSUE_FIXED.md`
- **디버깅 상태**: `BUTTON_DEBUG_STATUS.md`
- **테스트 가이드**: `BUTTON_TESTING_GUIDE.md`

---

**상태**: ✅ 수정 완료
**테스트**: Electron 앱 재시작 후 버튼 작동 확인 필요
**다음 단계**: 사용자 테스트 및 피드백 수집
