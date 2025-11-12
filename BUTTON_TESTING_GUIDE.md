# 버튼 클릭 테스트 가이드

**목적**: "이메일 추가 & 인증" 버튼이 작동하지 않는 문제 진단

## 📋 현재 상태

✅ **완료된 작업**:
- 디버깅 로그 추가 완료
- Electron 앱 재시작 완료 (포트 3000에서 실행 중)

❌ **남은 작업**:
- 개발자 콘솔에서 로그 확인
- 실제 문제 원인 파악
- 원인에 따른 수정 적용

---

## 🔍 테스트 절차

### 1단계: Electron 앱 열기

현재 앱이 실행 중입니다. 만약 창이 보이지 않으면:

```bash
# 앱이 실행 중인지 확인
ps aux | grep -i electron | grep -v grep

# 실행 중이면 창을 앞으로 가져오거나
# 실행 중이 아니면 새로 시작
npm start
```

### 2단계: 개발자 도구 열기

Electron 앱 창에서:
- **macOS**: `Cmd + Option + I`
- **Windows/Linux**: `Ctrl + Shift + I`

또는 메뉴에서:
- View → Toggle Developer Tools

### 3단계: Console 탭 선택

개발자 도구에서 **Console** 탭을 선택하세요.

### 4단계: "이메일 추가 & 인증" 버튼 찾기

1. Extensions 탭으로 이동
2. workspace-mcp extension을 찾으세요
3. "🔒 Google 계정 인증 상태" 섹션 확장
4. "📧 이메일 추가 & 인증" 버튼 찾기

### 5단계: 버튼 클릭 & 로그 확인

버튼을 클릭한 후 콘솔에 **다음 로그 중 어떤 것이 나타나는지** 확인하세요:

#### ✅ 정상 실행 시 (예상):
```
🔵 addEmailAndAuth 호출됨: workspace-mcp-workspace-intenet1
🔵 입력된 이메일: test@gmail.com
🔵 Claude Config 확인: { hasData: true, hasPath: true, path: '/Users/.../claude.json' }
🔵 홈 디렉토리 찾기: { homeDir: '/Users/...', hasProject: true, ... }
```

#### ❌ 문제 발생 시 (가능한 케이스):

**케이스 1: 함수가 전혀 호출되지 않음**
```
(아무 로그도 나타나지 않음)
```
→ **원인**: 버튼의 `onclick` 이벤트가 바인딩되지 않았거나 JavaScript 오류로 차단됨

**케이스 2: Claude Config가 없음**
```
🔵 addEmailAndAuth 호출됨: workspace-mcp-workspace-intenet1
🔵 입력된 이메일: test@gmail.com
🔵 Claude Config 확인: { hasData: false, hasPath: false, path: undefined }
❌ Claude Config가 없습니다
```
→ **원인**: Claude Config 파일이 로드되지 않음

**케이스 3: 서버를 찾을 수 없음**
```
🔵 addEmailAndAuth 호출됨: workspace-mcp-workspace-intenet1
🔵 입력된 이메일: test@gmail.com
🔵 Claude Config 확인: { hasData: true, hasPath: true, ... }
🔵 홈 디렉토리 찾기: { homeDir: '/Users/...', hasProject: false, ... }
❌ 서버를 찾을 수 없습니다: workspace-mcp-workspace-intenet1
```
→ **원인**: Extension이 Claude Config에 아직 추가되지 않음

**케이스 4: 이메일 입력 프롬프트가 나타나지 않음**
```
🔵 addEmailAndAuth 호출됨: workspace-mcp-workspace-intenet1
(이후 아무 로그도 없음)
```
→ **원인**: `prompt()` 함수가 차단되었거나 오류 발생

---

## 📝 로그 캡처 방법

### 콘솔 로그 복사하기

1. 콘솔에 나타난 모든 로그를 선택
2. 마우스 오른쪽 클릭 → "Copy"
3. 텍스트 파일에 붙여넣기

또는:

1. 콘솔에서 마우스 오른쪽 클릭
2. "Save as..." 선택
3. 로그를 파일로 저장

### 스크린샷 찍기

콘솔 로그가 보이는 상태에서:
- **macOS**: `Cmd + Shift + 4` (영역 선택)
- **Windows**: `Win + Shift + S`

---

## 🐛 추가 디버깅 정보

### 네트워크 탭 확인

개발자 도구에서 **Network** 탭도 확인하세요:
- API 호출이 실패했는지
- 어떤 엔드포인트가 호출되는지
- 응답 코드는 무엇인지

### 에러 메시지 확인

콘솔에서 빨간색 에러 메시지가 있는지 확인:
- `Uncaught TypeError: ...`
- `ReferenceError: ... is not defined`
- 기타 JavaScript 오류

---

## 📤 결과 전달

다음 정보를 전달해 주세요:

1. **콘솔 로그 전체** (텍스트 또는 스크린샷)
2. **버튼 클릭 시 어떤 동작이 있었는지**:
   - 아무 반응 없음
   - 프롬프트가 나타남
   - 에러 메시지 표시
   - 기타
3. **빨간색 에러 메시지** (있다면)

---

## 🔧 임시 해결 방법

만약 버튼이 작동하지 않는다면, 수동으로 환경 변수를 편집할 수 있습니다:

1. Extensions 탭에서 workspace-mcp 찾기
2. "▼ 환경 변수 보기" 클릭
3. "✏️ 편집" 버튼 클릭
4. `USER_GOOGLE_EMAIL` 필드에 이메일 입력
5. "저장" 클릭

이후 Google OAuth 인증은 별도로 진행해야 합니다.

---

## 📌 중요 참고사항

### 디버깅 로그가 추가된 위치

`/Users/gwanli/Documents/GitHub/myproduct_v4/auth converter/public/index.html`

- **라인 2479**: 함수 호출 로그
- **라인 2483**: 이메일 입력 로그
- **라인 2496-2500**: Claude Config 확인 로그
- **라인 2517-2523**: 서버 탐지 로그
- **라인 2525-2527**: 서버 없음 에러 로그

### 함수 위치

`addEmailAndAuth` 함수는 `index.html`의 라인 2478-2545에 있습니다.

---

**다음 단계**: 위 절차를 따라 테스트하고 콘솔 로그를 확인한 후, 결과를 알려주세요!
