# Google Workspace MCP 인증 도우미

Claude Code와 Claude Desktop에서 Google Workspace MCP Extension을 쉽게 설정하고 인증할 수 있도록 도와주는 Electron 기반 데스크톱 애플리케이션입니다.

## 주요 기능

### 🔐 Google OAuth 인증 관리
- 여러 Google 계정의 OAuth 인증을 한 곳에서 관리
- 브라우저 기반 OAuth 플로우 자동 처리
- 토큰 만료 상태 실시간 확인 및 자동 갱신
- Web Application과 Desktop Application 타입 모두 지원

### ⚙️ MCP Extension 설정
- Claude Desktop Extension 자동 스캔 및 로드
- 환경 변수 편집 (이메일, 포트 설정 등)
- client_secret.json 파일 업로드 및 관리
- 포트 자동 감지 기능

### 📋 JSON 파일 관리
- JSON 파일 뷰어 및 파서
- MCP 설정 병합 및 내보내기
- .claude.json 및 claude_desktop_config.json 편집

## 시작하기

### 설치

1. **의존성 설치**
   ```bash
   npm install
   ```

2. **개발 모드 실행**
   ```bash
   npm start
   ```

3. **빌드 (선택사항)**
   ```bash
   npm run build        # 현재 플랫폼용
   npm run build:mac    # macOS
   npm run build:win    # Windows
   npm run build:linux  # Linux
   ```

### 웹 전용 모드

Electron 없이 브라우저에서만 사용하려면:
```bash
npm run web
```
그런 다음 http://localhost:3000 접속

## 사용 방법

### 1️⃣ Extension 스캔

1. 프로그램 실행 시 자동으로 Claude Desktop Extension을 스캔합니다
2. **"Extension 설치된 서버 설정"** 탭에서 설치된 Extension 목록 확인

### 2️⃣ Google OAuth 설정

#### Google Cloud Console 설정

1. **Google Cloud Console 접속**
   - https://console.cloud.google.com

2. **새 프로젝트 생성** (또는 기존 프로젝트 선택)

3. **OAuth 동의 화면 구성**
   - "APIs & Services" > "OAuth consent screen"
   - User Type: External (개인용) 또는 Internal (조직용)
   - 필수 정보 입력 (앱 이름, 이메일 등)

4. **OAuth 2.0 Client ID 생성**
   - "APIs & Services" > "Credentials"
   - "CREATE CREDENTIALS" > "OAuth client ID"

   **Web Application 타입 (권장):**
   ```
   Application type: Web application
   Authorized redirect URIs:
     - http://localhost:8766/oauth2callback
     - http://localhost:8765/oauth2callback
     (계정별로 다른 포트 사용 가능)
   ```

   **Desktop Application 타입:**
   ```
   Application type: Desktop app
   (redirect_uri는 자동으로 http://localhost 설정됨)
   ```

5. **client_secret.json 다운로드**
   - OAuth Client ID 목록에서 다운로드 아이콘(⬇️) 클릭

6. **필요한 API 활성화**
   - "APIs & Services" > "Library"
   - 다음 API 검색 후 활성화:
     - Gmail API
     - Google Drive API
     - Google Sheets API
     - Google Docs API
     - Google Calendar API
     - Google Forms API
     - Google Slides API

#### 프로그램에서 설정

1. **Extension 편집**
   - "Extension 설치된 서버 설정" 탭
   - 설정할 Extension의 "⚙️ 편집" 버튼 클릭

2. **이메일 설정**
   - `USER_GOOGLE_EMAIL` 환경 변수에 Google 계정 이메일 입력
   - 예: `intenet1@gmail.com`

3. **client_secret.json 업로드**
   - "📁 client_secret.json 업로드" 버튼 클릭
   - Google Cloud Console에서 다운로드한 파일 선택
   - "자동으로 포트 추가" 옵션 체크 (권장)

4. **포트 자동 감지**
   - "🔍 포트 자동 감지" 버튼 클릭
   - client_secret.json에서 포트 자동 추출
   - `WORKSPACE_MCP_PORT` 환경 변수에 자동 입력

5. **저장**
   - "✅ 저장 및 설정 완료" 버튼 클릭

### 3️⃣ OAuth 인증

1. **"Google 계정 인증 상태"** 탭으로 이동

2. 설정한 Extension의 **"🔐 인증 시작"** 버튼 클릭

3. **브라우저에서 인증 진행**
   - Google 계정 선택
   - 앱 권한 승인
   - "이 앱은 Google에서 확인하지 않았습니다" 경고가 나올 수 있음
     - "고급" > "안전하지 않은 페이지로 이동" 클릭 (개발용 앱이므로 정상)

4. 인증 성공 시 "✅ 인증됨" 상태로 변경

### 4️⃣ Claude에서 사용

인증이 완료되면 Claude Code나 Claude Desktop에서 MCP 도구를 사용할 수 있습니다:

```
예시 명령어:
- "intenet1@gmail.com 계정의 최근 이메일 확인해줘"
- "Google Drive에서 'report.pdf' 파일 찾아줘"
- "내 캘린더에서 오늘 일정 알려줘"
```

## 문제 해결

### 인증 오류: "invalid_client"

**원인:** client_secret이 Google Cloud Console과 일치하지 않음

**해결 방법:**
1. Google Cloud Console에서 해당 OAuth Client ID가 존재하는지 확인
2. 상태가 "Active"인지 확인
3. 새로운 client_secret.json 파일 다운로드
4. 프로그램에 다시 업로드

### 포트 불일치 경고

**원인:** 설정된 포트와 client_secret.json의 포트가 다름

**해결 방법:**
1. "🔍 포트 자동 감지" 버튼 클릭
2. 또는 수동으로 `WORKSPACE_MCP_PORT` 값 수정
3. Google Cloud Console의 Authorized redirect URIs 확인

### 토큰 만료

**증상:** "토큰이 만료됨" 메시지 표시

**해결 방법:**
- Refresh token이 있는 경우: 자동으로 갱신됨
- Refresh token이 없는 경우: "🔐 인증 시작" 버튼으로 재인증

### Extension이 스캔되지 않음

**해결 방법:**
1. Claude Desktop Extension이 설치되어 있는지 확인
   - 경로: `~/Library/Application Support/Claude/Claude Extensions/`
2. Extension manifest.json 파일이 올바른지 확인
3. 프로그램 재시작

## 파일 구조

```
auth converter/
├── main.js                 # Electron 메인 프로세스
├── server.js               # Express 서버 (API 엔드포인트)
├── preload.js              # Electron 프리로드 스크립트
├── public/
│   └── index.html          # 프론트엔드 UI
├── package.json
├── CLAUDE.md               # AI 개발자용 문서
├── README.md               # 사용자용 문서 (이 파일)
└── TROUBLESHOOTING.md      # AI 트러블슈팅 가이드
```

## 설정 파일 위치

- **Claude Code 설정**: `~/.claude.json`
- **Claude Desktop 설정**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **OAuth 토큰**: `~/.google_workspace_mcp/credentials/{email}.json`
- **Client Secrets**: `~/Documents/GitHub/myproduct_v4/google_workspace_mcp/client_secret_{accountId}/`
- **포트 매핑**: `~/.mcp-workspace/oauth_port_map.json`

## 기술 스택

- **Electron** - 데스크톱 앱 프레임워크
- **Express** - 백엔드 서버
- **Vanilla JavaScript** - 프론트엔드 (프레임워크 없음)
- **Google OAuth 2.0** - 인증
- **MCP (Model Context Protocol)** - Claude 통합

## 개발자 정보

AI 개발자를 위한 상세 문서는 [CLAUDE.md](CLAUDE.md)를 참조하세요.

트러블슈팅 가이드는 [TROUBLESHOOTING.md](TROUBLESHOOTING.md)를 참조하세요.

## 라이선스

이 프로젝트는 개인 사용을 위해 제작되었습니다.

## 지원

문제가 발생하거나 질문이 있으시면 GitHub Issues를 통해 문의해주세요.
