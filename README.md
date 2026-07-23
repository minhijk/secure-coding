# Tiny Second-hand Shopping Platform

화이트햇 스쿨 4기 1차 교육 · 시큐어 코딩 과제

Flask + Flask-SocketIO + SQLite 기반의 중고거래 플랫폼입니다.
[ugonfor/secure-coding](https://github.com/ugonfor/secure-coding) 실습 코드를 기반으로
요구된 기능을 모두 구현하고, 발견한 보안 약점을 제거했습니다.

---

## 구현 기능

| 요구사항 | 구현 |
| --- | --- |
| 사람들이 플랫폼에 가입할 수 있어야 함 | 회원가입 / 로그인 / 로그아웃, 프로필(소개글·비밀번호 변경) |
| 상품들을 올리고 볼 수 있어야 함 | 상품 등록·조회·상세, **상품 사진 업로드**, 내 상품 관리(수정·삭제) |
| 플랫폼 사용자들끼리 소통이 가능해야 함 | 실시간 전체 채팅, 1:1 채팅(대화 내역 저장) |
| 악성 유저나 상품을 차단해야 함 | 신고 기능, 신고 누적 시 상품 자동 차단 / 유저 자동 휴면 |
| 유저들 간의 송금이 가능해야 함 | 지갑, 사용자 간 송금, 거래 내역 |
| 상품의 검색할 수 있어야 함 | 상품명·설명 키워드 검색 |
| 관리자가 플랫폼의 모든 요소를 관리할 수 있어야 함 | 관리자 페이지(유저 휴면 전환, 상품 차단·삭제, 신고 내역, 감사 로그) |

추가로, 요구사항을 실제 중고거래 흐름으로 잇기 위해 **에스크로 기반 거래 기능**을 구현했습니다.

```
상품 등록(사진 포함) → 검색 → 1:1 문의 → 구매 요청(대금 에스크로 보관)
  → 판매자 수락(예약중) → 구매 확정(판매자에게 정산, 판매완료)
  → 또는 취소(전액 환불, 판매중으로 복귀)
```

---

## 환경 설정

miniconda(또는 anaconda)가 없다면 먼저 설치하세요.
https://docs.anaconda.com/free/miniconda/index.html

```bash
git clone https://github.com/minhijk/secure-coding
cd secure-coding
conda env create -f enviroments.yaml
conda activate secure_coding
```

## 실행 방법

```bash
python app.py
```

기본적으로 `http://127.0.0.1:5000` 에서 동작하며, 최초 실행 시 `market.db` 가 자동 생성됩니다.

외부에서 접속 테스트를 하려면 ngrok 을 사용할 수 있습니다.

```bash
sudo snap install ngrok
ngrok http 5000
```

## 환경 변수

운영 환경에서는 아래 값을 반드시 설정하세요. 미설정 시 개발용 기본값으로 동작합니다.

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `MARKET_SECRET_KEY` | 실행 시 랜덤 생성 | 세션 서명 키. 설정하지 않으면 재시작마다 세션이 무효화됩니다. |
| `MARKET_DATABASE` | `market.db` | SQLite 파일 경로 |
| `MARKET_UPLOAD_DIR` | `uploads` | 상품 이미지 저장 경로. `static/` 밖에 두어 직접 서빙되지 않습니다. |
| `MARKET_HTTPS` | `0` | `1` 이면 세션 쿠키에 `Secure` 플래그를 적용합니다. HTTPS 배포 시 필수. |
| `MARKET_ADMIN_USERNAME` | 없음 | 관리자 계정 아이디. 존재하면 승격, 없으면 생성합니다. |
| `MARKET_ADMIN_PASSWORD` | 없음 | 관리자 계정 비밀번호 (10자 이상) |

관리자 계정 생성 예시:

```bash
MARKET_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')" \
MARKET_ADMIN_USERNAME=root \
MARKET_ADMIN_PASSWORD='change-this-long-password' \
python app.py
```

> 관리자 계정은 코드에 하드코딩하지 않고 환경 변수로만 부트스트랩합니다.
> 일반 회원가입 경로로는 관리자 권한을 얻을 수 없습니다.

## 테스트

```bash
python -m pytest tests/ -q
```

`tests/test_security.py` 에 인증·세션, IDOR, XSS, SQL 인젝션, 송금 무결성,
거래 상태 전이, 파일 업로드 검증, 신고 남용, 권한 상승, 채팅 기밀성에 대한
보안 회귀 테스트 **46건**이 있습니다.

---

## 적용한 보안 대책 요약

**인증 / 세션**
- 비밀번호는 `werkzeug.security` 의 scrypt 해시 + salt 로 저장 (평문 저장 금지)
- 로그인 성공 시 세션 재생성(session fixation 방지), 비밀번호 변경 시에도 세션 재발급
- 세션 쿠키에 `HttpOnly`, `SameSite=Lax`, HTTPS 환경에서 `Secure` 적용
- 유휴 30분 / 최대 8시간 세션 만료, 비밀번호 변경 시 현재 비밀번호로 재인증
- IP+아이디 기준 로그인 5회/5분 제한 (무차별 대입 방어)

**입력 검증 / 인젝션**
- 모든 SQL 은 파라미터 바인딩 사용, 검색어는 `LIKE` 와일드카드까지 이스케이프
- 아이디는 정규식(`^[A-Za-z0-9_]{3,20}$`), 비밀번호 10~128자, 가격·송금액은 정수 범위 검증
- 모든 리소스 ID 는 UUID 형식 검증 후 조회
- Jinja2 자동 이스케이프 유지, 클라이언트 채팅 렌더링은 `textContent` 만 사용

**접근 제어**
- 상품 수정·삭제 시 소유자 검증, 타인 리소스는 403 대신 404 로 응답(존재 여부 은닉)
- 관리자 권한은 세션이 아닌 DB 값으로 매 요청 확인, 비관리자에게는 404
- 1:1 대화는 본인이 참여한 대화만 조회 가능
- 휴면 계정은 로그인 차단 + 기존 세션 즉시 무효화

**파일 업로드**
- 확장자·Content-Type 을 신뢰하지 않고 **매직 바이트로 실제 형식 판별** (JPG/PNG/GIF만 허용)
- 스크립트를 내장할 수 있는 SVG 는 화이트리스트에서 제외
- 사용자 파일명을 버리고 **UUID 로 재생성** → 경로 조작(`../`), 널 바이트, 이중 확장자 무력화
- 업로드 파일은 `static/` 밖에 저장하고 전용 라우트로만 서빙, mimetype 명시 + `nosniff`
- 이미지 3MB / 요청 전체 5MB 상한

**무결성 / 남용 방지**
- 송금은 단일 트랜잭션(`BEGIN IMMEDIATE`) + 조건부 UPDATE 로 경쟁 상태·이중 지출 차단
- 거래는 에스크로 방식이며, 상태 전이를 조건부 UPDATE 의 `rowcount` 로 검증
  (권한·상태·멱등성을 한 번에 보장 → 중복 클릭·요청 재전송에도 이중 정산 없음)
- 구매 확정은 구매자만, 수락은 판매자만 가능. 거래 중인 상품은 수정·삭제 불가
- 음수·0원 송금, 자기 자신 송금·구매 차단
- 동일 대상 중복 신고는 DB UNIQUE 제약으로 차단, 신고·송금·채팅에 rate limit 적용
- 주요 행위(로그인, 권한 변경, 송금, 신고, IDOR 시도)를 `audit_log` 에 기록

**전송 / 응답 보안**
- `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store` 헤더 적용
- 모든 상태 변경 POST 요청에 CSRF 토큰 검증 (`secrets.compare_digest`)
- SocketIO 는 동일 출처만 허용, 요청 본문 크기 2MB 제한
- 4xx/5xx 응답에서 스택 트레이스·DB 오류 원문을 노출하지 않음

전체 점검 항목과 결과는 `secure_coding_checklist.csv` 를 참고하세요.
