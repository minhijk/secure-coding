import io
import re

import pytest
from werkzeug.security import check_password_hash

import app as market


PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    b"\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01"
    b"\x0d\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


@pytest.fixture()
def client(tmp_path):
    market.app.config.update(
        TESTING=True,
        SECRET_KEY="test-only-secret",
        DATABASE=str(tmp_path / "test.db"),
        UPLOAD_DIR=str(tmp_path / "uploads"),
        SESSION_COOKIE_SECURE=False,
    )
    market.login_attempts.clear()
    market.chat_attempts.clear()
    market.transfer_attempts.clear()
    market.report_attempts.clear()
    market.init_db()
    with market.app.test_client() as test_client:
        yield test_client


def csrf_token(client, path):
    response = client.get(path)
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, f"no csrf token on {path} (status={response.status_code})"
    return match.group(1).decode()


def register(client, username="alice", password="correct-horse"):
    return client.post(
        "/register",
        data={
            "csrf_token": csrf_token(client, "/register"),
            "username": username,
            "password": password,
        },
        follow_redirects=True,
    )


def login(client, username="alice", password="correct-horse"):
    return client.post(
        "/login",
        data={
            "csrf_token": csrf_token(client, "/login"),
            "username": username,
            "password": password,
        },
        follow_redirects=True,
    )


def logout(client):
    return client.post(
        "/logout",
        data={"csrf_token": csrf_token(client, "/dashboard")},
        follow_redirects=True,
    )


def create_product(client, title="상품", description="설명", price="1000"):
    client.post(
        "/product/new",
        data={
            "csrf_token": csrf_token(client, "/product/new"),
            "title": title,
            "description": description,
            "price": price,
        },
        follow_redirects=True,
    )
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT id FROM product WHERE title = ? ORDER BY rowid DESC", (title,)
        ).fetchone()
    return row["id"] if row else None


def user_id_of(username):
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT id FROM user WHERE username = ?", (username,)
        ).fetchone()
    return row["id"] if row else None


def balance_of(username):
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT balance FROM user WHERE username = ?", (username,)
        ).fetchone()
    return row["balance"]


def upload_product(client, filename, content, title="사진상품"):
    """이미지를 첨부해 상품을 등록하고 (응답, 상품 id) 를 돌려준다."""
    response = client.post(
        "/product/new",
        data={
            "csrf_token": csrf_token(client, "/product/new"),
            "title": title,
            "description": "설명입니다",
            "price": "1000",
            "image": (io.BytesIO(content), filename),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT id, image_name FROM product WHERE title = ? ORDER BY rowid DESC",
            (title,),
        ).fetchone()
    return response, row


def product_status(product_id):
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT status FROM product WHERE id = ?", (product_id,)
        ).fetchone()
    return row["status"] if row else None


def latest_trade():
    with market.app.app_context():
        return market.get_db().execute(
            "SELECT * FROM trade ORDER BY rowid DESC"
        ).fetchone()


def make_admin(username):
    with market.app.app_context():
        db = market.get_db()
        db.execute("UPDATE user SET is_admin = 1 WHERE username = ?", (username,))
        db.commit()


# ------------------------------------------------------------------ 인증/세션

def test_csrf_rejects_missing_token(client):
    response = client.post(
        "/register", data={"username": "alice", "password": "correct-horse"}
    )
    assert response.status_code == 400


def test_registration_hashes_password(client):
    response = register(client)
    assert response.status_code == 200
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT password FROM user WHERE username = ?", ("alice",)
        ).fetchone()
    assert row["password"] != "correct-horse"
    assert check_password_hash(row["password"], "correct-horse")


def test_login_rotates_session_and_logout_requires_post(client):
    register(client)
    response = login(client)
    assert "로그인했습니다" in response.get_data(as_text=True)
    assert client.get("/logout").status_code == 405
    response = logout(client)
    assert "로그아웃했습니다" in response.get_data(as_text=True)


def test_weak_password_is_rejected(client):
    response = register(client, password="short")
    assert "비밀번호는" in response.get_data(as_text=True)


def test_login_rate_limit_triggers_429(client):
    register(client)
    for _ in range(market.LOGIN_MAX_ATTEMPTS):
        login(client, password="wrong-password-x")
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(client, "/login"),
            "username": "alice",
            "password": "wrong-password-x",
        },
    )
    assert response.status_code == 429


def test_security_headers_are_present(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_password_change_requires_current_password(client):
    register(client)
    login(client)
    response = client.post(
        "/profile/password",
        data={
            "csrf_token": csrf_token(client, "/profile"),
            "current_password": "wrong-password",
            "new_password": "brand-new-secret",
            "confirm_password": "brand-new-secret",
        },
        follow_redirects=True,
    )
    assert "현재 비밀번호가 올바르지 않습니다" in response.get_data(as_text=True)
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT password FROM user WHERE username = ?", ("alice",)
        ).fetchone()
    assert check_password_hash(row["password"], "correct-horse")


def test_suspended_user_cannot_log_in(client):
    register(client)
    with market.app.app_context():
        db = market.get_db()
        db.execute("UPDATE user SET is_active = 0 WHERE username = ?", ("alice",))
        db.commit()
    response = login(client)
    assert "올바르지 않습니다" in response.get_data(as_text=True)
    assert client.get("/dashboard").status_code == 302


# ------------------------------------------------------------------ 상품/IDOR

def test_product_validation_rejects_non_numeric_price(client):
    register(client)
    login(client)
    response = client.post(
        "/product/new",
        data={
            "csrf_token": csrf_token(client, "/product/new"),
            "title": "상품",
            "description": "설명",
            "price": "not-a-number",
        },
        follow_redirects=True,
    )
    assert "가격은" in response.get_data(as_text=True)


def test_product_negative_price_is_rejected(client):
    register(client)
    login(client)
    response = client.post(
        "/product/new",
        data={
            "csrf_token": csrf_token(client, "/product/new"),
            "title": "상품",
            "description": "설명",
            "price": "-500",
        },
        follow_redirects=True,
    )
    assert "가격은" in response.get_data(as_text=True)


def test_cannot_edit_or_delete_other_users_product(client):
    register(client, "alice")
    login(client, "alice")
    product_id = create_product(client, title="앨리스상품")
    logout(client)

    register(client, "mallory", "another-strong-pass")
    login(client, "mallory", "another-strong-pass")
    assert client.get(f"/product/{product_id}/edit").status_code == 404
    response = client.post(
        f"/product/{product_id}/delete",
        data={"csrf_token": csrf_token(client, "/dashboard")},
    )
    assert response.status_code == 404
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT 1 FROM product WHERE id = ?", (product_id,)
        ).fetchone()
    assert row is not None, "타인이 상품을 삭제할 수 있으면 안 된다"


def test_xss_payload_in_product_is_escaped(client):
    register(client)
    login(client)
    payload = "<script>alert(1)</script>"
    product_id = create_product(client, title=payload, description=payload)
    body = client.get(f"/product/{product_id}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_search_does_not_allow_sql_injection(client):
    register(client)
    login(client)
    create_product(client, title="정상상품")
    response = client.get("/dashboard?q=%25%27+OR+%271%27%3D%271")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    # 인젝션이 성공했다면 전체 상품이 노출된다.
    assert "정상상품" not in body


def test_search_finds_matching_product(client):
    register(client)
    login(client)
    create_product(client, title="빈티지 카메라")
    body = client.get("/dashboard?q=카메라").get_data(as_text=True)
    assert "빈티지 카메라" in body


# ------------------------------------------------------------------ 이미지 업로드

def test_valid_image_upload_is_stored_and_served(client):
    register(client)
    login(client)
    _, row = upload_product(client, "photo.png", PNG_BYTES)
    assert row["image_name"] is not None
    # 사용자가 보낸 파일명은 버리고 서버가 UUID 로 새로 만든다.
    assert "photo" not in row["image_name"]
    assert market.IMAGE_NAME_RE.fullmatch(row["image_name"])

    response = client.get(f"/product/{row['id']}/image")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("image/png")
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_disguised_extension_is_rejected(client):
    """확장자만 이미지인 파일(shell.php.jpg 등)은 매직 바이트 검사에서 걸러진다."""
    register(client)
    login(client)
    payload = b"<?php system($_GET['c']); ?>"
    response, row = upload_product(client, "shell.php.jpg", payload, title="위장파일")
    assert "이미지만 업로드할 수 있습니다" in response.get_data(as_text=True)
    assert row is None, "검증에 실패한 업로드로 상품이 생성되면 안 된다"


def test_svg_upload_is_rejected(client):
    """SVG 는 스크립트를 내장할 수 있어 화이트리스트에서 제외한다."""
    register(client)
    login(client)
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    response, row = upload_product(client, "xss.svg", svg, title="SVG상품")
    assert "이미지만 업로드할 수 있습니다" in response.get_data(as_text=True)
    assert row is None


def test_path_traversal_filename_is_neutralised(client):
    """경로 조작 파일명을 보내도 서버가 파일명을 재생성하므로 무력화된다."""
    register(client)
    login(client)
    _, row = upload_product(client, "../../evil.png", PNG_BYTES, title="경로조작")
    assert row["image_name"] is not None
    assert ".." not in row["image_name"]
    assert "/" not in row["image_name"] and "\\" not in row["image_name"]
    assert market.IMAGE_NAME_RE.fullmatch(row["image_name"])


def test_oversized_image_is_rejected(client):
    register(client)
    login(client)
    huge = PNG_BYTES + b"\x00" * (market.MAX_IMAGE_BYTES + 1)
    response, row = upload_product(client, "huge.png", huge, title="대용량")
    assert "3MB 이하" in response.get_data(as_text=True)
    assert row is None


# ------------------------------------------------------------------ 거래(에스크로)

def test_buy_escrows_funds_and_reserves_product(client):
    register(client, "seller", "sellers-strong-pass")
    login(client, "seller", "sellers-strong-pass")
    product_id = create_product(client, title="거래상품", price="3000")
    logout(client)

    register(client, "buyer", "buyers-strong-pass")
    login(client, "buyer", "buyers-strong-pass")
    client.post(
        f"/product/{product_id}/buy",
        data={"csrf_token": csrf_token(client, f"/product/{product_id}")},
        follow_redirects=True,
    )

    # 구매자 잔액은 즉시 차감되지만 판매자에게는 아직 지급되지 않는다(에스크로).
    assert balance_of("buyer") == market.SIGNUP_BONUS - 3000
    assert balance_of("seller") == market.SIGNUP_BONUS
    assert product_status(product_id) == "reserved"
    assert latest_trade()["status"] == "requested"


def test_cannot_buy_own_product(client):
    register(client, "seller", "sellers-strong-pass")
    login(client, "seller", "sellers-strong-pass")
    product_id = create_product(client, title="내상품", price="1000")
    response = client.post(
        f"/product/{product_id}/buy",
        data={"csrf_token": csrf_token(client, f"/product/{product_id}")},
        follow_redirects=True,
    )
    assert "자신의 상품은 구매할 수 없습니다" in response.get_data(as_text=True)
    assert product_status(product_id) == "active"
    assert latest_trade() is None


def test_buy_with_insufficient_balance_is_rejected(client):
    register(client, "seller", "sellers-strong-pass")
    login(client, "seller", "sellers-strong-pass")
    product_id = create_product(client, title="비싼상품", price="999999")
    logout(client)

    register(client, "buyer", "buyers-strong-pass")
    login(client, "buyer", "buyers-strong-pass")
    response = client.post(
        f"/product/{product_id}/buy",
        data={"csrf_token": csrf_token(client, f"/product/{product_id}")},
        follow_redirects=True,
    )
    assert "잔액이 부족합니다" in response.get_data(as_text=True)
    # 롤백되어 상품 예약도 취소되어야 한다.
    assert product_status(product_id) == "active"
    assert balance_of("buyer") == market.SIGNUP_BONUS
    assert latest_trade() is None


def test_second_buyer_cannot_take_reserved_product(client):
    register(client, "seller", "sellers-strong-pass")
    login(client, "seller", "sellers-strong-pass")
    product_id = create_product(client, title="선점상품", price="1000")
    logout(client)

    register(client, "buyer1", "buyer1-strong-pass")
    login(client, "buyer1", "buyer1-strong-pass")
    client.post(
        f"/product/{product_id}/buy",
        data={"csrf_token": csrf_token(client, f"/product/{product_id}")},
        follow_redirects=True,
    )
    logout(client)

    register(client, "buyer2", "buyer2-strong-pass")
    login(client, "buyer2", "buyer2-strong-pass")
    client.post(
        f"/product/{product_id}/buy",
        data={"csrf_token": csrf_token(client, f"/product/{product_id}")},
        follow_redirects=True,
    )
    # 순차 요청은 status 사전 검사에서 막히고, 진짜 동시 요청은 트랜잭션 안의
    # 조건부 UPDATE(status='active')가 막는다. 어느 쪽이든 결과는 같아야 한다.
    assert balance_of("buyer2") == market.SIGNUP_BONUS, "두 번째 구매자가 과금되면 안 된다"
    with market.app.app_context():
        count = market.get_db().execute(
            "SELECT COUNT(*) AS c FROM trade WHERE product_id = ?", (product_id,)
        ).fetchone()["c"]
    assert count == 1, "상품 하나에 활성 거래는 하나만 생성되어야 한다"


def test_reserved_product_cannot_be_bought_even_if_precheck_bypassed(client):
    """사전 검사를 통과하더라도 조건부 UPDATE 가 이중 예약을 막는지 확인한다.

    동시 요청을 테스트에서 재현하기 어려우므로, 거래 레코드만 지워
    사전 검사(활성 거래 조회)는 통과하되 상품이 reserved 인 상태를 만든다.
    """
    register(client, "seller", "sellers-strong-pass")
    login(client, "seller", "sellers-strong-pass")
    product_id = create_product(client, title="경쟁상품", price="1000")
    logout(client)

    with market.app.app_context():
        db = market.get_db()
        db.execute("UPDATE product SET status = 'reserved' WHERE id = ?", (product_id,))
        db.commit()

    register(client, "buyer", "buyers-strong-pass")
    login(client, "buyer", "buyers-strong-pass")
    client.post(
        f"/product/{product_id}/buy",
        data={"csrf_token": csrf_token(client, f"/product/{product_id}")},
        follow_redirects=True,
    )
    assert balance_of("buyer") == market.SIGNUP_BONUS
    assert latest_trade() is None


def _setup_accepted_trade(client):
    """seller/buyer 를 만들고 수락까지 진행한 거래를 돌려준다."""
    register(client, "seller", "sellers-strong-pass")
    login(client, "seller", "sellers-strong-pass")
    product_id = create_product(client, title="거래상품", price="3000")
    logout(client)

    register(client, "buyer", "buyers-strong-pass")
    login(client, "buyer", "buyers-strong-pass")
    client.post(
        f"/product/{product_id}/buy",
        data={"csrf_token": csrf_token(client, f"/product/{product_id}")},
        follow_redirects=True,
    )
    logout(client)

    login(client, "seller", "sellers-strong-pass")
    trade = latest_trade()
    client.post(
        f"/trade/{trade['id']}/accept",
        data={"csrf_token": csrf_token(client, "/trades")},
        follow_redirects=True,
    )
    logout(client)
    return product_id, trade["id"]


def test_buyer_cannot_accept_own_trade(client):
    register(client, "seller", "sellers-strong-pass")
    login(client, "seller", "sellers-strong-pass")
    product_id = create_product(client, title="거래상품", price="3000")
    logout(client)

    register(client, "buyer", "buyers-strong-pass")
    login(client, "buyer", "buyers-strong-pass")
    client.post(
        f"/product/{product_id}/buy",
        data={"csrf_token": csrf_token(client, f"/product/{product_id}")},
        follow_redirects=True,
    )
    trade_id = latest_trade()["id"]
    # 수락은 판매자 권한이다.
    response = client.post(
        f"/trade/{trade_id}/accept",
        data={"csrf_token": csrf_token(client, "/trades")},
    )
    assert response.status_code == 404
    assert latest_trade()["status"] == "requested"


def test_seller_cannot_complete_trade_themselves(client):
    """판매자가 스스로 정산하면 물건 없이 대금을 챙길 수 있으므로 차단한다."""
    _product_id, trade_id = _setup_accepted_trade(client)
    login(client, "seller", "sellers-strong-pass")
    response = client.post(
        f"/trade/{trade_id}/complete",
        data={"csrf_token": csrf_token(client, "/trades")},
    )
    assert response.status_code == 404
    assert latest_trade()["status"] == "accepted"
    assert balance_of("seller") == market.SIGNUP_BONUS


def test_buyer_completes_trade_and_seller_is_paid(client):
    product_id, trade_id = _setup_accepted_trade(client)
    login(client, "buyer", "buyers-strong-pass")
    client.post(
        f"/trade/{trade_id}/complete",
        data={"csrf_token": csrf_token(client, "/trades")},
        follow_redirects=True,
    )
    assert latest_trade()["status"] == "completed"
    assert balance_of("seller") == market.SIGNUP_BONUS + 3000
    assert balance_of("buyer") == market.SIGNUP_BONUS - 3000
    assert product_status(product_id) == "sold"


def test_completing_twice_does_not_pay_seller_twice(client):
    """중복 클릭이나 요청 재전송으로 이중 정산이 일어나면 안 된다."""
    _product_id, trade_id = _setup_accepted_trade(client)
    login(client, "buyer", "buyers-strong-pass")
    for _ in range(2):
        client.post(
            f"/trade/{trade_id}/complete",
            data={"csrf_token": csrf_token(client, "/trades")},
            follow_redirects=True,
        )
    assert balance_of("seller") == market.SIGNUP_BONUS + 3000


def test_cancel_refunds_buyer_and_reopens_product(client):
    product_id, trade_id = _setup_accepted_trade(client)
    login(client, "buyer", "buyers-strong-pass")
    client.post(
        f"/trade/{trade_id}/cancel",
        data={"csrf_token": csrf_token(client, "/trades")},
        follow_redirects=True,
    )
    assert latest_trade()["status"] == "cancelled"
    assert balance_of("buyer") == market.SIGNUP_BONUS
    assert balance_of("seller") == market.SIGNUP_BONUS
    assert product_status(product_id) == "active"


def test_cancelling_twice_does_not_double_refund(client):
    _product_id, trade_id = _setup_accepted_trade(client)
    login(client, "buyer", "buyers-strong-pass")
    for _ in range(2):
        client.post(
            f"/trade/{trade_id}/cancel",
            data={"csrf_token": csrf_token(client, "/trades")},
            follow_redirects=True,
        )
    assert balance_of("buyer") == market.SIGNUP_BONUS


def test_outsider_cannot_touch_someone_elses_trade(client):
    _product_id, trade_id = _setup_accepted_trade(client)
    register(client, "mallory", "mallorys-strong-pass")
    login(client, "mallory", "mallorys-strong-pass")
    for action in ("accept", "complete", "cancel"):
        response = client.post(
            f"/trade/{trade_id}/{action}",
            data={"csrf_token": csrf_token(client, "/trades")},
        )
        assert response.status_code == 404, action
    assert latest_trade()["status"] == "accepted"


def test_product_in_trade_cannot_be_edited_or_deleted(client):
    product_id, _trade_id = _setup_accepted_trade(client)
    login(client, "seller", "sellers-strong-pass")
    # 예약중 상품 수정 시도
    response = client.get(f"/product/{product_id}/edit", follow_redirects=True)
    assert "수정할 수 없습니다" in response.get_data(as_text=True)
    # 예약중 상품 삭제 시도
    response = client.post(
        f"/product/{product_id}/delete",
        data={"csrf_token": csrf_token(client, "/my/products")},
        follow_redirects=True,
    )
    assert "진행 중인 거래가 있어 삭제할 수 없습니다" in response.get_data(as_text=True)
    assert product_status(product_id) == "reserved"


# ------------------------------------------------------------------ 송금

def test_transfer_moves_funds_and_rejects_overdraft(client):
    register(client, "alice")
    register(client, "bob", "bobs-strong-pass")
    login(client, "alice")

    response = client.post(
        "/wallet",
        data={
            "csrf_token": csrf_token(client, "/wallet"),
            "receiver": "bob",
            "amount": "3000",
        },
        follow_redirects=True,
    )
    assert "송금했습니다" in response.get_data(as_text=True)
    assert balance_of("alice") == market.SIGNUP_BONUS - 3000
    assert balance_of("bob") == market.SIGNUP_BONUS + 3000

    response = client.post(
        "/wallet",
        data={
            "csrf_token": csrf_token(client, "/wallet"),
            "receiver": "bob",
            "amount": "999999",
        },
        follow_redirects=True,
    )
    assert "잔액이 부족합니다" in response.get_data(as_text=True)
    assert balance_of("alice") == market.SIGNUP_BONUS - 3000


def test_transfer_rejects_negative_amount(client):
    register(client, "alice")
    register(client, "bob", "bobs-strong-pass")
    login(client, "alice")
    response = client.post(
        "/wallet",
        data={
            "csrf_token": csrf_token(client, "/wallet"),
            "receiver": "bob",
            "amount": "-5000",
        },
        follow_redirects=True,
    )
    assert "송금액은" in response.get_data(as_text=True)
    assert balance_of("alice") == market.SIGNUP_BONUS
    assert balance_of("bob") == market.SIGNUP_BONUS


def test_transfer_to_self_is_rejected(client):
    register(client, "alice")
    login(client, "alice")
    response = client.post(
        "/wallet",
        data={
            "csrf_token": csrf_token(client, "/wallet"),
            "receiver": "alice",
            "amount": "100",
        },
        follow_redirects=True,
    )
    assert "자기 자신에게는" in response.get_data(as_text=True)
    assert balance_of("alice") == market.SIGNUP_BONUS


# ------------------------------------------------------------------ 신고/차단

def test_duplicate_report_is_rejected(client):
    register(client, "alice")
    register(client, "bob", "bobs-strong-pass")
    login(client, "alice")
    target = user_id_of("bob")
    payload = {"target_id": target, "reason": "사기 의심 계정입니다."}

    client.post(
        "/report", data={"csrf_token": csrf_token(client, "/report"), **payload},
        follow_redirects=True,
    )
    response = client.post(
        "/report", data={"csrf_token": csrf_token(client, "/report"), **payload},
        follow_redirects=True,
    )
    assert "이미 신고한 대상입니다" in response.get_data(as_text=True)


def test_product_is_blocked_after_threshold_reports(client):
    register(client, "seller", "sellers-strong-pass")
    login(client, "seller", "sellers-strong-pass")
    product_id = create_product(client, title="불량상품")
    logout(client)

    for i in range(market.PRODUCT_BLOCK_THRESHOLD):
        name = f"reporter{i}"
        register(client, name, "reporters-strong-pass")
        login(client, name, "reporters-strong-pass")
        client.post(
            "/report",
            data={
                "csrf_token": csrf_token(client, "/report"),
                "target_id": product_id,
                "reason": "허위 매물로 의심됩니다.",
            },
            follow_redirects=True,
        )
        logout(client)

    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT status FROM product WHERE id = ?", (product_id,)
        ).fetchone()
    assert row["status"] == "blocked"

    register(client, "buyer", "buyers-strong-pass")
    login(client, "buyer", "buyers-strong-pass")
    assert "불량상품" not in client.get("/dashboard").get_data(as_text=True)


def test_self_report_is_rejected(client):
    register(client, "alice")
    login(client, "alice")
    response = client.post(
        "/report",
        data={
            "csrf_token": csrf_token(client, "/report"),
            "target_id": user_id_of("alice"),
            "reason": "테스트용 자기 신고입니다.",
        },
        follow_redirects=True,
    )
    assert "신고할 수 없는 대상입니다" in response.get_data(as_text=True)


# ------------------------------------------------------------------ 관리자

def test_normal_user_cannot_reach_admin_pages(client):
    register(client, "alice")
    login(client, "alice")
    assert client.get("/admin").status_code == 404
    response = client.post(
        f"/admin/user/{user_id_of('alice')}/toggle",
        data={"csrf_token": csrf_token(client, "/dashboard")},
    )
    assert response.status_code == 404


def test_admin_can_suspend_user_and_session_is_invalidated(client):
    register(client, "root", "roots-strong-pass")
    register(client, "mallory", "mallorys-strong-pass")
    make_admin("root")
    login(client, "root", "roots-strong-pass")

    response = client.post(
        f"/admin/user/{user_id_of('mallory')}/toggle",
        data={"csrf_token": csrf_token(client, "/admin")},
        follow_redirects=True,
    )
    assert response.status_code == 200
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT is_active FROM user WHERE username = ?", ("mallory",)
        ).fetchone()
    assert row["is_active"] == 0
    logout(client)

    response = login(client, "mallory", "mallorys-strong-pass")
    assert "올바르지 않습니다" in response.get_data(as_text=True)


def test_admin_cannot_suspend_another_admin(client):
    register(client, "root", "roots-strong-pass")
    register(client, "root2", "roots2-strong-pass")
    make_admin("root")
    make_admin("root2")
    login(client, "root", "roots-strong-pass")
    client.post(
        f"/admin/user/{user_id_of('root2')}/toggle",
        data={"csrf_token": csrf_token(client, "/admin")},
        follow_redirects=True,
    )
    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT is_active FROM user WHERE username = ?", ("root2",)
        ).fetchone()
    assert row["is_active"] == 1


# ------------------------------------------------------------------ 채팅

def test_socket_uses_server_side_username(client):
    register(client)
    login(client)
    socket_client = market.socketio.test_client(market.app, flask_test_client=client)
    assert socket_client.is_connected()
    socket_client.emit("send_message", {"username": "admin", "message": "hello"})
    received = socket_client.get_received()
    args = next(event["args"] for event in received if event["name"] == "message")
    payload = args[0] if isinstance(args, list) else args
    assert payload["username"] == "alice"
    assert payload["message"] == "hello"


def test_anonymous_socket_is_rejected(client):
    socket_client = market.socketio.test_client(market.app, flask_test_client=client)
    assert not socket_client.is_connected()


def test_oversized_chat_message_is_dropped(client):
    register(client)
    login(client)
    socket_client = market.socketio.test_client(market.app, flask_test_client=client)
    socket_client.emit("send_message", {"message": "A" * (market.MAX_CHAT_LENGTH + 1)})
    received = socket_client.get_received()
    assert not [event for event in received if event["name"] == "message"]


def test_private_message_is_persisted_and_not_broadcast(client):
    register(client, "alice")
    register(client, "bob", "bobs-strong-pass")
    login(client, "alice")
    bob_id = user_id_of("bob")

    socket_client = market.socketio.test_client(market.app, flask_test_client=client)
    socket_client.emit("private_message", {"to": bob_id, "message": "안녕하세요"})

    with market.app.app_context():
        row = market.get_db().execute(
            "SELECT content, receiver_id FROM message ORDER BY rowid DESC"
        ).fetchone()
    assert row["content"] == "안녕하세요"
    assert row["receiver_id"] == bob_id

    received = socket_client.get_received()
    assert not [event for event in received if event["name"] == "message"]


def test_cannot_read_other_users_private_chat(client):
    register(client, "alice")
    register(client, "bob", "bobs-strong-pass")
    register(client, "mallory", "mallorys-strong-pass")
    alice_id, bob_id = user_id_of("alice"), user_id_of("bob")

    with market.app.app_context():
        db = market.get_db()
        db.execute(
            "INSERT INTO message (id, sender_id, receiver_id, content, created_at) "
            "VALUES ('11111111-1111-4111-8111-111111111111', ?, ?, '비밀거래내용', datetime('now'))",
            (alice_id, bob_id),
        )
        db.commit()

    login(client, "mallory", "mallorys-strong-pass")
    body = client.get(f"/chat/{alice_id}").get_data(as_text=True)
    assert "비밀거래내용" not in body
