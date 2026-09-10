import os
import re
import sqlite3
from flask import Flask, render_template_string, request, escape
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 업로드 경로 설정
UPLOAD_FOLDER = "/tmp"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ==========================================
# 1. 메인 페이지 (Reflected XSS 취약점)
# ==========================================
@app.route("/")
def index():
    # [취약점] 사용자 입력값을 이스케이프 처리 없이 직접 출력
    name = request.args.get("name", "방문자")

    # [보안 조치 예시] escape(name)을 사용하여 HTML 태그 실행 방지
    # safe_name = escape(name)

    template = f"""
    <h1>보안 실습 웹사이트</h1>
    <form action="/" method="get">
        이름 입력: <input type="text" name="name">
        <input type="submit" value="전송">
    </form>
    <hr>
    <h3>안녕하세요, {name}님!</h3>
    <ul>
        <li><a href="/login">1. SQL Injection 실습 (로그인)</a></li>
        <li><a href="/ping">2. Command Injection 실습 (핑 테스트)</a></li>
        <li><a href="/upload">3. 취약한 파일 업로드 실습</a></li>
    </ul>
    """
    return render_template_string(template)


# ==========================================
# 2. 로그인 페이지 (SQL Injection 취약점)
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [취약점 시뮬레이션] 입력값 검증 없이 우회 구문 확인
        if "' or '1'='1" in username.lower() or "' or 1=1" in username.lower():
            msg = "로그인 성공! (SQL Injection 공격 성공)"
        elif username == "admin" and password == "1234":
            msg = "로그인 성공!"
        else:
            msg = "로그인 실패!"

        # [보안 조치 예시] Prepared Statement(파라미터화된 쿼리) 사용
        # cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))

    template = """
    <h2>SQL Injection 실습</h2>
    <form method="post">
        아이디: <input type="text" name="username"><br>
        비밀번호: <input type="password" name="password"><br>
        <input type="submit" value="로그인">
    </form>
    <p>{{ msg }}</p>
    <a href="/">메인으로 돌아가기</a>
    """
    return render_template_string(template, msg=msg)


# ==========================================
# 3. Ping 테스트 페이지 (Command Injection 취약점)
# ==========================================
@app.route("/ping", methods=["GET", "POST"])
def ping():
    result = ""
    if request.method == "POST":
        ip = request.form.get("ip", "")

        # [취약점] 사용자 입력값을 시스템 명령어로 직접 전달 (예: 127.0.0.1; ls -al)
        cmd = f"ping -c 1 {ip}"
        result = os.popen(cmd).read()

        # [보안 조치 예시] 입력값 화이트리스트 검증 (IP 형식만 허용)
        # if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        #     subprocess.run(["ping", "-c", "1", ip])

    template = """
    <h2>Command Injection 실습</h2>
    <form method="post">
        IP 주소: <input type="text" name="ip" placeholder="127.0.0.1">
        <input type="submit" value="Ping 전송">
    </form>
    <pre>{{ result }}</pre>
    <a href="/">메인으로 돌아가기</a>
    """
    return render_template_string(template, result=result)


# ==========================================
# 4. 파일 업로드 페이지 (Unrestricted File Upload 취약점)
# ==========================================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    msg = ""
    if request.method == "POST":
        file = request.files.get("file")
        if file:
            # [취약점] 파일 확장자 및 파일명 검사 없이 그대로 저장
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(filepath)
            msg = f"파일이 성공적으로 업로드되었습니다: {filepath}"

            # [보안 조치 예시] 파일 확장자 검사 및 filename 정제
            # if allowed_file(file.filename):
            #     filename = secure_filename(file.filename)
            #     file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    template = """
    <h2>취약한 파일 업로드 실습</h2>
    <form method="post" enctype="multipart/form-data">
        파일 선택: <input type="file" name="file">
        <input type="submit" value="업로드">
    </form>
    <p>{{ msg }}</p>
    <a href="/">메인으로 돌아가기</a>
    """
    return render_template_string(template, msg=msg)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
