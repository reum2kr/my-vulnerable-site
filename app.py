import os
from flask import Flask, render_template_string, request

app = Flask(__name__)


# 1. 메인 페이지 (XSS 취약점)
@app.route("/")
def index():
  name = request.args.get("name", "방문자")
  # 사용자 입력값(name)을 필터링 없이 그대로 HTML에 출력 (Reflected XSS)
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


# 2. 로그인 페이지 (SQL Injection 취약점 - 개념 실습용)
@app.route("/login", methods=["GET", "POST"])
def login():
  msg = ""
  if request.method == "POST":
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # 문자열 결합을 통한 취약한 쿼리 구문 우회 모사
    # 실제 DB 연동 없이 우회 패턴(' OR '1'='1) 입력 시 인증 성공
    if "' or '1'='1" in username.lower() or "' or 1=1" in username.lower():
      msg = "로그인 성공! (SQL Injection 공격에 성공했습니다)"
    elif username == "admin" and password == "1234":
      msg = "로그인 성공!"
    else:
      msg = "로그인 실패!"

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


# 3. Ping 테스트 페이지 (Command Injection 취약점)
@app.route("/ping", methods=["GET", "POST"])
def ping():
  result = ""
  if request.method == "POST":
    ip = request.form.get("ip", "")
    # 사용자 입력을 검증 없이 시스템 명령어로 직접 실행
    cmd = f"ping -c 1 {ip}"
    result = os.popen(cmd).read()

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


# 4. 파일 업로드 페이지 (Unrestricted File Upload 취약점)
UPLOAD_FOLDER = "/tmp"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/upload", methods=["GET", "POST"])
def upload():
  msg = ""
  if request.method == "POST":
    file = request.files.get("file")
    if file:
      # 확장자 검사 없이 바로 서버에 저장
      filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
      file.save(filepath)
      msg = f"파일이 성공적으로 업로드되었습니다: {filepath}"

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
  app.run(host="0.0.0.0", port=5000)
