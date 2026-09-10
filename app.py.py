from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
  return "<h1>보안 실습 웹사이트에 오신 것을 환영합니다!</h1>"


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000)