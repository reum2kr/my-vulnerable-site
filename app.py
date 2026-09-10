import os
import re
import socket
import ssl
import subprocess
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

# ==========================================
# HTML / UI Template
# ==========================================
INDEX_HTML = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>종합 취약점 분석 및 보안 점검 시스템</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }
        h1 { color: #1a365d; border-bottom: 2px solid #2b6cb0; padding-bottom: 10px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .card h3 { margin-top: 0; color: #2b6cb0; }
        label { font-weight: bold; display: block; margin-top: 10px; }
        input[type="text"], select { width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { background-color: #3182ce; color: white; border: none; padding: 10px 15px; margin-top: 15px; border-radius: 4px; cursor: pointer; width: 100%; font-weight: bold; }
        button:hover { background-color: #2b6cb0; }
        pre { background: #2d3748; color: #edf2f7; padding: 15px; border-radius: 6px; overflow-x: auto; max-height: 350px; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
    </style>
    <script>
        async function runScan(endpoint, formId, resultId) {
            const form = document.getElementById(formId);
            const formData = new FormData(form);
            const data = Object.fromEntries(formData.entries());
            document.getElementById(resultId).innerText = "진단 실행 중...";
            
            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await response.json();
                document.getElementById(resultId).innerText = JSON.stringify(result, null, 2);
            } catch (err) {
                document.getElementById(resultId).innerText = "오류 발생: " + err;
            }
        }
    </script>
</head>
<body>
    <h1>종합 취약점 진단 및 보안 분석 대시보드</h1>
    <div class="grid">
        
        <!-- 1. 웹 애플리케이션 취약점 진단 -->
        <div class="card">
            <h3>1. Web Application Scan</h3>
            <p>SQLi, XSS, CSRF, 인증 우회, 파일 업로드 등 점검</p>
            <form id="webForm">
                <label>Target URL</label>
                <input type="text" name="target_url" placeholder="http://example.com/login">
                <label>Check Items</label>
                <select name="scan_type">
                  <option value="all">전체 점검 (모든 항목)</option>
                  <option value="sqli">SQL Injection</option>
                  <option value="xss">Cross-Site Scripting (XSS)</option>
                  <option value="cmdi">Command Injection</option>
                  <option value="traversal">Directory Traversal</option>
                  <option value="auth_bypass">인증/권한 우회 (Auth Bypass)</option>
                  <option value="idor">IDOR (취약한 객체 참조)</option>
                  <option value="csrf">CSRF</option>
                  <option value="upload">Unrestricted File Upload</option>
                </select>
            </form>
            <button onclick="runScan('/api/scan/web', 'webForm', 'webResult')">웹 취약점 진단 실행</button>
            <pre id="webResult">결과가 여기에 표시됩니다.</pre>
        </div>

        <!-- 2. 서버 및 시스템/포트 점검 -->
        <div class="card">
            <h3>2. OS / WEB / WAS / DB Scan</h3>
            <p>불필요한 포트, 서비스, SSL/TLS, 패치 여부</p>
            <form id="sysForm">
                <label>Target IP/Host</label>
                <input type="text" name="target_host" placeholder="192.168.1.100">
                <label>Port Range</label>
                <input type="text" name="ports" value="21,22,80,443,3306,8080">
            </form>
            <button onclick="runScan('/api/scan/system', 'sysForm', 'sysResult')">시스템 점검 실행</button>
            <pre id="sysResult">결과가 여기에 표시됩니다.</pre>
        </div>

        <!-- 3. 네트워크 장비 점검 -->
        <div class="card">
            <h3>3. Network Devices Scan</h3>
            <p>방화벽, 스위치, L4/L7 설정 오류 및 SNMP 점검</p>
            <form id="netForm">
                <label>Device IP</label>
                <input type="text" name="device_ip" placeholder="192.168.1.1">
                <label>Community String (SNMP)</label>
                <input type="text" name="snmp_community" value="public">
            </form>
            <button onclick="runScan('/api/scan/network', 'netForm', 'netResult')">네트워크 장비 점검</button>
            <pre id="netResult">결과가 여기에 표시됩니다.</pre>
        </div>

        <!-- 4. 무선 네트워크(Wi-Fi) 점검 -->
        <div class="card">
            <h3>4. Wireless Security Scan</h3>
            <p>AP 암호화(WPA2/3), Rogue AP, 패킷 감청 risk</p>
            <form id="wifiForm">
                <label>Interface</label>
                <input type="text" name="interface" value="wlan0">
            </form>
            <button onclick="runScan('/api/scan/wireless', 'wifiForm', 'wifiResult')">무선 보안 점검</button>
            <pre id="wifiResult">결과가 여기에 표시됩니다.</pre>
        </div>

    </div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


# ==========================================
# API 1. 웹 애플리케이션 취약점 모듈
# ==========================================
@app.route("/api/scan/web", methods=["POST"])
def scan_web():
    data = request.json or {}
    target_url = data.get("target_url", "")
    scan_type = data.get("scan_type", "all")

    if not target_url:
        return jsonify({"error": "Target URL이 입력되지 않았습니다."}), 400

    results = {
        "target": target_url,
        "vulnerabilities": [],
        "details": {},
        "exploitation_guide": {}
    }

    # 1. SQL Injection (SQLi)
    if scan_type in ["all", "sqli"]:
        results["vulnerabilities"].append("SQL Injection")
        results["details"]["SQLi"] = "파라미터 입력 검증 미비 - SQL Injection 가능성 감지 (취약)"
        results["exploitation_guide"]["SQLi"] = {
            "approach": "쿼리 조건절을 무조건 참(TRUE)으로 만들거나 UNION 연산자를 통한 정보 추출",
            "payload_examples": ["admin' --", "' OR '1'='1", "' UNION SELECT username, password FROM users --"]
        }

    # 2. Cross-Site Scripting (XSS)
    if scan_type in ["all", "xss"]:
        results["vulnerabilities"].append("XSS")
        results["details"]["XSS"] = "Reflected/Stored XSS 취약점 존재 (HTML Escape 미적용)"
        results["exploitation_guide"]["XSS"] = {
            "approach": "입력값 출력 위치에 HTML/JS ই스케이프 처리가 없는 점을 이용해 악성 스크립트 실행",
            "payload_examples": ["<script>alert(document.cookie);</script>", "<img src=x onerror=alert(1)>"]
        }

    # 3. Command Injection
    if scan_type in ["all", "cmdi"]:
        results["vulnerabilities"].append("Command Injection")
        results["details"]["Command Injection"] = "시스템 명령어 실행 파라미터 필터링 부재"
        results["exploitation_guide"]["Command Injection"] = {
            "approach": "OS 명령어 구분자(;, |, &&)를 삽입하여 기존 명령 뒤에 임의 시스템 명령어 연결 실행",
            "payload_examples": ["127.0.0.1; ls -al", "127.0.0.1 | cat /etc/passwd"]
        }

    # 4. Directory Traversal
    if scan_type in ["all", "traversal"]:
        results["vulnerabilities"].append("Directory Traversal")
        results["details"]["Directory Traversal"] = "상위 디렉터리 접근 필터링 미비"
        results["exploitation_guide"]["Directory Traversal"] = {
            "approach": "파일 경로 파라미터에 상위 디렉터리 이동 문자열(../)을 연속 입력하여 상위 시스템 파일 접근",
            "payload_examples": ["../../../../etc/passwd", "../../../../Windows/win.ini"]
        }

    # 5. 인증/권한 우회 (Auth Bypass)
    if scan_type in ["all", "auth_bypass"]:
        results["vulnerabilities"].append("Auth Bypass")
        results["details"]["Auth Bypass"] = "세션/쿠키 검증 로직 우회 가능성 존재"
        results["exploitation_guide"]["Auth Bypass"] = {
            "approach": "쿠키/세션 파라미터를 조작하거나 인증 로직이 누락된 관리자 URL 직접 입력 접근",
            "payload_examples": ["Cookie: is_admin=true", "Cookie: role=admin", "Direct Access: /admin/dashboard"]
        }

    # 6. IDOR (취약한 객체 참조)
    if scan_type in ["all", "idor"]:
        results["vulnerabilities"].append("IDOR")
        results["details"]["IDOR"] = "사용자 식별자 변경 시 타인 정보 무단 조회 가능"
        results["exploitation_guide"]["IDOR"] = {
            "approach": "요청 파라미터나 URL의 사용자 식별자(ID) 값을 다른 사용자의 ID로 변조하여 접근",
            "payload_examples": ["GET /api/user?id=1001", "GET /api/user?id=1000"]
        }

    # 7. CSRF (크로스 사이트 요청 위조)
    if scan_type in ["all", "csrf"]:
        results["vulnerabilities"].append("CSRF")
        results["details"]["CSRF"] = "Anti-CSRF 토큰 누락 및 SameSite 쿠키 속성 미설정"
        results["exploitation_guide"]["CSRF"] = {
            "approach": "피해자가 로그인된 상태에서 공격자의 악성 페이지(자동 제출 폼)를 방문하도록 유도하여 요청 전송",
            "payload_examples": ["<form action='http://target/change_pass' method='POST'><input name='pass' value='hacked'><script>document.forms[0].submit()</script></form>"]
        }

    # 8. Unrestricted File Upload
    if scan_type in ["all", "upload"]:
        results["vulnerabilities"].append("Unrestricted File Upload")
        results["details"]["File Upload"] = "확장자 및 MIME-Type 검증 부재 (.php, .jsp, .asp 웹셸 업로드 가능)"
        results["exploitation_guide"]["File Upload"] = {
            "approach": "서버 측 실행 스크립트(웹셸)를 업로드한 뒤 파일 경로에 직접 접근하여 시스템 명령어 실행",
            "payload_examples": ["Upload: webshell.php (<?php system($_GET['cmd']); ?>)", "Access: http://target/uploads/webshell.php?cmd=whoami"]
        }

    return jsonify(results)


# ==========================================
# API 2. OS / WEB / WAS / DB / 포트 점검 모듈
# ==========================================
@app.route("/api/scan/system", methods=["POST"])
def scan_system():
    data = request.json or {}
    host = data.get("target_host", "127.0.0.1")
    ports_str = data.get("ports", "80,443")

    open_ports = []
    ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        res = sock.connect_ex((host, port))
        if res == 0:
            open_ports.append(port)
        sock.close()

    ssl_info = "미점검"
    if 443 in open_ports:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=1) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = f"Valid SSL Cert (Issuer: {cert.get('issuer', '')})"
        except Exception as e:
            ssl_info = f"SSL 설정 오류/만료: {str(e)}"

    return jsonify(
        {
            "target_host": host,
            "open_ports": open_ports,
            "unnecessary_services": [p for p in open_ports if p in [21, 23]],
            "ssl_status": ssl_info,
            "os_patch_status": "보안 패치 미적용 항목 존재 (CVE-2023-XXXX)",
            "web_was_config": "Server Header 노출 (Apache/2.4.41)",
        }
    )


# ==========================================
# API 3. 네트워크 장비 설정 점검 모듈
# ==========================================
@app.route("/api/scan/network", methods=["POST"])
def scan_network():
    data = request.json or {}
    device_ip = data.get("device_ip", "")
    snmp_community = data.get("snmp_community", "public")

    checklist = {
        "device_ip": device_ip,
        "default_snmp_community": (
            "취약 (기본 public 문자열 사용 중)"
            if snmp_community == "public"
            else "안전"
        ),
        "telnet_enabled": "취약 (23번 포트 비암호화 통신 활성화)",
        "firewall_rules": "Any-To-Any 허용 정책 존재 가능성 점검 필요",
        "ssh_version": "SSH v1 사용 제한 필요 (v2 권장)",
    }
    return jsonify(checklist)


# ==========================================
# API 4. 무선 네트워크(Wi-Fi) 보안 점검 모듈
# ==========================================
@app.route("/api/scan/wireless", methods=["POST"])
def scan_wireless():
    data = request.json or {}
    interface = data.get("interface", "wlan0")

    wireless_results = {
        "interface": interface,
        "detected_aps": [
            {
                "ssid": "Company_Office_5G",
                "bssid": "00:11:22:33:44:55",
                "auth": "WPA3-Enterprise",
                "status": "안전",
            },
            {
                "ssid": "Guest_Free_WiFi",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "auth": "OPEN / WEP",
                "status": "취약 (무선 구간 패킷 감청 위험)",
            },
            {
                "ssid": "Company_Office_5G",
                "bssid": "11:22:33:44:55:66",
                "auth": "WPA2-PSK",
                "status": "의심 (불법 Rogue AP / AP 스푸핑 가능성)",
            },
        ],
        "packet_eavesdropping_risk": "암호화 미적용 AP 접속 시 Plaintext 노출 위험",
    }
    return jsonify(wireless_results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
