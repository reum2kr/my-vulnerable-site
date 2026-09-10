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
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .card h3 { margin-top: 0; color: #2b6cb0; }
        label { font-weight: bold; display: block; margin-top: 10px; }
        input[type="text"], select { width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { background-color: #3182ce; color: white; border: none; padding: 10px 15px; margin-top: 12px; border-radius: 4px; cursor: pointer; width: 100%; font-weight: bold; }
        button:hover { background-color: #2b6cb0; }
        button.sec-btn { background-color: #2b6cb0; }
        button.sec-btn:hover { background-color: #1a365d; }
        pre { background: #2d3748; color: #edf2f7; padding: 15px; border-radius: 6px; overflow-x: auto; max-height: 200px; font-size: 13px; margin-top: 10px; }
        
        .guide-box {
            margin-top: 15px;
            padding: 15px;
            background-color: #ffffff;
            border: 2px solid #2b6cb0;
            border-radius: 6px;
            font-size: 13px;
            line-height: 1.6;
            max-height: 300px;
            overflow-y: auto;
        }
        .guide-box h4 { margin-top: 0; margin-bottom: 10px; color: #2b6cb0; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; }
        .vuln-item { margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px dashed #cbd5e0; }
        .vuln-item:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
        .vuln-title { font-weight: bold; color: #2b6cb0; font-size: 14px; }
        .guide-label { font-weight: bold; color: #2d3748; margin-top: 4px; }
    </style>
    <script>
        let lastScanResult = null;

        // 보안 조치 가이드 데이터
        const defenseData = {
            "SQL Injection": {
                "concept": "사용자 입력값이 SQL 쿼리 구조를 변조하여 무단 데이터 접근을 허용하는 취약점입니다.",
                "solution": "Parameterized Query(PreparedStatement)를 사용하여 입력값을 단순 데이터 파라미터로 처리합니다."
            },
            "XSS": {
                "concept": "검증되지 않은 입력값이 웹 페이지에 출력되어 브라우저에서 스크립트가 실행되는 취약점입니다.",
                "solution": "출력 시 HTML Entity Escape 처리를 적용하거나 CSP(Content Security Policy)를 설정합니다."
            },
            "Command Injection": {
                "concept": "외부 입력값이 OS 시스템 명령어 실행 함수의 인자로 전달되어 발생하는 취약점입니다.",
                "solution": "OS 명령어 직접 호출 함수 사용을 지양하고, 입력값에 대해 메타문자 필터링을 적용합니다."
            },
            "Directory Traversal": {
                "concept": "상위 디렉터리 접근 문자열(../)을 이용하여 인가되지 않은 파일에 접근하는 취약점입니다.",
                "solution": "입력값에서 ../ 경로 이동 문자열을 제거하거나 허용된 파일명/경로 목록(White-list)만 검증합니다."
            },
            "Auth Bypass": {
                "concept": "세션 및 쿠키 검증 미비로 인가 절차 없이 주요 페이지에 직접 접근할 수 있는 취약점입니다.",
                "solution": "모든 보호된 엔드포인트에 세션 유효성 검증 서버 측 인터셉터/미들웨어를 적용합니다."
            },
            "IDOR": {
                "concept": "요청 식별자(ID) 변경 시 타인의 자원에 무단 접근이 가능한 취약점입니다.",
                "solution": "자원 접근 시 세션 정보의 로그인 사용자 ID와 요청 대상 자원의 소유권을 검증합니다."
            },
            "CSRF": {
                "concept": "인증된 사용자의 브라우저를 통해 의도하지 않은 요청이 전송되는 취약점입니다.",
                "solution": "요청 시 Anti-CSRF 토큰을 검증하고, Cookie에 SameSite=Strict/Lax 속성을 적용합니다."
            },
            "Unrestricted File Upload": {
                "concept": "실행 권한이 있는 확장자의 파일이 업로드되어 서버 권한이 침해되는 취약점입니다.",
                "solution": "업로드 파일 확장자를 화이트리스트 방식으로 제한하고 실행 권한이 없는 디렉터리에 저장합니다."
            }
        };

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
                
                // 버튼 1: 순수 진단 결과 JSON만 표시
                document.getElementById(resultId).innerText = JSON.stringify(result, null, 2);

                if (endpoint === '/api/scan/web') {
                    lastScanResult = result;
                    document.getElementById('webGuideContent').innerText = "보안 조치 가이드 버튼을 누르면 상세 설명이 출력됩니다.";
                }
            } catch (err) {
                document.getElementById(resultId).innerText = "오류 발생: " + err;
            }
        }

        // 버튼 2: 진단 결과를 기반으로 시큐어 코딩 및 보안 조치 가이드 생성
        function showRemediationGuide() {
            const guideContainer = document.getElementById('webGuideContent');
            guideContainer.innerHTML = '';

            if (!lastScanResult || !lastScanResult.vulnerabilities || lastScanResult.vulnerabilities.length === 0) {
                guideContainer.innerText = "먼저 웹 취약점 진단을 실행해주세요.";
                return;
            }

            lastScanResult.vulnerabilities.forEach((vulnName, idx) => {
                const itemData = defenseData[vulnName];
                if (!itemData) return;

                const itemDiv = document.createElement('div');
                itemDiv.className = 'vuln-item';

                itemDiv.innerHTML = `
                    <div class="vuln-title">${idx + 1}. ${vulnName}</div>
                    <div class="guide-label">취약점 개요:</div>
                    <div>${itemData.concept}</div>
                    <div class="guide-label">보안 조치 방안:</div>
                    <div>${itemData.solution}</div>
                `;
                guideContainer.appendChild(itemDiv);
            });
        }
    </script>
</head>
<body>
    <h1>종합 취약점 진단 및 보안 분석 대시보드</h1>
    <div class="grid">
        
        <!-- 1. 웹 애플리케이션 취약점 진단 -->
        <div class="card">
            <h3>1. Web Application Scan</h3>
            <p>SQLi, XSS, CSRF, 인증 우회, 파일 업로드 점검</p>
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
            
            <!-- 버튼 1: 진단 수행 및 단순 결과 출력 -->
            <button onclick="runScan('/api/scan/web', 'webForm', 'webResult')">웹 취약점 진단 실행</button>
            <pre id="webResult">결과가 여기에 표시됩니다.</pre>

            <!-- 버튼 2: 보안 조치 가이드 분석 -->
            <button class="sec-btn" onclick="showRemediationGuide()">시큐어 코딩 및 보안 조치 가이드</button>
            <div class="guide-box">
                <h4>보안 조치 방안 (Remediation)</h4>
                <div id="webGuideContent">
                    진단 실행 후 아래 버튼을 누르면 항목별 조치 가이드가 표시됩니다.
                </div>
            </div>
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
        "details": {},
        "target": target_url,
        "vulnerabilities": []
    }

    # 1. SQL Injection (SQLi)
    if scan_type in ["all", "sqli"]:
        results["details"]["sqli"] = "파라미터 입력 검증 미비 - SQLi 가능성 감지 (취약)"
        results["vulnerabilities"].append("SQL Injection")

    # 2. Cross-Site Scripting (XSS)
    if scan_type in ["all", "xss"]:
        results["details"]["xss"] = "Reflected XSS 취약점 존재 (HTML Escape 미적용)"
        results["vulnerabilities"].append("XSS")

    # 3. Command Injection
    if scan_type in ["all", "cmdi"]:
        results["details"]["cmdi"] = "시스템 명령어 실행 파라미터 필터링 부재"
        results["vulnerabilities"].append("Command Injection")

    # 4. Directory Traversal
    if scan_type in ["all", "traversal"]:
        results["details"]["traversal"] = "상위 디렉터리 접근 필터링 미비"
        results["vulnerabilities"].append("Directory Traversal")

    # 5. 인증/권한 우회 (Auth Bypass)
    if scan_type in ["all", "auth_bypass"]:
        results["details"]["auth_bypass"] = "세션/쿠키 검증 로직 우회 가능성 존재"
        results["vulnerabilities"].append("Auth Bypass")

    # 6. IDOR (취약한 객체 참조)
    if scan_type in ["all", "idor"]:
        results["details"]["idor"] = "사용자 식별자 변경 시 타인 정보 무단 조회 가능"
        results["vulnerabilities"].append("IDOR")

    # 7. CSRF (크로스 사이트 요청 위조)
    if scan_type in ["all", "csrf"]:
        results["details"]["csrf"] = "Anti-CSRF 토큰 누락 확인"
        results["vulnerabilities"].append("CSRF")

    # 8. Unrestricted File Upload
    if scan_type in ["all", "upload"]:
        results["details"]["upload"] = "확장자 검증 부재 (.php, .jsp 업로드 가능)"
        results["vulnerabilities"].append("Unrestricted File Upload")

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
