#!/usr/bin/env python3
"""
SilverStrike 간단 테스트
"""

import os
import sys

print("=== SilverStrike 환경 테스트 ===")
print(f"현재 디렉토리: {os.getcwd()}")
print(f"Python 경로: {sys.executable}")

# 파일 구조 확인
print("\n폴더 구조 확인:")
folders = ['modules', 'scenarios', 'config', 'output']
for folder in folders:
    if os.path.exists(folder):
        files = os.listdir(folder)
        print(f"✓ {folder}/: {files}")
    else:
        print(f"✗ {folder}/ 없음")

# 필수 파일 확인
print("\n필수 파일 확인:")
required_files = [
    'modules/scanner.py',
    'modules/smb_attack.py', 
    'scenarios/corporate.py',
    'silverstrike.py'
]

for file in required_files:
    if os.path.exists(file):
        print(f"✓ {file}")
    else:
        print(f"✗ {file} 없음")

# 패키지 임포트 테스트
print("\n패키지 임포트 테스트:")
try:
    import nmap
    print("✓ nmap 패키지 OK")
except ImportError as e:
    print(f"✗ nmap 패키지 실패: {e}")

# 모듈 임포트 테스트
print("\n모듈 임포트 테스트:")
sys.path.insert(0, os.getcwd())

try:
    from modules.scanner import NetworkScanner
    print("✓ NetworkScanner 임포트 OK")
except Exception as e:
    print(f"✗ NetworkScanner 임포트 실패: {e}")

try:
    from scenarios.corporate import CorporateScenario
    print("✓ CorporateScenario 임포트 OK")
except Exception as e:
    print(f"✗ CorporateScenario 임포트 실패: {e}")

print("\n=== 테스트 완료 ===")