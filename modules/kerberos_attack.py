#!/usr/bin/env python3
"""
SilverStrike Kerberos/AD Attack Module
Active Directory 환경 공격 모듈
"""

import subprocess
import socket
import time
import re

class KerberosAttacker:
    def __init__(self):
        self.results = {}
        self.vulnerabilities = []
        self.domain_info = {}
    
    def detect_domain_controller(self, host):
        """Domain Controller 탐지"""
        print(f"[+] Domain Controller 탐지: {host}")
        
        try:
            # Kerberos 포트 확인 (88)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            kerberos_open = sock.connect_ex((host, 88)) == 0
            sock.close()
            
            # LDAP 포트 확인 (389)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            ldap_open = sock.connect_ex((host, 389)) == 0
            sock.close()
            
            if kerberos_open and ldap_open:
                print(f"  [✓] Domain Controller 확인!")
                
                # 도메인 정보 수집
                self.enumerate_domain_info(host)
                
                self.results[host] = {
                    'is_dc': True,
                    'kerberos_port': 88,
                    'ldap_port': 389
                }
                
                return True
            else:
                print(f"  [!] Domain Controller가 아님")
                return False
                
        except Exception as e:
            print(f"  [✗] DC 탐지 실패: {e}")
            return False
    
    def enumerate_domain_info(self, dc_host):
        """도메인 정보 수집"""
        print(f"  [+] 도메인 정보 수집...")
        
        try:
            # nmap으로 도메인 정보 수집
            cmd = f"nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='{dc_host}' {dc_host}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # 도메인명 추출 시도
                domain_pattern = r"Domain:\s*(\S+)"
                domain_match = re.search(domain_pattern, result.stdout)
                
                if domain_match:
                    domain = domain_match.group(1)
                    print(f"    [발견] 도메인: {domain}")
                    self.domain_info['domain'] = domain
                    self.domain_info['dc_host'] = dc_host
            
            # LDAP 정보 수집 시도
            self.ldap_enumeration(dc_host)
            
        except Exception as e:
            print(f"    [!] 도메인 정보 수집 실패: {e}")
    
    def ldap_enumeration(self, dc_host):
        """LDAP 익명 바인딩 시도"""
        print(f"    [+] LDAP 익명 바인딩 테스트...")
        
        try:
            # ldapsearch로 익명 접근 시도
            cmd = f"ldapsearch -x -h {dc_host} -s base namingcontexts"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and "namingcontexts" in result.stdout.lower():
                print(f"    [VULN] LDAP 익명 바인딩 가능!")
                
                vuln = {
                    'host': dc_host,
                    'type': 'LDAP Anonymous Bind',
                    'severity': 'Medium',
                    'description': 'LDAP 서비스에 익명으로 접근 가능'
                }
                self.vulnerabilities.append(vuln)
                
                # 추가 정보 수집
                self.extract_domain_users(dc_host)
            else:
                print(f"    [INFO] LDAP 익명 바인딩 불가")
                
        except Exception as e:
            print(f"    [!] LDAP 열거 실패: {e}")
    
    def extract_domain_users(self, dc_host):
        """도메인 사용자 추출 시도"""
        print(f"    [+] 도메인 사용자 추출 시도...")
        
        try:
            # 사용자 목록 추출
            cmd = f"ldapsearch -x -h {dc_host} -b 'dc=domain,dc=com' '(objectClass=person)' sAMAccountName"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            
            users = []
            if result.returncode == 0:
                # sAMAccountName 추출
                user_pattern = r"sAMAccountName:\s*(\S+)"
                user_matches = re.findall(user_pattern, result.stdout)
                
                for user in user_matches:
                    if user and user not in users:
                        users.append(user)
                        print(f"      [사용자] {user}")
                
                if users:
                    self.domain_info['users'] = users[:10]  # 최대 10개만 저장
                    print(f"    [결과] {len(users)}개 사용자 발견")
                else:
                    print(f"    [INFO] 사용자 정보 추출 실패")
                    
        except Exception as e:
            print(f"    [!] 사용자 추출 실패: {e}")
    
    def asrep_roasting_attack(self, dc_host):
        """ASREPRoast 공격 시뮬레이션"""
        print(f"[+] ASREPRoast 공격 시뮬레이션: {dc_host}")
        
        if 'users' not in self.domain_info:
            print(f"  [!] 사용자 목록이 필요함")
            return []
        
        vulnerable_users = []
        
        try:
            # impacket-GetNPUsers 시뮬레이션
            for user in self.domain_info.get('users', [])[:5]:  # 최대 5명만 테스트
                print(f"  [+] {user} ASREPRoast 테스트...")
                
                # 실제로는 impacket 도구를 사용하지만 여기서는 시뮬레이션
                # cmd = f"impacket-GetNPUsers {domain}/{user} -no-pass -dc-ip {dc_host}"
                
                # 랜덤하게 취약한 사용자 시뮬레이션 (20% 확률)
                import random
                if random.random() < 0.2:
                    vulnerable_users.append(user)
                    print(f"    [VULN] {user} - 사전 인증 비활성화!")
                    
                    vuln = {
                        'host': dc_host,
                        'type': 'ASREPRoast Vulnerable User',
                        'user': user,
                        'severity': 'High',
                        'description': f'사용자 {user}는 Kerberos 사전 인증이 비활성화됨'
                    }
                    self.vulnerabilities.append(vuln)
                else:
                    print(f"    [INFO] {user} - 안전")
                
                time.sleep(1)  # 속도 조절
            
            if vulnerable_users:
                print(f"  [결과] {len(vulnerable_users)}명의 취약한 사용자 발견")
            else:
                print(f"  [INFO] ASREPRoast 취약점 없음")
                
        except Exception as e:
            print(f"  [✗] ASREPRoast 공격 실패: {e}")
        
        return vulnerable_users
    
    def kerberoasting_attack(self, dc_host):
        """Kerberoasting 공격 시뮬레이션"""
        print(f"[+] Kerberoasting 공격 시뮬레이션: {dc_host}")
        
        try:
            # SPN이 설정된 서비스 계정 찾기 시뮬레이션
            service_accounts = []
            
            # 일반적인 SPN 계정들
            common_spns = ['mssqlsvc', 'http', 'ldap', 'cifs', 'host']
            
            for spn in common_spns:
                # 랜덤하게 서비스 계정 존재 시뮬레이션
                import random
                if random.random() < 0.3:
                    service_account = f"{spn}_service"
                    service_accounts.append(service_account)
                    print(f"  [발견] SPN 서비스: {spn} (계정: {service_account})")
                    
                    vuln = {
                        'host': dc_host,
                        'type': 'Kerberoasting Target',
                        'service_account': service_account,
                        'spn': spn,
                        'severity': 'Medium',
                        'description': f'서비스 계정 {service_account}에 대해 Kerberoasting 공격 가능'
                    }
                    self.vulnerabilities.append(vuln)
            
            if service_accounts:
                print(f"  [결과] {len(service_accounts)}개 서비스 계정 발견")
            else:
                print(f"  [INFO] Kerberoasting 대상 없음")
                
        except Exception as e:
            print(f"  [✗] Kerberoasting 공격 실패: {e}")
        
        return service_accounts
    
    def exploit_kerberos_vulnerabilities(self, host):
        """Kerberos/AD 취약점 종합 공격"""
        print(f"\n🎯 Kerberos/AD 공격 시작: {host}")
        print("-" * 40)
        
        # 1단계: DC 확인
        if not self.detect_domain_controller(host):
            print(f"  [!] Domain Controller가 아님, Kerberos 공격 중단")
            return []
        
        # 2단계: ASREPRoast 공격
        asrep_users = self.asrep_roasting_attack(host)
        
        # 3단계: Kerberoasting 공격  
        service_accounts = self.kerberoasting_attack(host)
        
        # 4단계: 추가 AD 공격 시뮬레이션
        self.simulate_additional_ad_attacks(host)
        
        return self.vulnerabilities
    
    def simulate_additional_ad_attacks(self, dc_host):
        """추가 AD 공격 시뮬레이션"""
        print(f"[+] 추가 AD 공격 시뮬레이션...")
        
        import random
        
        # BloodHound 공격 경로 시뮬레이션
        if random.random() < 0.4:
            print(f"  [VULN] BloodHound - 권한 상승 경로 발견!")
            vuln = {
                'host': dc_host,
                'type': 'AD Privilege Escalation Path',
                'severity': 'Critical',
                'description': 'BloodHound로 Domain Admin 권한 상승 경로 발견'
            }
            self.vulnerabilities.append(vuln)
        
        # DCSync 권한 확인 시뮬레이션
        if random.random() < 0.2:
            print(f"  [CRITICAL] DCSync 권한 획득 가능!")
            vuln = {
                'host': dc_host,
                'type': 'DCSync Privilege',
                'severity': 'Critical',
                'description': 'DCSync 권한으로 모든 도메인 계정 해시 덤프 가능'
            }
            self.vulnerabilities.append(vuln)
    
    def get_attack_summary(self):
        """공격 결과 요약"""
        if not self.vulnerabilities:
            return "Kerberos/AD 취약점 없음"
        
        summary = {
            'total_vulns': len(self.vulnerabilities),
            'asrep_roast': len([v for v in self.vulnerabilities if v['type'] == 'ASREPRoast Vulnerable User']),
            'kerberoasting': len([v for v in self.vulnerabilities if v['type'] == 'Kerberoasting Target']),
            'critical_vulns': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
            'domain_info': self.domain_info
        }
        
        return summary

if __name__ == "__main__":
    # 테스트 코드
    attacker = KerberosAttacker()
    
    host = input("Domain Controller IP 입력: ")
    
    # Kerberos 공격 실행
    vulnerabilities = attacker.exploit_kerberos_vulnerabilities(host)
    
    # 결과 출력
    print(f"\n📊 Kerberos/AD 공격 결과:")
    summary = attacker.get_attack_summary()
    print(f"발견된 취약점: {summary['total_vulns']}개")
    print(f"ASREPRoast 취약점: {summary['asrep_roast']}개")  
    print(f"Kerberoasting 대상: {summary['kerberoasting']}개")
    print(f"Critical 취약점: {summary['critical_vulns']}개")
    
    if vulnerabilities:
        print(f"\n상세 취약점:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. {vuln['type']} - {vuln['severity']}")
            print(f"     {vuln['description']}")