#!/usr/bin/env python3
"""
SilverStrike Corporate Network Scenario
기업 네트워크 침투 시나리오
"""

import sys
import os
import json
from datetime import datetime

# 상위 디렉토리의 modules 임포트
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.scanner import NetworkScanner
from modules.smb_attack import SMBAttacker
from modules.kerberos_attack import KerberosAttacker

class CorporateScenario:
    def __init__(self, target):
        self.target = target
        self.scanner = NetworkScanner()
        self.smb_attacker = SMBAttacker()
        self.kerberos_attacker = KerberosAttacker()
        
        self.results = {
            'target': target,
            'start_time': datetime.now().isoformat(),
            'hosts_discovered': [],
            'vulnerabilities': [],
            'compromised_hosts': [],
            'attack_summary': {}
        }
        
        print("""
╔═══════════════════════════════════════════════════════════╗
║                  SilverStrike v1.0                       ║
║              기업 네트워크 침투 시나리오                    ║
║                 by qu1cks1lv37                           ║
╠═══════════════════════════════════════════════════════════╣
║  Phase 1: Network Discovery                               ║
║  Phase 2: Service Enumeration                             ║  
║  Phase 3: Vulnerability Exploitation                      ║
║  Phase 4: Post-Exploitation                               ║
║  Phase 5: Reporting                                       ║
╚═══════════════════════════════════════════════════════════╝
        """)
        print(f"🎯 Target: {target}")
        print("="*60)
    
    def phase1_network_discovery(self):
        """Phase 1: 네트워크 탐지"""
        print(f"\n🔍 PHASE 1: NETWORK DISCOVERY")
        print("-" * 40)
        
        # 호스트 발견
        hosts = self.scanner.discover_hosts(self.target)
        self.results['hosts_discovered'] = hosts
        
        if not hosts:
            print("[!] 활성화된 호스트를 찾을 수 없습니다.")
            return False
        
        print(f"\n✅ Phase 1 완료: {len(hosts)}개 호스트 발견")
        return True
    
    def phase2_service_enumeration(self):
        """Phase 2: 서비스 열거"""
        print(f"\n🔎 PHASE 2: SERVICE ENUMERATION")
        print("-" * 40)
        
        smb_hosts = []
        kerberos_hosts = []
        
        for host in self.results['hosts_discovered']:
            print(f"\n[대상] {host}")
            
            # 포트 스캔
            services = self.scanner.port_scan(host)
            
            # 서비스별 분류
            for service in services:
                if service['port'] == 445:  # SMB
                    smb_hosts.append(host)
                    print(f"  ✓ SMB 서비스 감지")
                
                if service['port'] == 88:   # Kerberos
                    kerberos_hosts.append(host)
                    print(f"  ✓ Kerberos 서비스 감지 (Domain Controller 가능성)")
        
        self.results['smb_hosts'] = smb_hosts
        self.results['kerberos_hosts'] = kerberos_hosts
        
        print(f"\n✅ Phase 2 완료:")
        print(f"   SMB 호스트: {len(smb_hosts)}개")
        print(f"   Domain Controller: {len(kerberos_hosts)}개")
        return True
    
    def phase3_vulnerability_exploitation(self):
        """Phase 3: 취약점 공격"""
        print(f"\n💥 PHASE 3: VULNERABILITY EXPLOITATION")
        print("-" * 40)
        
        total_vulnerabilities = []
        compromised_hosts = []
        
        # SMB 공격
        if 'smb_hosts' in self.results and self.results['smb_hosts']:
            print(f"\n🎯 SMB 공격 단계")
            print("-" * 25)
            
            for host in self.results['smb_hosts']:
                smb_vulns = self.smb_attacker.exploit_smb_vulnerabilities(host)
                total_vulnerabilities.extend(smb_vulns)
                
                # 취약점 발견시 침투 성공으로 간주
                if smb_vulns:
                    compromised_hosts.append(host)
        
        # Kerberos/AD 공격
        if 'kerberos_hosts' in self.results and self.results['kerberos_hosts']:
            print(f"\n🎯 Active Directory 공격 단계")
            print("-" * 35)
            
            for host in self.results['kerberos_hosts']:
                kerberos_vulns = self.kerberos_attacker.exploit_kerberos_vulnerabilities(host)
                total_vulnerabilities.extend(kerberos_vulns)
                
                # Domain Controller 침투 성공시
                if kerberos_vulns:
                    compromised_hosts.append(host)
        
        self.results['vulnerabilities'] = total_vulnerabilities
        self.results['compromised_hosts'] = list(set(compromised_hosts))
        
        print(f"\n✅ Phase 3 완료:")
        print(f"   발견된 취약점: {len(total_vulnerabilities)}개")
        print(f"   침투 성공 호스트: {len(compromised_hosts)}개")
        return True
    
    def phase4_post_exploitation(self):
        """Phase 4: 사후 공격 (시뮬레이션)"""
        print(f"\n🔥 PHASE 4: POST-EXPLOITATION")
        print("-" * 40)
        
        if not self.results['compromised_hosts']:
            print("[!] 침투 성공한 호스트가 없어 Post-Exploitation 단계 스킵")
            return True
        
        post_exploit_activities = []
        
        for host in self.results['compromised_hosts']:
            print(f"\n[침투 호스트] {host}")
            
            # 권한 상승 시뮬레이션
            print("  [+] 권한 상승 시도...")
            if self.simulate_privilege_escalation(host):
                post_exploit_activities.append({
                    'host': host,
                    'activity': 'Privilege Escalation',
                    'status': 'Success'
                })
                print("    ✓ 관리자 권한 획득!")
            
            # 횡적 이동 시뮬레이션
            print("  [+] 횡적 이동 시도...")
            lateral_targets = self.simulate_lateral_movement(host)
            if lateral_targets:
                post_exploit_activities.append({
                    'host': host,
                    'activity': 'Lateral Movement',
                    'targets': lateral_targets,
                    'status': 'Success'
                })
                print(f"    ✓ {len(lateral_targets)}개 추가 호스트 침투!")
            
            # 지속성 확보 시뮬레이션
            print("  [+] 지속성 확보...")
            if self.simulate_persistence(host):
                post_exploit_activities.append({
                    'host': host,
                    'activity': 'Persistence',
                    'status': 'Success'
                })
                print("    ✓ 백도어 설치 완료!")
        
        self.results['post_exploitation'] = post_exploit_activities
        
        print(f"\n✅ Phase 4 완료:")
        print(f"   Post-Exploitation 활동: {len(post_exploit_activities)}개")
        return True
    
    def simulate_privilege_escalation(self, host):
        """권한 상승 시뮬레이션"""
        import random
        # 70% 확률로 권한 상승 성공
        return random.random() < 0.7
    
    def simulate_lateral_movement(self, host):
        """횡적 이동 시뮬레이션"""
        import random
        
        # 원래 호스트 리스트에서 랜덤하게 추가 침투
        available_hosts = [h for h in self.results['hosts_discovered'] if h != host]
        lateral_targets = []
        
        for target in available_hosts:
            if random.random() < 0.3:  # 30% 확률
                lateral_targets.append(target)
                if len(lateral_targets) >= 2:  # 최대 2개까지
                    break
        
        return lateral_targets
    
    def simulate_persistence(self, host):
        """지속성 확보 시뮬레이션"""
        import random
        # 80% 확률로 지속성 확보 성공
        return random.random() < 0.8
    
    def phase5_reporting(self):
        """Phase 5: 보고서 생성"""
        print(f"\n📊 PHASE 5: GENERATING REPORT")
        print("-" * 40)
        
        # 공격 요약 생성
        summary = self.generate_attack_summary()
        self.results['attack_summary'] = summary
        self.results['end_time'] = datetime.now().isoformat()
        
        # JSON 보고서 저장
        self.save_json_report()
        
        # 콘솔 요약 출력
        self.print_final_summary()
        
        return True
    
    def generate_attack_summary(self):
        """공격 결과 요약 생성"""
        vulns_by_severity = {
            'Critical': len([v for v in self.results['vulnerabilities'] if v['severity'] == 'Critical']),
            'High': len([v for v in self.results['vulnerabilities'] if v['severity'] == 'High']),
            'Medium': len([v for v in self.results['vulnerabilities'] if v['severity'] == 'Medium']),
            'Low': len([v for v in self.results['vulnerabilities'] if v['severity'] == 'Low'])
        }
        
        attack_vectors = {}
        for vuln in self.results['vulnerabilities']:
            attack_type = vuln['type']
            if attack_type not in attack_vectors:
                attack_vectors[attack_type] = 0
            attack_vectors[attack_type] += 1
        
        summary = {
            'total_hosts_scanned': len(self.results['hosts_discovered']),
            'total_vulnerabilities': len(self.results['vulnerabilities']),
            'vulnerabilities_by_severity': vulns_by_severity,
            'attack_vectors': attack_vectors,
            'compromised_hosts_count': len(self.results['compromised_hosts']),
            'post_exploitation_activities': len(self.results.get('post_exploitation', []))
        }
        
        return summary
    
    def save_json_report(self):
        """JSON 보고서 저장"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_clean = self.target.replace('/', '_').replace(':', '_')
        filename = f"output/reports/silverstrike_corporate_{target_clean}_{timestamp}.json"
        
        # 디렉토리 생성
        os.makedirs("output/reports", exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"📄 JSON 보고서 저장: {filename}")
        return filename
    
    def print_final_summary(self):
        """최종 요약 출력"""
        summary = self.results['attack_summary']
        
        print(f"\n" + "="*60)
        print("🎯 SILVERSTRIKE 침투 테스트 완료")
        print("="*60)
        print(f"대상 네트워크: {self.target}")
        print(f"스캔된 호스트: {summary['total_hosts_scanned']}개")
        print(f"침투 성공 호스트: {summary['compromised_hosts_count']}개")
        print(f"발견된 취약점: {summary['total_vulnerabilities']}개")
        
        print(f"\n📈 취약점 심각도별 분포:")
        for severity, count in summary['vulnerabilities_by_severity'].items():
            if count > 0:
                print(f"  {severity}: {count}개")
        
        print(f"\n🎯 주요 공격 벡터:")
        for attack_type, count in summary['attack_vectors'].items():
            print(f"  {attack_type}: {count}개")
        
        if self.results.get('post_exploitation'):
            print(f"\n🔥 Post-Exploitation 활동: {summary['post_exploitation_activities']}개")
        
        # 권장사항 출력
        self.print_recommendations()
    
    def print_recommendations(self):
        """보안 권장사항 출력"""
        print(f"\n🛡️  보안 권장사항:")
        
        vulns = self.results['vulnerabilities']
        
        # SMB 관련 권고
        smb_vulns = [v for v in vulns if 'SMB' in v['type']]
        if smb_vulns:
            print("  • SMB 익명 접근 차단 및 공유 폴더 권한 재검토")
            print("  • SMB v1 프로토콜 비활성화")
        
        # AD 관련 권고
        ad_vulns = [v for v in vulns if any(x in v['type'] for x in ['Kerberos', 'LDAP', 'ASREPRoast', 'DCSync'])]
        if ad_vulns:
            print("  • Kerberos 사전 인증 활성화")
            print("  • 서비스 계정 비밀번호 복잡도 강화")
            print("  • LDAP 익명 바인딩 비활성화")
        
        # 일반적인 권고사항
        critical_vulns = [v for v in vulns if v['severity'] == 'Critical']
        if critical_vulns:
            print("  • Critical 취약점 즉시 패치 적용")
            print("  • 네트워크 세그멘테이션 강화")
            print("  • 접근 권한 최소화 원칙 적용")
    
    def run(self):
        """전체 시나리오 실행"""
        try:
            # Phase 1: Network Discovery
            if not self.phase1_network_discovery():
                return False
            
            # Phase 2: Service Enumeration  
            if not self.phase2_service_enumeration():
                return False
            
            # Phase 3: Vulnerability Exploitation
            if not self.phase3_vulnerability_exploitation():
                return False
            
            # Phase 4: Post-Exploitation
            if not self.phase4_post_exploitation():
                return False
            
            # Phase 5: Reporting
            if not self.phase5_reporting():
                return False
            
            print(f"\n🎉 SilverStrike 기업 네트워크 침투 테스트 완료!")
            return True
            
        except KeyboardInterrupt:
            print(f"\n[!] 사용자에 의해 중단되었습니다.")
            return False
        except Exception as e:
            print(f"\n[ERROR] 예상치 못한 오류: {str(e)}")
            return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("사용법: python3 corporate.py <target>")
        print("예시: python3 corporate.py 192.168.1.0/24")
        sys.exit(1)
    
    target = sys.argv[1]
    scenario = CorporateScenario(target)
    scenario.run()