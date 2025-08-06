#!/usr/bin/env python3
"""
SilverStrike Scanner Module (nmap 없이 작동)
네트워크 스캔 및 서비스 탐지
"""

import socket
import threading
import ipaddress
import time
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.results = {}
    
    def discover_hosts(self, target):
        """네트워크에서 활성화된 호스트 찾기 (nmap 없이)"""
        print(f"[+] 호스트 탐지: {target}")
        
        alive_hosts = []
        try:
            # 단일 IP인지 네트워크인지 확인
            if '/' in target:
                # CIDR 네트워크
                network = ipaddress.ip_network(target, strict=False)
                test_ips = list(network.hosts())[:20]  # 처음 20개만 테스트
            else:
                # 단일 IP
                test_ips = [ipaddress.ip_address(target)]
            
            print(f"[정보] {len(test_ips)}개 IP 테스트 중...")
            
            for ip in test_ips:
                ip_str = str(ip)
                print(f"  [테스트] {ip_str}", end=" ")
                
                # 호스트 활성화 확인
                if self.test_host_alive(ip_str):
                    alive_hosts.append(ip_str)
                    print("- 활성화 ✓")
                else:
                    print("- 비활성화")
                
            print(f"[결과] {len(alive_hosts)}개 호스트 발견")
            return alive_hosts
            
        except Exception as e:
            print(f"[✗] 호스트 탐지 실패: {e}")
            return []
    
    def test_host_alive(self, host):
        """호스트가 살아있는지 간단 체크"""
        # 일반적으로 열려있을 가능성이 높은 포트들로 테스트
        test_ports = [80, 443, 22, 23, 21, 25, 53]
        
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # 2초 타임아웃
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:  # 연결 성공
                    return True
                    
            except:
                continue
        
        return False
    
    def port_scan(self, host):
        """포트 스캔 및 서비스 탐지 (nmap 없이)"""
        print(f"[+] 포트 스캔: {host}")
        
        # 주요 포트만 빠르게 스캔
        important_ports = [21, 22, 23, 25, 53, 80, 88, 135, 139, 389, 443, 445, 993, 995, 3389]
        
        services = []
        open_ports_list = []
        
        def scan_single_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    service_name = self.get_service_name(port)
                    service_data = {
                        'port': port,
                        'service': service_name,
                        'version': 'Unknown',
                        'product': 'Unknown'
                    }
                    services.append(service_data)
                    open_ports_list.append(port)
                    print(f"  [OPEN] {port}/tcp - {service_name}")
                    
                    # 배너 그래빙 시도
                    banner = self.get_service_banner(host, port)
                    if banner:
                        service_data['banner'] = banner[:50]  # 처음 50자만
                
                sock.close()
            except:
                pass
        
        # 멀티쓰레드로 포트 스캔
        threads = []
        for port in important_ports:
            thread = threading.Thread(target=scan_single_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        # 모든 쓰레드 완료 대기
        for thread in threads:
            thread.join()
        
        if not services:
            print(f"  [정보] 열린 포트 없음")
        
        self.results[host] = services
        return services
    
    def get_service_name(self, port):
        """포트 번호로 서비스 이름 매핑"""
        services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            88: 'kerberos',
            135: 'msrpc',
            139: 'netbios-ssn',
            389: 'ldap',
            443: 'https',
            445: 'microsoft-ds',
            993: 'imaps',
            995: 'pop3s',
            3389: 'ms-wbt-server'
        }
        return services.get(port, 'unknown')
    
    def quick_port_check(self, host, port, timeout=3):
        """특정 포트 빠른 확인"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_service_banner(self, host, port):
        """서비스 배너 가져오기"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # HTTP 포트라면 GET 요청 보내기
            if port in [80, 443, 8080, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
            else:
                # 기본적으로 연결 후 대기
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner and len(banner) > 10:
                print(f"    [BANNER] {banner[:100]}")
                return banner
                
        except Exception:
            pass
        
        return None

if __name__ == "__main__":
    # 테스트 코드
    scanner = NetworkScanner()
    
    target = input("스캔할 네트워크 입력 (예: scanme.nmap.org/32): ")
    
    # 1단계: 호스트 발견
    hosts = scanner.discover_hosts(target)
    
    # 2단계: 각 호스트의 포트 스캔
    for host in hosts:
        services = scanner.port_scan(host)
        
        # SMB 서비스 확인
        if scanner.quick_port_check(host, 445):
            print(f"  [INFO] {host} - SMB 서비스 감지!")
        
        # Kerberos 서비스 확인  
        if scanner.quick_port_check(host, 88):
            print(f"  [INFO] {host} - Kerberos 서비스 감지! (Domain Controller 가능성)")
        
        print("-" * 40)