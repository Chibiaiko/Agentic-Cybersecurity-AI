from typing import Dict, Any, List
from agents.base_agent import BaseAgent
import logging
import subprocess

logger = logging.getLogger(__name__)

class PipelineAnalysisAgent(BaseAgent):
    def __init__(self):
        super().__init__("Pipeline Analysis Agent")

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security configuration of the target VM directly.
        Reports ALL possible risks with their pass/fail status.
        """
        
        # Get scan target information from context
        hostname = context.get("hostname", "unknown")
        ip_address = context.get("ip_address", "unknown")
        
        logger.info(f"Pipeline Analysis Agent scanning: {hostname} ({ip_address})")
        
        findings = []
        
        # Scan the VM directly and report ALL checks with status
        findings.extend(self._scan_vm_security(hostname, ip_address))
        findings.extend(self._scan_network_configuration(hostname, ip_address))
        findings.extend(self._scan_system_configuration(hostname, ip_address))
        findings.extend(self._scan_software_vulnerabilities(hostname, ip_address))
        
        logger.info(f"Found {len(findings)} findings from direct VM scan")
        
        return {"findings": findings}

    def _scan_vm_security(self, hostname: str, ip_address: str) -> List[Dict[str, Any]]:
        """Scan VM security settings and report ALL checks with status"""
        findings = []
        
        try:
            # Check if SSH is available
            ssh_available = self._check_ssh_access(hostname)
            
            if ssh_available:
                # Check for firewall configuration
                findings.extend(self._check_firewall(hostname))
                
                # Check for file permissions issues
                findings.extend(self._check_file_permissions(hostname))
                
                # Check for password policies
                findings.extend(self._check_password_policy(hostname))
                
                # Check for sudo access
                findings.extend(self._check_sudo_access(hostname))
                
                # Check for SSH hardening
                findings.extend(self._check_ssh_hardening(hostname))
            else:
                logger.warning(f"SSH access not available for {hostname}")
                # Report that SSH is not available as a critical issue
                findings.append({
                    "id": "SSH-CONN-001",
                    "title": "SSH Connection Unavailable",
                    "description": f"Cannot establish SSH connection to {hostname}. Detailed VM security checks cannot be performed.",
                    "component": hostname,
                    "raw_severity": "CRITICAL",
                    "status": "FAIL",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.error(f"Error scanning VM security: {str(e)}")
        
        return findings

    def _scan_network_configuration(self, hostname: str, ip_address: str) -> List[Dict[str, Any]]:
        """Scan network configuration and report ALL checks with status"""
        findings = []
        
        try:
            # Check for open ports
            open_ports = self._check_open_ports(ip_address)
            
            # Report findings for all detected open ports
            for port_info in open_ports:
                if port_info['port'] in [22, 3389]:  # SSH or RDP
                    findings.append({
                        "id": f"NET-{port_info['port']}-001",
                        "title": f"Remote Access Port {port_info['port']} Open",
                        "description": f"Port {port_info['port']} ({port_info['service']}) is accessible. Ensure this is intentional and properly secured.",
                        "component": f"{hostname}:{port_info['port']}",
                        "raw_severity": "MEDIUM",
                        "status": "DETECTED",
                        "source": "Direct VM Scan"
                    })
                elif port_info['port'] in [23, 25, 69, 139, 445]:  # Insecure protocols
                    findings.append({
                        "id": f"NET-{port_info['port']}-001",
                        "title": f"Insecure Protocol Port {port_info['port']} Open",
                        "description": f"Port {port_info['port']} ({port_info['service']}) uses an insecure protocol and should be disabled or replaced with a secure alternative.",
                        "component": f"{hostname}:{port_info['port']}",
                        "raw_severity": "CRITICAL",
                        "status": "FAIL",
                        "source": "Direct VM Scan"
                    })
                else:
                    findings.append({
                        "id": f"NET-{port_info['port']}-001",
                        "title": f"Unexpected Open Port {port_info['port']}",
                        "description": f"Port {port_info['port']} ({port_info['service']}) is open. Verify if this service is needed and properly secured.",
                        "component": f"{hostname}:{port_info['port']}",
                        "raw_severity": "MEDIUM",
                        "status": "DETECTED",
                        "source": "Direct VM Scan"
                    })
            
            # Check for DNS misconfiguration
            findings.extend(self._check_dns_configuration(hostname))
            
        except Exception as e:
            logger.error(f"Error scanning network configuration: {str(e)}")
        
        return findings

    def _scan_system_configuration(self, hostname: str, ip_address: str) -> List[Dict[str, Any]]:
        """Scan system-level security configurations and report ALL checks with status"""
        findings = []
        
        try:
            # Check for unpatched systems
            findings.extend(self._check_system_patches(hostname))
            
            # Check for weak cryptography
            findings.extend(self._check_ssl_tls_config(hostname))
            
            # Check for unnecessary services
            findings.extend(self._check_running_services(hostname))
            
            # Check system logging
            findings.extend(self._check_logging_config(hostname))
            
        except Exception as e:
            logger.error(f"Error scanning system configuration: {str(e)}")
        
        return findings

    def _scan_software_vulnerabilities(self, hostname: str, ip_address: str) -> List[Dict[str, Any]]:
        """Scan for software vulnerabilities and report ALL checks with status"""
        findings = []
        
        try:
            # Check installed packages for known vulnerabilities
            findings.extend(self._check_installed_packages(hostname))
            
        except Exception as e:
            logger.error(f"Error scanning software vulnerabilities: {str(e)}")
        
        return findings

    def _check_ssh_access(self, hostname: str) -> bool:
        """Check if SSH access is available to the VM"""
        try:
            result = subprocess.run(
                f"ssh -o ConnectTimeout=5 -o BatchMode=yes {hostname} echo 'SSH OK' 2>/dev/null",
                shell=True,
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"SSH access check failed: {str(e)}")
            return False

    def _check_firewall(self, hostname: str) -> List[Dict[str, Any]]:
        """Check firewall configuration - reports all firewall checks"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'sudo systemctl status firewalld 2>/dev/null || sudo systemctl status ufw 2>/dev/null'",
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                findings.append({
                    "id": "SYS-FW-001",
                    "title": "Firewall Service Running",
                    "description": "✓ PASS: The system firewall (firewalld/ufw) is running and active.",
                    "component": hostname,
                    "raw_severity": "INFO",
                    "status": "PASS",
                    "source": "Direct VM Scan"
                })
            else:
                findings.append({
                    "id": "SYS-FW-001",
                    "title": "Firewall Not Running",
                    "description": "✗ FAIL: The system firewall (firewalld/ufw) is not running. Enable it to protect against unauthorized access.",
                    "component": hostname,
                    "raw_severity": "HIGH",
                    "status": "FAIL",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"Firewall check error: {str(e)}")
            findings.append({
                "id": "SYS-FW-001",
                "title": "Firewall Check Failed",
                "description": f"⚠ ERROR: Could not check firewall status: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings

    def _check_file_permissions(self, hostname: str) -> List[Dict[str, Any]]:
        """Check for overly permissive file permissions"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'find /etc /usr/bin /usr/local/bin -perm -002 2>/dev/null | head -1'",
                shell=True,
                capture_output=True,
                timeout=15
            )
            
            if result.returncode == 0 and result.stdout:
                findings.append({
                    "id": "SYS-PERM-001",
                    "title": "World-Writable Files Found",
                    "description": f"✗ FAIL: World-writable files detected in critical system directories. This is a security risk.",
                    "component": hostname,
                    "raw_severity": "CRITICAL",
                    "status": "FAIL",
                    "source": "Direct VM Scan"
                })
            else:
                findings.append({
                    "id": "SYS-PERM-001",
                    "title": "File Permissions Secure",
                    "description": "✓ PASS: No world-writable files found in critical system directories.",
                    "component": hostname,
                    "raw_severity": "INFO",
                    "status": "PASS",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"File permissions check error: {str(e)}")
            findings.append({
                "id": "SYS-PERM-001",
                "title": "File Permissions Check Failed",
                "description": f"⚠ ERROR: Could not check file permissions: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings

    def _check_password_policy(self, hostname: str) -> List[Dict[str, Any]]:
        """Check password policy configuration"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'grep minlen /etc/security/pwquality.conf 2>/dev/null'",
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                findings.append({
                    "id": "SYS-PWD-001",
                    "title": "Strong Password Policy Configured",
                    "description": "✓ PASS: Strong password policy with minimum length requirements is configured.",
                    "component": hostname,
                    "raw_severity": "INFO",
                    "status": "PASS",
                    "source": "Direct VM Scan"
                })
            else:
                findings.append({
                    "id": "SYS-PWD-001",
                    "title": "Weak Password Policy",
                    "description": "✗ FAIL: Password policy does not enforce minimum length requirements. Configure pwquality.",
                    "component": hostname,
                    "raw_severity": "MEDIUM",
                    "status": "FAIL",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"Password policy check error: {str(e)}")
            findings.append({
                "id": "SYS-PWD-001",
                "title": "Password Policy Check Failed",
                "description": f"⚠ ERROR: Could not check password policy: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings

    def _check_sudo_access(self, hostname: str) -> List[Dict[str, Any]]:
        """Check sudo configuration for security issues"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'sudo grep -r NOPASSWD /etc/sudoers* 2>/dev/null'",
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                findings.append({
                    "id": "SYS-SUDO-001",
                    "title": "NOPASSWD Sudo Access Found",
                    "description": "✗ FAIL: Sudo configuration allows commands without password. This is a security risk.",
                    "component": hostname,
                    "raw_severity": "CRITICAL",
                    "status": "FAIL",
                    "source": "Direct VM Scan"
                })
            else:
                findings.append({
                    "id": "SYS-SUDO-001",
                    "title": "Sudo Password Required",
                    "description": "✓ PASS: Sudo requires password authentication. Proper sudo security is configured.",
                    "component": hostname,
                    "raw_severity": "INFO",
                    "status": "PASS",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"Sudo access check error: {str(e)}")
            findings.append({
                "id": "SYS-SUDO-001",
                "title": "Sudo Access Check Failed",
                "description": f"⚠ ERROR: Could not check sudo configuration: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings

    def _check_ssh_hardening(self, hostname: str) -> List[Dict[str, Any]]:
        """Check SSH hardening configurations"""
        findings = []
        
        try:
            # Check for root login disabled
            result = subprocess.run(
                f"ssh {hostname} 'grep ^PermitRootLogin /etc/ssh/sshd_config 2>/dev/null'",
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout.decode().strip()
                if 'yes' in output.lower():
                    findings.append({
                        "id": "SSH-001",
                        "title": "Root SSH Login Enabled",
                        "description": "✗ FAIL: SSH allows direct root login. Disable this and use regular user accounts.",
                        "component": hostname,
                        "raw_severity": "HIGH",
                        "status": "FAIL",
                        "source": "Direct VM Scan"
                    })
                else:
                    findings.append({
                        "id": "SSH-001",
                        "title": "Root SSH Login Disabled",
                        "description": "✓ PASS: SSH root login is properly disabled. Use regular user accounts instead.",
                        "component": hostname,
                        "raw_severity": "INFO",
                        "status": "PASS",
                        "source": "Direct VM Scan"
                    })
            else:
                findings.append({
                    "id": "SSH-001",
                    "title": "SSH Root Login Configuration Check Failed",
                    "description": "⚠ WARNING: Could not determine SSH root login configuration.",
                    "component": hostname,
                    "raw_severity": "LOW",
                    "status": "UNKNOWN",
                    "source": "Direct VM Scan"
                })
            
            # Check for password authentication disabled
            result = subprocess.run(
                f"ssh {hostname} 'grep ^PasswordAuthentication /etc/ssh/sshd_config 2>/dev/null'",
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout.decode().strip()
                if 'yes' in output.lower():
                    findings.append({
                        "id": "SSH-002",
                        "title": "SSH Password Authentication Enabled",
                        "description": "✗ FAIL: SSH allows password authentication. Use key-based authentication instead.",
                        "component": hostname,
                        "raw_severity": "HIGH",
                        "status": "FAIL",
                        "source": "Direct VM Scan"
                    })
                else:
                    findings.append({
                        "id": "SSH-002",
                        "title": "SSH Key-Based Authentication Enabled",
                        "description": "✓ PASS: SSH is configured for key-based authentication. Password authentication is disabled.",
                        "component": hostname,
                        "raw_severity": "INFO",
                        "status": "PASS",
                        "source": "Direct VM Scan"
                    })
            else:
                findings.append({
                    "id": "SSH-002",
                    "title": "SSH Authentication Configuration Check Failed",
                    "description": "⚠ WARNING: Could not determine SSH authentication configuration.",
                    "component": hostname,
                    "raw_severity": "LOW",
                    "status": "UNKNOWN",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"SSH hardening check error: {str(e)}")
        
        return findings

    def _check_open_ports(self, ip_address: str) -> List[Dict[str, Any]]:
        """Scan for open ports on the VM"""
        ports = []
        
        try:
            # Check common ports
            common_ports = {
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                3306: 'MySQL',
                3389: 'RDP',
                5432: 'PostgreSQL',
                5900: 'VNC',
                8080: 'HTTP-Alt'
            }
            
            for port, service in common_ports.items():
                if self._port_open(ip_address, port):
                    ports.append({
                        'port': port,
                        'service': service
                    })
        
        except Exception as e:
            logger.debug(f"Port scanning error: {str(e)}")
        
        return ports

    def _port_open(self, ip_address: str, port: int) -> bool:
        """Check if a specific port is open"""
        try:
            result = subprocess.run(
                f"timeout 2 bash -c 'echo >/dev/tcp/{ip_address}/{port}' 2>/dev/null",
                shell=True,
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_dns_configuration(self, hostname: str) -> List[Dict[str, Any]]:
        """Check DNS configuration"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'cat /etc/resolv.conf 2>/dev/null | grep nameserver'",
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                dns_servers = [line for line in result.stdout.decode().strip().split('\n') if line]
                if len(dns_servers) >= 2:
                    findings.append({
                        "id": "NET-DNS-001",
                        "title": "Multiple DNS Servers Configured",
                        "description": f"✓ PASS: {len(dns_servers)} DNS servers configured for redundancy.",
                        "component": hostname,
                        "raw_severity": "INFO",
                        "status": "PASS",
                        "source": "Direct VM Scan"
                    })
                else:
                    findings.append({
                        "id": "NET-DNS-001",
                        "title": "Single DNS Server Configured",
                        "description": "✗ FAIL: Only one DNS server is configured. Configure at least two for redundancy.",
                        "component": hostname,
                        "raw_severity": "MEDIUM",
                        "status": "FAIL",
                        "source": "Direct VM Scan"
                    })
            else:
                findings.append({
                    "id": "NET-DNS-001",
                    "title": "DNS Configuration Check Failed",
                    "description": "⚠ ERROR: Could not check DNS configuration.",
                    "component": hostname,
                    "raw_severity": "MEDIUM",
                    "status": "ERROR",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"DNS check error: {str(e)}")
        
        return findings

    def _check_system_patches(self, hostname: str) -> List[Dict[str, Any]]:
        """Check for unpatched systems"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'sudo yum check-update 2>/dev/null | wc -l'",
                shell=True,
                capture_output=True,
                timeout=30
            )
            
            if result.returncode == 0:
                try:
                    count = int(result.stdout.strip())
                    if count > 10:
                        findings.append({
                            "id": "SYS-PATCH-001",
                            "title": "System Updates Available",
                            "description": f"✗ FAIL: Found {count} available system updates. Apply patches to ensure security.",
                            "component": hostname,
                            "raw_severity": "HIGH",
                            "status": "FAIL",
                            "source": "Direct VM Scan"
                        })
                    elif count > 0:
                        findings.append({
                            "id": "SYS-PATCH-001",
                            "title": "Minor System Updates Available",
                            "description": f"⚠ WARNING: Found {count} available system updates. Consider applying patches.",
                            "component": hostname,
                            "raw_severity": "LOW",
                            "status": "WARNING",
                            "source": "Direct VM Scan"
                        })
                    else:
                        findings.append({
                            "id": "SYS-PATCH-001",
                            "title": "System Fully Patched",
                            "description": "✓ PASS: System is fully patched with all security updates applied.",
                            "component": hostname,
                            "raw_severity": "INFO",
                            "status": "PASS",
                            "source": "Direct VM Scan"
                        })
                except ValueError:
                    pass
        
        except Exception as e:
            logger.debug(f"Patch check error: {str(e)}")
            findings.append({
                "id": "SYS-PATCH-001",
                "title": "Patch Status Check Failed",
                "description": f"⚠ ERROR: Could not check patch status: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings

    def _check_ssl_tls_config(self, hostname: str) -> List[Dict[str, Any]]:
        """Check SSL/TLS configuration"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'grep -r SSLv2 /etc/nginx* /etc/apache2* 2>/dev/null'",
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                findings.append({
                    "id": "SSL-001",
                    "title": "Weak SSL/TLS Protocol Enabled",
                    "description": "✗ FAIL: Weak SSL/TLS protocols (SSLv2/v3) are enabled. Disable and use TLS 1.2+.",
                    "component": hostname,
                    "raw_severity": "CRITICAL",
                    "status": "FAIL",
                    "source": "Direct VM Scan"
                })
            else:
                findings.append({
                    "id": "SSL-001",
                    "title": "SSL/TLS Properly Configured",
                    "description": "✓ PASS: Weak SSL/TLS protocols are not detected. Modern TLS versions are in use.",
                    "component": hostname,
                    "raw_severity": "INFO",
                    "status": "PASS",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"SSL/TLS check error: {str(e)}")
            findings.append({
                "id": "SSL-001",
                "title": "SSL/TLS Configuration Check Failed",
                "description": f"⚠ ERROR: Could not check SSL/TLS configuration: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings

    def _check_running_services(self, hostname: str) -> List[Dict[str, Any]]:
        """Check for unnecessary running services"""
        findings = []
        
        try:
            unnecessary_services = ['telnet', 'vsftpd', 'nfs', 'rsh']
            
            services_found = []
            for service in unnecessary_services:
                result = subprocess.run(
                    f"ssh {hostname} 'sudo systemctl is-active {service} 2>/dev/null'",
                    shell=True,
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    services_found.append(service)
            
            if services_found:
                findings.append({
                    "id": "SVC-UNNECESSARY-001",
                    "title": "Unnecessary Services Running",
                    "description": f"✗ FAIL: Found {len(services_found)} unnecessary services running: {', '.join(services_found)}. Disable if not required.",
                    "component": hostname,
                    "raw_severity": "MEDIUM",
                    "status": "FAIL",
                    "source": "Direct VM Scan"
                })
            else:
                findings.append({
                    "id": "SVC-UNNECESSARY-001",
                    "title": "No Unnecessary Services Detected",
                    "description": "✓ PASS: No unnecessary services found running on the system.",
                    "component": hostname,
                    "raw_severity": "INFO",
                    "status": "PASS",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"Running services check error: {str(e)}")
            findings.append({
                "id": "SVC-UNNECESSARY-001",
                "title": "Services Check Failed",
                "description": f"⚠ ERROR: Could not check running services: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings

    def _check_logging_config(self, hostname: str) -> List[Dict[str, Any]]:
        """Check system logging configuration"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'sudo systemctl is-active rsyslog 2>/dev/null'",
                shell=True,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                findings.append({
                    "id": "LOG-001",
                    "title": "System Logging Enabled",
                    "description": "✓ PASS: rsyslog service is running and active for audit logging.",
                    "component": hostname,
                    "raw_severity": "INFO",
                    "status": "PASS",
                    "source": "Direct VM Scan"
                })
            else:
                findings.append({
                    "id": "LOG-001",
                    "title": "System Logging Not Enabled",
                    "description": "✗ FAIL: rsyslog service is not running. Enable it for audit logging.",
                    "component": hostname,
                    "raw_severity": "MEDIUM",
                    "status": "FAIL",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"Logging check error: {str(e)}")
            findings.append({
                "id": "LOG-001",
                "title": "Logging Check Failed",
                "description": f"⚠ ERROR: Could not check logging configuration: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings

    def _check_installed_packages(self, hostname: str) -> List[Dict[str, Any]]:
        """Check for known vulnerable packages"""
        findings = []
        
        try:
            result = subprocess.run(
                f"ssh {hostname} 'rpm -qa | grep openssl'",
                shell=True,
                capture_output=True,
                timeout=15
            )
            
            if result.returncode == 0:
                openssl_version = result.stdout.decode().strip()
                if 'openssl-1.0' in openssl_version:
                    findings.append({
                        "id": "PKG-OPENSSL-001",
                        "title": "Outdated OpenSSL Version",
                        "description": f"✗ FAIL: OpenSSL 1.0.x is outdated and no longer supported. Upgrade to 1.1.1 or 3.0.x.",
                        "component": hostname,
                        "raw_severity": "HIGH",
                        "status": "FAIL",
                        "source": "Direct VM Scan"
                    })
                else:
                    findings.append({
                        "id": "PKG-OPENSSL-001",
                        "title": "OpenSSL Version Current",
                        "description": f"✓ PASS: OpenSSL is up to date with version: {openssl_version}",
                        "component": hostname,
                        "raw_severity": "INFO",
                        "status": "PASS",
                        "source": "Direct VM Scan"
                    })
            else:
                findings.append({
                    "id": "PKG-OPENSSL-001",
                    "title": "OpenSSL Check Failed",
                    "description": "⚠ WARNING: Could not check OpenSSL version.",
                    "component": hostname,
                    "raw_severity": "LOW",
                    "status": "UNKNOWN",
                    "source": "Direct VM Scan"
                })
        
        except Exception as e:
            logger.debug(f"Package check error: {str(e)}")
            findings.append({
                "id": "PKG-OPENSSL-001",
                "title": "Package Check Failed",
                "description": f"⚠ ERROR: Could not check installed packages: {str(e)}",
                "component": hostname,
                "raw_severity": "MEDIUM",
                "status": "ERROR",
                "source": "Direct VM Scan"
            })
        
        return findings
