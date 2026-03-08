from threat_detector import SecurityThreatDetector
import pandas as pd
from datetime import datetime

class SOCDashboard:
    """Real-time SOC monitoring dashboard"""
    
    def __init__(self):
        self.detector = SecurityThreatDetector()
        self.alerts = []
    
    def monitor_traffic(self, payloads):
        """Monitor incoming traffic"""
        for payload in payloads:
            result = self.detector.analyze_request(payload)
            if result['is_malicious']:
                self.alerts.append(result)
    
    def display_dashboard(self):
        """Display SOC dashboard"""
        if not self.alerts:
            print("✓ No threats detected")
            return
        
        print("\n" + "=" * 70)
        print("SOC THREAT DASHBOARD")
        print("=" * 70)
        
        threat_counts = {}
        for alert in self.alerts:
            for threat in alert['threats_detected']:
                threat_counts[threat] = threat_counts.get(threat, 0) + 1
        
        print(f"\nTotal Alerts: {len(self.alerts)}")
        print(f"Timestamp: {datetime.now()}\n")
        
        print("THREAT BREAKDOWN:")
        for threat, count in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  ⚠️  {threat}: {count}")
        
        print("\nCRITICAL ALERTS:")
        critical = [a for a in self.alerts if a['risk_level'] == 'CRITICAL']
        if critical:
            for alert in critical[:5]:
                print(f"  🔴 [{alert['risk_level']}] {alert['payload']}")
                print(f"    Threats: {', '.join(alert['threats_detected'])}\n")
        else:
            print("  No critical alerts")


if __name__ == "__main__":
    dashboard = SOCDashboard()
    
    sample_traffic = [
        "SELECT * FROM users WHERE id=1 OR '1'='1'",
        "<script>alert('XSS')</script>",
        "../../../etc/passwd",
        "normal search query",
        "cat /etc/shadow; ls -la",
    ]
    
    dashboard.monitor_traffic(sample_traffic)
    dashboard.display_dashboard()