import re
import json
from datetime import datetime

try:
    import pandas as pd
    import numpy as np
except ImportError:
    print("Warning: pandas/numpy not installed, some features may not work")

class SecurityThreatDetector:
    """
    Multi-threat detection system for SOC operations
    Detects: SQL Injection, XSS, DoS, Command Injection, Directory Traversal
    """
    
    def __init__(self):
        self.attack_patterns = {
            "SQL_INJECTION": [
                r"(?:')|(?:--)|(/\*)|(\*/)|(?:\b(select|update|delete|insert|drop|union|where|exec|execute)\b)",
                r"(\bOR\b|\bAND\b).+=.+",
                r"(UNION.*SELECT)",
                r"(SELECT.*FROM)",
                r"(DROP\s+TABLE)",
                r"(INSERT\s+INTO)",
                r"(UPDATE.*SET)",
                r"(DELETE\s+FROM)"
            ],
            "XSS": [
                r"(<script[^>]*>.*?</script>)",
                r"(javascript:|onerror=|onload=|onclick=|onmouseover=)",
                r"(<img[^>]*src=)",
                r"(<iframe[^>]*>)",
                r"(eval\()",
                r"(<svg[^>]*onload=)",
                r"(expression\()"
            ],
            "DOS": [
                r"(\bflooding?\b|\bslowloris\b|\bpingofdealth\b|\bddos\b)",
                r"(nmap|hping3|LOIC|HOIC)",
                r"(\x00{100,})",
                r"(GET.*HTTP.*x{1000,})"
            ],
            "COMMAND_INJECTION": [
                r"(\b(cat|ls|rm|echo|wget|curl|bash|sh|cmd|powershell)\b)",
                r"(;|\||&&|\`|$\()",
                r"(\bexec\b|\bsystem\b|\beval\b)",
                r"(>|<|&|\n|\r)",
            ],
            "DIRECTORY_TRAVERSAL": [
                r"(\.\./|\.\.\\)",
                r"(%2e%2e|%252e%252e)",
                r"(etc/passwd|etc/shadow|boot.ini|win.ini|windows/system32)",
                r"(root:|Administrator)",
                r"(\.\.%2f|\.\.%5c)"
            ]
        }
        
        self.ml_model = None
        self.vectorizer = None
        self.threat_counts = {}
    
    def pattern_based_detection(self, text):
        """Rule-based detection using regex patterns"""
        if not isinstance(text, str):
            text = str(text)
        
        detected_threats = []
        threat_details = {}
        
        for threat_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        detected_threats.append(threat_type)
                        if threat_type not in threat_details:
                            threat_details[threat_type] = pattern
                        break
                except re.error:
                    continue
        
        return list(set(detected_threats)), threat_details
    
    def calculate_risk_score(self, text, threats):
        """Calculate risk score based on threat count and severity"""
        threat_severity = {
            "SQL_INJECTION": 10,
            "COMMAND_INJECTION": 10,
            "XSS": 8,
            "DIRECTORY_TRAVERSAL": 8,
            "DOS": 6
        }
        
        score = sum(threat_severity.get(t, 5) for t in threats)
        risk_level = "CRITICAL" if score >= 16 else "HIGH" if score >= 10 else "MEDIUM" if score >= 5 else "LOW"
        
        return min(score, 100), risk_level
    
    def analyze_request(self, request_data):
        """Analyze HTTP request or payload"""
        threats, details = self.pattern_based_detection(request_data)
        risk_score, risk_level = self.calculate_risk_score(request_data, threats)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "payload": request_data[:100],
            "threats_detected": threats,
            "threat_details": details,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "is_malicious": len(threats) > 0
        }
    
    def process_dataset(self, dataset_path, output_path="detection_results.json"):
        """Process CSV dataset for threat detection"""
        try:
            df = pd.read_csv(dataset_path)
        except NameError:
            print("Error: pandas not installed. Run: pip install pandas")
            return None, None
        
        results = []
        
        for idx, row in df.iterrows():
            payload = row.get('payload', row.get('request', str(row.iloc[0])))
            analysis = self.analyze_request(payload)
            results.append(analysis)
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        threat_summary = self._generate_summary(results)
        return results, threat_summary
    
    def _generate_summary(self, results):
        """Generate summary statistics"""
        summary = {
            "total_analyzed": len(results),
            "malicious_detected": sum(1 for r in results if r['is_malicious']),
            "clean_traffic": sum(1 for r in results if not r['is_malicious']),
            "threat_breakdown": {},
            "risk_distribution": {}
        }
        
        threat_counts = {}
        risk_counts = {}
        
        for result in results:
            for threat in result['threats_detected']:
                threat_counts[threat] = threat_counts.get(threat, 0) + 1
            
            risk_level = result['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        summary["threat_breakdown"] = threat_counts
        summary["risk_distribution"] = risk_counts
        
        return summary
    
    def export_report(self, results, summary, filename="security_report.json"):
        """Export detailed security report"""
        if results is None:
            print("Error: No results to export")
            return None
            
        detection_rate = (summary['malicious_detected'] / len(results) * 100) if len(results) > 0 else 0
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "alerts": [r for r in results if r['is_malicious']],
            "detection_statistics": {
                "total_records": len(results),
                "detection_rate": f"{detection_rate:.2f}%"
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ Report exported to {filename}")
        return report


if __name__ == "__main__":
    
    detector = SecurityThreatDetector()
    
    test_payloads = [
        "SELECT * FROM users WHERE id=1",
        "<script>alert('XSS')</script>",
        "../../../etc/passwd",
        "cat /etc/shadow; ls -la",
        "GET /api HTTP/1.1\r\n\r\n" + "A" * 1000,
        "normal user input with no threats"
    ]
    
    print("=" * 70)
    print("SECURITY THREAT DETECTION - PATTERN BASED")
    print("=" * 70)
    
    for payload in test_payloads:
        result = detector.analyze_request(payload)
        print(f"\n📋 Payload: {result['payload']}")
        print(f"🔍 Threats Detected: {result['threats_detected'] if result['threats_detected'] else 'NONE'}")
        print(f"⚠️  Risk Level: {result['risk_level']} (Score: {result['risk_score']}/100)")
    
    print("\n" + "=" * 70)