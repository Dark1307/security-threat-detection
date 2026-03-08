# 🛡️ Security Threat Detection for SOC

A Python-based threat detection system designed for **Security Operations Centers (SOC)** to identify and analyze multiple types of security attacks in real-time from logs, APIs, or CSV datasets.

## 🎯 Features

✅ **Multi-Threat Detection:**
- SQL Injection
- Cross-Site Scripting (XSS)
- Denial of Service (DoS)
- Command Injection
- Directory Traversal

✅ **Pattern-Based Analysis** - Uses advanced regex matching for threat identification

✅ **Risk Scoring** - Automatically assigns risk levels:
- 🔴 **CRITICAL** (Score ≥ 16)
- 🟠 **HIGH** (Score 10-15)
- 🟡 **MEDIUM** (Score 5-9)
- 🟢 **LOW** (Score < 5)

✅ **Dataset Support** - Process CSV files from any log source

✅ **Synthetic Data Generation** - Create labeled training datasets

✅ **SOC Dashboard** - Real-time threat monitoring and alerting

✅ **JSON Reporting** - Export detailed threat analysis reports

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository:**

git clone https://github.com/Dark1307/security-threat-detection.git
cd security-threat-detection

2.Create a virtual environment
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate

3.Install dependencies:
pip install -r requirements.txt

📖 Usage
python threat_detector.py

Output:
======================================================================
SECURITY THREAT DETECTION - PATTERN BASED
======================================================================

📋 Payload: SELECT * FROM users WHERE id=1
🔍 Threats Detected: ['SQL_INJECTION']
⚠️  Risk Level: HIGH (Score: 10/100)

📋 Payload: <script>alert('XSS')</script>
🔍 Threats Detected: ['XSS']
⚠️  Risk Level: MEDIUM (Score: 8/100)

Option 2: Generate Synthetic Dataset
python dataset_generator.py
Creates security_dataset.csv with 600 labeled samples (100 each threat type + benign).

Option 3: View SOC Dashboard
python soc_dashboard.py

Output:
======================================================================
SOC THREAT DASHBOARD
======================================================================

Total Alerts: 4
Timestamp: 2026-03-08 14:35:22

THREAT BREAKDOWN:
  ⚠️  SQL_INJECTION: 1
  ⚠️  XSS: 1
  ⚠️  DIRECTORY_TRAVERSAL: 1
  ⚠️  COMMAND_INJECTION: 1

CRITICAL ALERTS:
  🔴 [CRITICAL] SELECT * FROM users WHERE id=1 OR '1'='1'
    Threats: ['SQL_INJECTION']

Copilot said: Perfect! Here's all the **information and files

Perfect! Here's all the information and files you need for GitHub:
📋 GitHub Repository Information
1. Create a Comprehensive README.md
README.mdv2

# 🛡️ Security Threat Detection for SOC

A Python-based threat detection system designed for **Security Operations Centers (SOC)** to identify and analyze multiple types of security attacks in real-time from logs, APIs, or CSV datasets.

## 🎯 Features

    Create a virtual environment (recommended):

bash

# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate

    Install dependencies:

bash

pip install -r requirements.txt

📖 Usage
Option 1: Test Basic Detection
bash

python threat_detector.py

Output:
Code

======================================================================
SECURITY THREAT DETECTION - PATTERN BASED
======================================================================

📋 Payload: SELECT * FROM users WHERE id=1
🔍 Threats Detected: ['SQL_INJECTION']
⚠️  Risk Level: HIGH (Score: 10/100)

📋 Payload: <script>alert('XSS')</script>
🔍 Threats Detected: ['XSS']
⚠️  Risk Level: MEDIUM (Score: 8/100)

Option 2: Generate Synthetic Dataset
bash

python dataset_generator.py

Creates security_dataset.csv with 600 labeled samples (100 each threat type + benign).
Option 3: View SOC Dashboard
bash

python soc_dashboard.py

Output:
Code

======================================================================
SOC THREAT DASHBOARD
======================================================================

Total Alerts: 4
Timestamp: 2026-03-08 14:35:22

THREAT BREAKDOWN:
  ⚠️  SQL_INJECTION: 1
  ⚠️  XSS: 1
  ⚠️  DIRECTORY_TRAVERSAL: 1
  ⚠️  COMMAND_INJECTION: 1

CRITICAL ALERTS:
  🔴 [CRITICAL] SELECT * FROM users WHERE id=1 OR '1'='1'
    Threats: ['SQL_INJECTION']

Option 4: Python Script Usage
from threat_detector import SecurityThreatDetector

# Initialize detector
detector = SecurityThreatDetector()

# Analyze a single payload
result = detector.analyze_request("SELECT * FROM users WHERE id=1 OR '1'='1'")
print(result)

# Process a CSV dataset
results, summary = detector.process_dataset('your_dataset.csv')

# Export detailed report
detector.export_report(results, summary, 'report.json')


📊 Dataset Format
For your own data, create a CSV file with this structure:

payload,attack_type,timestamp
"SELECT * FROM users WHERE id=1","SQL_INJECTION","2026-03-08T10:00:00"
"<script>alert('XSS')</script>","XSS","2026-03-08T10:05:00"
"normal user input","BENIGN","2026-03-08T10:10:00"

Required column: payload (the data to analyze)
Optional columns: attack_type, timestamp
