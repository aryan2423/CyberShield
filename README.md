# CyberShield: Digital Forensics File Analyzer

## Overview

CyberShield is a web-based cybersecurity project developed during a two-week Cybersecurity Summer Program. It analyzes uploaded files using file signatures (magic numbers) to determine their actual file type and detect suspicious extension mismatches.

## Features

* File Type Detection using Magic Numbers
* Extension Verification
* MD5 & SHA-256 Hash Generation
* File Size Analysis
* Header Signature Display
* Risk Level Detection
* Scan History Tracking
* Cybersecurity-Themed Dashboard

## Technologies Used

* HTML
* CSS
* JavaScript
* Python
* Flask

## Project Workflow

```text
Upload File
    ↓
Read File Header
    ↓
Identify File Type
    ↓
Verify Extension
    ↓
Generate Hashes
    ↓
Assign Risk Level
    ↓
Display Results
```

## Installation

```bash
pip install flask
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Advantages

* Detects fake file extensions
* Provides basic forensic analysis
* Generates cryptographic hashes
* User-friendly web interface

## Future Scope

* VirusTotal API Integration
* Malware Detection
* Batch File Scanning
* Downloadable Reports

## Learning Outcomes

* Digital Forensics Fundamentals
* File Signature Analysis
* Cryptographic Hashing
* Flask Web Development
* Cybersecurity Best Practices

## Author

**Aryan Chauhan**
