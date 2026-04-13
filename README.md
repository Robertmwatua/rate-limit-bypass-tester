# Rate Limiting Bypass Tester

A professional security tool to test rate limiting implementations for vulnerabilities.

## What This Tool Does

Rate limiting prevents brute force attacks and API abuse. This tool tests if those protections can be bypassed using common techniques.

## Techniques Tested

1. **IP Rotation** - Uses X-Forwarded-For headers
2. **Random Delays** - Bypasses fixed-window rate limiters
3. **User-Agent Rotation** - Rotates browser fingerprints
4. **Session Rotation** - Changes session IDs per request
5. **Concurrent Requests** - Overwhelms rate limiter with parallel requests
6. **Full Header Combo** - All evasion techniques simultaneously
7. **Adaptive Threshold Probe** - Binary search to discover exact rate-limit threshold
8. **Tor Circuit Routing** - New exit IP every N requests
9. **Request Fragmentation** - Vary payload to confuse body-aware limiters

## New Features (v4.1+)

### Baseline Measurement
Automatically measure normal endpoint behavior before running evasion techniques:
- Establishes success/failure baseline
- Detects 429 rate-limit blocks
- Estimates request-per-second limits
- **Disabled by default in config mode, enabled in interactive mode**

### Rate-Limit Header Detection
Automatically extracts and displays rate-limit information from response headers:
- `X-RateLimit-Limit` / `X-RateLimit-Remaining`
- `X-RateLimit-Reset` / `Retry-After`
- Custom vendor headers (CloudFlare, AWS, etc)
- Integrated into HTML and JSON reports

### HTML Report Generation
Beautiful interactive HTML reports with:
- Risk level dashboard with metrics
- Per-technique results with visual progress bars
- Baseline measurement comparison
- Remediation recommendations
- Searchable findings

### JSON Configuration Files
Run non-interactive scans with config files:
```bash
# Generate template
python bypass_tester.py --template

# Run with config
python bypass_tester.py --config config.json
```

### Request Logging
Optional JSONL request log for compliance and audit trails:
- Timestamp, method, HTTP status
- Response headers (including rate-limit info)
- Error messages
- Saved as `requests_<timestamp>.jsonl`

## Installation

```bash
# Clone repository
git clone https://github.com/Robertmwatua/rate-limit-bypass-tester.git
cd rate-limit-bypass-tester

# Install dependencies
pip install -r requirements.txt

# Run tool
python bypass_tester.py
```

## Usage

### Interactive Mode (Default)

```bash
python bypass_tester.py
```

Follow the prompts:
1. Enter target URL
2. Configure timeout and requests per technique
3. Enable Tor/proxy if needed
4. Choose techniques to test
5. Review results and save reports

### Config File Mode (Non-Interactive)

```bash
# Generate config template
python bypass_tester.py --template
# Outputs: config_template.json

# Edit the config file with your target details
# Run without interaction
python bypass_tester.py --config your_config.json
```

### Config File Example

```json
{
  "url": "https://api.example.com/endpoint",
  "timeout": 5,
  "requests_per_technique": 20,
  "use_tor": false,
  "proxy": "",
  "techniques": ["1", "2", "3", "4", "5", "6", "7"],
  "run_baseline": true,
  "save_requests_log": true
}
```

## Report Formats

### Interactive Results Display
- Live progress bars with spinner
- Real-time status code distribution
- Risk level assessment
- Remediation recommendations

### JSON Report
- Full metadata and scan details
- Per-technique statistics
- Rate-limit headers detected
- Baseline measurements
- Risk assessment

### HTML Report
- Professional dashboard layout
- Dark theme (GitHub-style)
- Visual progress indicators
- Interactive tables
- Mobile-responsive design
- **Saved as `results/scan_<timestamp>.html`**

### Request Log (Optional)
- JSONL format (one JSON object per line)
- Complete request/response details
- Useful for forensics and compliance
- **Saved as `results/requests_<timestamp>.jsonl`**

## Remediation Guidance

The tool provides 10+ remediation recommendations:
- Rate-limit by user ID instead of IP
- Use sliding-window / token-bucket algorithms
- Distribute counters via Redis for consistency
- Deploy adaptive WAF rules
- Implement CAPTCHA after violations
- Monitor for 429 spike patterns
- TLS/JA3 fingerprinting
- Device fingerprinting
- API key quotas
- And more...

## Security & Compliance

### Legal Notice
 **Unauthorized access is illegal.** This tool is for:
- Authorized security testing only
- Systems you own or have written permission to test
- Educational purposes in controlled environments

### Compliance Features
- Baseline measurements for before/after comparison
- Complete request logging for audit trails
- Timestamp all activities
- HTML reports for stakeholder review
- JSON export for SIEM integration

## Advanced Options

### Tor Support
```bash
# Enable Tor anonymity layer
# Requires: sudo systemctl start tor
# Route all requests through Tor SOCKS5
# Rotate exit IP periodically
```

### Proxy Support
```bash
# Route through local proxy (Burp, mitmproxy, etc)
# Useful for request inspection and debugging
# Compatible with Tor
```

### Request Logging
```bash
# Enable to capture all requests for compliance
# Includes request metadata and response headers
# JSONL format for easy parsing
```

## Understanding Results

### Vulnerability Assessment
- **SECURE** - Technique failed (<65% success rate)
- **VULNERABLE** - Technique succeeded (>65% success rate)

### Risk Levels
- **LOW** - 0% techniques vulnerable
- **MEDIUM** - 25-40% techniques vulnerable
- **HIGH** - 40-70% techniques vulnerable
- **CRITICAL** - 70%+ techniques vulnerable

### Baseline Metrics
- Requests Sent: Total baseline requests
- Successful: 2xx/3xx responses
- Blocked: 429 rate-limit responses
- Errors: 5xx server errors
- Success Rate: Percentage of successful requests
- Estimated Limit: Requests per second threshold

## Dependencies

**Required:**
- `requests` - HTTP client
- `rich` - Terminal UI/tables

**Optional:**
- `PySocks` - SOCKS proxy support
- `stem` - Tor circuit control
- `fake-useragent` - Realistic User-Agent generation

All are auto-installed on first run.

## Output Structure

```
results/
├── scan_20240415_143022.json      # Full scan data
├── scan_20240415_143022.html      # Interactive report
└── requests_20240415_143022.jsonl # Request log (if enabled)

config_template.json                 # Config file template
```

## Troubleshooting

### Tor Connection Issues
```bash
# Start Tor service
sudo systemctl start tor

# Verify connectivity
curl --socks5 127.0.0.1:9050 https://api.ipify.org
```

### Network Errors
- Increase timeout value (default 5s)
- Check target connectivity
- Verify proxy configuration
- Check firewall rules

### Rate-Limit Headers Not Detected
- Some servers don't send rate-limit headers
- Headers may be sent only on 429 responses
- Tool automatically detects common header names

## Contributing

Contributions welcome! Areas for enhancement:
- Additional bypass techniques
- Support for HTTP/2 and HTTP/3
- GraphQL-specific testing
- DNS rebinding detection
- Geographic IP spoofing

## License

Licensed under MIT. See LICENSE file for details.

**Remember:** Only test systems you own or have explicit written permission to test. Unauthorized access is illegal under laws like CFAA and Computer Misuse Act.