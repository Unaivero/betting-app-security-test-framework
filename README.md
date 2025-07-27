# 🎯 Betting App Security Test Framework

A comprehensive mobile test automation framework using **Python + Pytest + Appium** designed to validate security limits and regulatory business rules in betting applications. This framework simulates user actions that intentionally **violate system-imposed limits** to test fraud prevention and compliance mechanisms.

## 🚀 Features

### Security Testing Capabilities
- **Betting Limit Violations**: Test single bet, daily, and monthly limits
- **Profile Security**: Verify identity verification requirements for critical updates
- **Advanced Fraud Detection**: ML-based anomaly detection and behavioral pattern analysis
- **Cross-User Correlation**: Detect fraud networks and coordinated attacks
- **Mobile Security**: SSL pinning bypass, root detection, binary analysis, device policies
- **Injection Attack Prevention**: Test SQL injection, XSS, and other attack vectors
- **Authentication Security**: Validate token management and session security
- **Rate Limiting**: Test rapid API calls and UI interactions

### Architecture
- **Page Object Model**: Maintainable test structure with clear separation
- **Mock Backend**: Flask server simulating betting app with security endpoints
- **Comprehensive Reporting**: HTML reports with detailed test results
- **Fake Data Generation**: Realistic test data using Faker library
- **Concurrent Testing**: Multi-threaded tests for race condition detection

## 📁 Project Structure

```
betting-app-security-test-framework/
├── conftest.py                 # Pytest configuration and fixtures
├── pytest.ini                 # Pytest settings and markers
├── requirements.txt            # Python dependencies
├── requirements-dev.txt        # Enhanced ML and mobile security dependencies
├── run_tests.sh               # Test runner script with multiple options
│
├── fraud_detection/           # Advanced ML fraud detection
│   └── ml_anomaly_detector.py # ML-based behavioral analysis
│
├── mobile_security/           # Advanced mobile security testing
│   └── advanced_mobile_security.py # SSL pinning, root detection, binary analysis
│
├── mock_server/               # Flask mock backend
│   └── app.py                # Backend with security validations
│
├── pages/                     # Page Object Model classes
│   ├── base_page.py          # Common page functionality
│   ├── login_page.py         # Login screen interactions
│   ├── home_page.py          # Home/match list screen
│   ├── bet_page.py           # Bet placement screen
│   └── profile_page.py       # User profile screen
│
├── tests/                     # Test suites
│   ├── test_bet_limits_security.py    # Betting limit violation tests
│   ├── test_profile_security.py      # Profile update security tests
│   ├── test_mobile_ui_security.py    # Mobile UI security validations
│   ├── test_fraud_detection.py       # Fraud pattern detection tests
│   ├── test_ml_fraud_detection.py    # ML-based fraud analysis tests
│   └── test_advanced_mobile_security.py # Advanced mobile security tests
│
├── test_data/                 # Test data and configurations
│   ├── test_users.json       # User accounts for testing
│   ├── betting_limits.json   # Betting limits and violation scenarios
│   ├── malicious_payloads.json # Injection attack payloads
│   └── test_matches.json     # Match data and scenarios
│
├── performance/               # Load testing
│   └── locustfile.py         # Enhanced performance testing with security focus
│
├── reports/                   # Generated test reports
└── logs/                     # Test execution logs
```

## 🛠️ Setup and Installation

### Prerequisites
- Python 3.8 or higher
- Node.js (for Appium)
- Android SDK (for mobile testing)
- Java 8+ (for Appium)

### Installation Steps

1. **Clone or download the project**:
   ```bash
   cd /Users/josevergara/Documents/betting-app-security-test-framework
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Appium (optional for mobile testing)**:
   ```bash
   npm install -g appium
   npm install -g appium-doctor
   appium-doctor --android  # Verify Android setup
   ```

4. **Setup Android environment (for mobile tests)**:
   - Install Android Studio
   - Setup Android SDK
   - Create/start Android emulator
   - Enable USB debugging

## 🎮 Running Tests

### Quick Start
```bash
# Run all tests with automatic setup
./run_tests.sh -i all

# Run only security tests
./run_tests.sh security

# Run with clean reports
./run_tests.sh -c fraud
```

## 🤖 Advanced Security Features

### Machine Learning Fraud Detection

The framework now includes sophisticated ML-based fraud detection capabilities:

#### Behavioral Anomaly Detection
```python
from fraud_detection.ml_anomaly_detector import BehavioralAnomalyDetector

# Initialize and train the detector
detector = BehavioralAnomalyDetector()
detector.fit(training_data)

# Analyze user behavior
result = detector.predict_anomaly(user_data)
print(f"Risk Level: {result['risk_level']}")
print(f"Anomaly Score: {result['anomaly_score']}")
print(f"Key Indicators: {list(result['feature_importance'].keys())}")
```

#### Cross-User Correlation Analysis
```python
from fraud_detection.ml_anomaly_detector import CrossUserCorrelationAnalyzer

# Detect fraud networks
analyzer = CrossUserCorrelationAnalyzer()
analyzer.add_user_profile('user1', user1_data)
analyzer.add_user_profile('user2', user2_data)

results = analyzer.analyze_cross_user_correlations()
print(f"Detected Networks: {len(results['detected_networks'])}")
print(f"High-Risk Correlations: {results['high_risk_correlations']}")
```

#### ML Features Analyzed
- **Betting Patterns**: Amount variance, frequency, timing
- **Temporal Behavior**: Session patterns, rapid activity detection
- **Profile Changes**: Critical field updates, change frequency
- **Network Indicators**: Device sharing, IP correlation, payment overlap
- **Account Characteristics**: Age, verification status, failed attempts

### Advanced Mobile Security Testing

Comprehensive mobile application security testing including:

#### SSL Pinning Bypass Testing
```python
from mobile_security.advanced_mobile_security import SSLPinningTester

# Test SSL pinning security
tester = SSLPinningTester("com.betting.app", "api.betting-app.com")
results = tester.test_ssl_pinning_bypass()

# Check bypass techniques
for test_name, result in results['tests'].items():
    print(f"{test_name}: {result['status']} (Risk: {result['risk_level']})")
```

#### Root Detection Bypass Testing
```python
from mobile_security.advanced_mobile_security import RootDetectionTester

# Test root detection mechanisms
root_tester = RootDetectionTester("com.betting.app")
results = root_tester.test_root_detection_bypass()

# Analyze device security
device_status = results['device_rooted']
print(f"Device Rooted: {device_status['is_rooted']}")
print(f"Confidence: {device_status['confidence']:.2f}")
```

#### Binary Security Analysis
```python
from mobile_security.advanced_mobile_security import BinarySecurityAnalyzer

# Analyze APK security
analyzer = BinarySecurityAnalyzer("/path/to/app.apk")
results = analyzer.analyze_binary_security()

# Review security findings
for analysis_type, result in results['analyses'].items():
    print(f"{analysis_type}: {result['risk_level']} risk")
```

#### Mobile Security Tests Include
- **SSL Certificate Pinning**: Bypass detection and prevention
- **Root Detection**: Multiple hiding and bypass techniques
- **Binary Analysis**: Code obfuscation, anti-tampering, crypto usage
- **Device Policies**: Screen lock, encryption, installation policies
- **Certificate Validation**: Debug certs, weak algorithms, substitution
- **Network Security Config**: Android NSC analysis and weaknesses

### Test Categories

#### 1. Security Tests
```bash
./run_tests.sh security
```
Tests betting limits, authentication, and basic security validations.

#### 2. Mobile UI Tests
```bash
./run_tests.sh mobile
```
Tests security through mobile interface interactions.

#### 3. API Tests
```bash
./run_tests.sh api
```
Direct API endpoint security testing.

#### 4. Fraud Detection Tests
```bash
./run_tests.sh fraud
```
Advanced fraud pattern detection and prevention.

### Manual Test Execution
```bash
# Install dependencies
pip install -r requirements.txt

# Start mock server
cd mock_server && python app.py &

# Run specific test files
pytest tests/test_bet_limits_security.py -v
pytest tests/test_profile_security.py -v
pytest tests/test_fraud_detection.py -v
pytest tests/test_mobile_ui_security.py -v

# Run with markers
pytest -m security -v
pytest -m fraud_detection -v
```

## 🔍 Security Test Scenarios

### 1. Betting Limit Violations

#### Single Bet Limit Testing
```python
# Test amounts above maximum single bet limit
excessive_amounts = [1500, 2000, 5000, 10000]
# Expected: All should be rejected with appropriate error messages
```

#### Daily Limit Accumulation
```python
# Multiple bets totaling above daily limit
bets = [1000, 1000, 1000, 1000, 1500]  # Total: 5500 (above 5000 limit)
# Expected: System blocks when limit is reached
```

#### Monthly Limit Testing
```python
# Simulate month-long betting to exceed monthly limits
monthly_total = 55000  # Above 50000 limit
# Expected: Monthly limit enforcement triggers
```

### 2. Profile Security Violations

#### Unverified User Restrictions
```python
# Attempt to update critical fields without verification
critical_fields = ["email", "phone", "bank_account", "payment_method"]
# Expected: Verification required error for unverified users
```

#### Rapid Profile Changes
```python
# Multiple profile updates in short succession
updates = [
    {"first_name": "Name1"},
    {"last_name": "Name2"},
    {"address": "Address3"}
]
# Expected: Fraud detection triggers after rapid changes
```

### 3. Fraud Detection Scenarios

#### Suspicious Betting Patterns
```python
# Rapid high-value bets
pattern = [
    {"amount": 800, "delay": 0.1},
    {"amount": 900, "delay": 0.1},
    {"amount": 850, "delay": 0.1}
]
# Expected: High risk level and monitoring recommendation
```

#### Limit Bypass Attempts
```python
# Multiple smaller bets to circumvent daily limits
bypass_bets = [1000, 1500, 2000, 1500]  # Total exceeds limit
# Expected: Detection of cumulative limit violation
```

### 4. Injection Attack Prevention

#### SQL Injection Testing
```python
malicious_inputs = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "admin'--"
]
# Expected: All inputs properly sanitized or rejected
```

#### XSS Prevention
```python
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')"
]
# Expected: Scripts don't execute, content is sanitized
```

## 🎯 Mock Backend Endpoints

The Flask mock server provides realistic responses for security testing:

### Authentication
- `POST /login` - User authentication with brute force protection
- `GET /health` - Server health check

### Betting Operations
- `POST /bet` - Place bets with limit validations
- `GET /user_limits` - Current betting limits and usage
- `GET /bet_history` - User's betting history

### Profile Management
- `PUT /update_profile` - Update profile with verification checks
- `POST /fraud_check` - Fraud detection analysis

### Admin (Testing)
- `POST /admin/reset_limits` - Reset user limits for testing

## 📊 Test Reports

### HTML Reports
Generated in `reports/` directory:
- `security_report.html` - Security test results
- `mobile_report.html` - Mobile UI test results
- `fraud_report.html` - Fraud detection test results
- `full_report.html` - Complete test suite results

### Report Features
- ✅ Pass/fail status for each test
- 📊 Execution time and performance metrics
- 🔍 Detailed error messages and stack traces
- 📈 Test coverage and statistics
- 🎯 Security vulnerability summaries

## 🏢 Business Rules & Compliance

### Betting Limits (Configurable)
- **Single Bet**: $1,000 maximum
- **Daily Limit**: $5,000 maximum
- **Monthly Limit**: $50,000 maximum
- **Minimum Bet**: $1.00

### Identity Verification Requirements
- Email changes require verification
- Phone number updates require verification
- Payment method changes require verification
- Bank account updates require verification

### Fraud Detection Indicators
- Rapid betting frequency
- High-value betting patterns
- Limit bypass attempts
- Unusual account activity
- Multiple concurrent sessions

### Rate Limiting
- Login attempts: Max 5 per minute
- Bet placement: Max 10 per minute
- Profile updates: 24-hour cooldown period
- API calls: Rate limiting per endpoint

## 🔧 Configuration

### Environment Variables
```bash
export MOCK_SERVER_URL="http://localhost:5000"
export APPIUM_SERVER_URL="http://localhost:4723"
export TEST_TIMEOUT=30
export REPORT_FORMAT="html"
```

### Pytest Markers
- `@pytest.mark.security` - Security-focused tests
- `@pytest.mark.bet_limits` - Betting limit tests
- `@pytest.mark.profile_update` - Profile security tests
- `@pytest.mark.fraud_detection` - Fraud detection tests
- `@pytest.mark.integration` - Integration tests

## 🚨 Fraud Simulation Examples

### Example 1: Excessive Betting Violation
```python
def test_excessive_betting_fraud():
    # Simulate user placing bets above limits
    user_login("testuser", "password123")
    
    # Attempt bet above single limit
    result = place_bet(amount=1500)  # Above $1000 limit
    assert "Limit exceeded" in result.error_message
    assert result.violation_type == "single_bet_limit"
```

### Example 2: Identity Verification Bypass
```python
def test_profile_security_bypass():
    # Unverified user tries to change email
    user_login("unverified_user", "password123")
    
    result = update_profile({"email": "new@email.com"})
    assert "Identity verification required" in result.error_message
    assert result.verification_required == True
```

### Example 3: Rapid Activity Detection
```python
def test_rapid_activity_fraud():
    # Simulate rapid betting pattern
    for i in range(10):
        place_bet(amount=100, delay=0.1)
    
    fraud_check = get_fraud_assessment()
    assert fraud_check.risk_level in ["medium", "high"]
    assert "rapid_betting" in fraud_check.indicators
```

## 🧪 Test Data Management

### Fake Data Generation
Uses Faker library to generate realistic test data:
```python
fake_user = {
    "username": fake.user_name(),
    "email": fake.email(),
    "first_name": fake.first_name(),
    "phone": fake.phone_number(),
    "bank_account": fake.iban()
}
```

### Configurable Test Scenarios
JSON configuration files allow easy modification of:
- User accounts and permissions
- Betting limits and thresholds
- Malicious payload collections
- Match data and odds
- Fraud detection patterns

## 📋 Compliance & Regulatory Testing

### Responsible Gambling
- Daily loss limits enforcement
- Session time limit monitoring
- Self-exclusion options testing
- Cooling-off period validation

### Anti-Money Laundering (AML)
- Large transaction detection
- Suspicious pattern identification
- Identity verification thresholds
- Record keeping requirements

### Age Verification
- Minimum age enforcement (18+)
- Identity document validation
- Restricted region blocking
- Parental control features

## 🛡️ Security Best Practices Tested

### Input Validation
- ✅ SQL injection prevention
- ✅ XSS attack mitigation
- ✅ Command injection blocking
- ✅ Path traversal protection
- ✅ LDAP injection prevention

### Authentication Security
- ✅ Token validation and expiration
- ✅ Session management
- ✅ Brute force protection
- ✅ Account lockout mechanisms
- ✅ Password policy enforcement

### Data Protection
- ✅ Sensitive data exposure prevention
- ✅ Data integrity validation
- ✅ Encryption requirements
- ✅ Access control verification
- ✅ Audit trail generation

## 🤝 Contributing

### Adding New Tests
1. Create test file in `tests/` directory
2. Use appropriate pytest markers
3. Follow Page Object Model pattern
4. Include comprehensive assertions
5. Add test data to `test_data/` if needed

### Extending Mock Server
1. Add new endpoints in `mock_server/app.py`
2. Implement security validations
3. Include proper error handling
4. Add logging for security events
5. Update API documentation

## 📞 Support & Documentation

### Getting Help
- Check the generated HTML reports for detailed test results
- Review log files in `logs/` directory for debugging
- Examine mock server responses for API behavior
- Use `./run_tests.sh -h` for command help

### Common Issues
1. **Appium not found**: Install Appium or run with mock driver
2. **Port conflicts**: Change ports in configuration
3. **Permission errors**: Check file permissions and user access
4. **Database errors**: Restart mock server to reset state

## 🎉 Success Metrics

After running the complete test suite, you should see:

✅ **Security Validations**: All betting limits properly enforced  
✅ **ML Fraud Detection**: Behavioral anomalies and fraud networks identified  
✅ **Cross-User Correlation**: Coordinated attacks and shared indicators detected  
✅ **Mobile Security**: SSL pinning, root detection, and binary analysis complete  
✅ **Identity Verification**: Critical updates require proper verification  
✅ **Injection Prevention**: All malicious inputs properly handled  
✅ **Rate Limiting**: Rapid requests appropriately throttled  
✅ **Device Policies**: Mobile device security policies enforced  
✅ **Compliance Rules**: Regulatory requirements enforced  

This framework provides **industry-leading security testing** with advanced ML-based fraud detection and comprehensive mobile security analysis to ensure your betting application is protected against sophisticated attacks, enforces business rules, and maintains regulatory compliance.

---

**🤖 Generated with [Claude Code](https://claude.ai/code)**