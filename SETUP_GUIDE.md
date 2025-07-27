# 🚀 Betting App Security Test Framework - Setup Guide

This guide provides step-by-step instructions for setting up and running the comprehensive security testing framework.

## 📋 Prerequisites

### System Requirements
- **Operating System**: macOS, Linux, or Windows
- **Python**: 3.8 or higher
- **RAM**: Minimum 4GB, recommended 8GB+
- **Storage**: At least 2GB free space

### Required Software

#### Python Environment
```bash
# Check Python version
python --version  # Should be 3.8+

# Install pip if not available
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```

#### Node.js (for Appium)
```bash
# Install Node.js (version 14+)
# macOS with Homebrew
brew install node

# Ubuntu/Debian
sudo apt update
sudo apt install nodejs npm

# Windows - Download from nodejs.org
```

#### Java Development Kit
```bash
# Check if Java is installed
java -version

# Install Java 8+ if needed
# macOS with Homebrew
brew install openjdk@11

# Ubuntu/Debian
sudo apt install openjdk-11-jdk

# Windows - Download from Oracle or OpenJDK
```

## 🛠️ Installation Steps

### Step 1: Project Setup
```bash
# Navigate to the project directory
cd /Users/josevergara/Documents/betting-app-security-test-framework

# Verify project structure
ls -la
# Should show: conftest.py, pytest.ini, requirements.txt, run_tests.sh, etc.
```

### Step 2: Python Environment Setup
```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# macOS/Linux
source venv/bin/activate

# Windows
venv\\Scripts\\activate

# Install Python dependencies
pip install -r requirements.txt

# Verify installation
pip list
```

### Step 3: Appium Setup (Optional - for Mobile UI Tests)
```bash
# Install Appium globally
npm install -g appium

# Install Appium drivers
appium driver install uiautomator2  # For Android
appium driver install xcuitest      # For iOS (macOS only)

# Verify Appium installation
appium --version

# Install Appium Doctor for environment validation
npm install -g appium-doctor

# Check Android setup
appium-doctor --android
```

### Step 4: Android SDK Setup (for Mobile Tests)
```bash
# Install Android Studio from https://developer.android.com/studio

# Set environment variables (add to ~/.bashrc or ~/.zshrc)
export ANDROID_HOME=$HOME/Library/Android/sdk  # macOS
export ANDROID_HOME=$HOME/Android/Sdk          # Linux
export PATH=$PATH:$ANDROID_HOME/emulator
export PATH=$PATH:$ANDROID_HOME/tools
export PATH=$PATH:$ANDROID_HOME/tools/bin
export PATH=$PATH:$ANDROID_HOME/platform-tools

# Reload environment
source ~/.bashrc  # or ~/.zshrc

# Verify ADB is working
adb version
```

### Step 5: Create Android Virtual Device (for Mobile Tests)
```bash
# List available system images
avdmanager list target

# Create AVD (replace with desired API level)
avdmanager create avd -n TestDevice -k "system-images;android-29;google_apis;x86_64"

# Start emulator
emulator -avd TestDevice

# Verify device is connected
adb devices
```

## 🎯 Quick Start Guide

### Option 1: Automated Setup (Recommended)
```bash
# Make script executable
chmod +x run_tests.sh

# Install dependencies and run all tests
./run_tests.sh -i all

# This will:
# 1. Install Python dependencies
# 2. Start mock server
# 3. Run all security tests
# 4. Generate HTML reports
```

### Option 2: Manual Setup
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start mock server (in separate terminal)
cd mock_server
python app.py

# 3. Run tests (in another terminal)
pytest tests/ -v --html=reports/test_report.html

# 4. View results
open reports/test_report.html  # macOS
xdg-open reports/test_report.html  # Linux
```

## 🧪 Test Execution Options

### Basic Test Runs
```bash
# Run all security tests
./run_tests.sh security

# Run API tests only
./run_tests.sh api

# Run fraud detection tests
./run_tests.sh fraud

# Run mobile UI tests (requires Appium)
./run_tests.sh mobile
```

### Advanced Options
```bash
# Clean previous reports and run tests
./run_tests.sh -c security

# Skip starting mock server (if already running)
./run_tests.sh -s api

# Install dependencies and clean reports
./run_tests.sh -i -c all
```

### Direct Pytest Commands
```bash
# Run specific test file
pytest tests/test_bet_limits_security.py -v

# Run with specific markers
pytest -m security -v
pytest -m fraud_detection -v

# Run with coverage
pytest --cov=. tests/

# Run with allure reporting (if installed)
pytest --alluredir=allure-results tests/
allure serve allure-results
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the project root:
```bash
# Mock server configuration
MOCK_SERVER_URL=http://localhost:5000
MOCK_SERVER_PORT=5000

# Appium configuration
APPIUM_SERVER_URL=http://localhost:4723
APPIUM_PORT=4723

# Test configuration
TEST_TIMEOUT=30
IMPLICIT_WAIT=10
EXPLICIT_WAIT=10

# Reporting
REPORT_DIR=reports
LOG_DIR=logs
SCREENSHOT_DIR=screenshots
```

### Pytest Configuration
Edit `pytest.ini` to customize test execution:
```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    --html=reports/report.html 
    --self-contained-html
    --tb=short
    -v
    --strict-markers
```

### Mock Server Configuration
Edit `mock_server/app.py` to modify:
- Betting limits
- User accounts
- Security thresholds
- Response delays
- Error conditions

## 📱 Mobile Testing Setup

### Android Emulator Setup
```bash
# List available AVDs
emulator -list-avds

# Start specific AVD
emulator -avd TestDevice -no-snapshot-load

# Advanced emulator options
emulator -avd TestDevice -gpu on -memory 2048 -cores 2
```

### Real Device Setup
```bash
# Enable Developer Options on Android device
# Settings > About Phone > Tap Build Number 7 times

# Enable USB Debugging
# Settings > Developer Options > USB Debugging

# Connect device and verify
adb devices

# Should show: device_id    device
```

### iOS Setup (macOS only)
```bash
# Install Xcode from App Store

# Install iOS dependencies
npm install -g ios-deploy
npm install -g ios-simulator

# For real iOS devices, install WebDriverAgent
# Follow Appium iOS setup guide
```

## 🐛 Troubleshooting

### Common Issues and Solutions

#### Python Dependencies
```bash
# Issue: Package conflicts
# Solution: Use virtual environment
python -m venv fresh_env
source fresh_env/bin/activate
pip install -r requirements.txt
```

#### Mock Server Issues
```bash
# Issue: Port already in use
# Solution: Kill existing processes
lsof -ti:5000 | xargs kill -9

# Issue: Permission denied
# Solution: Check file permissions
chmod +x run_tests.sh
chmod 755 mock_server/app.py
```

#### Appium Issues
```bash
# Issue: Appium server not starting
# Solution: Check Node.js and dependencies
node --version
npm list -g appium

# Issue: Device not detected
# Solution: Restart ADB
adb kill-server
adb start-server
adb devices
```

#### Android Emulator Issues
```bash
# Issue: Emulator won't start
# Solution: Check virtualization and space
# Enable Intel VT-x/AMD-V in BIOS
# Free up disk space (need 2GB+)

# Issue: Emulator too slow
# Solution: Use x86_64 image and enable GPU
emulator -avd TestDevice -gpu on
```

### Log Analysis
```bash
# Check mock server logs
tail -f logs/test.log

# Check pytest logs
pytest --log-cli-level=INFO tests/

# Check Appium logs
appium --log-level debug
```

## 📊 Report Generation

### HTML Reports
```bash
# Basic HTML report
pytest --html=reports/report.html --self-contained-html

# With screenshots (for UI tests)
pytest --html=reports/report.html --capture=sys
```

### Allure Reports (Advanced)
```bash
# Install Allure
npm install -g allure-commandline

# Generate Allure report
pytest --alluredir=allure-results tests/
allure serve allure-results

# Generate static report
allure generate allure-results --output allure-report --clean
```

### Custom Reporting
```bash
# JSON report
pytest --json-report --json-report-file=reports/report.json

# JUnit XML (for CI/CD)
pytest --junitxml=reports/junit.xml

# Coverage report
pytest --cov=. --cov-report=html:reports/coverage
```

## 🔐 Security Considerations

### Test Environment Security
- Use isolated test environment
- Don't test against production systems
- Secure test data and credentials
- Monitor for actual security vulnerabilities

### Mock Server Security
- Run on localhost only
- Use non-standard ports if needed
- Don't expose to external networks
- Reset state between test runs

### Data Protection
- Use fake/synthetic test data
- Don't store real user information
- Clean up test data after runs
- Secure test reports and logs

## 🚀 CI/CD Integration

### GitHub Actions Example
```yaml
name: Security Tests
on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    - name: Install dependencies
      run: pip install -r requirements.txt
    - name: Run security tests
      run: ./run_tests.sh -s security
    - name: Upload reports
      uses: actions/upload-artifact@v2
      with:
        name: test-reports
        path: reports/
```

### Jenkins Pipeline Example
```groovy
pipeline {
    agent any
    stages {
        stage('Setup') {
            steps {
                sh 'pip install -r requirements.txt'
            }
        }
        stage('Security Tests') {
            steps {
                sh './run_tests.sh -s security'
            }
        }
        stage('Reports') {
            steps {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: '*.html',
                    reportName: 'Security Test Report'
                ])
            }
        }
    }
}
```

## 🎯 Performance Optimization

### Test Execution Speed
```bash
# Parallel test execution
pytest -n auto tests/  # Requires pytest-xdist

# Skip slow tests in development
pytest -m "not slow" tests/

# Use faster assertion introspection
pytest --tb=no tests/
```

### Resource Management
```bash
# Limit emulator resources
emulator -avd TestDevice -memory 1024 -cores 1

# Use headless browser for web tests
export HEADLESS=true
pytest tests/
```

## 📚 Additional Resources

### Documentation
- [Pytest Documentation](https://docs.pytest.org/)
- [Appium Documentation](https://appium.io/docs/)
- [Selenium Python Bindings](https://selenium-python.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)

### Security Testing Resources
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Security Testing Methodologies](https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html)

### Betting Industry Standards
- [Responsible Gambling Guidelines](https://www.responsiblegambling.org/)
- [Gaming Compliance Standards](https://www.gamblingcommission.gov.uk/)
- [Anti-Money Laundering Requirements](https://www.fincen.gov/)

---

🎉 **Congratulations!** You've successfully set up the Betting App Security Test Framework. You're now ready to run comprehensive security tests to validate betting limits, fraud detection, and regulatory compliance in your application.

For questions or issues, refer to the troubleshooting section above or check the generated test reports for detailed information.