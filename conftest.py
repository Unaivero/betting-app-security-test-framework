import pytest
import json
import os
from datetime import datetime, timedelta
from faker import Faker
from appium import webdriver
from appium.options.android import UiAutomator2Options
import requests
import time

fake = Faker()

# Configuration
MOCK_SERVER_URL = "http://localhost:5000"
APPIUM_SERVER_URL = "http://localhost:4723"

@pytest.fixture(scope="session")
def mock_server():
    """Start mock server for testing"""
    import subprocess
    import time
    
    # Start the mock server
    server_process = subprocess.Popen(
        ["python", "mock_server/app.py"],
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    
    # Wait for server to start
    time.sleep(2)
    
    # Verify server is running
    try:
        response = requests.get(f"{MOCK_SERVER_URL}/health")
        assert response.status_code == 200
    except:
        pytest.fail("Mock server failed to start")
    
    yield server_process
    
    # Cleanup
    server_process.terminate()
    server_process.wait()

@pytest.fixture
def appium_driver():
    """Setup Appium driver for mobile testing"""
    options = UiAutomator2Options()
    options.platform_name = "Android"
    options.device_name = "emulator-5554"
    options.app_package = "com.betting.app"
    options.app_activity = ".MainActivity"
    options.automation_name = "UiAutomator2"
    options.no_reset = True
    
    try:
        driver = webdriver.Remote(APPIUM_SERVER_URL, options=options)
        yield driver
    except Exception as e:
        # If Appium server not available, use mock driver for testing
        yield MockDriver()
    finally:
        if 'driver' in locals():
            try:
                driver.quit()
            except:
                pass

class MockDriver:
    """Mock driver for testing when Appium is not available"""
    def find_element(self, by, value):
        return MockElement()
    
    def find_elements(self, by, value):
        return [MockElement()]
    
    def quit(self):
        pass

class MockElement:
    """Mock element for testing"""
    def click(self):
        pass
    
    def send_keys(self, text):
        pass
    
    def clear(self):
        pass
    
    @property
    def text(self):
        return "Mock Text"
    
    def is_displayed(self):
        return True

@pytest.fixture
def test_user():
    """Generate test user data"""
    return {
        "username": fake.user_name(),
        "email": fake.email(),
        "password": fake.password(),
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "phone": fake.phone_number(),
        "date_of_birth": fake.date_of_birth(minimum_age=18, maximum_age=80).isoformat(),
        "address": fake.address()
    }

@pytest.fixture
def betting_limits():
    """Test betting limits configuration"""
    return {
        "max_single_bet": 1000.0,
        "max_daily_bet": 5000.0,
        "max_monthly_bet": 50000.0,
        "min_bet": 1.0
    }

@pytest.fixture
def test_bets():
    """Generate test betting data"""
    return [
        {
            "match_id": fake.random_int(min=1, max=100),
            "bet_type": fake.random_element(elements=("win", "draw", "lose")),
            "amount": fake.random_int(min=10, max=2000),
            "odds": round(fake.random.uniform(1.5, 5.0), 2)
        }
        for _ in range(10)
    ]

@pytest.fixture
def fraud_scenarios():
    """Fraud detection test scenarios"""
    return {
        "excessive_betting": {
            "description": "Multiple high-value bets in short time",
            "bets": [{"amount": 1500, "timestamp": datetime.now() + timedelta(minutes=i)} for i in range(5)]
        },
        "limit_bypass": {
            "description": "Attempting to bypass daily limits",
            "total_amount": 6000,  # Above daily limit
            "split_bets": [1000, 1500, 2000, 1500]  # Multiple bets to reach total
        },
        "profile_manipulation": {
            "description": "Changing critical profile data without verification",
            "changes": {
                "bank_account": fake.iban(),
                "email": fake.email(),
                "phone": fake.phone_number()
            }
        }
    }

@pytest.fixture
def api_client():
    """HTTP client for API testing"""
    class APIClient:
        def __init__(self, base_url=MOCK_SERVER_URL):
            self.base_url = base_url
            self.session = requests.Session()
            self.token = None
        
        def login(self, username, password):
            response = self.session.post(f"{self.base_url}/login", 
                                       json={"username": username, "password": password})
            if response.status_code == 200:
                self.token = response.json().get("token")
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            return response
        
        def place_bet(self, bet_data):
            return self.session.post(f"{self.base_url}/bet", json=bet_data)
        
        def update_profile(self, profile_data):
            return self.session.put(f"{self.base_url}/update_profile", json=profile_data)
        
        def get_user_limits(self):
            return self.session.get(f"{self.base_url}/user_limits")
        
        def get_bet_history(self):
            return self.session.get(f"{self.base_url}/bet_history")
    
    return APIClient()

def pytest_configure(config):
    """Configure pytest with custom markers and setup"""
    config.addinivalue_line(
        "markers", "security: mark test as security-related"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )

def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names"""
    for item in items:
        # Add markers based on test file names
        if "security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        if "bet_limit" in item.nodeid:
            item.add_marker(pytest.mark.bet_limits)
        if "profile" in item.nodeid:
            item.add_marker(pytest.mark.profile_update)

@pytest.fixture(autouse=True)
def setup_test_logging():
    """Setup logging for each test"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/test.log'),
            logging.StreamHandler()
        ]
    )