"""
Locust Load Testing for Betting App Security Framework
High-performance load testing with security-focused scenarios
"""

import random
import time
import json
from locust import HttpUser, task, between, events
from locust.exception import RescheduleTask
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BettingAppUser(HttpUser):
    """Simulated betting app user for load testing"""
    
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks
    
    def on_start(self):
        """Initialize user session"""
        self.token = None
        self.user_id = random.randint(1, 1000)
        self.username = f"loadtest_user_{self.user_id}"
        self.login()
    
    def login(self):
        """Login to get authentication token"""
        try:
            response = self.client.post("/login", json={
                "username": "testuser",  # Use default test user
                "password": "password123"
            }, name="Authentication")
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("token")
                if self.token:
                    self.client.headers.update({"Authorization": f"Bearer {self.token}"})
                    logger.info(f"User {self.username} logged in successfully")
                else:
                    logger.error(f"No token received for user {self.username}")
            else:
                logger.error(f"Login failed for user {self.username}: {response.status_code}")
                raise RescheduleTask()
                
        except Exception as e:
            logger.error(f"Login error for user {self.username}: {str(e)}")
            raise RescheduleTask()
    
    @task(3)
    def get_user_limits(self):
        """Check user betting limits"""
        with self.client.get("/user_limits", 
                           catch_response=True, 
                           name="Get User Limits") as response:
            if response.status_code == 200:
                data = response.json()
                # Validate response structure
                if "limits" in data and "current_usage" in data:
                    response.success()
                else:
                    response.failure("Invalid limits response structure")
            elif response.status_code == 401:
                # Re-login if token expired
                self.login()
                response.success()  # Don't count as failure, it's expected
            else:
                response.failure(f"Unexpected status code: {response.status_code}")
    
    @task(5)
    def place_bet(self):
        """Place a betting transaction"""
        bet_amounts = [10, 25, 50, 100, 200, 500]
        bet_types = ["home_win", "draw", "away_win"]
        match_ids = [1, 2, 3, 4, 5]
        
        bet_data = {
            "match_id": random.choice(match_ids),
            "bet_type": random.choice(bet_types),
            "amount": random.choice(bet_amounts),
            "odds": round(random.uniform(1.5, 5.0), 2)
        }
        
        with self.client.post("/bet", 
                            json=bet_data,
                            catch_response=True,
                            name="Place Bet") as response:
            if response.status_code == 200:
                response.success()
                logger.debug(f"Bet placed: ${bet_data['amount']}")
            elif response.status_code == 400:
                # Expected for limit violations
                error_data = response.json()
                if "limit" in error_data.get("error", "").lower():
                    response.success()  # Limit enforcement is working
                    logger.debug(f"Bet rejected - limit violation: {error_data.get('error')}")
                else:
                    response.failure(f"Unexpected bet rejection: {error_data.get('error')}")
            elif response.status_code == 401:
                self.login()
                response.success()
            else:
                response.failure(f"Bet failed with status: {response.status_code}")
    
    @task(2)
    def get_bet_history(self):
        """Retrieve betting history"""
        with self.client.get("/bet_history",
                           catch_response=True,
                           name="Get Bet History") as response:
            if response.status_code == 200:
                data = response.json()
                if "bets" in data and isinstance(data["bets"], list):
                    response.success()
                else:
                    response.failure("Invalid bet history response")
            elif response.status_code == 401:
                self.login()
                response.success()
            else:
                response.failure(f"History request failed: {response.status_code}")
    
    @task(1)
    def update_profile(self):
        """Update user profile (for verified users)"""
        profile_updates = [
            {"first_name": f"LoadTest{random.randint(1, 100)}"},
            {"last_name": f"User{random.randint(1, 100)}"},
            {"address": f"Test Address {random.randint(1, 1000)}"}
        ]
        
        update_data = random.choice(profile_updates)
        
        with self.client.put("/update_profile",
                           json=update_data,
                           catch_response=True,
                           name="Update Profile") as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code in [403, 429]:
                # Expected for unverified users or rate limiting
                response.success()
                logger.debug(f"Profile update restricted: {response.status_code}")
            elif response.status_code == 401:
                self.login()
                response.success()
            else:
                response.failure(f"Profile update failed: {response.status_code}")
    
    @task(1)
    def fraud_check(self):
        """Trigger fraud detection check"""
        with self.client.post("/fraud_check",
                            json={},
                            catch_response=True,
                            name="Fraud Check") as response:
            if response.status_code == 200:
                data = response.json()
                if "risk_level" in data and "fraud_indicators" in data:
                    response.success()
                    # Log high-risk users for analysis
                    if data.get("risk_level") == "high":
                        logger.warning(f"High-risk user detected: {self.username}")
                else:
                    response.failure("Invalid fraud check response")
            elif response.status_code == 401:
                self.login()
                response.success()
            else:
                response.failure(f"Fraud check failed: {response.status_code}")

class AggressiveBettingUser(HttpUser):
    """User that aggressively tests betting limits"""
    
    wait_time = between(0.1, 0.5)  # Very fast requests
    weight = 1  # Lower weight for this user type
    
    def on_start(self):
        self.token = None
        self.user_id = random.randint(2000, 3000)
        self.username = f"aggressive_user_{self.user_id}"
        self.consecutive_failures = 0
        self.login()
    
    def login(self):
        """Login for aggressive user"""
        response = self.client.post("/login", json={
            "username": "testuser",
            "password": "password123"
        })
        
        if response.status_code == 200:
            data = response.json()
            self.token = data.get("token")
            if self.token:
                self.client.headers.update({"Authorization": f"Bearer {self.token}"})
                self.consecutive_failures = 0
    
    @task(10)
    def aggressive_betting(self):
        """Rapidly place high-value bets to test limits"""
        high_amounts = [800, 900, 1000, 1100, 1200]  # Some above single bet limit
        
        bet_data = {
            "match_id": random.randint(1, 5),
            "bet_type": random.choice(["home_win", "draw", "away_win"]),
            "amount": random.choice(high_amounts),
            "odds": 2.0
        }
        
        with self.client.post("/bet",
                            json=bet_data,
                            catch_response=True,
                            name="Aggressive Betting") as response:
            if response.status_code == 400:
                # Expected - limits should be enforced
                error_data = response.json()
                if "limit" in error_data.get("error", "").lower():
                    response.success()
                    self.consecutive_failures = 0
                else:
                    response.failure("Unexpected error for high bet amount")
                    self.consecutive_failures += 1
            elif response.status_code == 200:
                response.success()
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1
                if self.consecutive_failures > 5:
                    self.login()  # Try re-login
                response.failure(f"Unexpected response: {response.status_code}")

class FraudDetectionUser(HttpUser):
    """User that triggers fraud detection patterns"""
    
    wait_time = between(0.05, 0.2)  # Very rapid requests
    weight = 1
    
    def on_start(self):
        self.token = None
        self.user_id = random.randint(4000, 5000)
        self.username = f"fraud_test_user_{self.user_id}"
        self.login()
    
    def login(self):
        """Login for fraud detection user"""
        response = self.client.post("/login", json={
            "username": "verified_user",  # Use verified user for profile updates
            "password": "password123"
        })
        
        if response.status_code == 200:
            data = response.json()
            self.token = data.get("token")
            if self.token:
                self.client.headers.update({"Authorization": f"Bearer {self.token}"})
    
    @task(5)
    def rapid_profile_changes(self):
        """Rapidly change profile to trigger fraud detection"""
        changes = [
            {"first_name": f"Rapid{random.randint(1, 1000)}"},
            {"last_name": f"Change{random.randint(1, 1000)}"},
            {"address": f"Fast Address {random.randint(1, 10000)}"}
        ]
        
        update_data = random.choice(changes)
        
        with self.client.put("/update_profile",
                           json=update_data,
                           catch_response=True,
                           name="Rapid Profile Changes") as response:
            if response.status_code in [200, 429]:
                # 429 indicates rate limiting is working
                response.success()
                if response.status_code == 429:
                    logger.info(f"Rate limiting triggered for {self.username}")
            else:
                response.failure(f"Unexpected profile response: {response.status_code}")
    
    @task(3)
    def suspicious_betting_pattern(self):
        """Create suspicious betting patterns"""
        # Bet on same match with varying amounts
        suspicious_amounts = [750, 800, 850, 900, 950]
        
        bet_data = {
            "match_id": 1,  # Always same match
            "bet_type": "home_win",
            "amount": random.choice(suspicious_amounts),
            "odds": 2.5
        }
        
        with self.client.post("/bet",
                            json=bet_data,
                            catch_response=True,
                            name="Suspicious Betting") as response:
            if response.status_code in [200, 400]:
                response.success()
            else:
                response.failure(f"Suspicious bet failed: {response.status_code}")

# Event listeners for custom metrics
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when test starts"""
    logger.info("🚀 Starting Betting App Load Test")
    logger.info(f"Target host: {environment.host}")

@events.test_stop.add_listener 
def on_test_stop(environment, **kwargs):
    """Called when test stops"""
    logger.info("🏁 Betting App Load Test Completed")
    
    # Log summary statistics
    stats = environment.stats
    logger.info(f"Total requests: {stats.total.num_requests}")
    logger.info(f"Total failures: {stats.total.num_failures}")
    logger.info(f"Average response time: {stats.total.avg_response_time:.2f}ms")
    logger.info(f"RPS: {stats.total.current_rps:.2f}")

@events.request_failure.add_listener
def on_request_failure(request_type, name, response_time, exception, **kwargs):
    """Log request failures"""
    logger.warning(f"Request failed: {request_type} {name} - {exception}")

@events.user_error.add_listener
def on_user_error(user_instance, exception, tb, **kwargs):
    """Log user errors"""
    logger.error(f"User error in {user_instance.__class__.__name__}: {exception}")

# Custom metrics collection
security_violations = 0
fraud_detections = 0

@events.request_success.add_listener
def on_request_success(request_type, name, response_time, response_length, **kwargs):
    """Track security-related metrics"""
    global security_violations, fraud_detections
    
    # Track betting limit violations
    if name == "Place Bet" and "limit" in str(kwargs.get("response", "")):
        security_violations += 1
    
    # Track fraud detections
    if name == "Fraud Check":
        fraud_detections += 1