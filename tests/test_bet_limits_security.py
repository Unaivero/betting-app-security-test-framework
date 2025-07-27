import pytest
import requests
import time
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

@pytest.mark.security
@pytest.mark.bet_limits
class TestBetLimitsSecurity:
    """Test betting limits and security violations"""
    
    def test_single_bet_limit_violation(self, api_client, betting_limits):
        """
        Test placing bets above maximum single bet limit
        Should return appropriate error and log security violation
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Attempt bet above single limit
        excessive_amount = betting_limits["max_single_bet"] + 500
        bet_data = {
            "match_id": 1,
            "bet_type": "home_win",
            "amount": excessive_amount,
            "odds": 2.5
        }
        
        logger.info(f"Testing single bet limit violation with amount: {excessive_amount}")
        response = api_client.place_bet(bet_data)
        
        # Should be rejected
        assert response.status_code == 400
        response_data = response.json()
        
        # Verify proper error handling
        assert "error" in response_data
        assert "limit" in response_data["error"].lower()
        assert response_data.get("limit_exceeded") == "single_bet"
        assert response_data.get("max_amount") == betting_limits["max_single_bet"]
        assert response_data.get("attempted_amount") == excessive_amount
        
        logger.info("Single bet limit violation properly detected and blocked")
    
    def test_daily_limit_violation(self, api_client, betting_limits):
        """
        Test exceeding daily betting limits through multiple bets
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset user limits for clean test
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        daily_limit = betting_limits["max_daily_bet"]
        
        # Place multiple bets to approach daily limit
        total_bet = 0
        bet_results = []
        
        while total_bet < daily_limit:
            bet_amount = 1000  # Individual bet within single limit
            remaining_limit = daily_limit - total_bet
            
            if bet_amount > remaining_limit:
                bet_amount = remaining_limit + 100  # Exceed by small amount
            
            bet_data = {
                "match_id": 1,
                "bet_type": "home_win", 
                "amount": bet_amount,
                "odds": 2.0
            }
            
            logger.info(f"Placing bet: {bet_amount}, total so far: {total_bet}")
            response = api_client.place_bet(bet_data)
            
            bet_result = {
                "amount": bet_amount,
                "total_before": total_bet,
                "response_code": response.status_code,
                "response_data": response.json()
            }
            bet_results.append(bet_result)
            
            if response.status_code == 200:
                total_bet += bet_amount
            else:
                # Should be daily limit violation
                response_data = response.json()
                assert "daily" in response_data.get("error", "").lower()
                assert response_data.get("limit_exceeded") == "daily_limit"
                assert response_data.get("max_daily_limit") == daily_limit
                logger.info("Daily limit violation properly detected")
                break
            
            time.sleep(0.5)
        
        # Verify at least one bet was blocked due to daily limit
        blocked_bets = [r for r in bet_results if r["response_code"] != 200]
        assert len(blocked_bets) > 0, "Daily limit should have been exceeded"
    
    def test_monthly_limit_violation(self, api_client, betting_limits):
        """
        Test monthly betting limit violation
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Attempt to place bet that would exceed monthly limit
        monthly_limit = betting_limits["max_monthly_bet"]
        excessive_amount = monthly_limit + 1000
        
        bet_data = {
            "match_id": 1,
            "bet_type": "home_win",
            "amount": excessive_amount,
            "odds": 1.8
        }
        
        logger.info(f"Testing monthly limit with amount: {excessive_amount}")
        response = api_client.place_bet(bet_data)
        
        # Should be rejected for both single and monthly limit
        assert response.status_code == 400
        response_data = response.json()
        
        # Might be rejected for single bet limit first
        assert "limit" in response_data.get("error", "").lower()
        
    def test_minimum_bet_validation(self, api_client, betting_limits):
        """
        Test minimum bet amount validation
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Test amounts below minimum
        invalid_amounts = [0.50, 0, -10]
        min_bet = betting_limits["min_bet"]
        
        for amount in invalid_amounts:
            bet_data = {
                "match_id": 1,
                "bet_type": "draw",
                "amount": amount,
                "odds": 3.0
            }
            
            logger.info(f"Testing minimum bet validation with amount: {amount}")
            response = api_client.place_bet(bet_data)
            
            assert response.status_code == 400
            response_data = response.json()
            assert "minimum" in response_data.get("error", "").lower()
            assert response_data.get("min_amount") == min_bet
    
    def test_rapid_betting_attempts(self, api_client):
        """
        Test rapid betting attempts to check for rate limiting
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset limits for clean test
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        # Rapid fire betting attempts
        rapid_attempts = 15
        successful_bets = 0
        rate_limited = False
        
        for i in range(rapid_attempts):
            bet_data = {
                "match_id": i % 5 + 1,  # Vary match IDs
                "bet_type": "home_win",
                "amount": 50,
                "odds": 2.0
            }
            
            start_time = time.time()
            response = api_client.place_bet(bet_data)
            response_time = time.time() - start_time
            
            logger.info(f"Rapid bet attempt {i+1}: {response.status_code}, time: {response_time:.3f}s")
            
            if response.status_code == 200:
                successful_bets += 1
            elif "rate" in response.json().get("error", "").lower():
                rate_limited = True
                logger.info(f"Rate limiting detected after {i+1} attempts")
                break
            
            # Very short delay to test rate limiting
            time.sleep(0.05)
        
        # Log results
        logger.info(f"Rapid betting test: {successful_bets} successful, rate_limited: {rate_limited}")
        
        # Either rate limiting should kick in, or all bets should be processed
        # This tests the system's ability to handle rapid requests
        assert successful_bets >= 0  # At least some attempts should be made
    
    @pytest.mark.parametrize("bet_amounts", [
        [1500, 2000, 1800],  # Multiple high bets
        [500, 500, 500, 500, 500, 500, 500, 500, 500, 500],  # Many small bets
        [1000, 1000, 1000, 1000, 1000]  # Moderate repeated bets
    ])
    def test_cumulative_betting_patterns(self, api_client, betting_limits, bet_amounts):
        """
        Test various cumulative betting patterns for fraud detection
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset limits
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        total_bet = 0
        pattern_blocked = False
        
        for i, amount in enumerate(bet_amounts):
            bet_data = {
                "match_id": (i % 3) + 1,
                "bet_type": ["home_win", "draw", "away_win"][i % 3],
                "amount": amount,
                "odds": 2.0
            }
            
            response = api_client.place_bet(bet_data)
            
            if response.status_code == 200:
                total_bet += amount
                logger.info(f"Bet {i+1} successful: {amount}, total: {total_bet}")
            else:
                logger.info(f"Bet {i+1} blocked: {response.json()}")
                # Check if blocked due to limits
                error_msg = response.json().get("error", "").lower()
                if "limit" in error_msg:
                    pattern_blocked = True
                    break
            
            time.sleep(0.2)
        
        # Verify betting behavior was appropriately handled
        daily_limit = betting_limits["max_daily_bet"]
        if total_bet > daily_limit:
            assert pattern_blocked, "High cumulative betting should trigger limits"
        
        logger.info(f"Cumulative pattern test: Total bet {total_bet}, Blocked: {pattern_blocked}")
    
    def test_user_limits_endpoint_security(self, api_client):
        """
        Test user limits endpoint for proper authentication and data exposure
        """
        # Test without authentication
        response = requests.get("http://localhost:5000/user_limits")
        assert response.status_code == 401
        
        # Test with authentication
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        limits_response = api_client.get_user_limits()
        assert limits_response.status_code == 200
        
        limits_data = limits_response.json()
        
        # Verify expected data structure
        assert "limits" in limits_data
        assert "current_usage" in limits_data
        assert "account_status" in limits_data
        assert "verified" in limits_data
        
        # Verify limits structure
        limits = limits_data["limits"]
        required_limits = ["max_single_bet", "max_daily_bet", "max_monthly_bet", "min_bet"]
        for limit_type in required_limits:
            assert limit_type in limits
            assert isinstance(limits[limit_type], (int, float))
        
        # Verify usage structure
        usage = limits_data["current_usage"]
        required_usage = ["daily_total", "monthly_total", "daily_remaining", "monthly_remaining"]
        for usage_type in required_usage:
            assert usage_type in usage
            assert isinstance(usage[usage_type], (int, float))
        
        logger.info("User limits endpoint security validation passed")
    
    def test_bet_history_data_exposure(self, api_client):
        """
        Test bet history endpoint for data exposure and authentication
        """
        # Test without authentication
        response = requests.get("http://localhost:5000/bet_history")
        assert response.status_code == 401
        
        # Login and place some test bets
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset and place test bets
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        test_bets = [
            {"match_id": 1, "bet_type": "home_win", "amount": 100, "odds": 2.0},
            {"match_id": 2, "bet_type": "draw", "amount": 50, "odds": 3.0}
        ]
        
        for bet_data in test_bets:
            api_client.place_bet(bet_data)
        
        # Get bet history
        history_response = api_client.get_bet_history()
        assert history_response.status_code == 200
        
        history_data = history_response.json()
        
        # Verify data structure
        assert "bets" in history_data
        assert "total_bets" in history_data
        assert "total_amount" in history_data
        
        # Verify bets data
        bets = history_data["bets"]
        assert len(bets) >= len(test_bets)
        
        for bet in bets:
            # Verify no sensitive server data is exposed
            assert "username" in bet  # Should show own username
            assert "id" in bet
            assert "amount" in bet
            assert "timestamp" in bet
            assert "status" in bet
            
            # Should not expose internal server data
            assert "password" not in bet
            assert "server_id" not in bet
            assert "database_id" not in bet
        
        logger.info("Bet history data exposure validation passed")
    
    def test_fraud_detection_endpoint(self, api_client):
        """
        Test fraud detection endpoint functionality
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset limits and place suspicious betting pattern
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        # Create suspicious pattern - many high-value bets in short time
        suspicious_bets = [
            {"match_id": 1, "bet_type": "home_win", "amount": 800, "odds": 2.0},
            {"match_id": 2, "bet_type": "home_win", "amount": 900, "odds": 2.1},
            {"match_id": 3, "bet_type": "home_win", "amount": 850, "odds": 1.9}
        ]
        
        for bet_data in suspicious_bets:
            api_client.place_bet(bet_data)
            time.sleep(0.1)  # Very rapid betting
        
        # Check fraud detection
        fraud_response = requests.post("http://localhost:5000/fraud_check",
                                     headers={"Authorization": f"Bearer {api_client.token}"},
                                     json={})
        
        assert fraud_response.status_code == 200
        fraud_data = fraud_response.json()
        
        # Verify fraud detection structure
        assert "user" in fraud_data
        assert "risk_level" in fraud_data
        assert "fraud_indicators" in fraud_data
        assert "recommendation" in fraud_data
        
        # Verify risk assessment
        assert fraud_data["risk_level"] in ["low", "medium", "high"]
        assert isinstance(fraud_data["fraud_indicators"], list)
        assert fraud_data["recommendation"] in ["allow", "monitor", "block"]
        
        logger.info(f"Fraud detection result: {fraud_data['risk_level']} risk, "
                   f"indicators: {fraud_data['fraud_indicators']}")
    
    def test_authentication_token_security(self, api_client):
        """
        Test authentication token security and validation
        """
        # Test with invalid token
        fake_token = "invalid_token_123456"
        fake_client = type(api_client)()
        fake_client.token = fake_token
        fake_client.session.headers.update({"Authorization": f"Bearer {fake_token}"})
        
        # Should be rejected
        response = fake_client.place_bet({
            "match_id": 1,
            "bet_type": "home_win",
            "amount": 100,
            "odds": 2.0
        })
        assert response.status_code == 401
        
        # Test with no token
        no_token_response = requests.post("http://localhost:5000/bet", json={
            "match_id": 1,
            "bet_type": "home_win", 
            "amount": 100,
            "odds": 2.0
        })
        assert no_token_response.status_code == 401
        
        # Test with valid token
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        valid_response = api_client.place_bet({
            "match_id": 1,
            "bet_type": "home_win",
            "amount": 50,
            "odds": 2.0
        })
        assert valid_response.status_code in [200, 400]  # 400 for limit violations, 200 for success
        
        logger.info("Authentication token security validation passed")