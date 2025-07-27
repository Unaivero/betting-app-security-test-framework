import pytest
import time
import logging
from pages.login_page import LoginPage
from pages.home_page import HomePage
from pages.bet_page import BetPage
from pages.profile_page import ProfilePage
from faker import Faker

fake = Faker()
logger = logging.getLogger(__name__)

@pytest.mark.security
@pytest.mark.integration
class TestMobileUISecurityValidation:
    """Test mobile UI security validations and user interactions"""
    
    def test_login_security_validations(self, appium_driver):
        """
        Test login security including brute force protection and input validation
        """
        login_page = LoginPage(appium_driver)
        
        # Navigate to login
        assert login_page.navigate_to_login()
        
        # Test SQL injection attempts
        sql_payloads = [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]
        
        injection_results = login_page.test_sql_injection_attempts(sql_payloads)
        
        # Verify SQL injection is properly handled
        for result in injection_results:
            # Should not show signs of successful injection
            assert not result.get("successful_injection", False), \
                f"SQL injection may have succeeded with payload: {result['payload']}"
            
            # Should show error for malicious input
            assert result.get("error_displayed", False) or \
                   "invalid" in result.get("error_message", "").lower()
        
        logger.info("✓ SQL injection protection verified")
        
        # Test brute force protection
        brute_force_passwords = ["password", "123456", "admin", "test", "wrong1", "wrong2"]
        brute_force_results = login_page.attempt_brute_force_login("testuser", brute_force_passwords, delay=0.5)
        
        # Should trigger security measures after multiple attempts
        captcha_triggered = any(r.get("captcha_displayed") for r in brute_force_results)
        account_locked = any(r.get("account_locked") for r in brute_force_results)
        warning_shown = any(r.get("failed_attempts_warning") for r in brute_force_results)
        
        security_triggered = captcha_triggered or account_locked or warning_shown
        assert security_triggered, "Brute force protection should trigger security measures"
        
        logger.info("✓ Brute force protection verified")
        
        # Test rapid login attempts
        rapid_results = login_page.simulate_rapid_login_attempts("testuser", "wrongpass", attempts=10, delay=0.1)
        
        # Should detect rapid attempts
        rate_limited = any(r.get("rate_limited") for r in rapid_results)
        if rate_limited:
            logger.info("✓ Rate limiting on login attempts detected")
        else:
            logger.info("No rate limiting detected - verify if intentional")
    
    def test_bet_placement_security_ui(self, appium_driver, mock_server):
        """
        Test bet placement security through UI interactions
        """
        # Login first
        login_page = LoginPage(appium_driver)
        login_page.navigate_to_login()
        assert login_page.login("testuser", "password123")
        
        # Navigate to home and select match
        home_page = HomePage(appium_driver)
        assert home_page.wait_for_home_page_load()
        
        selected_match = home_page.select_match_for_betting()
        assert selected_match is not None
        
        # Navigate to bet page
        bet_page = BetPage(appium_driver)
        assert bet_page.wait_for_bet_page_load()
        
        # Test excessive bet amounts
        excessive_amounts = [1500, 2000, 5000, 10000]  # Above single bet limit
        excessive_results = bet_page.test_excessive_bet_amount(excessive_amounts)
        
        for result in excessive_results:
            if result["test_amount"] > 1000:  # Above mock server limit
                assert not result.get("success", True), \
                    f"Excessive bet amount {result['test_amount']} should be rejected"
                assert result.get("limit_violation_detected", False), \
                    f"Limit violation should be detected for amount {result['test_amount']}"
        
        logger.info("✓ Excessive bet amount validation working")
        
        # Test negative and invalid amounts
        invalid_results = bet_page.test_negative_bet_amounts()
        
        for result in invalid_results:
            assert not result.get("success", True) or result.get("validation_working", False), \
                f"Invalid amount {result['test_amount']} should be rejected"
        
        logger.info("✓ Invalid bet amount validation working")
        
        # Test rapid bet placement
        rapid_results = bet_page.test_rapid_bet_placement(bet_count=10, amount=50, delay=0.1)
        
        # Should handle rapid betting appropriately
        successful_bets = sum(1 for r in rapid_results if r.get("success"))
        rate_limited_bets = sum(1 for r in rapid_results if r.get("rate_limited"))
        
        logger.info(f"Rapid betting: {successful_bets} successful, {rate_limited_bets} rate limited")
        
        # Test cumulative limit violations
        cumulative_results = bet_page.test_cumulative_limit_violation()
        
        # Should detect when approaching/exceeding limits
        limit_warnings = [r for r in cumulative_results if r.get("limit_warning_shown")]
        limit_violations = [r for r in cumulative_results if not r.get("success") and "limit" in r.get("error", "").lower()]
        
        if sum(r.get("cumulative_total", 0) for r in cumulative_results) > 5000:  # Daily limit
            assert len(limit_violations) > 0, "Daily limit violations should be detected"
        
        logger.info("✓ Cumulative betting limit protection working")
    
    def test_profile_security_ui(self, appium_driver, mock_server):
        """
        Test profile security through UI interactions
        """
        # Login first
        login_page = LoginPage(appium_driver)
        login_page.navigate_to_login()
        assert login_page.login("testuser", "password123")  # Unverified user
        
        # Navigate to profile
        home_page = HomePage(appium_driver)
        home_page.wait_for_home_page_load()
        home_page.navigate_to_profile()
        
        # Profile page
        profile_page = ProfilePage(appium_driver)
        assert profile_page.wait_for_profile_page_load()
        
        # Test critical field updates without verification
        critical_results = profile_page.attempt_critical_field_updates_without_verification()
        
        for result in critical_results:
            field = result.get("field_tested")
            if field in ["email", "phone", "bank_account", "payment_method"]:
                assert result.get("security_working", False), \
                    f"Critical field {field} should require verification"
        
        logger.info("✓ Critical field update protection working")
        
        # Test rapid profile changes
        rapid_change_results = profile_page.test_rapid_profile_changes(change_count=3, delay=0.5)
        
        # Should detect rapid changes
        fraud_detected = any(r.get("fraud_detection_triggered") for r in rapid_change_results)
        if len(rapid_change_results) > 1:
            # At least some fraud detection should kick in for rapid changes
            logger.info(f"Rapid profile changes: fraud detection triggered = {fraud_detected}")
        
        # Test malicious data injection
        injection_results = profile_page.test_malicious_data_injection()
        
        high_risk_results = [r for r in injection_results if r.get("security_risk") == "HIGH"]
        assert len(high_risk_results) == 0, \
            f"High risk injections detected: {[r['payload'] for r in high_risk_results]}"
        
        logger.info("✓ Malicious data injection protection working")
    
    def test_session_security_ui(self, appium_driver, mock_server):
        """
        Test session security through UI
        """
        # Login and monitor session
        login_page = LoginPage(appium_driver)
        login_page.navigate_to_login()
        assert login_page.login("testuser", "password123")
        
        home_page = HomePage(appium_driver)
        assert home_page.wait_for_home_page_load()
        
        # Check session timer display
        session_timer = home_page.get_session_timer()
        if session_timer:
            logger.info(f"Session timer displayed: {session_timer}")
        
        # Test session timeout behavior (short test)
        timeout_result = home_page.monitor_session_timeout(check_interval=5, max_duration=30)
        
        logger.info(f"Session timeout test: {timeout_result}")
        
        # Test rapid match selections
        rapid_selection_results = home_page.rapid_match_selection_test(selections=5, delay=0.2)
        
        rate_limited_selections = sum(1 for r in rapid_selection_results if r.get("rate_limited"))
        if rate_limited_selections > 0:
            logger.info("✓ Rate limiting on rapid selections detected")
    
    def test_ui_data_exposure_security(self, appium_driver, mock_server):
        """
        Test that UI doesn't expose sensitive data
        """
        # Login first
        login_page = LoginPage(appium_driver)
        login_page.navigate_to_login()
        assert login_page.login("testuser", "password123")
        
        home_page = HomePage(appium_driver)
        assert home_page.wait_for_home_page_load()
        
        # Check balance display
        balance = home_page.get_user_balance()
        assert isinstance(balance, (int, float)), "Balance should be numeric"
        assert balance >= 0, "Balance should not be negative"
        
        # Navigate to profile and check data exposure
        home_page.navigate_to_profile()
        
        profile_page = ProfilePage(appium_driver)
        profile_page.wait_for_profile_page_load()
        
        # Get current profile data
        profile_data = profile_page.get_current_profile_data()
        
        # Verify no sensitive data is exposed in UI
        sensitive_patterns = [
            "password", "hash", "salt", "secret", "key", 
            "token", "session", "admin", "database", "server"
        ]
        
        for field, value in profile_data.items():
            if value:
                value_lower = str(value).lower()
                for pattern in sensitive_patterns:
                    assert pattern not in value_lower, \
                        f"Sensitive pattern '{pattern}' found in {field}: {value}"
        
        logger.info("✓ No sensitive data exposed in UI")
        
        # Check verification status
        is_verified = profile_page.is_verified_user()
        verification_status = profile_page.get_verification_status()
        
        logger.info(f"User verification status: {is_verified}, {verification_status}")
    
    def test_ui_input_validation_comprehensive(self, appium_driver, mock_server):
        """
        Comprehensive UI input validation testing
        """
        # Login first
        login_page = LoginPage(appium_driver)
        login_page.navigate_to_login()
        assert login_page.login("testuser", "password123")
        
        # Test home page search input
        home_page = HomePage(appium_driver)
        home_page.wait_for_home_page_load()
        
        # Test malicious search inputs
        malicious_searches = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE matches; --",
            "../../../etc/passwd",
            "{{7*7}}"
        ]
        
        for search_term in malicious_searches:
            try:
                home_page.search_matches(search_term)
                time.sleep(1)
                # Should handle malicious input gracefully
                logger.info(f"Search input '{search_term[:20]}...' processed")
            except Exception as e:
                logger.info(f"Search input '{search_term[:20]}...' rejected: {str(e)}")
        
        # Test bet page input validation
        selected_match = home_page.select_match_for_betting()
        if selected_match:
            bet_page = BetPage(appium_driver)
            bet_page.wait_for_bet_page_load()
            
            # Test malicious bet amounts
            malicious_amounts = [
                "<script>alert('xss')</script>",
                "'; DROP TABLE bets; --",
                "{{7*7}}",
                "javascript:alert('xss')"
            ]
            
            for amount in malicious_amounts:
                try:
                    bet_page.enter_bet_amount(amount)
                    time.sleep(0.5)
                    # Should properly validate or sanitize
                    logger.info(f"Bet amount input '{amount[:20]}...' processed")
                except Exception as e:
                    logger.info(f"Bet amount input '{amount[:20]}...' rejected: {str(e)}")
        
        logger.info("✓ Comprehensive input validation testing completed")
    
    def test_ui_error_message_security(self, appium_driver, mock_server):
        """
        Test that error messages don't expose sensitive information
        """
        login_page = LoginPage(appium_driver)
        login_page.navigate_to_login()
        
        # Test various login failures
        test_scenarios = [
            ("nonexistent_user", "password123"),
            ("testuser", "wrong_password"),
            ("admin", "admin"),
            ("", ""),
            ("testuser", "")
        ]
        
        for username, password in test_scenarios:
            login_page.login(username, password)
            
            if login_page.is_error_displayed():
                error_msg = login_page.get_error_message()
                
                # Error messages should not expose sensitive information
                sensitive_info = [
                    "database", "sql", "server", "stack trace", "exception",
                    "internal error", "debug", "path", "file not found"
                ]
                
                error_lower = error_msg.lower()
                for sensitive in sensitive_info:
                    assert sensitive not in error_lower, \
                        f"Error message exposes sensitive info '{sensitive}': {error_msg}"
                
                # Should be generic user-friendly message
                assert len(error_msg) < 200, "Error message should be concise"
                
                logger.info(f"Error message validation passed: {error_msg[:50]}...")
            
            time.sleep(0.5)
        
        logger.info("✓ Error message security validation completed")
    
    @pytest.mark.parametrize("user_type,expected_access", [
        ("testuser", False),      # Unverified user
        ("verified_user", True),  # Verified user  
        ("admin", True),          # Admin user (if exists)
    ])
    def test_role_based_access_control_ui(self, appium_driver, mock_server, user_type, expected_access):
        """
        Test role-based access control through UI
        """
        login_page = LoginPage(appium_driver)
        login_page.navigate_to_login()
        
        # Try to login with different user types
        login_success = login_page.login(user_type, "password123")
        
        if login_success:
            home_page = HomePage(appium_driver)
            home_page.wait_for_home_page_load()
            
            # Navigate to profile
            home_page.navigate_to_profile()
            
            profile_page = ProfilePage(appium_driver)
            profile_page.wait_for_profile_page_load()
            
            # Test critical field update access
            critical_update_data = {"email": fake.email()}
            result = profile_page.update_profile(critical_update_data, save=False)
            
            if expected_access:
                # Should allow or show proper verification process
                assert not (result.get("error_displayed") and "verification" in result.get("error_message", "").lower()), \
                    f"User {user_type} should have access to critical field updates"
            else:
                # Should require verification
                assert result.get("verification_required") or \
                       (result.get("error_displayed") and "verification" in result.get("error_message", "").lower()), \
                    f"User {user_type} should not have direct access to critical field updates"
            
            logger.info(f"✓ Role-based access control verified for {user_type}")
        else:
            if user_type in ["testuser", "verified_user"]:
                assert False, f"User {user_type} should be able to login"
            else:
                logger.info(f"User {user_type} login failed as expected")