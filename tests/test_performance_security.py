import pytest
import requests
import time
import threading
import queue
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

@pytest.mark.performance
@pytest.mark.security
class TestPerformanceSecurity:
    """Performance and load testing with security focus"""
    
    def test_concurrent_login_stress(self, api_client):
        """
        Test system under high concurrent login load
        Verify no race conditions in authentication
        """
        results = queue.Queue()
        
        def concurrent_login(thread_id):
            """Concurrent login function"""
            try:
                start_time = time.time()
                # Use different user accounts to avoid lockout
                username = f"testuser_{thread_id % 10}"  # Cycle through 10 users
                response = requests.post("http://localhost:5000/login", 
                                       json={"username": "testuser", "password": "password123"})
                end_time = time.time()
                
                results.put({
                    "thread_id": thread_id,
                    "response_time": end_time - start_time,
                    "status_code": response.status_code,
                    "success": response.status_code == 200
                })
                
            except Exception as e:
                results.put({
                    "thread_id": thread_id,
                    "error": str(e),
                    "success": False
                })
        
        # Start concurrent login attempts
        concurrent_users = 50
        threads = []
        
        logger.info(f"Starting concurrent login stress test with {concurrent_users} users")
        start_test_time = time.time()
        
        for i in range(concurrent_users):
            thread = threading.Thread(target=concurrent_login, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_test_time = time.time()
        
        # Collect and analyze results
        login_results = []
        while not results.empty():
            login_results.append(results.get())
        
        # Performance analysis
        successful_logins = [r for r in login_results if r.get("success")]
        failed_logins = [r for r in login_results if not r.get("success")]
        response_times = [r["response_time"] for r in successful_logins if "response_time" in r]
        
        total_test_time = end_test_time - start_test_time
        requests_per_second = len(login_results) / total_test_time
        
        logger.info(f"Concurrent login stress test results:")
        logger.info(f"  Total requests: {len(login_results)}")
        logger.info(f"  Successful: {len(successful_logins)}")
        logger.info(f"  Failed: {len(failed_logins)}")
        logger.info(f"  Test duration: {total_test_time:.2f}s")
        logger.info(f"  Requests/second: {requests_per_second:.2f}")
        
        if response_times:
            logger.info(f"  Avg response time: {statistics.mean(response_times):.3f}s")
            logger.info(f"  95th percentile: {statistics.quantiles(response_times, n=20)[18]:.3f}s")
        
        # Security validations
        assert len(login_results) == concurrent_users, "All login attempts should be processed"
        assert len(successful_logins) > 0, "Some logins should succeed under normal load"
        
        # Performance validations
        if response_times:
            avg_response_time = statistics.mean(response_times)
            assert avg_response_time < 5.0, f"Average response time too high: {avg_response_time:.3f}s"
    
    def test_betting_load_testing(self, api_client):
        """
        Test betting endpoint under high load
        Verify limit enforcement remains accurate under stress
        """
        # Reset limits for clean test
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        results = []
        
        def place_concurrent_bet(bet_id):
            """Place bet concurrently"""
            try:
                bet_data = {
                    "match_id": (bet_id % 5) + 1,
                    "bet_type": ["home_win", "draw", "away_win"][bet_id % 3],
                    "amount": 100,  # Small amounts to test many bets
                    "odds": 2.0
                }
                
                start_time = time.time()
                response = api_client.place_bet(bet_data)
                end_time = time.time()
                
                return {
                    "bet_id": bet_id,
                    "response_time": end_time - start_time,
                    "status_code": response.status_code,
                    "response_data": response.json(),
                    "success": response.status_code == 200
                }
                
            except Exception as e:
                return {
                    "bet_id": bet_id,
                    "error": str(e),
                    "success": False
                }
        
        # Execute concurrent betting
        concurrent_bets = 100
        logger.info(f"Starting concurrent betting load test with {concurrent_bets} bets")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(place_concurrent_bet, i) for i in range(concurrent_bets)]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        # Analyze results
        successful_bets = [r for r in results if r.get("success")]
        failed_bets = [r for r in results if not r.get("success")]
        limit_violations = [r for r in failed_bets 
                          if r.get("response_data", {}).get("limit_exceeded")]
        
        # Calculate metrics
        total_bet_amount = len(successful_bets) * 100
        response_times = [r["response_time"] for r in successful_bets if "response_time" in r]
        
        logger.info(f"Concurrent betting load test results:")
        logger.info(f"  Total bets attempted: {len(results)}")
        logger.info(f"  Successful bets: {len(successful_bets)}")
        logger.info(f"  Failed bets: {len(failed_bets)}")
        logger.info(f"  Limit violations: {len(limit_violations)}")
        logger.info(f"  Total amount bet: ${total_bet_amount}")
        
        if response_times:
            logger.info(f"  Avg response time: {statistics.mean(response_times):.3f}s")
        
        # Security validations - limits should still be enforced
        assert len(results) == concurrent_bets, "All bet attempts should be processed"
        
        # Should hit daily limit ($5000) and start rejecting bets
        if total_bet_amount > 5000:
            assert len(limit_violations) > 0, "Daily limit should be enforced under load"
        
        # Performance validations
        if response_times:
            avg_response_time = statistics.mean(response_times)
            assert avg_response_time < 2.0, f"Betting response time too high: {avg_response_time:.3f}s"
    
    def test_ddos_simulation(self, api_client):
        """
        Simulate DDoS attack on various endpoints
        Verify rate limiting and system stability
        """
        endpoints = [
            {"url": "http://localhost:5000/health", "method": "GET"},
            {"url": "http://localhost:5000/user_limits", "method": "GET", "auth": True},
            {"url": "http://localhost:5000/bet_history", "method": "GET", "auth": True}
        ]
        
        # Login for authenticated endpoints
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        headers = {"Authorization": f"Bearer {api_client.token}"}
        
        def ddos_attack(endpoint, request_id):
            """Simulate DDoS request"""
            try:
                start_time = time.time()
                
                if endpoint["method"] == "GET":
                    if endpoint.get("auth"):
                        response = requests.get(endpoint["url"], headers=headers, timeout=5)
                    else:
                        response = requests.get(endpoint["url"], timeout=5)
                
                end_time = time.time()
                
                return {
                    "request_id": request_id,
                    "endpoint": endpoint["url"],
                    "response_time": end_time - start_time,
                    "status_code": response.status_code,
                    "rate_limited": response.status_code == 429
                }
                
            except Exception as e:
                return {
                    "request_id": request_id,
                    "endpoint": endpoint["url"],
                    "error": str(e),
                    "timeout": "timeout" in str(e).lower()
                }
        
        # Run DDoS simulation
        requests_per_endpoint = 200
        
        for endpoint in endpoints:
            logger.info(f"DDoS simulation on {endpoint['url']}")
            results = []
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(ddos_attack, endpoint, i) 
                          for i in range(requests_per_endpoint)]
                
                for future in as_completed(futures):
                    results.append(future.result())
            
            # Analyze DDoS results
            successful_requests = [r for r in results if r.get("status_code") == 200]
            rate_limited_requests = [r for r in results if r.get("rate_limited")]
            timeout_requests = [r for r in results if r.get("timeout")]
            error_requests = [r for r in results if "error" in r]
            
            logger.info(f"DDoS results for {endpoint['url']}:")
            logger.info(f"  Total requests: {len(results)}")
            logger.info(f"  Successful: {len(successful_requests)}")
            logger.info(f"  Rate limited: {len(rate_limited_requests)}")
            logger.info(f"  Timeouts: {len(timeout_requests)}")
            logger.info(f"  Errors: {len(error_requests)}")
            
            # Security validations
            total_processed = len(successful_requests) + len(rate_limited_requests)
            
            # System should remain responsive (not all requests should timeout)
            timeout_rate = len(timeout_requests) / len(results)
            assert timeout_rate < 0.5, f"Too many timeouts ({timeout_rate:.2%}) - system may be overwhelmed"
            
            # Rate limiting should kick in for high request volumes
            if len(results) > 100:
                assert len(rate_limited_requests) > 0 or len(error_requests) > 0, \
                    "Rate limiting should engage under DDoS load"
    
    def test_memory_exhaustion_protection(self, api_client):
        """
        Test protection against memory exhaustion attacks
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Test large payload attacks
        large_payloads = [
            {"field": "first_name", "size": 1000000},  # 1MB
            {"field": "address", "size": 500000},      # 500KB
            {"field": "bet_amount", "size": 100000}    # 100KB
        ]
        
        for payload_test in large_payloads:
            large_data = "A" * payload_test["size"]
            
            logger.info(f"Testing large payload: {payload_test['field']} - {payload_test['size']} bytes")
            
            start_time = time.time()
            
            if payload_test["field"] == "bet_amount":
                # Test large bet data
                response = api_client.place_bet({
                    "match_id": 1,
                    "bet_type": "home_win",
                    "amount": large_data,  # Invalid large string
                    "odds": 2.0
                })
            else:
                # Test large profile data
                response = api_client.update_profile({payload_test["field"]: large_data})
            
            end_time = time.time()
            response_time = end_time - start_time
            
            logger.info(f"Large payload response: {response.status_code} in {response_time:.3f}s")
            
            # Security validations
            assert response.status_code != 200, "Large payloads should be rejected"
            assert response_time < 10.0, "Server should reject large payloads quickly"
            
            # Should get appropriate error
            if response.status_code == 400:
                response_data = response.json()
                assert "error" in response_data, "Should return error message for large payload"
    
    def test_rapid_profile_update_stress(self, api_client):
        """
        Test rapid profile updates under stress
        Verify fraud detection and rate limiting
        """
        # Login with verified user to avoid verification errors
        login_response = api_client.login("verified_user", "password123")
        assert login_response.status_code == 200
        
        def rapid_profile_update(update_id):
            """Rapid profile update function"""
            try:
                profile_data = {
                    "first_name": f"StressTest{update_id}",
                    "address": f"Address {update_id}"
                }
                
                start_time = time.time()
                response = api_client.update_profile(profile_data)
                end_time = time.time()
                
                return {
                    "update_id": update_id,
                    "response_time": end_time - start_time,
                    "status_code": response.status_code,
                    "response_data": response.json(),
                    "fraud_detected": response.status_code == 429
                }
                
            except Exception as e:
                return {
                    "update_id": update_id,
                    "error": str(e),
                    "success": False
                }
        
        # Execute rapid profile updates
        rapid_updates = 20
        results = []
        
        logger.info(f"Testing rapid profile updates: {rapid_updates} updates")
        
        # Execute updates with minimal delay
        for i in range(rapid_updates):
            result = rapid_profile_update(i)
            results.append(result)
            time.sleep(0.1)  # Minimal delay to simulate rapid updates
        
        # Analyze results
        successful_updates = [r for r in results if r.get("status_code") == 200]
        fraud_detected = [r for r in results if r.get("fraud_detected")]
        rate_limited = [r for r in results if r.get("status_code") == 429]
        
        logger.info(f"Rapid profile update stress results:")
        logger.info(f"  Total updates: {len(results)}")
        logger.info(f"  Successful: {len(successful_updates)}")
        logger.info(f"  Fraud detected: {len(fraud_detected)}")
        logger.info(f"  Rate limited: {len(rate_limited)}")
        
        # Security validations
        assert len(results) == rapid_updates, "All update attempts should be processed"
        
        # Should detect rapid changes and trigger fraud prevention
        if len(results) > 5:
            fraud_prevention_triggered = len(fraud_detected) > 0 or len(rate_limited) > 0
            assert fraud_prevention_triggered, "Rapid profile changes should trigger fraud detection"
    
    def test_concurrent_user_sessions(self, api_client):
        """
        Test multiple concurrent user sessions
        Verify session management and security
        """
        def create_user_session(user_id):
            """Create and test user session"""
            try:
                # Create new API client for each user
                session = requests.Session()
                
                # Login
                login_response = session.post("http://localhost:5000/login",
                                            json={"username": "testuser", "password": "password123"})
                
                if login_response.status_code == 200:
                    token = login_response.json().get("token")
                    session.headers.update({"Authorization": f"Bearer {token}"})
                    
                    # Test session with some operations
                    operations = []
                    
                    # Get user limits
                    limits_response = session.get("http://localhost:5000/user_limits")
                    operations.append({"operation": "limits", "status": limits_response.status_code})
                    
                    # Get bet history
                    history_response = session.get("http://localhost:5000/bet_history")
                    operations.append({"operation": "history", "status": history_response.status_code})
                    
                    # Place a bet
                    bet_response = session.post("http://localhost:5000/bet", json={
                        "match_id": 1,
                        "bet_type": "home_win",
                        "amount": 50,
                        "odds": 2.0
                    })
                    operations.append({"operation": "bet", "status": bet_response.status_code})
                    
                    return {
                        "user_id": user_id,
                        "login_success": True,
                        "token": token,
                        "operations": operations
                    }
                else:
                    return {
                        "user_id": user_id,
                        "login_success": False,
                        "error": login_response.json()
                    }
                    
            except Exception as e:
                return {
                    "user_id": user_id,
                    "error": str(e),
                    "login_success": False
                }
        
        # Test concurrent sessions
        concurrent_users = 25
        results = []
        
        logger.info(f"Testing concurrent user sessions: {concurrent_users} users")
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(create_user_session, i) for i in range(concurrent_users)]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        # Analyze session results
        successful_sessions = [r for r in results if r.get("login_success")]
        failed_sessions = [r for r in results if not r.get("login_success")]
        
        # Check for unique tokens (no token reuse)
        tokens = [r.get("token") for r in successful_sessions if r.get("token")]
        unique_tokens = set(tokens)
        
        logger.info(f"Concurrent session results:")
        logger.info(f"  Total sessions: {len(results)}")
        logger.info(f"  Successful logins: {len(successful_sessions)}")
        logger.info(f"  Failed logins: {len(failed_sessions)}")
        logger.info(f"  Unique tokens: {len(unique_tokens)}")
        
        # Security validations
        assert len(results) == concurrent_users, "All session attempts should be processed"
        
        # Should generate unique tokens for each session
        assert len(unique_tokens) == len(successful_sessions), \
            "Each successful session should have a unique token"
        
        # Most sessions should succeed under normal load
        success_rate = len(successful_sessions) / len(results)
        assert success_rate > 0.8, f"Success rate too low: {success_rate:.2%}"
    
    @pytest.mark.slow
    def test_sustained_load_testing(self, api_client):
        """
        Sustained load test over extended period
        Verify system stability and memory management
        """
        # Login first
        login_response = api_client.login("testuser", "password123")
        assert login_response.status_code == 200
        
        # Reset limits for extended testing
        requests.post("http://localhost:5000/admin/reset_limits", 
                     json={"username": "testuser"})
        
        test_duration = 60  # 1 minute sustained test
        request_interval = 0.5  # Request every 500ms
        
        results = []
        start_time = time.time()
        
        logger.info(f"Starting sustained load test for {test_duration} seconds")
        
        while time.time() - start_time < test_duration:
            operation_start = time.time()
            
            # Mix of operations
            operations = [
                lambda: api_client.get_user_limits(),
                lambda: api_client.get_bet_history(),
                lambda: api_client.place_bet({
                    "match_id": 1, "bet_type": "home_win", "amount": 10, "odds": 2.0
                })
            ]
            
            # Random operation
            import random
            operation = random.choice(operations)
            
            try:
                response = operation()
                operation_end = time.time()
                
                results.append({
                    "timestamp": operation_start,
                    "response_time": operation_end - operation_start,
                    "status_code": response.status_code,
                    "success": response.status_code in [200, 400]  # 400 is OK for limit violations
                })
                
            except Exception as e:
                results.append({
                    "timestamp": operation_start,
                    "error": str(e),
                    "success": False
                })
            
            # Wait for next request
            time.sleep(request_interval)
        
        total_test_time = time.time() - start_time
        
        # Analyze sustained load results
        successful_ops = [r for r in results if r.get("success")]
        failed_ops = [r for r in results if not r.get("success")]
        response_times = [r["response_time"] for r in successful_ops if "response_time" in r]
        
        logger.info(f"Sustained load test results:")
        logger.info(f"  Test duration: {total_test_time:.2f}s")
        logger.info(f"  Total operations: {len(results)}")
        logger.info(f"  Successful: {len(successful_ops)}")
        logger.info(f"  Failed: {len(failed_ops)}")
        logger.info(f"  Operations/second: {len(results)/total_test_time:.2f}")
        
        if response_times:
            logger.info(f"  Avg response time: {statistics.mean(response_times):.3f}s")
            logger.info(f"  Max response time: {max(response_times):.3f}s")
        
        # Performance validations
        success_rate = len(successful_ops) / len(results) if results else 0
        assert success_rate > 0.8, f"Success rate too low during sustained load: {success_rate:.2%}"
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            assert avg_response_time < 3.0, f"Average response time too high: {avg_response_time:.3f}s"