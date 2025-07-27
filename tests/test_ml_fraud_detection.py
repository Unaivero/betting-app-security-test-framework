        ]
        
        # Analyze session patterns
        session_patterns = analyzer._identify_session_patterns(betting_times)
        
        # Should detect different session types
        expected_patterns = ['burst_session', 'marathon_session']
        detected_patterns = [pattern for pattern in expected_patterns if pattern in session_patterns]
        
        assert len(detected_patterns) > 0, f"Should detect session patterns: {session_patterns}"
        
        logger.info(f"✓ Session patterns detected: {session_patterns}")
    
    def test_coordinated_betting_detection(self):
        """Test detection of coordinated betting between users"""
        logger.info("Testing coordinated betting detection")
        
        analyzer = CrossUserCorrelationAnalyzer()
        
        # Create coordinated users (betting on same events at similar times)
        base_time = datetime.now()
        
        coordinated_user_1 = {
            'user_id': 'coord_user_1',
            'bets': [
                {'match_id': 5, 'bet_type': 'home_win', 'amount': 800, 
                 'timestamp': (base_time - timedelta(minutes=30)).isoformat()},
                {'match_id': 7, 'bet_type': 'away_win', 'amount': 900, 
                 'timestamp': (base_time - timedelta(minutes=25)).isoformat()},
                {'match_id': 3, 'bet_type': 'draw', 'amount': 750, 
                 'timestamp': (base_time - timedelta(minutes=20)).isoformat()},
            ],
            'device_fingerprints': ['device_coord_1'],
            'ip_addresses': ['203.0.113.100'],
            'payment_methods': ['card_coord_1']
        }
        
        coordinated_user_2 = {
            'user_id': 'coord_user_2',
            'bets': [
                {'match_id': 5, 'bet_type': 'home_win', 'amount': 850, 
                 'timestamp': (base_time - timedelta(minutes=29)).isoformat()},
                {'match_id': 7, 'bet_type': 'away_win', 'amount': 900, 
                 'timestamp': (base_time - timedelta(minutes=24)).isoformat()},
                {'match_id': 3, 'bet_type': 'draw', 'amount': 800, 
                 'timestamp': (base_time - timedelta(minutes=19)).isoformat()},
            ],
            'device_fingerprints': ['device_coord_2'],
            'ip_addresses': ['203.0.113.101'],
            'payment_methods': ['card_coord_2']
        }
        
        # Add to analyzer
        analyzer.add_user_profile('coord_user_1', coordinated_user_1)
        analyzer.add_user_profile('coord_user_2', coordinated_user_2)
        
        # Analyze correlations
        results = analyzer.analyze_cross_user_correlations()
        
        # Should detect coordination
        correlations = results['correlation_details']
        coordination_detected = any(c['correlation_score'] > 0.6 for c in correlations)
        
        assert coordination_detected, f"Should detect coordinated betting: {correlations}"
        
        logger.info(f"✓ Coordinated betting detected")
    
    def test_account_takeover_pattern_detection(self):
        """Test detection of account takeover patterns"""
        logger.info("Testing account takeover pattern detection")
        
        detector = BehavioralAnomalyDetector()
        
        # Create user data showing account takeover pattern
        takeover_user = {
            'user_id': 'takeover_user',
            'bets': [
                # Normal betting pattern first
                {'match_id': 1, 'bet_type': 'home_win', 'amount': 50, 
                 'timestamp': (datetime.now() - timedelta(days=10)).isoformat()},
                {'match_id': 2, 'bet_type': 'draw', 'amount': 75, 
                 'timestamp': (datetime.now() - timedelta(days=9)).isoformat()},
                {'match_id': 3, 'bet_type': 'away_win', 'amount': 100, 
                 'timestamp': (datetime.now() - timedelta(days=8)).isoformat()},
                
                # Sudden change in pattern (takeover)
                {'match_id': 1, 'bet_type': 'home_win', 'amount': 1000, 
                 'timestamp': (datetime.now() - timedelta(hours=2)).isoformat()},
                {'match_id': 1, 'bet_type': 'home_win', 'amount': 1000, 
                 'timestamp': (datetime.now() - timedelta(hours=1)).isoformat()},
                {'match_id': 1, 'bet_type': 'home_win', 'amount': 1000, 
                 'timestamp': datetime.now().isoformat()},
            ],
            'profile_changes': [
                # Multiple critical changes in short time
                {'field': 'email', 'timestamp': (datetime.now() - timedelta(hours=3)).isoformat()},
                {'field': 'phone', 'timestamp': (datetime.now() - timedelta(hours=2)).isoformat()},
                {'field': 'bank_account', 'timestamp': (datetime.now() - timedelta(hours=1)).isoformat()},
            ],
            'sessions': [
                # Different device/IP pattern
                {'duration': 3600, 'concurrent_count': 1, 'ip_address': '10.0.0.1'},  # Historical
                {'duration': 300, 'concurrent_count': 3, 'ip_address': '203.0.113.50'},  # Recent
            ],
            'created_at': (datetime.now() - timedelta(days=365)).isoformat(),  # Old account
            'verification_score': 80,  # Was verified
            'failed_login_attempts': 12,  # Recent failed attempts
            'password_changes': 3,  # Recent password changes
            'device_fingerprints': ['old_device', 'new_device_1', 'new_device_2']
        }
        
        # Train with normal data
        normal_training_data = [self._generate_normal_user_data(f"normal_{i}") for i in range(20)]
        detector.fit(normal_training_data)
        
        # Test takeover detection
        result = detector.predict_anomaly(takeover_user)
        
        # Should detect high risk due to pattern change
        assert result['risk_level'] in ['medium', 'high'], f"Should detect account takeover risk: {result}"
        
        # Should identify relevant features
        important_features = result['feature_importance']
        takeover_indicators = ['critical_changes', 'max_concurrent_sessions', 'failed_login_attempts']
        
        detected_indicators = [indicator for indicator in takeover_indicators if indicator in important_features]
        assert len(detected_indicators) > 0, f"Should detect takeover indicators: {important_features}"
        
        logger.info(f"✓ Account takeover pattern detected: {result['risk_level']} risk")
        logger.info(f"  Indicators: {list(important_features.keys())[:3]}")
    
    def _generate_normal_user_data(self, user_id: str) -> dict:
        """Generate normal user data for testing"""
        now = datetime.now()
        return {
            'user_id': user_id,
            'bets': [
                {'match_id': fake.random_int(1, 10), 'bet_type': fake.random_element(['home_win', 'draw', 'away_win']),
                 'amount': fake.random_int(10, 200), 'timestamp': (now - timedelta(hours=i)).isoformat()}
                for i in range(fake.random_int(5, 15))
            ],
            'profile_changes': [],
            'sessions': [{'duration': fake.random_int(600, 3600), 'concurrent_count': 1, 'ip_address': fake.ipv4()}],
            'created_at': (now - timedelta(days=fake.random_int(30, 365))).isoformat(),
            'verification_score': fake.random_int(70, 100),
            'failed_login_attempts': fake.random_int(0, 2),
            'password_changes': fake.random_int(0, 1),
            'device_fingerprints': [fake.uuid4()],
            'ip_addresses': [fake.ipv4()],
            'payment_methods': [f"card_{fake.random_int(1000, 9999)}"]
        }
