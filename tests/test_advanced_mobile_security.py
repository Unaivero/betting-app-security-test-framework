-tampering analysis")
        
        tampering_analysis = binary_analyzer._analyze_anti_tampering()
        
        # Verify analysis structure
        assert 'status' in tampering_analysis
        assert 'protection_mechanisms' in tampering_analysis
        assert 'protection_count' in tampering_analysis
        assert 'protection_level' in tampering_analysis
        
        mechanisms = tampering_analysis['protection_mechanisms']
        count = tampering_analysis['protection_count']
        level = tampering_analysis['protection_level']
        
        logger.info(f"Anti-tampering mechanisms: {count}/{len(mechanisms)}")
        logger.info(f"Protection level: {level}")
        
        # Log individual mechanisms
        for mechanism, present in mechanisms.items():
            status = "IMPLEMENTED" if present else "MISSING"
            logger.info(f"  {mechanism}: {status}")
        
        # Security assessment
        if level == 'strong':
            logger.info("✓ Strong anti-tampering protection")
            assert tampering_analysis['risk_level'] == 'low'
        elif level == 'moderate':
            logger.info("ℹ️  Moderate anti-tampering protection")
            assert tampering_analysis['risk_level'] == 'medium'
        else:
            logger.warning("⚠️  Weak anti-tampering protection - HIGH RISK")
            assert tampering_analysis['risk_level'] == 'high'
    
    def test_cryptographic_implementation_analysis(self, binary_analyzer):
        """Test cryptographic implementation analysis"""
        logger.info("Testing cryptographic implementation analysis")
        
        crypto_analysis = binary_analyzer._analyze_crypto_usage()
        
        # Verify analysis structure
        assert 'status' in crypto_analysis
        assert 'vulnerabilities' in crypto_analysis
        assert 'vulnerability_count' in crypto_analysis
        assert 'security_rating' in crypto_analysis
        assert 'analysis_details' in crypto_analysis
        
        vulnerabilities = crypto_analysis['vulnerabilities']
        count = crypto_analysis['vulnerability_count']
        rating = crypto_analysis['security_rating']
        details = crypto_analysis['analysis_details']
        
        logger.info(f"Crypto vulnerabilities: {count}")
        logger.info(f"Security rating: {rating}")
        
        # Log vulnerabilities
        for vuln in vulnerabilities:
            logger.warning(f"  - {vuln}")
        
        # Log detailed analysis
        for check, result in details.items():
            status = "VULNERABLE" if result else "SECURE"
            logger.info(f"  {check}: {status}")
        
        # Security assessment
        if rating == 'good':
            logger.info("✓ Good cryptographic implementation")
            assert crypto_analysis['risk_level'] == 'low'
        elif rating == 'moderate':
            logger.info("ℹ️  Moderate cryptographic security")
            assert crypto_analysis['risk_level'] == 'medium'
        else:
            logger.warning("⚠️  Poor cryptographic implementation - HIGH RISK")
            assert crypto_analysis['risk_level'] == 'high'
    
    def test_native_library_analysis(self, binary_analyzer):
        """Test native library security analysis"""
        logger.info("Testing native library analysis")
        
        native_analysis = binary_analyzer._analyze_native_libraries()
        
        # Verify analysis structure
        assert 'status' in native_analysis
        
        if native_analysis['status'] == 'analyzed':
            assert 'library_count' in native_analysis
            assert 'libraries' in native_analysis
            assert 'overall_risk' in native_analysis
            
            lib_count = native_analysis['library_count']
            libraries = native_analysis['libraries']
            overall_risk = native_analysis['overall_risk']
            
            logger.info(f"Native libraries analyzed: {lib_count}")
            logger.info(f"Overall risk: {overall_risk}")
            
            # Log individual library analysis
            for lib in libraries:
                lib_name = lib['name']
                lib_risk = lib['analysis']['risk_level']
                logger.info(f"  {lib_name}: {lib_risk} risk")
                
                if lib['analysis'].get('is_vulnerable', False):
                    logger.warning(f"    ⚠️  Vulnerable library detected")
                
                if lib['analysis'].get('has_debug_symbols', False):
                    logger.info(f"    ℹ️  Debug symbols present")
            
            # Overall assessment
            high_risk_count = native_analysis.get('high_risk_count', 0)
            if high_risk_count > 0:
                logger.warning(f"⚠️  {high_risk_count} high-risk native libraries")
            else:
                logger.info("✓ No high-risk native libraries detected")
        
        elif native_analysis['status'] == 'no_native_libs':
            logger.info("ℹ️  No native libraries found")
            assert native_analysis['risk_level'] == 'low'
        
        logger.info(f"Native library analysis: {native_analysis['status']}")
    
    def test_certificate_analysis(self, binary_analyzer):
        """Test application certificate analysis"""
        logger.info("Testing certificate analysis")
        
        cert_analysis = binary_analyzer._analyze_certificates()
        
        # Verify analysis structure
        assert 'status' in cert_analysis
        
        if cert_analysis['status'] == 'analyzed':
            assert 'certificate_count' in cert_analysis
            assert 'certificates' in cert_analysis
            assert 'security_status' in cert_analysis
            
            cert_count = cert_analysis['certificate_count']
            certificates = cert_analysis['certificates']
            security_status = cert_analysis['security_status']
            
            logger.info(f"Certificates analyzed: {cert_count}")
            logger.info(f"Security status: {security_status}")
            
            # Check for security issues
            debug_count = cert_analysis.get('debug_certificates', 0)
            weak_count = cert_analysis.get('weak_certificates', 0)
            
            if debug_count > 0:
                logger.warning(f"⚠️  {debug_count} debug certificates found - HIGH RISK")
                assert cert_analysis['risk_level'] == 'high'
            elif weak_count > 0:
                logger.warning(f"⚠️  {weak_count} weak certificates found - MEDIUM RISK")
                assert cert_analysis['risk_level'] == 'medium'
            else:
                logger.info("✓ Certificate security acceptable")
                assert cert_analysis['risk_level'] == 'low'
            
            # Log individual certificates
            for cert in certificates:
                cert_name = cert['name']
                is_debug = cert.get('is_debug', False)
                is_weak = cert.get('is_weak', False)
                
                if is_debug:
                    logger.warning(f"  {cert_name}: DEBUG CERTIFICATE")
                elif is_weak:
                    logger.warning(f"  {cert_name}: WEAK CERTIFICATE")
                else:
                    logger.info(f"  {cert_name}: OK")
        
        elif cert_analysis['status'] == 'no_certificates':
            logger.warning("⚠️  No certificates found - HIGH RISK")
            assert cert_analysis['risk_level'] == 'high'
        
        logger.info(f"Certificate analysis: {cert_analysis['status']}")

@pytest.mark.mobile_security
@pytest.mark.device_policy
class TestMobileDevicePolicySecurity:
    """Test mobile device security policy enforcement"""
    
    @pytest.fixture
    def policy_tester(self):
        """Initialize device policy tester"""
        return MobileDevicePolicyTester(app_package="com.betting.app")
    
    def test_comprehensive_device_policy_testing(self, policy_tester):
        """Test comprehensive device security policy enforcement"""
        logger.info("Testing comprehensive device security policies")
        
        # Run comprehensive policy tests
        results = policy_tester.test_device_security_policies()
        
        # Verify test structure
        assert 'app_package' in results
        assert 'timestamp' in results
        assert 'policy_tests' in results
        assert results['app_package'] == "com.betting.app"
        
        # Check all policy categories
        expected_policies = [
            'screen_lock',
            'encryption',
            'app_installation',
            'usb_debugging',
            'unknown_sources',
            'device_admin',
            'location_services',
            'biometric_auth'
        ]
        
        policy_violations = 0
        secure_policies = 0
        
        for policy_name in expected_policies:
            assert policy_name in results['policy_tests'], f"Missing policy test: {policy_name}"
            policy_result = results['policy_tests'][policy_name]
            assert 'status' in policy_result
            assert 'risk_level' in policy_result
            
            if policy_result['risk_level'] == 'high':
                policy_violations += 1
                logger.warning(f"  ⚠️  {policy_name}: {policy_result['status']} (HIGH RISK)")
            elif policy_result['risk_level'] == 'low':
                secure_policies += 1
                logger.info(f"  ✓ {policy_name}: {policy_result['status']} (SECURE)")
            else:
                logger.info(f"  ℹ️  {policy_name}: {policy_result['status']} (MEDIUM RISK)")
        
        logger.info(f"✓ Device Policy Test Summary:")
        logger.info(f"  Total policies tested: {len(results['policy_tests'])}")
        logger.info(f"  Policy violations: {policy_violations}")
        logger.info(f"  Secure policies: {secure_policies}")
        
        # Overall security assessment
        if policy_violations > 3:
            logger.warning("⚠️  Multiple device policy violations - Review device security")
        elif policy_violations > 1:
            logger.info("ℹ️  Some device policy issues - Consider hardening")
        else:
            logger.info("✓ Device security policies well enforced")
    
    @patch('mobile_security.advanced_mobile_security.subprocess.run')
    def test_screen_lock_policy(self, mock_subprocess, policy_tester):
        """Test screen lock policy enforcement"""
        logger.info("Testing screen lock policy")
        
        # Mock secure screen lock
        mock_subprocess.return_value.stdout = "Trust state: secured"
        mock_subprocess.return_value.returncode = 0
        
        screen_lock_test = policy_tester._test_screen_lock_policy()
        
        # Verify test structure
        assert 'status' in screen_lock_test
        assert 'lock_type' in screen_lock_test
        assert 'risk_level' in screen_lock_test
        
        if screen_lock_test['status'] == 'enforced':
            logger.info(f"✓ Screen lock enforced: {screen_lock_test['lock_type']}")
            assert screen_lock_test['risk_level'] == 'low'
        else:
            logger.warning("⚠️  Screen lock not enforced - HIGH RISK")
            assert screen_lock_test['risk_level'] == 'high'
        
        logger.info(f"Screen lock policy: {screen_lock_test['status']}")
    
    @patch('mobile_security.advanced_mobile_security.subprocess.run')
    def test_device_encryption_policy(self, mock_subprocess, policy_tester):
        """Test device encryption policy"""
        logger.info("Testing device encryption policy")
        
        # Mock encrypted device
        mock_subprocess.return_value.stdout = "encrypted"
        mock_subprocess.return_value.returncode = 0
        
        encryption_test = policy_tester._test_device_encryption_policy()
        
        # Verify test structure
        assert 'status' in encryption_test
        assert 'encryption_type' in encryption_test
        assert 'risk_level' in encryption_test
        
        if encryption_test['status'] == 'enforced':
            logger.info(f"✓ Device encryption enabled: {encryption_test['encryption_type']}")
            assert encryption_test['risk_level'] == 'low'
        else:
            logger.warning("⚠️  Device encryption not enabled - HIGH RISK")
            assert encryption_test['risk_level'] == 'high'
        
        logger.info(f"Device encryption: {encryption_test['status']}")
    
    @patch('mobile_security.advanced_mobile_security.subprocess.run')
    def test_usb_debugging_policy(self, mock_subprocess, policy_tester):
        """Test USB debugging policy"""
        logger.info("Testing USB debugging policy")
        
        # Mock USB debugging disabled
        mock_subprocess.return_value.stdout = "0"
        mock_subprocess.return_value.returncode = 0
        
        usb_debug_test = policy_tester._test_usb_debugging_policy()
        
        # Verify test structure
        assert 'status' in usb_debug_test
        assert 'adb_enabled' in usb_debug_test
        assert 'risk_level' in usb_debug_test
        
        if usb_debug_test['status'] == 'disabled':
            logger.info("✓ USB debugging properly disabled")
            assert usb_debug_test['risk_level'] == 'low'
        else:
            logger.warning("⚠️  USB debugging enabled - HIGH RISK")
            assert usb_debug_test['risk_level'] == 'high'
        
        logger.info(f"USB debugging: {usb_debug_test['status']}")
    
    def test_app_installation_policy(self, policy_tester):
        """Test app installation policy"""
        logger.info("Testing app installation policy")
        
        installation_test = policy_tester._test_app_installation_policy()
        
        # Verify test structure
        assert 'status' in installation_test
        assert 'play_protect_enabled' in installation_test
        assert 'unknown_sources_allowed' in installation_test
        assert 'app_verification_enabled' in installation_test
        
        play_protect = installation_test['play_protect_enabled']
        unknown_sources = installation_test['unknown_sources_allowed']
        verification = installation_test['app_verification_enabled']
        
        logger.info(f"Play Protect: {'ENABLED' if play_protect else 'DISABLED'}")
        logger.info(f"Unknown sources: {'ALLOWED' if unknown_sources else 'BLOCKED'}")
        logger.info(f"App verification: {'ENABLED' if verification else 'DISABLED'}")
        
        # Security assessment
        security_features = sum([play_protect, not unknown_sources, verification])
        
        if security_features >= 2:
            logger.info("✓ Good app installation security")
        else:
            logger.warning("⚠️  Weak app installation security")
        
        logger.info(f"App installation policy: {installation_test['status']}")
    
    @patch('mobile_security.advanced_mobile_security.subprocess.run')
    def test_device_admin_policy(self, mock_subprocess, policy_tester):
        """Test device administrator policy"""
        logger.info("Testing device administrator policy")
        
        # Mock managed device
        mock_subprocess.return_value.stdout = "com.company.mdm"
        mock_subprocess.return_value.returncode = 0
        
        device_admin_test = policy_tester._test_device_admin_policy()
        
        # Verify test structure
        assert 'status' in device_admin_test
        assert 'admin_apps' in device_admin_test
        assert 'admin_count' in device_admin_test
        assert 'mdm_enrolled' in device_admin_test
        
        admin_count = device_admin_test['admin_count']
        mdm_enrolled = device_admin_test['mdm_enrolled']
        
        logger.info(f"Device admin apps: {admin_count}")
        logger.info(f"MDM enrolled: {'YES' if mdm_enrolled else 'NO'}")
        
        if mdm_enrolled:
            logger.info("✓ Device properly managed by MDM")
        else:
            logger.info("ℹ️  Device not managed by MDM")
        
        logger.info(f"Device admin policy: {device_admin_test['status']}")
    
    def test_biometric_authentication_policy(self, policy_tester):
        """Test biometric authentication policy"""
        logger.info("Testing biometric authentication policy")
        
        biometric_test = policy_tester._test_biometric_auth_policy()
        
        # Verify test structure
        assert 'status' in biometric_test
        assert 'fingerprint_enabled' in biometric_test
        assert 'biometric_prompt_available' in biometric_test
        
        fingerprint = biometric_test['fingerprint_enabled']
        face_unlock = biometric_test.get('face_unlock_enabled', False)
        biometric_prompt = biometric_test['biometric_prompt_available']
        
        logger.info(f"Fingerprint: {'AVAILABLE' if fingerprint else 'NOT AVAILABLE'}")
        logger.info(f"Face unlock: {'AVAILABLE' if face_unlock else 'NOT AVAILABLE'}")
        logger.info(f"Biometric prompt: {'AVAILABLE' if biometric_prompt else 'NOT AVAILABLE'}")
        
        # Security assessment
        biometric_methods = sum([fingerprint, face_unlock])
        
        if biometric_methods > 0:
            logger.info("✓ Biometric authentication available")
        else:
            logger.info("ℹ️  No biometric authentication available")
        
        logger.info(f"Biometric auth: {biometric_test['status']}")

@pytest.mark.mobile_security
@pytest.mark.integration
class TestMobileSecurityIntegration:
    """Integration tests for mobile security components"""
    
    def test_ssl_pinning_with_root_detection(self):
        """Test SSL pinning effectiveness on rooted devices"""
        logger.info("Testing SSL pinning on potentially rooted device")
        
        # Initialize both testers
        ssl_tester = SSLPinningTester("com.betting.app", "api.betting-app.com")
        root_tester = RootDetectionTester("com.betting.app")
        
        # Check root status first
        root_status = root_tester._check_device_root_status()
        ssl_results = ssl_tester.test_ssl_pinning_bypass()
        
        # Analyze correlation
        is_rooted = root_status['is_rooted']
        ssl_bypassed = any(test.get('status') == 'bypassed' 
                          for test in ssl_results['tests'].values())
        
        logger.info(f"Device rooted: {is_rooted}")
        logger.info(f"SSL pinning bypassed: {ssl_bypassed}")
        
        # Security correlation analysis
        if is_rooted and ssl_bypassed:
            logger.warning("⚠️  Rooted device with SSL pinning bypass - CRITICAL RISK")
        elif is_rooted and not ssl_bypassed:
            logger.info("ℹ️  Rooted device but SSL pinning holds - GOOD PROTECTION")
        elif not is_rooted and ssl_bypassed:
            logger.warning("⚠️  SSL bypass on non-rooted device - REVIEW IMPLEMENTATION")
        else:
            logger.info("✓ Non-rooted device with SSL pinning intact - SECURE")
    
    def test_comprehensive_mobile_security_posture(self):
        """Test comprehensive mobile security posture"""
        logger.info("Testing comprehensive mobile security posture")
        
        # Create temporary APK for testing
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp_apk:
            import zipfile
            with zipfile.ZipFile(tmp_apk.name, 'w') as zipf:
                zipf.writestr('AndroidManifest.xml', '<?xml version="1.0"?><manifest></manifest>')
                zipf.writestr('META-INF/CERT.RSA', 'certificate_content')
            
            try:
                # Initialize all testers
                ssl_tester = SSLPinningTester("com.betting.app", "api.betting-app.com")
                root_tester = RootDetectionTester("com.betting.app")
                binary_analyzer = BinarySecurityAnalyzer(tmp_apk.name)
                policy_tester = MobileDevicePolicyTester("com.betting.app")
                
                # Run all tests
                ssl_results = ssl_tester.test_ssl_pinning_bypass()
                root_results = root_tester.test_root_detection_bypass()
                binary_results = binary_analyzer.analyze_binary_security()
                policy_results = policy_tester.test_device_security_policies()
                
                # Aggregate security assessment
                security_scores = {
                    'ssl_pinning': self._assess_ssl_security(ssl_results),
                    'root_detection': self._assess_root_security(root_results),
                    'binary_security': self._assess_binary_security(binary_results),
                    'device_policy': self._assess_policy_security(policy_results)
                }
                
                overall_score = sum(security_scores.values()) / len(security_scores)
                
                logger.info("🔒 Comprehensive Mobile Security Assessment:")
                for category, score in security_scores.items():
                    logger.info(f"  {category}: {score:.2f}/10")
                
                logger.info(f"  Overall Security Score: {overall_score:.2f}/10")
                
                # Security recommendations
                if overall_score < 6:
                    logger.warning("⚠️  POOR mobile security posture - Immediate action required")
                elif overall_score < 8:
                    logger.info("ℹ️  MODERATE mobile security - Improvements recommended")
                else:
                    logger.info("✓ GOOD mobile security posture")
                
                # Detailed recommendations
                self._generate_security_recommendations(security_scores)
                
            finally:
                # Cleanup
                os.unlink(tmp_apk.name)
    
    def _assess_ssl_security(self, ssl_results: dict) -> float:
        """Assess SSL pinning security score"""
        tests = ssl_results.get('tests', {})
        secure_tests = sum(1 for test in tests.values() 
                          if test.get('risk_level') == 'low')
        return (secure_tests / len(tests)) * 10 if tests else 5
    
    def _assess_root_security(self, root_results: dict) -> float:
        """Assess root detection security score"""
        tests = root_results.get('tests', {})
        secure_tests = sum(1 for test in tests.values() 
                          if test.get('status') not in ['bypassed', 'hidden'])
        return (secure_tests / len(tests)) * 10 if tests else 5
    
    def _assess_binary_security(self, binary_results: dict) -> float:
        """Assess binary security score"""
        analyses = binary_results.get('analyses', {})
        secure_analyses = sum(1 for analysis in analyses.values() 
                             if analysis.get('risk_level') == 'low')
        return (secure_analyses / len(analyses)) * 10 if analyses else 5
    
    def _assess_policy_security(self, policy_results: dict) -> float:
        """Assess device policy security score"""
        policies = policy_results.get('policy_tests', {})
        secure_policies = sum(1 for policy in policies.values() 
                             if policy.get('risk_level') == 'low')
        return (secure_policies / len(policies)) * 10 if policies else 5
    
    def _generate_security_recommendations(self, security_scores: dict):
        """Generate security recommendations based on scores"""
        logger.info("📋 Security Recommendations:")
        
        for category, score in security_scores.items():
            if score < 6:
                if category == 'ssl_pinning':
                    logger.info("  • Implement stronger SSL certificate pinning")
                    logger.info("  • Add certificate transparency validation")
                elif category == 'root_detection':
                    logger.info("  • Enhance root detection mechanisms")
                    logger.info("  • Add runtime application self-protection (RASP)")
                elif category == 'binary_security':
                    logger.info("  • Implement code obfuscation")
                    logger.info("  • Add anti-debugging protections")
                elif category == 'device_policy':
                    logger.info("  • Enforce stricter device policies")
                    logger.info("  • Implement device compliance checking")
            elif score < 8:
                logger.info(f"  • {category.replace('_', ' ').title()}: Minor improvements needed")
