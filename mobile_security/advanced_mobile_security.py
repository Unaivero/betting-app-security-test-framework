d', False),
                'developer_options_enabled': usb_debug_status.get('developer_options', False),
                'risk_level': 'high' if usb_debug_status['enabled'] else 'low',
                'details': f"USB debugging: {'enabled' if usb_debug_status['enabled'] else 'disabled'}"
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'risk_level': 'unknown'
            }
    
    def _test_unknown_sources_policy(self) -> Dict:
        """Test unknown sources installation policy"""
        try:
            unknown_sources_status = self._check_unknown_sources()
            
            return {
                'status': 'blocked' if not unknown_sources_status['allowed'] else 'allowed',
                'install_unknown_apps': unknown_sources_status.get('allowed', True),
                'per_app_permission': unknown_sources_status.get('per_app_permission', False),
                'risk_level': 'high' if unknown_sources_status['allowed'] else 'low',
                'details': f"Unknown sources: {'allowed' if unknown_sources_status['allowed'] else 'blocked'}"
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'risk_level': 'unknown'
            }
    
    def _test_device_admin_policy(self) -> Dict:
        """Test device administrator policy"""
        try:
            device_admin_status = self._check_device_admin()
            
            return {
                'status': device_admin_status['status'],
                'admin_apps': device_admin_status.get('admin_apps', []),
                'admin_count': len(device_admin_status.get('admin_apps', [])),
                'mdm_enrolled': device_admin_status.get('mdm_enrolled', False),
                'risk_level': device_admin_status.get('risk_level', 'medium'),
                'details': f"Device admin: {len(device_admin_status.get('admin_apps', []))} apps"
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'risk_level': 'unknown'
            }
    
    def _test_location_services_policy(self) -> Dict:
        """Test location services policy"""
        try:
            location_policy = self._check_location_services()
            
            return {
                'status': location_policy['status'],
                'location_enabled': location_policy.get('enabled', False),
                'high_accuracy_mode': location_policy.get('high_accuracy', False),
                'location_history': location_policy.get('location_history', False),
                'risk_level': location_policy.get('risk_level', 'medium'),
                'details': f"Location services: {location_policy['status']}"
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'risk_level': 'unknown'
            }
    
    def _test_biometric_auth_policy(self) -> Dict:
        """Test biometric authentication policy"""
        try:
            biometric_policy = self._check_biometric_auth()
            
            return {
                'status': biometric_policy['status'],
                'fingerprint_enabled': biometric_policy.get('fingerprint', False),
                'face_unlock_enabled': biometric_policy.get('face_unlock', False),
                'biometric_prompt_available': biometric_policy.get('biometric_prompt', False),
                'risk_level': biometric_policy.get('risk_level', 'low'),
                'details': f"Biometric auth: {biometric_policy['status']}"
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'risk_level': 'unknown'
            }
    
    # Helper methods for device policy testing
    def _check_screen_lock_status(self) -> Dict:
        """Check screen lock configuration"""
        try:
            # Simulate checking screen lock via adb or system APIs
            result = subprocess.run(['adb', 'shell', 'dumpsys', 'trust'], 
                                  capture_output=True, text=True, timeout=10)
            
            # Parse output to determine lock status
            # This is simplified for testing
            return {
                'is_secured': True,  # Simulate secure lock
                'lock_type': 'pattern',  # Simulate pattern lock
                'timeout_configured': True
            }
            
        except Exception as e:
            return {
                'is_secured': False,
                'error': str(e)
            }
    
    def _check_device_encryption(self) -> Dict:
        """Check device encryption status"""
        try:
            # Check encryption status
            result = subprocess.run(['adb', 'shell', 'getprop', 'ro.crypto.state'], 
                                  capture_output=True, text=True, timeout=10)
            
            encrypted = 'encrypted' in result.stdout.lower()
            
            return {
                'is_encrypted': encrypted,
                'encryption_type': 'file' if encrypted else 'none',
                'file_based_encryption': encrypted
            }
            
        except Exception as e:
            return {
                'is_encrypted': False,
                'error': str(e)
            }
    
    def _check_app_installation_policy(self) -> Dict:
        """Check app installation policy"""
        try:
            # Simulate policy checks
            return {
                'status': 'restricted',
                'play_protect_enabled': True,
                'unknown_sources_allowed': False,
                'app_verification_enabled': True,
                'risk_level': 'low'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'risk_level': 'unknown'
            }
    
    def _check_usb_debugging(self) -> Dict:
        """Check USB debugging status"""
        try:
            result = subprocess.run(['adb', 'shell', 'getprop', 'ro.debuggable'], 
                                  capture_output=True, text=True, timeout=10)
            
            debug_enabled = '1' in result.stdout.strip()
            
            return {
                'enabled': debug_enabled,
                'developer_options': debug_enabled
            }
            
        except Exception as e:
            return {
                'enabled': False,
                'error': str(e)
            }
    
    def _check_unknown_sources(self) -> Dict:
        """Check unknown sources policy"""
        try:
            # Check unknown sources setting
            result = subprocess.run(['adb', 'shell', 'settings', 'get', 'global', 'install_non_market_apps'], 
                                  capture_output=True, text=True, timeout=10)
            
            allowed = '1' in result.stdout.strip()
            
            return {
                'allowed': allowed,
                'per_app_permission': not allowed  # Android 8+ uses per-app permissions
            }
            
        except Exception as e:
            return {
                'allowed': True,  # Default to unsafe assumption
                'error': str(e)
            }
    
    def _check_device_admin(self) -> Dict:
        """Check device administrator apps"""
        try:
            # List device admin apps
            result = subprocess.run(['adb', 'shell', 'dpm', 'list-owners'], 
                                  capture_output=True, text=True, timeout=10)
            
            admin_apps = []
            if result.stdout:
                # Parse admin apps from output
                lines = result.stdout.strip().split('\n')
                admin_apps = [line.strip() for line in lines if line.strip()]
            
            return {
                'status': 'managed' if admin_apps else 'unmanaged',
                'admin_apps': admin_apps,
                'mdm_enrolled': len(admin_apps) > 0,
                'risk_level': 'low' if admin_apps else 'medium'
            }
            
        except Exception as e:
            return {
                'status': 'unknown',
                'admin_apps': [],
                'error': str(e),
                'risk_level': 'medium'
            }
    
    def _check_location_services(self) -> Dict:
        """Check location services configuration"""
        try:
            # Check location services
            result = subprocess.run(['adb', 'shell', 'settings', 'get', 'secure', 'location_providers_allowed'], 
                                  capture_output=True, text=True, timeout=10)
            
            location_enabled = bool(result.stdout.strip())
            
            return {
                'status': 'enabled' if location_enabled else 'disabled',
                'enabled': location_enabled,
                'high_accuracy': location_enabled,  # Simplified
                'location_history': False,  # Simplified
                'risk_level': 'medium' if location_enabled else 'low'
            }
            
        except Exception as e:
            return {
                'status': 'unknown',
                'error': str(e),
                'risk_level': 'medium'
            }
    
    def _check_biometric_auth(self) -> Dict:
        """Check biometric authentication availability"""
        try:
            # Check for biometric hardware
            fingerprint_result = subprocess.run(['adb', 'shell', 'getprop', 'ro.hardware.fingerprint'], 
                                              capture_output=True, text=True, timeout=10)
            
            fingerprint_available = bool(fingerprint_result.stdout.strip())
            
            return {
                'status': 'available' if fingerprint_available else 'unavailable',
                'fingerprint': fingerprint_available,
                'face_unlock': False,  # Simplified
                'biometric_prompt': fingerprint_available,
                'risk_level': 'low'
            }
            
        except Exception as e:
            return {
                'status': 'unknown',
                'error': str(e),
                'risk_level': 'medium'
            }
