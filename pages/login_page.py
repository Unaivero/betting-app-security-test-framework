from selenium.webdriver.common.by import By
from pages.base_page import BasePage
import time

class LoginPage(BasePage):
    """Login page object model"""
    
    # Locators
    USERNAME_FIELD = (By.ID, "username")
    PASSWORD_FIELD = (By.ID, "password")
    LOGIN_BUTTON = (By.ID, "login-btn")
    ERROR_MESSAGE = (By.CLASS_NAME, "error-message")
    FORGOT_PASSWORD_LINK = (By.ID, "forgot-password")
    REGISTER_LINK = (By.ID, "register-link")
    REMEMBER_ME_CHECKBOX = (By.ID, "remember-me")
    
    # Security-related elements
    CAPTCHA_CONTAINER = (By.ID, "captcha-container")
    SECURITY_WARNING = (By.CLASS_NAME, "security-warning")
    FAILED_ATTEMPTS_WARNING = (By.ID, "failed-attempts-warning")
    ACCOUNT_LOCKED_MESSAGE = (By.ID, "account-locked")
    
    def __init__(self, driver):
        super().__init__(driver)
        self.page_url = "/login"
    
    def navigate_to_login(self):
        """Navigate to login page"""
        try:
            # For mobile app testing, this would navigate to login screen
            # For now, we'll simulate navigation
            self.logger.info("Navigating to login page")
            return True
        except Exception as e:
            self.logger.error(f"Failed to navigate to login: {str(e)}")
            return False
    
    def enter_username(self, username):
        """Enter username"""
        return self.enter_text(self.USERNAME_FIELD, username)
    
    def enter_password(self, password):
        """Enter password"""
        return self.enter_text(self.PASSWORD_FIELD, password)
    
    def click_login(self):
        """Click login button"""
        return self.click_element(self.LOGIN_BUTTON)
    
    def login(self, username, password):
        """Complete login process"""
        try:
            self.logger.info(f"Attempting login for user: {username}")
            
            if not self.enter_username(username):
                return False
            
            if not self.enter_password(password):
                return False
            
            if not self.click_login():
                return False
            
            # Wait for login to process
            time.sleep(2)
            
            # Check for success indicators or error messages
            if self.is_error_displayed():
                error_msg = self.get_error_message()
                self.logger.warning(f"Login failed with error: {error_msg}")
                return False
            
            self.logger.info(f"Login successful for user: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Login failed for {username}: {str(e)}")
            return False
    
    def get_error_message(self):
        """Get error message text"""
        try:
            return self.get_text(self.ERROR_MESSAGE)
        except:
            return ""
    
    def is_error_displayed(self):
        """Check if error message is displayed"""
        return self.is_element_visible(self.ERROR_MESSAGE)
    
    def is_captcha_displayed(self):
        """Check if CAPTCHA is displayed"""
        return self.is_element_visible(self.CAPTCHA_CONTAINER)
    
    def is_account_locked(self):
        """Check if account locked message is displayed"""
        return self.is_element_visible(self.ACCOUNT_LOCKED_MESSAGE)
    
    def get_failed_attempts_warning(self):
        """Get failed attempts warning text"""
        try:
            return self.get_text(self.FAILED_ATTEMPTS_WARNING)
        except:
            return ""
    
    def click_forgot_password(self):
        """Click forgot password link"""
        return self.click_element(self.FORGOT_PASSWORD_LINK)
    
    def click_register(self):
        """Click register link"""
        return self.click_element(self.REGISTER_LINK)
    
    def check_remember_me(self):
        """Check remember me checkbox"""
        try:
            checkbox = self.find_element(self.REMEMBER_ME_CHECKBOX)
            if not checkbox.is_selected():
                checkbox.click()
            return True
        except:
            return False
    
    def attempt_brute_force_login(self, username, password_list, delay=1):
        """
        Attempt brute force login for security testing
        This should trigger security measures
        """
        self.logger.info(f"Starting brute force test for user: {username}")
        results = []
        
        for i, password in enumerate(password_list):
            self.logger.info(f"Brute force attempt {i+1}: {password}")
            
            # Clear fields first
            self.enter_text(self.USERNAME_FIELD, "", clear_first=True)
            self.enter_text(self.PASSWORD_FIELD, "", clear_first=True)
            
            # Enter credentials
            self.enter_username(username)
            self.enter_password(password)
            self.click_login()
            
            # Wait and check result
            time.sleep(delay)
            
            result = {
                "attempt": i + 1,
                "password": password,
                "error_displayed": self.is_error_displayed(),
                "error_message": self.get_error_message(),
                "captcha_displayed": self.is_captcha_displayed(),
                "account_locked": self.is_account_locked(),
                "failed_attempts_warning": self.get_failed_attempts_warning()
            }
            
            results.append(result)
            
            # Stop if account is locked
            if self.is_account_locked():
                self.logger.warning("Account locked detected, stopping brute force test")
                break
            
            # Stop if CAPTCHA appears (security measure)
            if self.is_captcha_displayed():
                self.logger.warning("CAPTCHA detected, stopping brute force test")
                break
        
        return results
    
    def simulate_rapid_login_attempts(self, username, password, attempts=10, delay=0.1):
        """
        Simulate rapid login attempts to test rate limiting
        """
        self.logger.info(f"Testing rapid login attempts for user: {username}")
        results = []
        
        for i in range(attempts):
            start_time = time.time()
            
            self.enter_text(self.USERNAME_FIELD, "", clear_first=True)
            self.enter_text(self.PASSWORD_FIELD, "", clear_first=True)
            
            self.enter_username(username)
            self.enter_password(password)
            self.click_login()
            
            end_time = time.time()
            
            result = {
                "attempt": i + 1,
                "response_time": end_time - start_time,
                "error_displayed": self.is_error_displayed(),
                "rate_limited": "rate limit" in self.get_error_message().lower()
            }
            
            results.append(result)
            
            # Check for rate limiting
            if result["rate_limited"]:
                self.logger.warning(f"Rate limiting detected on attempt {i+1}")
                break
            
            time.sleep(delay)
        
        return results
    
    def test_sql_injection_attempts(self, injection_payloads):
        """
        Test SQL injection in login fields
        """
        self.logger.info("Testing SQL injection attempts")
        results = []
        
        for payload in injection_payloads:
            self.logger.info(f"Testing SQL injection payload: {payload}")
            
            # Clear fields
            self.enter_text(self.USERNAME_FIELD, "", clear_first=True)
            self.enter_text(self.PASSWORD_FIELD, "", clear_first=True)
            
            # Try payload in username field
            self.enter_username(payload)
            self.enter_password("password")
            self.click_login()
            
            time.sleep(1)
            
            result = {
                "payload": payload,
                "field": "username",
                "error_displayed": self.is_error_displayed(),
                "error_message": self.get_error_message(),
                "successful_injection": "error" not in self.get_error_message().lower()
            }
            
            results.append(result)
            
            # Also test in password field
            self.enter_text(self.USERNAME_FIELD, "", clear_first=True)
            self.enter_text(self.PASSWORD_FIELD, "", clear_first=True)
            
            self.enter_username("testuser")
            self.enter_password(payload)
            self.click_login()
            
            time.sleep(1)
            
            result = {
                "payload": payload,
                "field": "password",
                "error_displayed": self.is_error_displayed(),
                "error_message": self.get_error_message(),
                "successful_injection": "error" not in self.get_error_message().lower()
            }
            
            results.append(result)
        
        return results