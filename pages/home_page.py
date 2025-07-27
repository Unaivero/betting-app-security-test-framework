from selenium.webdriver.common.by import By
from pages.base_page import BasePage
import time

class HomePage(BasePage):
    """Home page object model with match listings"""
    
    # Locators
    MATCHES_CONTAINER = (By.ID, "matches-container")
    MATCH_ITEM = (By.CLASS_NAME, "match-item")
    BET_BUTTON = (By.CLASS_NAME, "bet-button")
    ODDS_DISPLAY = (By.CLASS_NAME, "odds")
    MATCH_TITLE = (By.CLASS_NAME, "match-title")
    MATCH_TIME = (By.CLASS_NAME, "match-time")
    
    # Navigation elements
    PROFILE_BUTTON = (By.ID, "profile-btn")
    BALANCE_DISPLAY = (By.ID, "balance")
    LOGOUT_BUTTON = (By.ID, "logout-btn")
    BET_HISTORY_BUTTON = (By.ID, "bet-history-btn")
    
    # Security indicators
    SESSION_TIMER = (By.ID, "session-timer")
    SECURITY_BADGE = (By.CLASS_NAME, "security-badge")
    LIMIT_WARNING = (By.CLASS_NAME, "limit-warning")
    
    # Filters and search
    SPORT_FILTER = (By.ID, "sport-filter")
    SEARCH_BOX = (By.ID, "search-matches")
    DATE_FILTER = (By.ID, "date-filter")
    
    def __init__(self, driver):
        super().__init__(driver)
        self.page_url = "/home"
    
    def wait_for_home_page_load(self):
        """Wait for home page to load completely"""
        try:
            self.wait_for_visible(self.MATCHES_CONTAINER, timeout=15)
            self.logger.info("Home page loaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Home page failed to load: {str(e)}")
            return False
    
    def get_available_matches(self):
        """Get list of available matches"""
        try:
            matches = []
            match_elements = self.find_elements(self.MATCH_ITEM)
            
            for match_element in match_elements:
                try:
                    title = match_element.find_element(By.CLASS_NAME, "match-title").text
                    time_str = match_element.find_element(By.CLASS_NAME, "match-time").text
                    odds_elements = match_element.find_elements(By.CLASS_NAME, "odds")
                    
                    odds = {}
                    for odds_element in odds_elements:
                        bet_type = odds_element.get_attribute("data-bet-type")
                        odds_value = odds_element.text
                        odds[bet_type] = odds_value
                    
                    match_data = {
                        "title": title,
                        "time": time_str,
                        "odds": odds,
                        "element": match_element
                    }
                    matches.append(match_data)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to parse match element: {str(e)}")
                    continue
            
            self.logger.info(f"Found {len(matches)} available matches")
            return matches
            
        except Exception as e:
            self.logger.error(f"Failed to get available matches: {str(e)}")
            return []
    
    def select_match_for_betting(self, match_index=0):
        """Select a match for betting"""
        try:
            matches = self.get_available_matches()
            if not matches or match_index >= len(matches):
                self.logger.error(f"No match available at index {match_index}")
                return None
            
            selected_match = matches[match_index]
            bet_button = selected_match["element"].find_element(By.CLASS_NAME, "bet-button")
            bet_button.click()
            
            self.logger.info(f"Selected match for betting: {selected_match['title']}")
            return selected_match
            
        except Exception as e:
            self.logger.error(f"Failed to select match for betting: {str(e)}")
            return None
    
    def get_user_balance(self):
        """Get user's current balance"""
        try:
            balance_text = self.get_text(self.BALANCE_DISPLAY)
            # Extract numeric value from balance text (e.g., "$1,500.00" -> 1500.00)
            import re
            balance_match = re.search(r'[\d,]+\.?\d*', balance_text.replace(',', ''))
            if balance_match:
                return float(balance_match.group().replace(',', ''))
            return 0.0
        except Exception as e:
            self.logger.error(f"Failed to get user balance: {str(e)}")
            return 0.0
    
    def navigate_to_profile(self):
        """Navigate to user profile"""
        return self.click_element(self.PROFILE_BUTTON)
    
    def navigate_to_bet_history(self):
        """Navigate to bet history"""
        return self.click_element(self.BET_HISTORY_BUTTON)
    
    def logout(self):
        """Logout from the application"""
        return self.click_element(self.LOGOUT_BUTTON)
    
    def get_session_timer(self):
        """Get remaining session time"""
        try:
            timer_text = self.get_text(self.SESSION_TIMER)
            return timer_text
        except:
            return ""
    
    def is_limit_warning_displayed(self):
        """Check if betting limit warning is displayed"""
        return self.is_element_visible(self.LIMIT_WARNING)
    
    def get_limit_warning_message(self):
        """Get limit warning message"""
        try:
            return self.get_text(self.LIMIT_WARNING)
        except:
            return ""
    
    def search_matches(self, search_term):
        """Search for specific matches"""
        return self.enter_text(self.SEARCH_BOX, search_term)
    
    def filter_by_sport(self, sport):
        """Filter matches by sport"""
        try:
            sport_dropdown = self.find_element(self.SPORT_FILTER)
            sport_dropdown.click()
            
            # Find and click sport option
            sport_option = (By.XPATH, f"//option[text()='{sport}']")
            return self.click_element(sport_option)
        except:
            return False
    
    def rapid_match_selection_test(self, selections=10, delay=0.1):
        """
        Test rapid match selections to check for rate limiting
        """
        self.logger.info("Testing rapid match selections")
        results = []
        
        for i in range(selections):
            start_time = time.time()
            
            matches = self.get_available_matches()
            if matches:
                match_index = i % len(matches)
                selected = self.select_match_for_betting(match_index)
                
                # Go back to home to select next match
                self.driver.back()
                time.sleep(0.5)
            
            end_time = time.time()
            
            result = {
                "selection": i + 1,
                "response_time": end_time - start_time,
                "success": selected is not None if 'selected' in locals() else False,
                "rate_limited": self.is_limit_warning_displayed()
            }
            
            results.append(result)
            
            if result["rate_limited"]:
                self.logger.warning(f"Rate limiting detected on selection {i+1}")
                break
            
            time.sleep(delay)
        
        return results
    
    def monitor_session_timeout(self, check_interval=30, max_duration=1800):
        """
        Monitor session timeout behavior
        """
        self.logger.info("Monitoring session timeout")
        start_time = time.time()
        timeout_detected = False
        
        while time.time() - start_time < max_duration:
            current_timer = self.get_session_timer()
            current_url = self.get_current_url()
            
            # Check if redirected to login (session expired)
            if "login" in current_url.lower():
                timeout_detected = True
                session_duration = time.time() - start_time
                self.logger.info(f"Session timeout detected after {session_duration} seconds")
                break
            
            self.logger.info(f"Session timer: {current_timer}")
            time.sleep(check_interval)
        
        return {
            "timeout_detected": timeout_detected,
            "duration": time.time() - start_time,
            "final_timer": self.get_session_timer()
        }
    
    def test_concurrent_sessions(self, additional_drivers):
        """
        Test multiple concurrent sessions with same user
        """
        self.logger.info("Testing concurrent sessions")
        results = []
        
        for i, driver in enumerate(additional_drivers):
            try:
                # Attempt to login with same user on different driver
                from pages.login_page import LoginPage
                login_page = LoginPage(driver)
                login_page.navigate_to_login()
                success = login_page.login("testuser", "password123")
                
                if success:
                    home_page = HomePage(driver)
                    home_loaded = home_page.wait_for_home_page_load()
                    
                    result = {
                        "session": i + 1,
                        "login_success": success,
                        "home_loaded": home_loaded,
                        "concurrent_allowed": True
                    }
                else:
                    result = {
                        "session": i + 1,
                        "login_success": success,
                        "home_loaded": False,
                        "concurrent_allowed": False,
                        "error": login_page.get_error_message()
                    }
                
                results.append(result)
                
            except Exception as e:
                result = {
                    "session": i + 1,
                    "login_success": False,
                    "error": str(e)
                }
                results.append(result)
        
        return results