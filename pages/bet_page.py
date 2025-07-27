from selenium.webdriver.common.by import By
from pages.base_page import BasePage
import time
import random

class BetPage(BasePage):
    """Bet placement page object model"""
    
    # Locators
    MATCH_INFO = (By.ID, "match-info")
    BET_TYPE_SELECTOR = (By.ID, "bet-type-selector")
    BET_AMOUNT_INPUT = (By.ID, "bet-amount")
    ODDS_DISPLAY = (By.ID, "selected-odds")
    POTENTIAL_WIN_DISPLAY = (By.ID, "potential-win")
    PLACE_BET_BUTTON = (By.ID, "place-bet-btn")
    
    # Bet type options
    HOME_WIN_OPTION = (By.ID, "home-win")
    DRAW_OPTION = (By.ID, "draw")
    AWAY_WIN_OPTION = (By.ID, "away-win")
    
    # Validation and error messages
    ERROR_MESSAGE = (By.CLASS_NAME, "bet-error")
    SUCCESS_MESSAGE = (By.CLASS_NAME, "bet-success")
    LIMIT_WARNING = (By.CLASS_NAME, "limit-warning")
    CONFIRMATION_DIALOG = (By.ID, "bet-confirmation")
    CONFIRM_YES = (By.ID, "confirm-yes")
    CONFIRM_NO = (By.ID, "confirm-no")
    
    # Limit displays
    DAILY_LIMIT_DISPLAY = (By.ID, "daily-limit")
    MONTHLY_LIMIT_DISPLAY = (By.ID, "monthly-limit")
    REMAINING_DAILY = (By.ID, "remaining-daily")
    REMAINING_MONTHLY = (By.ID, "remaining-monthly")
    
    # Quick bet amounts
    QUICK_BET_10 = (By.ID, "quick-bet-10")
    QUICK_BET_50 = (By.ID, "quick-bet-50")
    QUICK_BET_100 = (By.ID, "quick-bet-100")
    QUICK_BET_500 = (By.ID, "quick-bet-500")
    
    def __init__(self, driver):
        super().__init__(driver)
        self.page_url = "/bet"
    
    def wait_for_bet_page_load(self):
        """Wait for bet page to load"""
        try:
            self.wait_for_visible(self.MATCH_INFO, timeout=10)
            self.wait_for_visible(self.BET_AMOUNT_INPUT, timeout=10)
            self.logger.info("Bet page loaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Bet page failed to load: {str(e)}")
            return False
    
    def select_bet_type(self, bet_type="home_win"):
        """Select bet type (home_win, draw, away_win)"""
        try:
            bet_type_map = {
                "home_win": self.HOME_WIN_OPTION,
                "draw": self.DRAW_OPTION,
                "away_win": self.AWAY_WIN_OPTION
            }
            
            if bet_type in bet_type_map:
                success = self.click_element(bet_type_map[bet_type])
                if success:
                    self.logger.info(f"Selected bet type: {bet_type}")
                return success
            else:
                self.logger.error(f"Invalid bet type: {bet_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to select bet type: {str(e)}")
            return False
    
    def enter_bet_amount(self, amount):
        """Enter bet amount"""
        try:
            success = self.enter_text(self.BET_AMOUNT_INPUT, str(amount), clear_first=True)
            if success:
                self.logger.info(f"Entered bet amount: {amount}")
                # Wait for potential win calculation
                time.sleep(1)
            return success
        except Exception as e:
            self.logger.error(f"Failed to enter bet amount: {str(e)}")
            return False
    
    def get_potential_win(self):
        """Get potential win amount"""
        try:
            win_text = self.get_text(self.POTENTIAL_WIN_DISPLAY)
            # Extract numeric value
            import re
            win_match = re.search(r'[\d,]+\.?\d*', win_text.replace(',', ''))
            if win_match:
                return float(win_match.group().replace(',', ''))
            return 0.0
        except Exception as e:
            self.logger.error(f"Failed to get potential win: {str(e)}")
            return 0.0
    
    def get_current_odds(self):
        """Get current odds for selected bet"""
        try:
            odds_text = self.get_text(self.ODDS_DISPLAY)
            import re
            odds_match = re.search(r'\d+\.?\d*', odds_text)
            if odds_match:
                return float(odds_match.group())
            return 0.0
        except Exception as e:
            self.logger.error(f"Failed to get current odds: {str(e)}")
            return 0.0
    
    def click_place_bet(self):
        """Click place bet button"""
        return self.click_element(self.PLACE_BET_BUTTON)
    
    def confirm_bet(self, confirm=True):
        """Confirm or cancel bet in confirmation dialog"""
        try:
            if self.is_element_visible(self.CONFIRMATION_DIALOG):
                if confirm:
                    return self.click_element(self.CONFIRM_YES)
                else:
                    return self.click_element(self.CONFIRM_NO)
            return True  # No confirmation dialog
        except Exception as e:
            self.logger.error(f"Failed to handle bet confirmation: {str(e)}")
            return False
    
    def place_bet(self, bet_type="home_win", amount=10, confirm=True):
        """Complete bet placement process"""
        try:
            self.logger.info(f"Placing bet: {bet_type}, amount: {amount}")
            
            # Select bet type
            if not self.select_bet_type(bet_type):
                return {"success": False, "error": "Failed to select bet type"}
            
            # Enter amount
            if not self.enter_bet_amount(amount):
                return {"success": False, "error": "Failed to enter bet amount"}
            
            # Get odds and potential win for verification
            odds = self.get_current_odds()
            potential_win = self.get_potential_win()
            
            # Place bet
            if not self.click_place_bet():
                return {"success": False, "error": "Failed to click place bet"}
            
            # Wait for response
            time.sleep(2)
            
            # Handle confirmation if present
            self.confirm_bet(confirm)
            
            # Check for errors or success
            if self.is_error_displayed():
                error_msg = self.get_error_message()
                self.logger.warning(f"Bet placement failed: {error_msg}")
                return {
                    "success": False,
                    "error": error_msg,
                    "amount": amount,
                    "odds": odds,
                    "potential_win": potential_win
                }
            
            if self.is_success_displayed():
                success_msg = self.get_success_message()
                self.logger.info(f"Bet placed successfully: {success_msg}")
                return {
                    "success": True,
                    "message": success_msg,
                    "amount": amount,
                    "odds": odds,
                    "potential_win": potential_win
                }
            
            # If no clear success/error indication
            return {
                "success": None,
                "message": "Bet status unclear",
                "amount": amount,
                "odds": odds,
                "potential_win": potential_win
            }
            
        except Exception as e:
            self.logger.error(f"Bet placement failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
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
    
    def is_limit_warning_displayed(self):
        """Check if limit warning is displayed"""
        return self.is_element_visible(self.LIMIT_WARNING)
    
    def get_limit_warning(self):
        """Get limit warning message"""
        try:
            return self.get_text(self.LIMIT_WARNING)
        except:
            return ""
    
    def get_betting_limits_info(self):
        """Get betting limits information"""
        try:
            limits_info = {
                "daily_limit": self.get_text(self.DAILY_LIMIT_DISPLAY),
                "monthly_limit": self.get_text(self.MONTHLY_LIMIT_DISPLAY),
                "remaining_daily": self.get_text(self.REMAINING_DAILY),
                "remaining_monthly": self.get_text(self.REMAINING_MONTHLY)
            }
            return limits_info
        except Exception as e:
            self.logger.error(f"Failed to get limits info: {str(e)}")
            return {}
    
    def use_quick_bet_amount(self, amount):
        """Use quick bet amount buttons"""
        quick_bet_map = {
            10: self.QUICK_BET_10,
            50: self.QUICK_BET_50,
            100: self.QUICK_BET_100,
            500: self.QUICK_BET_500
        }
        
        if amount in quick_bet_map:
            return self.click_element(quick_bet_map[amount])
        return False
    
    def test_excessive_bet_amount(self, excessive_amounts):
        """Test placing bets with excessive amounts"""
        self.logger.info("Testing excessive bet amounts")
        results = []
        
        for amount in excessive_amounts:
            self.logger.info(f"Testing excessive bet amount: {amount}")
            
            result = self.place_bet(amount=amount, confirm=False)
            result["test_amount"] = amount
            result["excessive_amount_test"] = True
            
            # Check for specific limit violation messages
            if not result["success"] and result.get("error"):
                error_msg = result["error"].lower()
                if "limit" in error_msg or "exceed" in error_msg:
                    result["limit_violation_detected"] = True
                else:
                    result["limit_violation_detected"] = False
            
            results.append(result)
            
            # Small delay between attempts
            time.sleep(1)
        
        return results
    
    def test_rapid_bet_placement(self, bet_count=10, amount=10, delay=0.1):
        """Test rapid bet placement to trigger rate limiting"""
        self.logger.info(f"Testing rapid bet placement: {bet_count} bets")
        results = []
        
        for i in range(bet_count):
            start_time = time.time()
            
            # Randomize bet type for variation
            bet_types = ["home_win", "draw", "away_win"]
            bet_type = random.choice(bet_types)
            
            result = self.place_bet(bet_type=bet_type, amount=amount)
            result["attempt"] = i + 1
            result["response_time"] = time.time() - start_time
            result["rate_limited"] = "rate" in result.get("error", "").lower()
            
            results.append(result)
            
            # Stop if rate limiting detected
            if result.get("rate_limited"):
                self.logger.warning(f"Rate limiting detected on attempt {i+1}")
                break
            
            time.sleep(delay)
        
        return results
    
    def test_cumulative_limit_violation(self, daily_limit=5000, monthly_limit=50000):
        """Test cumulative betting limit violations"""
        self.logger.info("Testing cumulative limit violations")
        results = []
        total_bet = 0
        
        # Start with smaller bets that individually are within limits
        bet_amounts = [500, 1000, 800, 1200, 900, 1500, 600]
        
        for i, amount in enumerate(bet_amounts):
            result = self.place_bet(amount=amount)
            
            if result["success"]:
                total_bet += amount
            
            result["attempt"] = i + 1
            result["cumulative_total"] = total_bet
            result["approaching_daily_limit"] = total_bet > daily_limit * 0.8
            result["exceeds_daily_limit"] = total_bet > daily_limit
            
            # Check if limit warning is displayed
            result["limit_warning_shown"] = self.is_limit_warning_displayed()
            if result["limit_warning_shown"]:
                result["warning_message"] = self.get_limit_warning()
            
            results.append(result)
            
            # Stop if we hit the daily limit
            if not result["success"] and "daily" in result.get("error", "").lower():
                self.logger.info("Daily limit violation detected, stopping test")
                break
            
            time.sleep(1)
        
        return results
    
    def test_negative_bet_amounts(self):
        """Test negative and invalid bet amounts"""
        self.logger.info("Testing negative and invalid bet amounts")
        invalid_amounts = [-10, -100, 0, -0.01, "abc", "!", ""]
        results = []
        
        for amount in invalid_amounts:
            self.logger.info(f"Testing invalid bet amount: {amount}")
            
            # Try to enter the invalid amount
            try:
                self.enter_bet_amount(amount)
                result = self.place_bet(amount=amount, confirm=False)
                result["test_amount"] = amount
                result["invalid_amount_test"] = True
                
                # Check if proper validation occurred
                if not result["success"]:
                    result["validation_working"] = True
                else:
                    result["validation_working"] = False
                    self.logger.warning(f"Invalid amount {amount} was accepted!")
                
            except Exception as e:
                result = {
                    "test_amount": amount,
                    "success": False,
                    "error": str(e),
                    "validation_working": True,
                    "invalid_amount_test": True
                }
            
            results.append(result)
        
        return results