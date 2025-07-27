from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import logging

class BasePage:
    """Base page class with common functionality for all pages"""
    
    def __init__(self, driver, timeout=10):
        self.driver = driver
        self.timeout = timeout
        self.wait = WebDriverWait(driver, timeout)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def find_element(self, locator, timeout=None):
        """Find element with wait"""
        try:
            timeout = timeout or self.timeout
            return WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located(locator)
            )
        except TimeoutException:
            self.logger.error(f"Element not found: {locator}")
            raise
    
    def find_elements(self, locator, timeout=None):
        """Find multiple elements with wait"""
        try:
            timeout = timeout or self.timeout
            WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located(locator)
            )
            return self.driver.find_elements(*locator)
        except TimeoutException:
            self.logger.error(f"Elements not found: {locator}")
            return []
    
    def click_element(self, locator, timeout=None):
        """Click element with wait"""
        try:
            element = self.wait_for_clickable(locator, timeout)
            element.click()
            self.logger.info(f"Clicked element: {locator}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to click element {locator}: {str(e)}")
            return False
    
    def enter_text(self, locator, text, clear_first=True, timeout=None):
        """Enter text into element"""
        try:
            element = self.find_element(locator, timeout)
            if clear_first:
                element.clear()
            element.send_keys(text)
            self.logger.info(f"Entered text into {locator}: {text}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to enter text into {locator}: {str(e)}")
            return False
    
    def get_text(self, locator, timeout=None):
        """Get text from element"""
        try:
            element = self.find_element(locator, timeout)
            text = element.text
            self.logger.info(f"Got text from {locator}: {text}")
            return text
        except Exception as e:
            self.logger.error(f"Failed to get text from {locator}: {str(e)}")
            return ""
    
    def wait_for_clickable(self, locator, timeout=None):
        """Wait for element to be clickable"""
        timeout = timeout or self.timeout
        return WebDriverWait(self.driver, timeout).until(
            EC.element_to_be_clickable(locator)
        )
    
    def wait_for_visible(self, locator, timeout=None):
        """Wait for element to be visible"""
        timeout = timeout or self.timeout
        return WebDriverWait(self.driver, timeout).until(
            EC.visibility_of_element_located(locator)
        )
    
    def wait_for_invisible(self, locator, timeout=None):
        """Wait for element to be invisible"""
        timeout = timeout or self.timeout
        return WebDriverWait(self.driver, timeout).until(
            EC.invisibility_of_element_located(locator)
        )
    
    def is_element_present(self, locator):
        """Check if element is present"""
        try:
            self.driver.find_element(*locator)
            return True
        except NoSuchElementException:
            return False
    
    def is_element_visible(self, locator):
        """Check if element is visible"""
        try:
            element = self.driver.find_element(*locator)
            return element.is_displayed()
        except NoSuchElementException:
            return False
    
    def scroll_to_element(self, locator):
        """Scroll to element"""
        try:
            element = self.find_element(locator)
            self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
            return True
        except Exception as e:
            self.logger.error(f"Failed to scroll to element {locator}: {str(e)}")
            return False
    
    def take_screenshot(self, filename):
        """Take screenshot"""
        try:
            self.driver.save_screenshot(filename)
            self.logger.info(f"Screenshot saved: {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to take screenshot: {str(e)}")
            return False
    
    def get_current_url(self):
        """Get current URL"""
        return self.driver.current_url
    
    def refresh_page(self):
        """Refresh current page"""
        self.driver.refresh()
        self.logger.info("Page refreshed")
    
    def wait_for_page_load(self, timeout=None):
        """Wait for page to load completely"""
        timeout = timeout or self.timeout
        WebDriverWait(self.driver, timeout).until(
            lambda driver: driver.execute_script("return document.readyState") == "complete"
        )