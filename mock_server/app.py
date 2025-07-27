from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import os
import uuid
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory storage for testing
users_db = {}
bets_db = {}
user_sessions = {}

# Security limits configuration
BETTING_LIMITS = {
    "max_single_bet": 1000.0,
    "max_daily_bet": 5000.0,
    "max_monthly_bet": 50000.0,
    "min_bet": 1.0
}

# Mock user data
DEFAULT_USERS = {
    "testuser": {
        "username": "testuser",
        "password": "password123",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "verified": False,
        "daily_bet_total": 0.0,
        "monthly_bet_total": 0.0,
        "last_bet_date": None,
        "account_status": "active"
    },
    "verified_user": {
        "username": "verified_user",
        "password": "password123",
        "email": "verified@example.com",
        "first_name": "Verified",
        "last_name": "User",
        "verified": True,
        "daily_bet_total": 0.0,
        "monthly_bet_total": 0.0,
        "last_bet_date": None,
        "account_status": "active"
    }
}

# Initialize with default users
users_db.update(DEFAULT_USERS)

def validate_token(token):
    """Validate authentication token"""
    return token in user_sessions

def get_user_from_token(token):
    """Get user data from token"""
    if token in user_sessions:
        return user_sessions[token]
    return None

def calculate_user_totals(username):
    """Calculate user's daily and monthly bet totals"""
    user_bets = [bet for bet in bets_db.values() if bet['username'] == username]
    
    today = datetime.now().date()
    this_month = datetime.now().replace(day=1).date()
    
    daily_total = sum(bet['amount'] for bet in user_bets 
                     if datetime.fromisoformat(bet['timestamp']).date() == today)
    
    monthly_total = sum(bet['amount'] for bet in user_bets 
                       if datetime.fromisoformat(bet['timestamp']).date() >= this_month)
    
    return daily_total, monthly_total

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    logger.info(f"Login attempt for user: {username}")
    
    if username in users_db and users_db[username]['password'] == password:
        token = str(uuid.uuid4())
        user_sessions[token] = users_db[username]
        
        logger.info(f"Successful login for user: {username}")
        return jsonify({
            "status": "success",
            "token": token,
            "user": {
                "username": username,
                "verified": users_db[username]['verified']
            }
        })
    
    logger.warning(f"Failed login attempt for user: {username}")
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/bet', methods=['POST'])
def place_bet():
    """Place bet endpoint with security validations"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not validate_token(token):
        return jsonify({"error": "Authentication required"}), 401
    
    user = get_user_from_token(token)
    data = request.get_json()
    
    bet_amount = float(data.get('amount', 0))
    match_id = data.get('match_id')
    bet_type = data.get('bet_type')
    
    logger.info(f"Bet placement attempt: {user['username']}, amount: {bet_amount}")
    
    # Security validation: Single bet limit
    if bet_amount > BETTING_LIMITS['max_single_bet']:
        logger.warning(f"SECURITY VIOLATION: Single bet limit exceeded by {user['username']}: {bet_amount}")
        return jsonify({
            "error": "Bet amount exceeds maximum allowed limit",
            "limit_exceeded": "single_bet",
            "max_amount": BETTING_LIMITS['max_single_bet'],
            "attempted_amount": bet_amount
        }), 400
    
    # Security validation: Minimum bet
    if bet_amount < BETTING_LIMITS['min_bet']:
        return jsonify({
            "error": "Bet amount below minimum allowed",
            "min_amount": BETTING_LIMITS['min_bet']
        }), 400
    
    # Calculate current totals
    daily_total, monthly_total = calculate_user_totals(user['username'])
    
    # Security validation: Daily limit
    if daily_total + bet_amount > BETTING_LIMITS['max_daily_bet']:
        logger.warning(f"SECURITY VIOLATION: Daily limit exceeded by {user['username']}: {daily_total + bet_amount}")
        return jsonify({
            "error": "Daily betting limit would be exceeded",
            "limit_exceeded": "daily_limit",
            "current_daily_total": daily_total,
            "max_daily_limit": BETTING_LIMITS['max_daily_bet'],
            "attempted_total": daily_total + bet_amount
        }), 400
    
    # Security validation: Monthly limit
    if monthly_total + bet_amount > BETTING_LIMITS['max_monthly_bet']:
        logger.warning(f"SECURITY VIOLATION: Monthly limit exceeded by {user['username']}: {monthly_total + bet_amount}")
        return jsonify({
            "error": "Monthly betting limit would be exceeded",
            "limit_exceeded": "monthly_limit",
            "current_monthly_total": monthly_total,
            "max_monthly_limit": BETTING_LIMITS['max_monthly_bet'],
            "attempted_total": monthly_total + bet_amount
        }), 400
    
    # Place bet
    bet_id = str(uuid.uuid4())
    bet_data = {
        "id": bet_id,
        "username": user['username'],
        "amount": bet_amount,
        "match_id": match_id,
        "bet_type": bet_type,
        "timestamp": datetime.now().isoformat(),
        "status": "placed"
    }
    
    bets_db[bet_id] = bet_data
    
    logger.info(f"Bet placed successfully: {bet_id} by {user['username']}")
    return jsonify({
        "status": "success",
        "bet_id": bet_id,
        "message": "Bet placed successfully"
    })

@app.route('/update_profile', methods=['PUT'])
def update_profile():
    """Update user profile with security validations"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not validate_token(token):
        return jsonify({"error": "Authentication required"}), 401
    
    user = get_user_from_token(token)
    data = request.get_json()
    
    logger.info(f"Profile update attempt by: {user['username']}")
    
    # Critical fields that require verification
    critical_fields = ['email', 'phone', 'bank_account', 'payment_method']
    
    for field in critical_fields:
        if field in data:
            if not user.get('verified', False):
                logger.warning(f"SECURITY VIOLATION: Unverified user {user['username']} attempting to update {field}")
                return jsonify({
                    "error": "Identity verification required",
                    "field": field,
                    "verification_required": True,
                    "message": f"You must verify your identity before updating {field}"
                }), 403
    
    # Fraud detection: Rapid profile changes
    last_update = user.get('last_profile_update')
    if last_update:
        last_update_time = datetime.fromisoformat(last_update)
        if datetime.now() - last_update_time < timedelta(hours=24):
            logger.warning(f"SECURITY VIOLATION: Rapid profile changes by {user['username']}")
            return jsonify({
                "error": "Profile was recently updated",
                "fraud_detection": "rapid_changes",
                "cooldown_period": "24 hours"
            }), 429
    
    # Update allowed fields
    allowed_fields = ['first_name', 'last_name', 'address']
    for field in allowed_fields:
        if field in data:
            users_db[user['username']][field] = data[field]
    
    users_db[user['username']]['last_profile_update'] = datetime.now().isoformat()
    
    logger.info(f"Profile updated successfully for: {user['username']}")
    return jsonify({"status": "success", "message": "Profile updated successfully"})

@app.route('/user_limits', methods=['GET'])
def get_user_limits():
    """Get user's current betting limits and usage"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not validate_token(token):
        return jsonify({"error": "Authentication required"}), 401
    
    user = get_user_from_token(token)
    daily_total, monthly_total = calculate_user_totals(user['username'])
    
    return jsonify({
        "limits": BETTING_LIMITS,
        "current_usage": {
            "daily_total": daily_total,
            "monthly_total": monthly_total,
            "daily_remaining": max(0, BETTING_LIMITS['max_daily_bet'] - daily_total),
            "monthly_remaining": max(0, BETTING_LIMITS['max_monthly_bet'] - monthly_total)
        },
        "account_status": user.get('account_status', 'active'),
        "verified": user.get('verified', False)
    })

@app.route('/bet_history', methods=['GET'])
def get_bet_history():
    """Get user's betting history"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not validate_token(token):
        return jsonify({"error": "Authentication required"}), 401
    
    user = get_user_from_token(token)
    user_bets = [bet for bet in bets_db.values() if bet['username'] == user['username']]
    
    # Sort by timestamp, most recent first
    user_bets.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        "bets": user_bets,
        "total_bets": len(user_bets),
        "total_amount": sum(bet['amount'] for bet in user_bets)
    })

@app.route('/fraud_check', methods=['POST'])
def fraud_check():
    """Fraud detection endpoint"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not validate_token(token):
        return jsonify({"error": "Authentication required"}), 401
    
    user = get_user_from_token(token)
    data = request.get_json()
    
    fraud_indicators = []
    
    # Check for unusual betting patterns
    user_bets = [bet for bet in bets_db.values() if bet['username'] == user['username']]
    recent_bets = [bet for bet in user_bets 
                   if datetime.now() - datetime.fromisoformat(bet['timestamp']) < timedelta(hours=1)]
    
    if len(recent_bets) > 10:
        fraud_indicators.append("excessive_betting_frequency")
    
    if len(recent_bets) > 0:
        avg_bet = sum(bet['amount'] for bet in recent_bets) / len(recent_bets)
        if avg_bet > BETTING_LIMITS['max_single_bet'] * 0.8:
            fraud_indicators.append("high_value_betting_pattern")
    
    risk_level = "low"
    if len(fraud_indicators) > 0:
        risk_level = "medium"
    if len(fraud_indicators) > 2:
        risk_level = "high"
    
    return jsonify({
        "user": user['username'],
        "risk_level": risk_level,
        "fraud_indicators": fraud_indicators,
        "recommendation": "monitor" if risk_level == "medium" else "block" if risk_level == "high" else "allow"
    })

@app.route('/admin/reset_limits', methods=['POST'])
def reset_user_limits():
    """Admin endpoint to reset user limits (for testing)"""
    data = request.get_json()
    username = data.get('username')
    
    if username in users_db:
        # Clear bet history for testing
        user_bets = [bet_id for bet_id, bet in bets_db.items() if bet['username'] == username]
        for bet_id in user_bets:
            del bets_db[bet_id]
        
        return jsonify({"status": "success", "message": f"Limits reset for {username}"})
    
    return jsonify({"error": "User not found"}), 404

@app.errorhandler(Exception)
def handle_error(error):
    """Global error handler"""
    logger.error(f"Unhandled error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    print("Starting Betting App Mock Server...")
    print("Available endpoints:")
    print("- POST /login - User authentication")
    print("- POST /bet - Place bets with security validations")
    print("- PUT /update_profile - Update profile with verification checks")
    print("- GET /user_limits - Get betting limits and usage")
    print("- GET /bet_history - Get user's betting history")
    print("- POST /fraud_check - Check for fraud indicators")
    print("- GET /health - Health check")
    
    app.run(host='0.0.0.0', port=5000, debug=True)