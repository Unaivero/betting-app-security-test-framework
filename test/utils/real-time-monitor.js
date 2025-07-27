/**
 * Real-Time Fraud Detection Monitor
 * Enterprise-grade real-time monitoring system for betting application fraud detection
 * 
 * Features:
 * - Live behavioral analysis with ML pattern detection
 * - Real-time anomaly detection and scoring
 * - Automated alert triggering and escalation
 * - Risk assessment and profiling
 * - Integration with external fraud services
 * 
 * @author Betting App Security Team
 * @version 1.0.0
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class RealTimeFraudMonitor extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            alertThreshold: config.alertThreshold || 75,
            criticalThreshold: config.criticalThreshold || 90,
            monitoringInterval: config.monitoringInterval || 1000,
            maxEventsPerSecond: config.maxEventsPerSecond || 100,
            riskDecayRate: config.riskDecayRate || 0.95,
            sessionTimeout: config.sessionTimeout || 30 * 60 * 1000, // 30 minutes
            enableMLDetection: config.enableMLDetection !== false,
            logLevel: config.logLevel || 'info',
            ...config
        };

        this.userSessions = new Map();
        this.riskScores = new Map();
        this.eventBuffer = new Map();
        this.alertHistory = new Map();
        this.patterns = new Map();
        this.isMonitoring = false;
        this.eventCounter = 0;
        this.lastResetTime = Date.now();
        
        this.initializeMLModels();
        this.setupEventHandlers();
        this.startBackgroundTasks();
    }

    /**
     * Initialize machine learning models for fraud detection
     */
    async initializeMLModels() {
        try {
            this.mlModels = {
                behavioralAnalyzer: await this.loadBehavioralModel(),
                anomalyDetector: await this.loadAnomalyModel(),
                riskAssessor: await this.loadRiskModel()
            };
            
            this.log('info', 'ML models initialized successfully');
        } catch (error) {
            this.log('error', 'Failed to initialize ML models', { error: error.message });
            this.config.enableMLDetection = false;
        }
    }

    /**
     * Load behavioral analysis model
     */
    async loadBehavioralModel() {
        // Simulated ML model - in production, load actual trained model
        return {
            predict: (features) => {
                const suspiciousPatterns = [
                    features.rapidClicks > 10,
                    features.unusualTimePattern,
                    features.velocityAnomaly > 0.8,
                    features.deviceMismatch
                ];
                return suspiciousPatterns.filter(Boolean).length / suspiciousPatterns.length;
            }
        };
    }

    /**
     * Load anomaly detection model
     */
    async loadAnomalyModel() {
        return {
            detectAnomaly: (eventSequence) => {
                const timestamps = eventSequence.map(e => e.timestamp);
                const intervals = [];
                
                for (let i = 1; i < timestamps.length; i++) {
                    intervals.push(timestamps[i] - timestamps[i-1]);
                }
                
                if (intervals.length === 0) return 0;
                
                const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
                const variance = intervals.reduce((sum, interval) => {
                    return sum + Math.pow(interval - avgInterval, 2);
                }, 0) / intervals.length;
                
                // Higher variance indicates more anomalous behavior
                return Math.min(variance / 10000, 1);
            }
        };
    }

    /**
     * Load risk assessment model
     */
    async loadRiskModel() {
        return {
            assessRisk: (userProfile, currentBehavior) => {
                let riskScore = 0;
                
                // Historical risk factors
                if (userProfile.previousIncidents > 0) riskScore += 20;
                if (userProfile.accountAge < 7) riskScore += 15;
                if (userProfile.verificationLevel < 2) riskScore += 10;
                
                // Current behavior risk factors
                if (currentBehavior.unusualBettingPattern) riskScore += 25;
                if (currentBehavior.highVelocityActions) riskScore += 20;
                if (currentBehavior.deviceAnomaly) riskScore += 15;
                if (currentBehavior.locationAnomaly) riskScore += 15;
                
                return Math.min(riskScore, 100);
            }
        };
    }

    /**
     * Setup event handlers for different types of fraud indicators
     */
    setupEventHandlers() {
        this.on('userAction', this.handleUserAction.bind(this));
        this.on('betPlaced', this.handleBetEvent.bind(this));
        this.on('login', this.handleLoginEvent.bind(this));
        this.on('withdrawal', this.handleWithdrawalEvent.bind(this));
        this.on('profileUpdate', this.handleProfileUpdate.bind(this));
        this.on('deviceChange', this.handleDeviceChange.bind(this));
        this.on('alertTriggered', this.handleAlert.bind(this));
    }

    /**
     * Start background monitoring tasks
     */
    startBackgroundTasks() {
        this.isMonitoring = true;
        
        // Rate limiting reset
        setInterval(() => {
            this.eventCounter = 0;
            this.lastResetTime = Date.now();
        }, 1000);
        
        // Session cleanup
        setInterval(() => {
            this.cleanupExpiredSessions();
        }, 60000);
        
        // Risk score decay
        setInterval(() => {
            this.applyRiskDecay();
        }, 5000);
        
        // Pattern analysis
        setInterval(() => {
            this.analyzePatterns();
        }, this.config.monitoringInterval);
    }

    /**
     * Process incoming user action event
     */
    async handleUserAction(eventData) {
        try {
            if (!this.isRateLimited()) {
                await this.processEvent('userAction', eventData);
            }
        } catch (error) {
            this.log('error', 'Error handling user action', { error: error.message, eventData });
        }
    }

    /**
     * Process betting event
     */
    async handleBetEvent(eventData) {
        try {
            const riskFactors = await this.analyzeBettingRisk(eventData);
            await this.processEvent('bet', { ...eventData, riskFactors });
            
            if (riskFactors.highRisk) {
                await this.triggerAlert('HIGH_RISK_BET', eventData.userId, {
                    betAmount: eventData.amount,
                    riskFactors
                });
            }
        } catch (error) {
            this.log('error', 'Error handling bet event', { error: error.message, eventData });
        }
    }

    /**
     * Process login event
     */
    async handleLoginEvent(eventData) {
        try {
            const session = this.createUserSession(eventData.userId, eventData);
            const loginRisk = await this.analyzeLoginRisk(eventData);
            
            await this.processEvent('login', { ...eventData, loginRisk });
            
            if (loginRisk.suspicious) {
                await this.triggerAlert('SUSPICIOUS_LOGIN', eventData.userId, loginRisk);
            }
        } catch (error) {
            this.log('error', 'Error handling login event', { error: error.message, eventData });
        }
    }

    /**
     * Process withdrawal event
     */
    async handleWithdrawalEvent(eventData) {
        try {
            const withdrawalRisk = await this.analyzeWithdrawalRisk(eventData);
            await this.processEvent('withdrawal', { ...eventData, withdrawalRisk });
            
            if (withdrawalRisk.score > this.config.alertThreshold) {
                await this.triggerAlert('HIGH_RISK_WITHDRAWAL', eventData.userId, {
                    amount: eventData.amount,
                    riskScore: withdrawalRisk.score,
                    reasons: withdrawalRisk.reasons
                });
            }
        } catch (error) {
            this.log('error', 'Error handling withdrawal event', { error: error.message, eventData });
        }
    }

    /**
     * Process profile update event
     */
    async handleProfileUpdate(eventData) {
        try {
            const updateRisk = await this.analyzeProfileUpdateRisk(eventData);
            await this.processEvent('profileUpdate', { ...eventData, updateRisk });
            
            if (updateRisk.suspicious) {
                await this.triggerAlert('SUSPICIOUS_PROFILE_UPDATE', eventData.userId, updateRisk);
            }
        } catch (error) {
            this.log('error', 'Error handling profile update', { error: error.message, eventData });
        }
    }

    /**
     * Process device change event
     */
    async handleDeviceChange(eventData) {
        try {
            const deviceRisk = await this.analyzeDeviceRisk(eventData);
            await this.processEvent('deviceChange', { ...eventData, deviceRisk });
            
            if (deviceRisk.newDevice && deviceRisk.riskScore > 60) {
                await this.triggerAlert('NEW_DEVICE_HIGH_RISK', eventData.userId, deviceRisk);
            }
        } catch (error) {
            this.log('error', 'Error handling device change', { error: error.message, eventData });
        }
    }

    /**
     * Core event processing logic
     */
    async processEvent(eventType, eventData) {
        const userId = eventData.userId;
        const timestamp = Date.now();
        
        // Add to event buffer
        if (!this.eventBuffer.has(userId)) {
            this.eventBuffer.set(userId, []);
        }
        
        const userEvents = this.eventBuffer.get(userId);
        userEvents.push({ type: eventType, data: eventData, timestamp });
        
        // Keep only recent events (last 100 or last hour)
        const oneHourAgo = timestamp - 60 * 60 * 1000;
        this.eventBuffer.set(userId, userEvents
            .filter(event => event.timestamp > oneHourAgo)
            .slice(-100)
        );

        // Update user session
        this.updateUserSession(userId, eventData);

        // Calculate risk score
        const riskScore = await this.calculateRiskScore(userId, eventType, eventData);
        this.updateRiskScore(userId, riskScore);

        // Check for immediate alerts
        if (riskScore > this.config.criticalThreshold) {
            await this.triggerAlert('CRITICAL_RISK_DETECTED', userId, {
                riskScore,
                eventType,
                eventData
            });
        }

        this.eventCounter++;
    }

    /**
     * Calculate comprehensive risk score for user action
     */
    async calculateRiskScore(userId, eventType, eventData) {
        let riskScore = 0;
        const userEvents = this.eventBuffer.get(userId) || [];
        const userSession = this.userSessions.get(userId);
        
        try {
            // Frequency analysis
            const recentEvents = userEvents.filter(e => 
                Date.now() - e.timestamp < 60000 // Last minute
            );
            
            if (recentEvents.length > 20) riskScore += 25;
            else if (recentEvents.length > 10) riskScore += 15;
            
            // Velocity analysis
            const velocityScore = this.calculateVelocityRisk(userEvents);
            riskScore += velocityScore * 30;
            
            // Pattern analysis
            if (this.config.enableMLDetection && this.mlModels.behavioralAnalyzer) {
                const behavioralFeatures = this.extractBehavioralFeatures(userEvents, userSession);
                const mlScore = await this.mlModels.behavioralAnalyzer.predict(behavioralFeatures);
                riskScore += mlScore * 40;
            }
            
            // Anomaly detection
            if (this.config.enableMLDetection && this.mlModels.anomalyDetector) {
                const anomalyScore = await this.mlModels.anomalyDetector.detectAnomaly(userEvents);
                riskScore += anomalyScore * 35;
            }
            
            // Context-specific risk factors
            switch (eventType) {
                case 'bet':
                    riskScore += this.calculateBettingRisk(eventData);
                    break;
                case 'withdrawal':
                    riskScore += this.calculateWithdrawalRisk(eventData);
                    break;
                case 'login':
                    riskScore += this.calculateLoginRisk(eventData, userSession);
                    break;
            }
            
            return Math.min(Math.max(riskScore, 0), 100);
            
        } catch (error) {
            this.log('error', 'Error calculating risk score', { error: error.message, userId, eventType });
            return 50; // Default moderate risk on error
        }
    }

    /**
     * Calculate velocity-based risk
     */
    calculateVelocityRisk(events) {
        if (events.length < 2) return 0;
        
        const now = Date.now();
        const fiveMinutesAgo = now - 5 * 60 * 1000;
        const recentEvents = events.filter(e => e.timestamp > fiveMinutesAgo);
        
        if (recentEvents.length === 0) return 0;
        
        const timeSpan = now - recentEvents[0].timestamp;
        const eventsPerMinute = (recentEvents.length / timeSpan) * 60 * 1000;
        
        // Risk increases exponentially with velocity
        if (eventsPerMinute > 10) return 1.0;
        if (eventsPerMinute > 5) return 0.7;
        if (eventsPerMinute > 2) return 0.4;
        
        return 0;
    }

    /**
     * Extract behavioral features for ML analysis
     */
    extractBehavioralFeatures(events, session) {
        const now = Date.now();
        const recentEvents = events.filter(e => now - e.timestamp < 10 * 60 * 1000);
        
        return {
            rapidClicks: recentEvents.filter(e => e.type === 'userAction').length,
            unusualTimePattern: this.detectUnusualTimePattern(recentEvents),
            velocityAnomaly: this.calculateVelocityRisk(events),
            deviceMismatch: session ? session.deviceChanges > 0 : false,
            sessionDuration: session ? now - session.startTime : 0,
            eventDiversity: new Set(recentEvents.map(e => e.type)).size
        };
    }

    /**
     * Detect unusual time patterns in user behavior
     */
    detectUnusualTimePattern(events) {
        if (events.length < 3) return false;
        
        const intervals = [];
        for (let i = 1; i < events.length; i++) {
            intervals.push(events[i].timestamp - events[i-1].timestamp);
        }
        
        // Check for too regular patterns (bot-like)
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, interval) => {
            return sum + Math.pow(interval - avgInterval, 2);
        }, 0) / intervals.length;
        
        // Very low variance suggests automated behavior
        return variance < 100;
    }

    /**
     * Analyze betting-specific risk factors
     */
    async analyzeBettingRisk(eventData) {
        const riskFactors = {
            highRisk: false,
            reasons: []
        };
        
        // Large bet amount
        if (eventData.amount > 10000) {
            riskFactors.highRisk = true;
            riskFactors.reasons.push('Large bet amount');
        }
        
        // Unusual betting pattern
        const userEvents = this.eventBuffer.get(eventData.userId) || [];
        const recentBets = userEvents
            .filter(e => e.type === 'bet' && Date.now() - e.timestamp < 60 * 60 * 1000)
            .map(e => e.data.amount);
        
        if (recentBets.length > 0) {
            const avgBet = recentBets.reduce((a, b) => a + b, 0) / recentBets.length;
            if (eventData.amount > avgBet * 5) {
                riskFactors.highRisk = true;
                riskFactors.reasons.push('Bet amount significantly higher than usual');
            }
        }
        
        // Rapid betting
        const recentBetCount = userEvents
            .filter(e => e.type === 'bet' && Date.now() - e.timestamp < 5 * 60 * 1000)
            .length;
        
        if (recentBetCount > 10) {
            riskFactors.highRisk = true;
            riskFactors.reasons.push('Rapid betting pattern detected');
        }
        
        return riskFactors;
    }

    /**
     * Analyze login-specific risk factors
     */
    async analyzeLoginRisk(eventData) {
        const riskFactors = {
            suspicious: false,
            reasons: [],
            score: 0
        };
        
        // Check for unusual location
        if (eventData.location && eventData.expectedLocation) {
            const distance = this.calculateDistance(
                eventData.location,
                eventData.expectedLocation
            );
            
            if (distance > 1000) { // More than 1000km from usual location
                riskFactors.suspicious = true;
                riskFactors.reasons.push('Login from unusual location');
                riskFactors.score += 30;
            }
        }
        
        // Check for new device
        if (eventData.newDevice) {
            riskFactors.suspicious = true;
            riskFactors.reasons.push('Login from new device');
            riskFactors.score += 20;
        }
        
        // Check for VPN/Proxy usage
        if (eventData.vpnDetected) {
            riskFactors.suspicious = true;
            riskFactors.reasons.push('VPN/Proxy detected');
            riskFactors.score += 25;
        }
        
        // Check login frequency
        const userEvents = this.eventBuffer.get(eventData.userId) || [];
        const recentLogins = userEvents
            .filter(e => e.type === 'login' && Date.now() - e.timestamp < 60 * 60 * 1000)
            .length;
        
        if (recentLogins > 5) {
            riskFactors.suspicious = true;
            riskFactors.reasons.push('Multiple login attempts');
            riskFactors.score += 15;
        }
        
        return riskFactors;
    }

    /**
     * Analyze withdrawal-specific risk factors
     */
    async analyzeWithdrawalRisk(eventData) {
        const riskFactors = {
            score: 0,
            reasons: []
        };
        
        // Large withdrawal amount
        if (eventData.amount > 50000) {
            riskFactors.score += 40;
            riskFactors.reasons.push('Large withdrawal amount');
        }
        
        // New withdrawal method
        if (eventData.newWithdrawalMethod) {
            riskFactors.score += 25;
            riskFactors.reasons.push('New withdrawal method');
        }
        
        // Rapid withdrawal after deposit
        const userEvents = this.eventBuffer.get(eventData.userId) || [];
        const recentDeposit = userEvents
            .filter(e => e.type === 'deposit' && Date.now() - e.timestamp < 24 * 60 * 60 * 1000)
            .pop();
        
        if (recentDeposit && Date.now() - recentDeposit.timestamp < 60 * 60 * 1000) {
            riskFactors.score += 30;
            riskFactors.reasons.push('Rapid withdrawal after deposit');
        }
        
        // Account age consideration
        const session = this.userSessions.get(eventData.userId);
        if (session && session.accountAge < 7) {
            riskFactors.score += 20;
            riskFactors.reasons.push('New account withdrawal');
        }
        
        return riskFactors;
    }

    /**
     * Analyze profile update risk factors
     */
    async analyzeProfileUpdateRisk(eventData) {
        const riskFactors = {
            suspicious: false,
            reasons: []
        };
        
        // Critical field changes
        const criticalFields = ['email', 'phone', 'bankAccount', 'address'];
        const changedFields = Object.keys(eventData.changes || {});
        const criticalChanges = changedFields.filter(field => 
            criticalFields.includes(field)
        );
        
        if (criticalChanges.length > 0) {
            riskFactors.suspicious = true;
            riskFactors.reasons.push(`Critical fields changed: ${criticalChanges.join(', ')}`);
        }
        
        // Multiple recent changes
        const userEvents = this.eventBuffer.get(eventData.userId) || [];
        const recentUpdates = userEvents
            .filter(e => e.type === 'profileUpdate' && Date.now() - e.timestamp < 24 * 60 * 60 * 1000)
            .length;
        
        if (recentUpdates > 3) {
            riskFactors.suspicious = true;
            riskFactors.reasons.push('Multiple recent profile updates');
        }
        
        return riskFactors;
    }

    /**
     * Analyze device-related risk factors
     */
    async analyzeDeviceRisk(eventData) {
        const riskFactors = {
            newDevice: eventData.newDevice,
            riskScore: 0,
            reasons: []
        };
        
        if (eventData.newDevice) {
            riskFactors.riskScore += 30;
            riskFactors.reasons.push('New device detected');
        }
        
        if (eventData.deviceAnomaly) {
            riskFactors.riskScore += 25;
            riskFactors.reasons.push('Device fingerprint anomaly');
        }
        
        if (eventData.rootedDevice) {
            riskFactors.riskScore += 35;
            riskFactors.reasons.push('Rooted/jailbroken device');
        }
        
        return riskFactors;
    }

    /**
     * Create new user session
     */
    createUserSession(userId, eventData) {
        const session = {
            userId,
            startTime: Date.now(),
            lastActivity: Date.now(),
            ipAddress: eventData.ipAddress,
            userAgent: eventData.userAgent,
            deviceFingerprint: eventData.deviceFingerprint,
            location: eventData.location,
            eventCount: 0,
            deviceChanges: 0,
            riskEvents: []
        };
        
        this.userSessions.set(userId, session);
        return session;
    }

    /**
     * Update existing user session
     */
    updateUserSession(userId, eventData) {
        const session = this.userSessions.get(userId);
        if (!session) return this.createUserSession(userId, eventData);
        
        session.lastActivity = Date.now();
        session.eventCount++;
        
        // Detect device changes
        if (eventData.deviceFingerprint && 
            eventData.deviceFingerprint !== session.deviceFingerprint) {
            session.deviceChanges++;
            session.deviceFingerprint = eventData.deviceFingerprint;
        }
        
        // Update location
        if (eventData.location) {
            session.location = eventData.location;
        }
        
        return session;
    }

    /**
     * Update user risk score with weighted average
     */
    updateRiskScore(userId, newScore) {
        const currentScore = this.riskScores.get(userId) || 0;
        const weightedScore = (currentScore * 0.7) + (newScore * 0.3);
        this.riskScores.set(userId, Math.min(weightedScore, 100));
    }

    /**
     * Trigger fraud alert
     */
    async triggerAlert(alertType, userId, details) {
        const alertId = crypto.randomUUID();
        const alert = {
            id: alertId,
            type: alertType,
            userId,
            timestamp: Date.now(),
            details,
            severity: this.getAlertSeverity(alertType, details),
            acknowledged: false
        };
        
        // Store alert
        if (!this.alertHistory.has(userId)) {
            this.alertHistory.set(userId, []);
        }
        this.alertHistory.get(userId).push(alert);
        
        // Emit alert event
        this.emit('alertTriggered', alert);
        
        // Log alert
        this.log('alert', `Fraud alert triggered: ${alertType}`, {
            alertId,
            userId,
            severity: alert.severity,
            details
        });
        
        // Auto-escalate critical alerts
        if (alert.severity === 'critical') {
            await this.escalateAlert(alert);
        }
        
        return alertId;
    }

    /**
     * Handle triggered alerts
     */
    async handleAlert(alert) {
        try {
            // Update user risk score
            const riskIncrease = this.getAlertRiskIncrease(alert.type);
            const currentScore = this.riskScores.get(alert.userId) || 0;
            this.riskScores.set(alert.userId, Math.min(currentScore + riskIncrease, 100));
            
            // Check for automatic actions
            await this.checkAutomaticActions(alert);
            
        } catch (error) {
            this.log('error', 'Error handling alert', { error: error.message, alert });
        }
    }

    /**
     * Determine alert severity
     */
    getAlertSeverity(alertType, details) {
        const criticalAlerts = [
            'CRITICAL_RISK_DETECTED',
            'HIGH_RISK_WITHDRAWAL',
            'COORDINATED_ATTACK'
        ];
        
        const highAlerts = [
            'HIGH_RISK_BET',
            'SUSPICIOUS_LOGIN',
            'NEW_DEVICE_HIGH_RISK'
        ];
        
        if (criticalAlerts.includes(alertType)) return 'critical';
        if (highAlerts.includes(alertType)) return 'high';
        if (details && details.riskScore > this.config.criticalThreshold) return 'critical';
        if (details && details.riskScore > this.config.alertThreshold) return 'high';
        
        return 'medium';
    }

    /**
     * Get risk score increase for alert type
     */
    getAlertRiskIncrease(alertType) {
        const riskMap = {
            'CRITICAL_RISK_DETECTED': 30,
            'HIGH_RISK_BET': 20,
            'HIGH_RISK_WITHDRAWAL': 25,
            'SUSPICIOUS_LOGIN': 15,
            'NEW_DEVICE_HIGH_RISK': 15,
            'SUSPICIOUS_PROFILE_UPDATE': 10,
            'COORDINATED_ATTACK': 40
        };
        
        return riskMap[alertType] || 10;
    }

    /**
     * Escalate critical alerts
     */
    async escalateAlert(alert) {
        // In production, this would integrate with external systems
        this.log('critical', 'ALERT ESCALATED', {
            alertId: alert.id,
            type: alert.type,
            userId: alert.userId,
            details: alert.details
        });
        
        // Could trigger external notifications, suspend accounts, etc.
    }

    /**
     * Check for automatic actions based on alert
     */
    async checkAutomaticActions(alert) {
        const userRiskScore = this.riskScores.get(alert.userId) || 0;
        
        // Automatic account suspension for critical risk
        if (userRiskScore > 95) {
            this.log('action', 'Auto-suspend recommended', {
                userId: alert.userId,
                riskScore: userRiskScore
            });
        }
        
        // Enhanced monitoring for high risk
        if (userRiskScore > this.config.alertThreshold) {
            this.log('action', 'Enhanced monitoring enabled', {
                userId: alert.userId,
                riskScore: userRiskScore
            });
        }
    }

    /**
     * Clean up expired user sessions
     */
    cleanupExpiredSessions() {
        const now = Date.now();
        const expiredSessions = [];
        
        for (const [userId, session] of this.userSessions.entries()) {
            if (now - session.lastActivity > this.config.sessionTimeout) {
                expiredSessions.push(userId);
            }
        }
        
        expiredSessions.forEach(userId => {
            this.userSessions.delete(userId);
            this.log('debug', 'Session expired', { userId });
        });
    }

    /**
     * Apply risk score decay over time
     */
    applyRiskDecay() {
        for (const [userId, score] of this.riskScores.entries()) {
            const decayedScore = score * this.config.riskDecayRate;
            if (decayedScore < 1) {
                this.riskScores.delete(userId);
            } else {
                this.riskScores.set(userId, decayedScore);
            }
        }
    }

    /**
     * Analyze patterns across all users
     */
    analyzePatterns() {
        // Cross-user pattern analysis
        this.detectCoordinatedAttacks();
        this.detectAnomalousPatterns();
        this.updateThreatIntelligence();
    }

    /**
     * Detect coordinated attacks across multiple users
     */
    detectCoordinatedAttacks() {
        const recentEvents = new Map();
        const now = Date.now();
        const timeWindow = 10 * 60 * 1000; // 10 minutes
        
        // Collect recent events
        for (const [userId, events] of this.eventBuffer.entries()) {
            const userRecentEvents = events.filter(e => now - e.timestamp < timeWindow);
            if (userRecentEvents.length > 0) {
                recentEvents.set(userId, userRecentEvents);
            }
        }
        
        // Look for coordinated patterns
        const coordinatedPatterns = this.findCoordinatedPatterns(recentEvents);
        
        if (coordinatedPatterns.length > 0) {
            this.triggerAlert('COORDINATED_ATTACK', 'SYSTEM', {
                patterns: coordinatedPatterns,
                affectedUsers: coordinatedPatterns.flatMap(p => p.users)
            });
        }
    }

    /**
     * Find coordinated patterns in user events
     */
    findCoordinatedPatterns(recentEvents) {
        const patterns = [];
        
        // Pattern 1: Simultaneous similar events
        const eventsByType = new Map();
        
        for (const [userId, events] of recentEvents.entries()) {
            for (const event of events) {
                if (!eventsByType.has(event.type)) {
                    eventsByType.set(event.type, []);
                }
                eventsByType.get(event.type).push({ userId, event });
            }
        }
        
        for (const [eventType, eventList] of eventsByType.entries()) {
            if (eventList.length >= 5) { // 5+ users doing same thing
                const timeGroups = this.groupEventsByTime(eventList, 60000); // 1 minute window
                
                for (const group of timeGroups) {
                    if (group.length >= 3) { // 3+ users in same time window
                        patterns.push({
                            type: 'simultaneous_events',
                            eventType,
                            users: group.map(e => e.userId),
                            timeWindow: group.map(e => e.event.timestamp)
                        });
                    }
                }
            }
        }
        
        return patterns;
    }

    /**
     * Group events by time windows
     */
    groupEventsByTime(events, windowSize) {
        const groups = [];
        const sortedEvents = events.sort((a, b) => a.event.timestamp - b.event.timestamp);
        
        let currentGroup = [];
        let groupStartTime = null;
        
        for (const event of sortedEvents) {
            if (!groupStartTime || event.event.timestamp - groupStartTime > windowSize) {
                if (currentGroup.length > 0) {
                    groups.push(currentGroup);
                }
                currentGroup = [event];
                groupStartTime = event.event.timestamp;
            } else {
                currentGroup.push(event);
            }
        }
        
        if (currentGroup.length > 0) {
            groups.push(currentGroup);
        }
        
        return groups;
    }

    /**
     * Detect anomalous patterns in system behavior
     */
    detectAnomalousPatterns() {
        // System-wide anomaly detection
        const totalEvents = Array.from(this.eventBuffer.values())
            .reduce((sum, events) => sum + events.length, 0);
        
        const activeUsers = this.eventBuffer.size;
        const avgEventsPerUser = activeUsers > 0 ? totalEvents / activeUsers : 0;
        
        // Detect unusual system load
        if (avgEventsPerUser > 50) {
            this.log('warning', 'Unusual system activity detected', {
                totalEvents,
                activeUsers,
                avgEventsPerUser
            });
        }
    }

    /**
     * Update threat intelligence patterns
     */
    updateThreatIntelligence() {
        // Update known attack patterns
        const highRiskUsers = Array.from(this.riskScores.entries())
            .filter(([_, score]) => score > this.config.alertThreshold)
            .map(([userId, _]) => userId);
        
        if (highRiskUsers.length > 10) {
            this.log('intelligence', 'High number of risky users detected', {
                count: highRiskUsers.length,
                threshold: this.config.alertThreshold
            });
        }
    }

    /**
     * Check if rate limited
     */
    isRateLimited() {
        return this.eventCounter >= this.config.maxEventsPerSecond;
    }

    /**
     * Calculate distance between two coordinates
     */
    calculateDistance(coord1, coord2) {
        if (!coord1 || !coord2) return 0;
        
        const R = 6371; // Earth's radius in km
        const dLat = this.toRadians(coord2.lat - coord1.lat);
        const dLon = this.toRadians(coord2.lon - coord1.lon);
        
        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                  Math.cos(this.toRadians(coord1.lat)) * Math.cos(this.toRadians(coord2.lat)) *
                  Math.sin(dLon/2) * Math.sin(dLon/2);
        
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        return R * c;
    }

    /**
     * Convert degrees to radians
     */
    toRadians(degrees) {
        return degrees * (Math.PI / 180);
    }

    /**
     * Get current risk score for user
     */
    getUserRiskScore(userId) {
        return this.riskScores.get(userId) || 0;
    }

    /**
     * Get user session information
     */
    getUserSession(userId) {
        return this.userSessions.get(userId);
    }

    /**
     * Get alert history for user
     */
    getUserAlerts(userId) {
        return this.alertHistory.get(userId) || [];
    }

    /**
     * Get system monitoring statistics
     */
    getMonitoringStats() {
        return {
            totalUsers: this.userSessions.size,
            totalEvents: Array.from(this.eventBuffer.values())
                .reduce((sum, events) => sum + events.length, 0),
            highRiskUsers: Array.from(this.riskScores.entries())
                .filter(([_, score]) => score > this.config.alertThreshold).length,
            totalAlerts: Array.from(this.alertHistory.values())
                .reduce((sum, alerts) => sum + alerts.length, 0),
            eventsPerSecond: this.eventCounter,
            isMonitoring: this.isMonitoring
        };
    }

    /**
     * Start monitoring
     */
    startMonitoring() {
        this.isMonitoring = true;
        this.log('info', 'Real-time fraud monitoring started');
    }

    /**
     * Stop monitoring
     */
    stopMonitoring() {
        this.isMonitoring = false;
        this.log('info', 'Real-time fraud monitoring stopped');
    }

    /**
     * Logging utility
     */
    log(level, message, data = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            level,
            message,
            data,
            component: 'RealTimeFraudMonitor'
        };
        
        if (this.config.logLevel === 'debug' || 
            (this.config.logLevel === 'info' && ['info', 'warning', 'error', 'alert', 'critical'].includes(level)) ||
            (this.config.logLevel === 'warning' && ['warning', 'error', 'alert', 'critical'].includes(level)) ||
            (this.config.logLevel === 'error' && ['error', 'alert', 'critical'].includes(level))) {
            
            console.log(JSON.stringify(logEntry));
        }
    }
}

module.exports = RealTimeFraudMonitor;