"""
Machine Learning-based Anomaly Detection for Fraud Testing
Advanced behavioral pattern analysis and anomaly detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime, timedelta
import json
import logging
from typing import Dict, List, Tuple, Optional
import pickle
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class BehavioralAnomalyDetector:
    """ML-based fraud detection using behavioral pattern analysis"""
    
    def __init__(self, contamination=0.1, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        
        # Initialize models
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100
        )
        
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()
        self.is_fitted = False
        
        # Feature importance tracking
        self.feature_names = []
        self.anomaly_scores = {}
        
    def extract_behavioral_features(self, user_data: Dict) -> np.ndarray:
        """Extract behavioral features from user data"""
        features = []
        
        # Betting pattern features
        bets = user_data.get('bets', [])
        if bets:
            bet_amounts = [bet['amount'] for bet in bets]
            bet_times = [datetime.fromisoformat(bet['timestamp']) for bet in bets]
            
            # Statistical features
            features.extend([
                np.mean(bet_amounts),                    # Average bet amount
                np.std(bet_amounts),                     # Bet amount variance
                np.max(bet_amounts),                     # Maximum bet
                np.min(bet_amounts),                     # Minimum bet
                len(bets),                              # Total number of bets
                np.percentile(bet_amounts, 95),         # 95th percentile
                np.percentile(bet_amounts, 5),          # 5th percentile
            ])
            
            # Temporal features
            if len(bet_times) > 1:
                time_diffs = [(bet_times[i] - bet_times[i-1]).total_seconds() 
                             for i in range(1, len(bet_times))]
                features.extend([
                    np.mean(time_diffs),                # Average time between bets
                    np.std(time_diffs),                 # Time variance
                    np.min(time_diffs),                 # Minimum time gap
                    len([t for t in time_diffs if t < 60]),  # Rapid bets (<1 min)
                ])
            else:
                features.extend([0, 0, 0, 0])
            
            # Pattern features
            unique_matches = len(set(bet['match_id'] for bet in bets))
            unique_bet_types = len(set(bet['bet_type'] for bet in bets))
            features.extend([
                unique_matches / len(bets),             # Match diversity ratio
                unique_bet_types / len(bets),           # Bet type diversity
                len([b for b in bets if b['amount'] > 500]) / len(bets),  # High value ratio
            ])
            
            # Time-of-day features
            hours = [t.hour for t in bet_times]
            features.extend([
                np.mean(hours),                         # Average betting hour
                np.std(hours),                          # Hour variance
                len([h for h in hours if 22 <= h or h <= 6]) / len(hours),  # Night betting
            ])
            
        else:
            # No betting data - suspicious for active users
            features.extend([0] * 17)
        
        # Profile change features
        profile_changes = user_data.get('profile_changes', [])
        if profile_changes:
            change_times = [datetime.fromisoformat(change['timestamp']) 
                           for change in profile_changes]
            critical_changes = sum(1 for change in profile_changes 
                                 if change.get('field') in ['email', 'phone', 'bank_account'])
            
            features.extend([
                len(profile_changes),                   # Total profile changes
                critical_changes,                       # Critical field changes
                critical_changes / len(profile_changes) if profile_changes else 0,
            ])
            
            if len(change_times) > 1:
                change_intervals = [(change_times[i] - change_times[i-1]).total_seconds() 
                                  for i in range(1, len(change_times))]
                features.extend([
                    np.mean(change_intervals),          # Average change interval
                    len([i for i in change_intervals if i < 3600]),  # Rapid changes (<1 hour)
                ])
            else:
                features.extend([0, 0])
        else:
            features.extend([0] * 5)
        
        # Session features
        sessions = user_data.get('sessions', [])
        if sessions:
            session_durations = [session.get('duration', 0) for session in sessions]
            concurrent_sessions = max(session.get('concurrent_count', 1) for session in sessions)
            
            features.extend([
                len(sessions),                          # Total sessions
                np.mean(session_durations),             # Average session duration
                concurrent_sessions,                    # Max concurrent sessions
                len([s for s in sessions if s.get('duration', 0) > 7200]),  # Long sessions (>2h)
            ])
        else:
            features.extend([0] * 4)
        
        # Account features
        account_age_days = (datetime.now() - 
                           datetime.fromisoformat(user_data.get('created_at', datetime.now().isoformat()))
                          ).days
        verification_score = user_data.get('verification_score', 0)
        
        features.extend([
            account_age_days,                           # Account age
            verification_score,                         # Verification completeness
            user_data.get('failed_login_attempts', 0), # Failed logins
            user_data.get('password_changes', 0),      # Password changes
        ])
        
        return np.array(features).reshape(1, -1)
    
    def fit(self, training_data: List[Dict]) -> None:
        """Train the anomaly detection models"""
        logger.info(f"Training fraud detection models on {len(training_data)} users")
        
        # Extract features for all users
        feature_matrix = []
        for user_data in training_data:
            features = self.extract_behavioral_features(user_data)
            feature_matrix.append(features.flatten())
        
        feature_matrix = np.array(feature_matrix)
        
        # Scale features
        feature_matrix_scaled = self.scaler.fit_transform(feature_matrix)
        
        # Train models
        self.isolation_forest.fit(feature_matrix_scaled)
        self.dbscan.fit(feature_matrix_scaled)
        
        self.is_fitted = True
        
        # Store feature names for interpretation
        self.feature_names = [
            'avg_bet_amount', 'bet_amount_std', 'max_bet', 'min_bet', 'total_bets',
            'bet_95_percentile', 'bet_5_percentile', 'avg_time_between_bets',
            'time_variance', 'min_time_gap', 'rapid_bets_count', 'match_diversity',
            'bet_type_diversity', 'high_value_ratio', 'avg_betting_hour',
            'hour_variance', 'night_betting_ratio', 'total_profile_changes',
            'critical_changes', 'critical_change_ratio', 'avg_change_interval',
            'rapid_profile_changes', 'total_sessions', 'avg_session_duration',
            'max_concurrent_sessions', 'long_sessions', 'account_age_days',
            'verification_score', 'failed_login_attempts', 'password_changes'
        ]
        
        logger.info("Fraud detection models trained successfully")
    
    def predict_anomaly(self, user_data: Dict) -> Dict:
        """Predict if user behavior is anomalous"""
        if not self.is_fitted:
            raise ValueError("Models must be fitted before prediction")
        
        features = self.extract_behavioral_features(user_data)
        features_scaled = self.scaler.transform(features)
        
        # Get predictions from different models
        isolation_score = self.isolation_forest.decision_function(features_scaled)[0]
        isolation_prediction = self.isolation_forest.predict(features_scaled)[0]
        
        # DBSCAN clustering (-1 means outlier)
        dbscan_prediction = self.dbscan.fit_predict(features_scaled)[0]
        
        # Calculate composite anomaly score
        anomaly_score = abs(isolation_score)
        is_anomaly = isolation_prediction == -1 or dbscan_prediction == -1
        
        # Risk level determination
        if anomaly_score > 0.6 or is_anomaly:
            risk_level = "high"
        elif anomaly_score > 0.3:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Feature importance analysis
        feature_importance = self._analyze_feature_importance(features.flatten())
        
        result = {
            "user_id": user_data.get('user_id', 'unknown'),
            "anomaly_score": float(anomaly_score),
            "is_anomaly": bool(is_anomaly),
            "risk_level": risk_level,
            "isolation_score": float(isolation_score),
            "dbscan_cluster": int(dbscan_prediction),
            "feature_importance": feature_importance,
            "model_confidence": float(abs(isolation_score)),
            "timestamp": datetime.now().isoformat()
        }
        
        return result
    
    def _analyze_feature_importance(self, features: np.ndarray) -> Dict:
        """Analyze which features contribute most to anomaly detection"""
        importance_dict = {}
        
        # Compare features to training data means
        for i, (feature_name, feature_value) in enumerate(zip(self.feature_names, features)):
            # Simplified importance based on deviation from normal ranges
            if 'bet_amount' in feature_name and feature_value > 1000:
                importance_dict[feature_name] = min(feature_value / 1000, 5.0)
            elif 'rapid' in feature_name and feature_value > 5:
                importance_dict[feature_name] = min(feature_value / 5, 3.0)
            elif 'time' in feature_name and feature_value < 60:
                importance_dict[feature_name] = max(2.0, 60 / max(feature_value, 1))
            else:
                importance_dict[feature_name] = max(0.1, abs(feature_value) / 100)
        
        # Return top 5 most important features
        sorted_features = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_features[:5])
    
    def save_model(self, filepath: str) -> None:
        """Save trained models to file"""
        model_data = {
            'isolation_forest': self.isolation_forest,
            'dbscan': self.dbscan,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_fitted': self.is_fitted
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Models saved to {filepath}")
    
    def load_model(self, filepath: str) -> None:
        """Load trained models from file"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.isolation_forest = model_data['isolation_forest']
        self.dbscan = model_data['dbscan']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_fitted = model_data['is_fitted']
        
        logger.info(f"Models loaded from {filepath}")

class CrossUserCorrelationAnalyzer:
    """Analyze fraud patterns across multiple users"""
    
    def __init__(self):
        self.user_profiles = {}
        self.correlation_matrix = None
        self.fraud_networks = []
    
    def add_user_profile(self, user_id: str, user_data: Dict) -> None:
        """Add user profile for correlation analysis"""
        self.user_profiles[user_id] = {
            'user_id': user_id,
            'betting_patterns': self._extract_betting_signature(user_data),
            'network_indicators': self._extract_network_indicators(user_data),
            'temporal_patterns': self._extract_temporal_patterns(user_data),
            'device_fingerprints': user_data.get('device_fingerprints', []),
            'ip_addresses': user_data.get('ip_addresses', []),
            'last_updated': datetime.now().isoformat()
        }
    
    def _extract_betting_signature(self, user_data: Dict) -> Dict:
        """Extract unique betting signature for correlation"""
        bets = user_data.get('bets', [])
        if not bets:
            return {}
        
        amounts = [bet['amount'] for bet in bets]
        return {
            'favorite_amounts': self._find_frequent_values(amounts),
            'amount_patterns': self._find_amount_sequences(amounts),
            'match_preferences': self._find_frequent_values([bet['match_id'] for bet in bets]),
            'bet_type_preferences': self._find_frequent_values([bet['bet_type'] for bet in bets]),
            'timing_signature': self._extract_timing_signature(bets)
        }
    
    def _extract_network_indicators(self, user_data: Dict) -> Dict:
        """Extract network-based fraud indicators"""
        return {
            'shared_devices': user_data.get('device_fingerprints', []),
            'shared_ips': user_data.get('ip_addresses', []),
            'shared_payment_methods': user_data.get('payment_methods', []),
            'referral_connections': user_data.get('referrals', []),
            'social_connections': user_data.get('social_connections', [])
        }
    
    def _extract_temporal_patterns(self, user_data: Dict) -> Dict:
        """Extract temporal behavior patterns"""
        bets = user_data.get('bets', [])
        if not bets:
            return {}
        
        bet_times = [datetime.fromisoformat(bet['timestamp']) for bet in bets]
        
        return {
            'active_hours': [t.hour for t in bet_times],
            'active_days': [t.weekday() for t in bet_times],
            'session_patterns': self._identify_session_patterns(bet_times),
            'burst_patterns': self._identify_burst_patterns(bet_times)
        }
    
    def analyze_cross_user_correlations(self) -> Dict:
        """Analyze correlations between users to detect fraud networks"""
        logger.info(f"Analyzing correlations across {len(self.user_profiles)} users")
        
        correlations = []
        user_ids = list(self.user_profiles.keys())
        
        # Compare each pair of users
        for i in range(len(user_ids)):
            for j in range(i + 1, len(user_ids)):
                user1_id, user2_id = user_ids[i], user_ids[j]
                user1_data = self.user_profiles[user1_id]
                user2_data = self.user_profiles[user2_id]
                
                correlation_score = self._calculate_user_similarity(user1_data, user2_data)
                
                if correlation_score > 0.7:  # High correlation threshold
                    correlations.append({
                        'user1': user1_id,
                        'user2': user2_id,
                        'correlation_score': correlation_score,
                        'shared_indicators': self._identify_shared_indicators(user1_data, user2_data),
                        'risk_level': 'high' if correlation_score > 0.9 else 'medium'
                    })
        
        # Identify fraud networks
        fraud_networks = self._identify_fraud_networks(correlations)
        
        return {
            'total_correlations': len(correlations),
            'high_risk_correlations': len([c for c in correlations if c['risk_level'] == 'high']),
            'detected_networks': fraud_networks,
            'correlation_details': correlations,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _calculate_user_similarity(self, user1_data: Dict, user2_data: Dict) -> float:
        """Calculate similarity score between two users"""
        similarity_scores = []
        
        # Betting pattern similarity
        betting_sim = self._compare_betting_patterns(
            user1_data['betting_patterns'], 
            user2_data['betting_patterns']
        )
        similarity_scores.append(betting_sim * 0.4)
        
        # Network indicator similarity
        network_sim = self._compare_network_indicators(
            user1_data['network_indicators'], 
            user2_data['network_indicators']
        )
        similarity_scores.append(network_sim * 0.3)
        
        # Temporal pattern similarity
        temporal_sim = self._compare_temporal_patterns(
            user1_data['temporal_patterns'], 
            user2_data['temporal_patterns']
        )
        similarity_scores.append(temporal_sim * 0.3)
        
        return sum(similarity_scores)
    
    def _compare_betting_patterns(self, pattern1: Dict, pattern2: Dict) -> float:
        """Compare betting patterns between users"""
        if not pattern1 or not pattern2:
            return 0.0
        
        similarity = 0.0
        
        # Compare favorite amounts
        amounts1 = set(pattern1.get('favorite_amounts', []))
        amounts2 = set(pattern2.get('favorite_amounts', []))
        if amounts1 and amounts2:
            similarity += len(amounts1.intersection(amounts2)) / len(amounts1.union(amounts2)) * 0.3
        
        # Compare match preferences
        matches1 = set(pattern1.get('match_preferences', []))
        matches2 = set(pattern2.get('match_preferences', []))
        if matches1 and matches2:
            similarity += len(matches1.intersection(matches2)) / len(matches1.union(matches2)) * 0.3
        
        # Compare bet type preferences
        types1 = set(pattern1.get('bet_type_preferences', []))
        types2 = set(pattern2.get('bet_type_preferences', []))
        if types1 and types2:
            similarity += len(types1.intersection(types2)) / len(types1.union(types2)) * 0.4
        
        return similarity
    
    def _compare_network_indicators(self, network1: Dict, network2: Dict) -> float:
        """Compare network indicators between users"""
        similarity = 0.0
        
        # Shared devices
        devices1 = set(network1.get('shared_devices', []))
        devices2 = set(network2.get('shared_devices', []))
        if devices1.intersection(devices2):
            similarity += 0.4
        
        # Shared IPs
        ips1 = set(network1.get('shared_ips', []))
        ips2 = set(network2.get('shared_ips', []))
        if ips1.intersection(ips2):
            similarity += 0.3
        
        # Shared payment methods
        payments1 = set(network1.get('shared_payment_methods', []))
        payments2 = set(network2.get('shared_payment_methods', []))
        if payments1.intersection(payments2):
            similarity += 0.3
        
        return min(similarity, 1.0)
    
    def _compare_temporal_patterns(self, temporal1: Dict, temporal2: Dict) -> float:
        """Compare temporal patterns between users"""
        if not temporal1 or not temporal2:
            return 0.0
        
        similarity = 0.0
        
        # Compare active hours
        hours1 = set(temporal1.get('active_hours', []))
        hours2 = set(temporal2.get('active_hours', []))
        if hours1 and hours2:
            similarity += len(hours1.intersection(hours2)) / len(hours1.union(hours2)) * 0.5
        
        # Compare active days
        days1 = set(temporal1.get('active_days', []))
        days2 = set(temporal2.get('active_days', []))
        if days1 and days2:
            similarity += len(days1.intersection(days2)) / len(days1.union(days2)) * 0.5
        
        return similarity
    
    def _identify_shared_indicators(self, user1_data: Dict, user2_data: Dict) -> List[str]:
        """Identify specific shared indicators between users"""
        indicators = []
        
        network1 = user1_data['network_indicators']
        network2 = user2_data['network_indicators']
        
        if set(network1.get('shared_devices', [])).intersection(set(network2.get('shared_devices', []))):
            indicators.append('shared_device_fingerprints')
        
        if set(network1.get('shared_ips', [])).intersection(set(network2.get('shared_ips', []))):
            indicators.append('shared_ip_addresses')
        
        if set(network1.get('shared_payment_methods', [])).intersection(set(network2.get('shared_payment_methods', []))):
            indicators.append('shared_payment_methods')
        
        # Behavioral indicators
        betting1 = user1_data['betting_patterns']
        betting2 = user2_data['betting_patterns']
        
        if set(betting1.get('favorite_amounts', [])).intersection(set(betting2.get('favorite_amounts', []))):
            indicators.append('similar_betting_amounts')
        
        if set(betting1.get('timing_signature', [])).intersection(set(betting2.get('timing_signature', []))):
            indicators.append('synchronized_betting_times')
        
        return indicators
    
    def _identify_fraud_networks(self, correlations: List[Dict]) -> List[Dict]:
        """Identify connected fraud networks from correlations"""
        networks = []
        processed_users = set()
        
        for correlation in correlations:
            if correlation['risk_level'] == 'high':
                user1, user2 = correlation['user1'], correlation['user2']
                
                if user1 not in processed_users and user2 not in processed_users:
                    # Start new network
                    network = {
                        'network_id': len(networks) + 1,
                        'users': [user1, user2],
                        'correlations': [correlation],
                        'risk_score': correlation['correlation_score'],
                        'shared_indicators': correlation['shared_indicators']
                    }
                    networks.append(network)
                    processed_users.update([user1, user2])
                
                elif user1 in processed_users or user2 in processed_users:
                    # Add to existing network
                    for network in networks:
                        if user1 in network['users'] or user2 in network['users']:
                            if user1 not in network['users']:
                                network['users'].append(user1)
                                processed_users.add(user1)
                            if user2 not in network['users']:
                                network['users'].append(user2)
                                processed_users.add(user2)
                            network['correlations'].append(correlation)
                            break
        
        return networks
    
    def _find_frequent_values(self, values: List) -> List:
        """Find most frequent values in a list"""
        if not values:
            return []
        
        from collections import Counter
        counter = Counter(values)
        # Return values that appear more than 20% of the time
        threshold = max(1, len(values) * 0.2)
        return [value for value, count in counter.items() if count >= threshold]
    
    def _find_amount_sequences(self, amounts: List[float]) -> List[List[float]]:
        """Find common betting amount sequences"""
        sequences = []
        for i in range(len(amounts) - 2):
            seq = amounts[i:i+3]
            if seq not in sequences:
                sequences.append(seq)
        return sequences[:5]  # Return top 5 sequences
    
    def _extract_timing_signature(self, bets: List[Dict]) -> List[str]:
        """Extract timing signature from betting history"""
        if len(bets) < 2:
            return []
        
        signatures = []
        bet_times = [datetime.fromisoformat(bet['timestamp']) for bet in bets]
        
        for i in range(1, len(bet_times)):
            time_diff = (bet_times[i] - bet_times[i-1]).total_seconds()
            if time_diff < 300:  # 5 minutes
                signatures.append(f"rapid_{int(time_diff)}")
            elif time_diff > 3600:  # 1 hour
                signatures.append(f"delayed_{int(time_diff//3600)}")
        
        return signatures
    
    def _identify_session_patterns(self, bet_times: List[datetime]) -> List[str]:
        """Identify betting session patterns"""
        patterns = []
        
        # Group bets by sessions (gaps > 30 minutes)
        sessions = []
        current_session = [bet_times[0]]
        
        for i in range(1, len(bet_times)):
            if (bet_times[i] - bet_times[i-1]).total_seconds() > 1800:  # 30 minutes
                sessions.append(current_session)
                current_session = [bet_times[i]]
            else:
                current_session.append(bet_times[i])
        
        sessions.append(current_session)
        
        # Analyze session patterns
        for session in sessions:
            duration = (session[-1] - session[0]).total_seconds()
            bet_count = len(session)
            
            if duration < 300 and bet_count > 5:
                patterns.append("burst_session")
            elif duration > 7200:
                patterns.append("marathon_session")
            elif bet_count > 20:
                patterns.append("high_frequency_session")
        
        return patterns
    
    def _identify_burst_patterns(self, bet_times: List[datetime]) -> List[str]:
        """Identify burst betting patterns"""
        patterns = []
        
        for i in range(len(bet_times) - 4):
            # Check for 5 bets within 2 minutes
            window_bets = bet_times[i:i+5]
            if (window_bets[-1] - window_bets[0]).total_seconds() < 120:
                patterns.append(f"burst_5_bets_{window_bets[0].strftime('%H:%M')}")
        
        return patterns
