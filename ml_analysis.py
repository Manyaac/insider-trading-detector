import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime

class SuspiciousTradeDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        
    def detect_anomalies(self, trades):
        """Detect anomalous trades using ML"""
        if len(trades) < 3:
            return []
            
        # Convert to features: [amount, days_since_reported, severity_weight]
        X = np.array([
            [t['amount'], 
             (datetime.now() - t['date']).days,
             self._severity_weight(t['severity'])]
            for t in trades
        ])
        
        self.model.fit(X)
        scores = self.model.decision_function(X)
        return [i for i, score in enumerate(scores) if score < 0]
    
    def _severity_weight(self, severity):
        weights = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.1}
        return weights.get(severity, 0.5)