# 🦅 skywatch.py
# ---------------------------------------------------------
# SentinelHawk — Log Collection Layer
# Responsible ONLY for ingestion + normalization
# ---------------------------------------------------------

from nest.ingestion import LogIngestion
from nest.event_normalizer import EventNormalizer
from nest.baseline_engine import BaselineEngine
from nest.correlation_engine import CorrelationEngine
from nest.mitre_mapper import MITREMapper
from nest.response_engine import ResponseEngine
from nest.talonscore import TalonScore

class Skywatch:

    def __init__(self):
        self.ingestion = LogIngestion()
        self.baseline = BaselineEngine()
        self.correlation = CorrelationEngine()
        self.mitre = MITREMapper()
        self.scorer = TalonScore()
        self.response = ResponseEngine()

    def collect(self):
        raw_events = self.ingestion.fetch_logs()
        results = []

        for raw in raw_events:
            event = EventNormalizer.normalize(raw)

            anomaly = self.baseline.analyze(event)
            correlation = self.correlation.analyze(event)
            mitre = self.mitre.map(event)

            # Pass dict to scorer
            # Scorer returns a dict with risk, confidence, etc.
            scoring = self.scorer.score({
                "event": event,
                "anomaly_score": anomaly,
                "correlation_score": correlation,
                "mitre": mitre
            })

            results.append(scoring)

        return results
