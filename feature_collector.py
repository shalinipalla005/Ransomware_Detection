class FeatureCollector:
    def __init__(self):
        self.features = {
            "honey": 0,
            "rename": 0,
            "entropy": 0,
            "modification": 0
        }

    def update(self, key):
        if key in self.features:
            self.features[key] += 1

    def score(self):
        return sum(self.features.values())

    def is_suspicious(self):
        return self.score() >= 3