import os
import random

class PayloadManager:
    def __init__(self):
        self.payload_dir = "payloads"
        self.cache = {}
    
    def load(self, method):
        if method in self.cache:
            return self.cache[method]
        fname = f"{self.payload_dir}/{method}_payloads.txt"
        payloads = []
        if os.path.exists(fname):
            with open(fname, "r", encoding="utf-8", errors="ignore") as f:
                payloads = [
                    l.strip()
                    for l in f
                    if l.strip() and not l.lstrip().startswith("#")
                ]
        self.cache[method] = payloads
        return payloads
    
    def get(self, method, limit=None):
        p = self.load(method)
        if limit:
            return p[:limit]
        return p
    
    def count(self, method):
        return len(self.load(method))
