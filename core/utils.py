import os
import sys
import json
import time
import random
import socket
from datetime import datetime
from urllib.parse import urlparse

class Utils:
    @staticmethod
    def validate_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    @staticmethod
    def get_domain(url):
        return urlparse(url).netloc
    
    @staticmethod
    def save_state(data, filename="temp/session_save.txt"):
        with open(filename, 'w') as f:
            json.dump(data, f)
    
    @staticmethod
    def load_state(filename="temp/session_save.txt"):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
        return None
    
    @staticmethod
    def log(message, level="INFO", logfile="logs/scan.log"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(logfile, 'a') as f:
            f.write(f"[{ts}] [{level}] {message}\n")
    
    @staticmethod
    def random_ua():
        ua = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/94.0"
        ]
        return random.choice(ua)
    
    @staticmethod
    def check_internet():
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except:
            return False
    
    @staticmethod
    def ensure_folders():
        for f in ['reports', 'logs', 'temp']:
            if not os.path.exists(f):
                os.makedirs(f)
