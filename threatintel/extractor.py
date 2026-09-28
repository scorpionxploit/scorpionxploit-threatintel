"""
ScorpionXploit ThreatIntel - Defensive IOC Extraction & Structuring
Author: Aditya Sharma (scorpionxploit)
License: MIT
"""
import re
from typing import Dict, List, Set

IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')

class ThreatIntelExtractor:
    @staticmethod
    def defang(text: str) -> str:
        text = text.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
        text = text.replace(".", "[.]")
        return text

    @staticmethod
    def refang(text: str) -> str:
        text = text.replace("hxxps[://]", "https://").replace("hxxp[://]", "http://")
        text = text.replace("[.]", ".")
        return text

    def extract_iocs(self, raw_text: str) -> Dict[str, List[str]]:
        ips = list(set(IPV4_PATTERN.findall(raw_text)))
        sha256 = list(set(SHA256_PATTERN.findall(raw_text)))
        md5 = list(set(MD5_PATTERN.findall(raw_text)))
        
        # Filter out hashes from md5 if part of sha256
        return {
            "ipv4": ips,
            "sha256": sha256,
            "md5": md5
        }
