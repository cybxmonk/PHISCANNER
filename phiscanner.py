import requests
import re
import argparse
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
import urllib.parse
import time  # Added for rate limiting
import random # Added for randomizing user agents

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('phiscanner')

class PhishingScanner:
    def __init__(self, vt_api_key: Optional[str] = None, gsb_api_key: Optional[str] = None):
        self.vt_api_key = vt_api_key
        self.gsb_api_key = gsb_api_key
        
    def check_heuristic(self, url: str) -> bool:
        """Check if URL contains suspicious patterns."""
        # Parse the URL to separate components
        try:
            parsed_url = urllib.parse.urlparse(url)
            hostname = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            query = parsed_url.query.lower()
            
            # Whitelist of legitimate security services that should never be flagged
            security_services_whitelist = [
                'virustotal.com',
                'www.virustotal.com',
                'safebrowsing.google.com',
                'safebrowsing-cache.google.com',
                'transparencyreport.google.com',
                'www.google.com',
                'security.microsoft.com',
                'securitycenter.windows.com',
                'www.hybrid-analysis.com',
                'urlscan.io',
                'www.urlscan.io',
                'www.phishtank.com',
                'checkphish.ai',
                'opentip.kaspersky.com',
                'global.sitesafety.trendmicro.com',
                'scanurl.net',
                'metadefender.opswat.com',
                'www.psafe.com',
                'sitecheck.sucuri.net',
                'isitphishing.org',
                'maltiverse.com'
            ]
            
            # If the domain is in our security services whitelist, return False immediately
            for trusted_domain in security_services_whitelist:
                if hostname == trusted_domain or hostname.endswith('.' + trusted_domain):
                    logger.info(f"Domain {hostname} is a trusted security service, skipping heuristic check")
                    return False
            
            # Common phishing keywords in the URL
            phishing_keywords = [
                'login', 'account', 'secure', 'verify', 'bank', 'paypal', 'ebay', 
                'update', 'confirm', 'password', 'credit', 'signin', 'security', 
                'auth', 'authenticate', 'authenticate', 'wallet', 'verification'
            ]
            
            # Common phishing TLDs and domain patterns
            suspicious_domains = [
                r'\.workers\.dev',    # Cloud worker domains
                r'\.repl\.co',        # Replit domains
                r'\.glitch\.me',      # Glitch domains
                r'\.000webhost\.com', # Free hosting
                r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$', r'\.gq$', # Free TLDs
                r'\.xyz$',            # Often abused TLD
                r'bit\.ly', r'goo\.gl', r'tinyurl\.com', r't\.co', # URL shorteners
                r'amazonaws\.com',    # AWS hosting
                r'azurewebsites\.net', # Azure hosting
                r'herokuapp\.com'     # Heroku hosting
            ]
            
            # Check for numeric patterns in hostname (common in phishing domains)
            if re.search(r'\d{4,}', hostname):
                # Exception for legitimate sites with version numbers (like api2.service.com)
                if not re.match(r'^(api|v|version)\d+\.', hostname):
                    logger.info(f"Suspicious pattern: numeric pattern in hostname: {hostname}")
                    return True
            
            # Check for random alphanumeric strings (common in generated phishing domains)
            # Modified to reduce false positives by requiring more randomness
            random_pattern = r'[a-z0-9]{12,}'  # Increased from 10 to 12 characters
            random_match = re.search(random_pattern, hostname)
            if random_match:
                # Skip if the match is a legitimate subdomain or known pattern
                matched_text = random_match.group(0)
                if not (matched_text in ['githubusercontent', 'cloudfront', 'amazonaws'] or 
                       any(safe_word in matched_text for safe_word in ['security', 'protection', 'antivirus', 'scanner'])):
                    logger.info(f"Suspicious pattern: random alphanumeric in hostname: {hostname}")
                    return True
            
            # Check for suspicious domain patterns
            for pattern in suspicious_domains:
                if re.search(pattern, hostname):
                    # Exclude security-related or legitimate service domains
                    if not any(safe_word in hostname for safe_word in ['security', 'protection', 'scan', 'antivirus', 'official']):
                        logger.info(f"Suspicious domain pattern: {pattern} in {hostname}")
                        return True
            
            # Check for phishing keywords in hostname or path
            # Only flag if multiple keywords are present or they're in suspicious locations
            keyword_count = 0
            for keyword in phishing_keywords:
                if keyword in hostname:
                    keyword_count += 1
                elif keyword in path and any(bank_name in hostname for bank_name in ['bank', 'pay', 'account', 'secure']):
                    keyword_count += 1
            
            if keyword_count >= 2:  # Require at least 2 suspicious keywords to trigger
                logger.info(f"Multiple suspicious keywords found: {keyword_count} in URL")
                return True
            
            # Check for suspicious URL parameters - only flag if multiple suspicious patterns exist
            suspicious_param_count = 0
            suspicious_params = ['token', 'auth', 'id', 'account', 'key', 'password', 'email', 'login']
            query_params = urllib.parse.parse_qs(query)
            for param in suspicious_params:
                if param in query_params:
                    suspicious_param_count += 1
            
            if suspicious_param_count >= 2:  # Require at least 2 suspicious parameters
                logger.info(f"Multiple suspicious query parameters: {suspicious_param_count}")
                return True
            
            # Check for URLs with IP addresses instead of domain names
            if re.search(r'^(https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url):
                logger.info(f"Suspicious pattern: IP address used as hostname")
                return True
            
            # Check for excessive subdomain levels (phishing often uses many subdomains)
            subdomain_count = hostname.count('.')
            if subdomain_count > 3:
                logger.info(f"Suspicious pattern: excessive subdomains ({subdomain_count})")
                return True
            
            # Check for obfuscation attempts like hexadecimal encoding
            if re.search(r'%[0-9a-fA-F]{2}', url):
                logger.info("Suspicious pattern: URL contains hex encoding")
                return True
                
        except Exception as e:
            logger.error(f"Error parsing URL for heuristic check: {str(e)}")
        
        return False

    def check_virustotal(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL against VirusTotal API."""
        if not self.vt_api_key:
            logger.warning("VirusTotal API key not provided")
            return None
            
        try:
            vt_url = "https://www.virustotal.com/api/v3/urls"
            headers = {"x-apikey": self.vt_api_key}
            data = {"url": url}
            
            response = requests.post(vt_url, headers=headers, data=data)
            response.raise_for_status()
            
            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                
                analysis_response = requests.get(analysis_url, headers=headers)
                analysis_response.raise_for_status()
                
                return analysis_response.json()
                
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error: {str(e)}")
        except (KeyError, json.JSONDecodeError) as e:
            logger.error(f"Error parsing VirusTotal response: {str(e)}")
            
        return None

    def check_google_safe_browsing(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL against Google Safe Browsing API."""
        if not self.gsb_api_key:
            logger.warning("Google Safe Browsing API key not provided")
            return None
            
        try:
            gsb_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            headers = {"Content-Type": "application/json"}
            data = {
                "client": {"clientId": "phishing-scanner", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(f"{gsb_url}?key={self.gsb_api_key}", headers=headers, json=data)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Google Safe Browsing API error: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Google Safe Browsing response: {str(e)}")
            
        return None

    def fetch_virustotal_web_info(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch information about a URL directly from VirusTotal's website.
        This method is a fallback for when no API key is available.
        """
        logger.info(f"Fetching VirusTotal web information for: {url}")
        
        try:
            # Encode the URL for the query parameter
            encoded_url = urllib.parse.quote(url)
            
            # Random User-Agent to make the request look like it's coming from a browser
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
            ]
            
            headers = {
                "User-Agent": random.choice(user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0"
            }
            
            # First, fetch the search page to initiate a session
            search_url = f"https://www.virustotal.com/gui/home/url?q={encoded_url}"
            session = requests.Session()
            response = session.get(search_url, headers=headers, timeout=15)
            response.raise_for_status()
            
            # Sleep to avoid rate limiting
            time.sleep(2)
            
            # Now fetch the URL report page
            report_url = f"https://www.virustotal.com/gui/url/{urllib.parse.quote(encoded_url)}/detection"
            report_response = session.get(report_url, headers=headers, timeout=15)
            report_response.raise_for_status()
            
            # Parse the response text to extract data (limited without proper API access)
            # For a real implementation, you might need to use a browser automation tool like Selenium
            # This is a simplified example that extracts basic information
            
            result = {
                "url": url,
                "status": "retrieved",
                "source": "virustotal_web",
                "timestamp": datetime.now().isoformat(),
                "html_size": len(report_response.text),
                "is_available": report_response.status_code == 200,
            }
            
            # Try to extract some basic information (this is simplified and might not work perfectly)
            if "has been identified as malicious" in report_response.text.lower():
                result["detected"] = True
                result["detection_note"] = "URL identified as malicious by VirusTotal"
            elif "clean" in report_response.text.lower() and "safe" in report_response.text.lower():
                result["detected"] = False
                result["detection_note"] = "URL appears to be clean according to VirusTotal"
            else:
                result["detected"] = None
                result["detection_note"] = "Could not determine status from VirusTotal website"
            
            logger.info(f"Successfully fetched VirusTotal web information for: {url}")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching VirusTotal web information: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error when fetching VirusTotal web info: {str(e)}")
            
        return None

    def fetch_gsb_web_info(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch information about a URL from Google Safe Browsing's Transparency Report.
        This method is a fallback for when no API key is available.
        """
        logger.info(f"Fetching Google Safe Browsing web information for: {url}")
        
        try:
            # Encode the URL for the query parameter
            encoded_url = urllib.parse.quote(url)
            
            # Random User-Agent to make the request look like it's coming from a browser
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
            ]
            
            headers = {
                "User-Agent": random.choice(user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0"
            }
            
            # Fetch the URL from Google's Transparency Report
            transparency_url = f"https://transparencyreport.google.com/safe-browsing/search?url={encoded_url}"
            session = requests.Session()
            response = session.get(transparency_url, headers=headers, timeout=15)
            response.raise_for_status()
            
            result = {
                "url": url,
                "status": "retrieved",
                "source": "google_safe_browsing_web",
                "timestamp": datetime.now().isoformat(),
                "html_size": len(response.text),
                "is_available": response.status_code == 200,
            }
            
            # Try to analyze the response to determine if the site is unsafe
            response_text = response.text.lower()
            if "unsafe" in response_text and "site status" in response_text:
                result["detected"] = True
                if "malware" in response_text:
                    result["detection_type"] = "malware"
                    result["detection_note"] = "Site may contain malware according to Google Safe Browsing"
                elif "phishing" in response_text:
                    result["detection_type"] = "phishing"
                    result["detection_note"] = "Site may be a phishing attempt according to Google Safe Browsing"
                elif "unwanted software" in response_text:
                    result["detection_type"] = "unwanted_software"
                    result["detection_note"] = "Site may distribute unwanted software according to Google Safe Browsing"
                else:
                    result["detection_type"] = "unknown"
                    result["detection_note"] = "Site flagged as unsafe by Google Safe Browsing"
            elif "no unsafe content found" in response_text or "status: not dangerous" in response_text:
                result["detected"] = False
                result["detection_note"] = "No unsafe content found according to Google Safe Browsing"
            else:
                result["detected"] = None
                result["detection_note"] = "Unable to determine status from Google Safe Browsing website"
            
            logger.info(f"Successfully fetched Google Safe Browsing web information for: {url}")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Google Safe Browsing web information: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error when fetching Google Safe Browsing web info: {str(e)}")
            
        return None

    def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan a URL using all available methods."""
        logger.info(f"Scanning: {url}")
        
        # Add timestamp
        timestamp = datetime.now().isoformat()
        
        # Perform checks
        heuristic_result = self.check_heuristic(url)
        vt_result = self.check_virustotal(url)
        gsb_result = self.check_google_safe_browsing(url)
        
        # If VirusTotal API is not available, try the web fetching method
        vt_web_result = None
        if not vt_result and not self.vt_api_key:
            try:
                vt_web_result = self.fetch_virustotal_web_info(url)
            except Exception as e:
                logger.error(f"Error fetching VirusTotal web info: {str(e)}")
        
        # If Google Safe Browsing API is not available, try the web fetching method
        gsb_web_result = None
        if not gsb_result and not self.gsb_api_key:
            try:
                gsb_web_result = self.fetch_gsb_web_info(url)
            except Exception as e:
                logger.error(f"Error fetching Google Safe Browsing web info: {str(e)}")
        
        # Determine overall risk level
        risk_level = "Low"
        if heuristic_result:
            risk_level = "Medium"
            
        # Check for positive matches in GSB
        if gsb_result and gsb_result.get("matches"):
            risk_level = "High"
            
        # Check GSB web results if available
        if gsb_web_result and gsb_web_result.get("detected") is True:
            risk_level = "High"
            
        # Check VT results if available
        if vt_result and vt_result.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0) > 0:
            risk_level = "High"
        
        # Check VT web results if available
        if vt_web_result and vt_web_result.get("detected") is True:
            risk_level = "High"
        
        result = {
            "url": url,
            "timestamp": timestamp,
            "risk_level": risk_level,
            "heuristic_suspicious": heuristic_result,
            "virustotal": vt_result,
            "virustotal_web": vt_web_result,
            "google_safe_browsing": gsb_result,
            "google_safe_browsing_web": gsb_web_result
        }
        return result

def main():
    parser = argparse.ArgumentParser(description="Phishing Link Scanner")
    parser.add_argument("urls", nargs='+', help="URLs to scan")
    parser.add_argument("--vt-api-key", help="VirusTotal API Key")
    parser.add_argument("--gsb-api-key", help="Google Safe Browsing API Key")
    parser.add_argument("--output", help="Output report file")
    args = parser.parse_args()
    
    scanner = PhishingScanner(vt_api_key=args.vt_api_key, gsb_api_key=args.gsb_api_key)
    
    results = []
    for url in args.urls:
        results.append(scanner.scan_url(url))
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=4))
    
if __name__ == "__main__":
    main()
