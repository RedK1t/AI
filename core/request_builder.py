import requests
import time
import logging
import random
import urllib3

# Disable SSL warnings (common in security testing)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup Logger
logger = logging.getLogger(__name__)


class RequestBuilder:
    """
    Handles all HTTP requests for the scanner.
    Manages sessions, cookies, headers, and timeouts.
    """

    def __init__(self):
        # Use a Session object to persist cookies across requests
        self.session = requests.Session()

        # Default timeout configuration from Waymap logic
        self.timeout = 10

        # List of User-Agents for rotation (Stealth)
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0"
        ]

    def _get_random_headers(self):
        """Generates random headers to bypass basic WAF/Bot detection."""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            # IP Spoofing header (seen in random_headers.py)
            "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        }

    def send_request(self, url, method="GET", params=None, data=None):
        """
        Sends an HTTP request and returns a structured response object.

        Args:
            url (str): Target URL.
            method (str): HTTP method (GET/POST).
            params (dict): Query parameters for GET.
            data (dict): Body data for POST.

        Returns:
            dict: Contains status_code, response_time, length, and body.
        """
        headers = self._get_random_headers()

        try:
            # Measure response time accurately (Crucial for Time-Based SQLi)
            start_time = time.time()

            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=False,  # Ignore SSL errors
                allow_redirects=True
            )

            end_time = time.time()
            latency = end_time - start_time
            import hashlib
            content_hash = hashlib.md5(response.text.encode()).hexdigest()

            # Return a normalized dictionary for the Analyzer/Mutator
            return {
                "success": True,
                "url": response.url,
                "status_code": response.status_code,
                "length": len(response.text),  # Response size
                "redirected": response.url != url,
                "word_count": len(response.text.split()),  # Word count (more stable than length)
                "response_time": latency,
                "hash": content_hash,
                "headers": dict(response.headers),
                "body": response.text
            }

        except requests.exceptions.Timeout:
            logger.warning(f"Request timed out: {url}")
            return {"success": False, "error": "timeout"}

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"success": False, "error": str(e)}

    def get_baseline(self, parsed_data):
        """
        Fetches the initial 'normal' state of the target using data from the Parser.
        """
        logger.info(f"Establishing baseline for: {parsed_data['url']}")

        # reconstruct params from parser format {key: {value: val, type: type}}
        clean_params = {k: v['value'] for k, v in parsed_data['params'].items()}

        return self.send_request(
            url=parsed_data['url'],
            method=parsed_data['method'],
            params=clean_params
        )