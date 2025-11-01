import re
import socket
import ipaddress
from urllib.parse import urlparse
import tldextract
import whois
import requests
from datetime import datetime, timezone
from bs4 import BeautifulSoup
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import warnings
import urllib3

# Suppress ALL SSL warnings
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url = "http://" + url
    return url

def _parsed(url: str):
    u = _normalize_url(url)
    p = urlparse(u)
    ext = tldextract.extract(u)
    host = p.hostname or ""
    reg_domain = ext.registered_domain or ""
    return u, p, ext, host, reg_domain

def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    h = host[1:-1] if host.startswith('[') and host.endswith(']') else host
    try:
        ipaddress.ip_address(h)
        return True
    except Exception:
        return False

def _fetch_html_selenium(url: str):
    """Fetch HTML using Selenium headless browser to bypass bot detection"""
    driver = None
    try:
        u = _normalize_url(url)
        
        # Setup Chrome options
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-images')
        chrome_options.add_argument('--disable-javascript')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        chrome_options.page_load_strategy = 'eager'
        
        # Initialize driver with webdriver-manager
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(8)
        
        # Navigate to URL
        driver.get(u)
        
        # Get page source immediately
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, 'html.parser')
        
        logger.info(f"Selenium: Successfully fetched page")
        return soup, None
        
    except TimeoutException:
        logger.warning(f"Selenium: Page load timeout - using partial content")
        try:
            if driver:
                page_source = driver.page_source
                soup = BeautifulSoup(page_source, 'html.parser')
                return soup, None
        except:
            pass
        return None, None
    except WebDriverException as e:
        logger.warning(f"Selenium: WebDriver error - {e}")
        return None, None
    except Exception as e:
        logger.warning(f"Selenium: Failed to fetch - {e}")
        return None, None
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass

def _fetch_html(url: str):
    """Try requests first, fallback to Selenium if blocked"""
    try:
        u = _normalize_url(url)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        r = requests.get(u, headers=headers, allow_redirects=True, timeout=10, verify=False)
        logger.info(f"HTTP Status: {r.status_code}")
        
        if r.status_code == 200:
            return BeautifulSoup(r.content, 'html.parser'), r
        elif r.status_code == 403:
            logger.warning(f"403 Forbidden - Trying Selenium...")
            return _fetch_html_selenium(url)
        else:
            logger.warning(f"Non-200 status code: {r.status_code}")
            return None, None
    except requests.exceptions.RequestException as e:
        logger.warning(f"Request failed: {e} - Trying Selenium...")
        return _fetch_html_selenium(url)
    except Exception as e:
        logger.warning(f"Failed to fetch HTML: {e}")
        return None, None

def _safe_whois(domain: str):
    if not domain:
        return None
    try:
        return whois.whois(domain)
    except Exception as e:
        logger.warning(f"WHOIS failed for {domain}: {e}")
        return None

# Feature 1: IP Address
def havingIP(url):
    try:
        _, _, _, host, _ = _parsed(url)
        result = 1 if _is_ip_host(host) else -1
        logger.info(f"havingIP: {result}")
        return result
    except Exception as e:
        logger.error(f"havingIP error: {e}")
        return 1

# Feature 2: Subdomain
def havingSubDomain(url):
    try:
        _, _, ext, _, _ = _parsed(url)
        sub = ext.subdomain or ""
        
        if not sub:
            result = -1
        else:
            dot_count = sub.count(".")
            result = 1 if dot_count >= 1 else 0
        
        logger.info(f"havingSubDomain: {result} (subdomain: '{sub}')")
        return result
    except Exception as e:
        logger.error(f"havingSubDomain error: {e}")
        return 1

# Feature 3: SSL State
def SSLfinalState(url):
    try:
        u, p, _, _, _ = _parsed(url)
        
        if p.scheme != "https":
            logger.info(f"SSLfinalState: 1 (no HTTPS)")
            return 1
        
        try:
            requests.head(u, timeout=3, verify=True)
            logger.info(f"SSLfinalState: -1 (valid SSL)")
            return -1
        except requests.exceptions.SSLError:
            logger.info(f"SSLfinalState: 1 (SSL error)")
            return 1
        except Exception as e:
            logger.warning(f"SSLfinalState: 0 (check failed: {e})")
            return 0
    except Exception as e:
        logger.error(f"SSLfinalState error: {e}")
        return 1

# Feature 4: Domain Registration Length
def domainRegistrationLength(url):
    try:
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            logger.info(f"domainRegistrationLength: 1 (no domain)")
            return 1
        
        w = _safe_whois(reg_domain)
        if not w:
            logger.info(f"domainRegistrationLength: 1 (WHOIS failed)")
            return 1
        
        creation = w.creation_date
        expiration = w.expiration_date
        
        if isinstance(creation, list):
            creation = min([d for d in creation if d], default=None)
        if isinstance(expiration, list):
            expiration = max([d for d in expiration if d], default=None)
        
        if not creation or not expiration:
            logger.info(f"domainRegistrationLength: 1 (no dates)")
            return 1
        
        # Make both timezone-aware
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        else:
            creation = creation.astimezone(timezone.utc)
            
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        else:
            expiration = expiration.astimezone(timezone.utc)
        
        days = (expiration - creation).days
        result = 1 if days <= 365 else -1
        logger.info(f"domainRegistrationLength: {result} ({days} days)")
        return result
    except Exception as e:
        logger.error(f"domainRegistrationLength error: {e}")
        return 1

# Feature 5: Request URL
def requestURL(url):
    try:
        soup, _ = _fetch_html(url)
        if not soup:
            logger.info(f"requestURL: 1 (no HTML)")
            return 1
        
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            logger.info(f"requestURL: 1 (no domain)")
            return 1
        
        tags = soup.find_all(['img', 'video', 'audio', 'script', 'link'])
        if not tags:
            logger.info(f"requestURL: -1 (no tags)")
            return -1
        
        external = 0
        total = 0
        
        for tag in tags:
            src = tag.get('src') or tag.get('href', '')
            if src and src.startswith('http'):
                total += 1
                try:
                    src_domain = tldextract.extract(src).registered_domain
                    if src_domain and src_domain != reg_domain:
                        external += 1
                except:
                    pass
        
        if total == 0:
            logger.info(f"requestURL: -1 (no external resources)")
            return -1
        
        pct = (external / total) * 100
        
        if pct < 22:
            result = -1
        elif pct <= 61:
            result = 0
        else:
            result = 1
        
        logger.info(f"requestURL: {result} ({pct:.1f}% external)")
        return result
    except Exception as e:
        logger.error(f"requestURL error: {e}")
        return 1

# Feature 6: URL of Anchor
def urlOfAnchor(url):
    try:
        soup, _ = _fetch_html(url)
        if not soup:
            logger.info(f"urlOfAnchor: 0 (no HTML)")
            return 0
        
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            logger.info(f"urlOfAnchor: 0 (no domain)")
            return 0
        
        anchors = soup.find_all('a', href=True)
        if not anchors:
            logger.info(f"urlOfAnchor: -1 (no anchors)")
            return -1
        
        suspicious = 0
        
        for a in anchors:
            href = a['href'].strip()
            
            if href in ['#', '#content', '#skip', 'javascript:void(0)', 
                       'javascript::void(0)', '']:
                suspicious += 1
            elif href.startswith('http'):
                try:
                    href_domain = tldextract.extract(href).registered_domain
                    if href_domain and href_domain != reg_domain:
                        suspicious += 1
                except:
                    pass
        
        pct = (suspicious / len(anchors)) * 100
        
        if pct < 31:
            result = -1
        elif pct <= 67:
            result = 0
        else:
            result = 1
        
        logger.info(f"urlOfAnchor: {result} ({pct:.1f}% suspicious)")
        return result
    except Exception as e:
        logger.error(f"urlOfAnchor error: {e}")
        return 0

# Feature 7: Links in Tags
def linksInTags(url):
    try:
        soup, _ = _fetch_html(url)
        if not soup:
            logger.info(f"linksInTags: 0 (no HTML)")
            return 0
        
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            logger.info(f"linksInTags: 0 (no domain)")
            return 0
        
        tags = soup.find_all(['meta', 'script', 'link'])
        if not tags:
            logger.info(f"linksInTags: -1 (no tags)")
            return -1
        
        external = 0
        total = 0
        
        for tag in tags:
            for attr in ['href', 'src', 'content']:
                val = tag.get(attr, '')
                if val and val.startswith('http'):
                    total += 1
                    try:
                        val_domain = tldextract.extract(val).registered_domain
                        if val_domain and val_domain != reg_domain:
                            external += 1
                    except:
                        pass
        
        if total == 0:
            logger.info(f"linksInTags: -1 (no links)")
            return -1
        
        pct = (external / total) * 100
        
        if pct < 17:
            result = -1
        elif pct <= 81:
            result = 0
        else:
            result = 1
        
        logger.info(f"linksInTags: {result} ({pct:.1f}% external)")
        return result
    except Exception as e:
        logger.error(f"linksInTags error: {e}")
        return 0

# Feature 8: SFH (Server Form Handler)
def sfh(url):
    try:
        soup, _ = _fetch_html(url)
        if not soup:
            logger.info(f"SFH: -1 (no HTML)")
            return -1
        
        forms = soup.find_all('form')
        if not forms:
            logger.info(f"SFH: -1 (no forms)")
            return -1
        
        _, _, _, _, reg_domain = _parsed(url)
        
        for form in forms:
            action = form.get('action', '').strip()
            
            if not action or action in ['', 'about:blank']:
                logger.info(f"SFH: 1 (empty/blank action)")
                return 1
            
            if action.startswith('http'):
                try:
                    action_domain = tldextract.extract(action).registered_domain
                    if action_domain != reg_domain:
                        logger.info(f"SFH: 1 (external form action)")
                        return 1
                except:
                    pass
        
        logger.info(f"SFH: -1 (forms OK)")
        return -1
    except Exception as e:
        logger.error(f"SFH error: {e}")
        return -1

# Feature 9: Age of Domain
def ageOfDomain(url):
    try:
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            logger.info(f"ageOfDomain: 1 (no domain)")
            return 1
        
        w = _safe_whois(reg_domain)
        if not w:
            logger.info(f"ageOfDomain: 1 (WHOIS failed)")
            return 1
        
        creation = w.creation_date
        if isinstance(creation, list):
            creation = min([d for d in creation if d], default=None)
        
        if not creation:
            logger.info(f"ageOfDomain: 1 (no creation date)")
            return 1
        
        # Make timezone-aware
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        else:
            creation = creation.astimezone(timezone.utc)
        
        days = (datetime.now(timezone.utc) - creation).days
        result = 1 if days <= 180 else -1
        logger.info(f"ageOfDomain: {result} ({days} days old)")
        return result
    except Exception as e:
        logger.error(f"ageOfDomain error: {e}")
        return 1

# Feature 10: DNS Record
def dnsRecord(url):
    try:
        _, _, _, host, _ = _parsed(url)
        if not host:
            logger.info(f"dnsRecord: 1 (no host)")
            return 1
        
        try:
            socket.setdefaulttimeout(3)
            socket.getaddrinfo(host, 80)
            logger.info(f"dnsRecord: -1 (DNS OK)")
            return -1
        except socket.gaierror:
            logger.info(f"dnsRecord: 1 (no DNS)")
            return 1
        except Exception as e:
            logger.warning(f"dnsRecord: 0 (check failed: {e})")
            return 0
    except Exception as e:
        logger.error(f"dnsRecord error: {e}")
        return -1

def extract_features(url):
    """Extract all 10 features with logging"""
    logger.info(f"\n{'='*60}\nExtracting features for: {url}\n{'='*60}")
    
    features = []
    features.append(havingIP(url))
    features.append(havingSubDomain(url))
    features.append(SSLfinalState(url))
    features.append(domainRegistrationLength(url))
    features.append(requestURL(url))
    features.append(urlOfAnchor(url))
    features.append(linksInTags(url))
    features.append(sfh(url))
    features.append(ageOfDomain(url))
    features.append(dnsRecord(url))
    
    logger.info(f"{'='*60}\nFeature extraction complete\n{'='*60}\n")
    return features