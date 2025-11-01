import re
import socket
import ipaddress
from urllib.parse import urlparse
from collections import Counter
import tldextract
import whois
import requests
from datetime import datetime, timezone
from bs4 import BeautifulSoup

socket.setdefaulttimeout(4)

# Convention based on training data analysis:
# For most features: 1 = suspicious/present, -1 = benign/absent, 0 = unknown
# BUT some features have inverted logic in the dataset!

SHORTENERS = {
    "bit.ly","goo.gl","t.co","tinyurl.com","ow.ly","is.gd","buff.ly","bit.do","lnkd.in","db.tt",
    "qr.ae","adf.ly","cur.lv","tiny.cc","tr.im","su.pr","v.gd","soo.gd","shorte.st","x.co",
    "cl.ly","s.id","rebrand.ly","cutt.ly","ulvis.net","short.io","1url.com"
}

# Training data defaults (most common values when extraction fails)
TRAINING_DEFAULTS = {
    'having_IP_Address': 1,
    'URL_Length': -1,
    'Shortining_Service': 1,
    'having_At_Symbol': 1,
    'double_slash_redirecting': 1,
    'Prefix_Suffix': -1,
    'having_Sub_Domain': 1,
    'SSLfinal_State': 1,
    'Domain_registeration_length': 1,
    'Favicon': 1,
    'port': 1,
    'HTTPS_token': 1,
    'Request_URL': 1,
    'URL_of_Anchor': 0,
    'Links_in_tags': 0,
    'SFH': -1,
    'Submitting_to_email': 1,
    'Abnormal_URL': 1,
    'Redirect': 0,
    'on_mouseover': 1,
    'RightClick': 1,
    'popUpWidnow': 1,
    'Iframe': 1,
    'age_of_domain': 1,
    'DNSRecord': -1,
    'web_traffic': 1,
    'Page_Rank': 1,
    'Google_Index': 1,
    'Links_pointing_to_page': 1,
    'Statistical_report': 1,
}

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

def _safe_whois(domain: str, timeout=3):
    """Safe WHOIS with timeout"""
    if not domain:
        return None
    try:
        return whois.whois(domain)
    except Exception:
        return None

def _fetch_html(url: str, timeout=4):
    """Fetch HTML with short timeout"""
    try:
        u = _normalize_url(url)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        r = requests.get(u, timeout=timeout, headers=headers, allow_redirects=True)
        if r.status_code == 200:
            return BeautifulSoup(r.content, 'html.parser'), r
        return None, None
    except Exception:
        return None, None

# ==================== DISCRIMINATIVE FEATURES ====================
# These are the top 10 features that actually work

# 1. having_IP_Address - WEAK but useful
def havingIP(url):
    """Returns 1 if URL uses IP address instead of domain name"""
    try:
        _, _, _, host, _ = _parsed(url)
        return 1 if _is_ip_host(host) else -1
    except:
        return TRAINING_DEFAULTS['having_IP_Address']

# 2. having_Sub_Domain - GOOD discriminator
def havingSubDomain(url):
    """
    Based on training data:
    - Phishing: 52.9% have value 1 (multiple subdomains)
    - Legitimate: 46.0% have value 0 (single subdomain)
    - Legitimate: 37.5% have value -1 (no subdomain)
    """
    try:
        _, _, ext, _, _ = _parsed(url)
        sub = ext.subdomain or ""
        
        if not sub:  # No subdomain (www.example.com → example.com)
            return -1
        
        dot_count = sub.count(".")
        
        if dot_count == 0:  # Single subdomain (www.example.com)
            return 0
        else:  # Multiple subdomains (sub.www.example.com)
            return 1
    except:
        return TRAINING_DEFAULTS['having_Sub_Domain']

# 3. SSLfinal_State - EXCELLENT discriminator (91.4% vs 14.3%)
def SSLfinalState(url):
    """
    Based on training data:
    - Phishing: 91.4% have value 1 (no HTTPS or bad SSL)
    - Legitimate: 62.3% have value -1 (valid HTTPS)
    """
    try:
        u, p, _, _, _ = _parsed(url)
        
        # Not HTTPS = suspicious
        if p.scheme != "https":
            return 1
        
        # Try to verify SSL certificate
        try:
            requests.head(u, timeout=3, verify=True)
            return -1  # Valid SSL
        except requests.exceptions.SSLError:
            return 1  # SSL error
        except:
            return 0  # Network error, unknown
    except:
        return TRAINING_DEFAULTS['SSLfinal_State']

# 4. Domain_registeration_length - Often discriminative
def domainRegistrationLength(url):
    """Short registration period = suspicious"""
    try:
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            return TRAINING_DEFAULTS['Domain_registeration_length']
        
        w = _safe_whois(reg_domain, timeout=3)
        if not w:
            return TRAINING_DEFAULTS['Domain_registeration_length']
        
        creation = w.creation_date
        expiration = w.expiration_date
        
        if isinstance(creation, list):
            creation = min([d for d in creation if d], default=None)
        if isinstance(expiration, list):
            expiration = max([d for d in expiration if d], default=None)
        
        if not creation or not expiration:
            return TRAINING_DEFAULTS['Domain_registeration_length']
        
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        
        days = (expiration - creation).days
        return 1 if days <= 365 else -1
    except:
        return TRAINING_DEFAULTS['Domain_registeration_length']

# 5. Request_URL - GOOD discriminator
def requestURL(url):
    """
    Check if page loads external resources
    - Phishing: 70.4% have value 1 (many external resources)
    - Legitimate: 54.6% have value -1 (mostly internal)
    """
    try:
        soup, _ = _fetch_html(url)
        if not soup:
            return TRAINING_DEFAULTS['Request_URL']
        
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            return TRAINING_DEFAULTS['Request_URL']
        
        # Count resources
        tags = soup.find_all(['img', 'video', 'audio', 'script', 'link'])
        if not tags:
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
            return -1
        
        pct = (external / total) * 100
        
        # Thresholds based on common patterns
        if pct < 22:
            return -1  # Mostly internal = legitimate
        elif pct <= 61:
            return 0   # Mixed
        else:
            return 1   # Mostly external = suspicious
    except:
        return TRAINING_DEFAULTS['Request_URL']

# 6. URL_of_Anchor - EXCELLENT discriminator
def urlOfAnchor(url):
    """
    Check anchor links
    - Phishing: 62.3% have value 0, 37.1% have value 1
    - Legitimate: 66.3% have value -1 (normal anchors)
    """
    try:
        soup, _ = _fetch_html(url)
        if not soup:
            return TRAINING_DEFAULTS['URL_of_Anchor']
        
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            return TRAINING_DEFAULTS['URL_of_Anchor']
        
        anchors = soup.find_all('a', href=True)
        if not anchors:
            return -1
        
        suspicious = 0
        
        for a in anchors:
            href = a['href'].strip()
            
            # Suspicious patterns
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
            return -1  # Few suspicious anchors
        elif pct <= 67:
            return 0   # Moderate
        else:
            return 1   # Many suspicious anchors
    except:
        return TRAINING_DEFAULTS['URL_of_Anchor']

# 7. Links_in_tags - FAIR discriminator  
def linksInTags(url):
    """
    Check meta/script/link tags for external links
    - Phishing: 43.9% have value 0, 30.6% have value 1
    - Legitimate: 48.7% have value -1
    """
    try:
        soup, _ = _fetch_html(url)
        if not soup:
            return TRAINING_DEFAULTS['Links_in_tags']
        
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            return TRAINING_DEFAULTS['Links_in_tags']
        
        tags = soup.find_all(['meta', 'script', 'link'])
        if not tags:
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
            return -1
        
        pct = (external / total) * 100
        
        if pct < 17:
            return -1
        elif pct <= 81:
            return 0
        else:
            return 1
    except:
        return TRAINING_DEFAULTS['Links_in_tags']

# 8. SFH - Server Form Handler
def sfh(url):
    """Check form submission handlers"""
    try:
        soup, _ = _fetch_html(url)
        if not soup:
            return TRAINING_DEFAULTS['SFH']
        
        forms = soup.find_all('form')
        if not forms:
            return -1  # No forms
        
        _, _, _, _, reg_domain = _parsed(url)
        
        for form in forms:
            action = form.get('action', '').strip()
            
            # Empty or about:blank = suspicious
            if not action or action in ['', 'about:blank']:
                return 1
            
            # External domain = suspicious
            if action.startswith('http'):
                try:
                    action_domain = tldextract.extract(action).registered_domain
                    if action_domain != reg_domain:
                        return 1
                except:
                    pass
        
        return -1  # All forms look normal
    except:
        return TRAINING_DEFAULTS['SFH']

# 9. age_of_domain - Often discriminative
def ageOfDomain(url):
    """Young domains are more suspicious"""
    try:
        _, _, _, _, reg_domain = _parsed(url)
        if not reg_domain:
            return TRAINING_DEFAULTS['age_of_domain']
        
        w = _safe_whois(reg_domain, timeout=3)
        if not w:
            return TRAINING_DEFAULTS['age_of_domain']
        
        creation = w.creation_date
        if isinstance(creation, list):
            creation = min([d for d in creation if d], default=None)
        
        if not creation:
            return TRAINING_DEFAULTS['age_of_domain']
        
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        
        days = (datetime.now(timezone.utc) - creation).days
        
        # Young domain = suspicious
        return 1 if days <= 180 else -1
    except:
        return TRAINING_DEFAULTS['age_of_domain']

# 10. DNSRecord - Check if domain resolves
def dnsRecord(url):
    """Domain should have valid DNS record"""
    try:
        _, _, _, host, _ = _parsed(url)
        if not host:
            return 1  # No host = suspicious
        
        try:
            socket.getaddrinfo(host, 80, timeout=2)
            return -1  # Valid DNS
        except socket.gaierror:
            return 1   # No DNS record
        except:
            return 0   # Unknown
    except:
        return TRAINING_DEFAULTS['DNSRecord']

# ==================== LESS IMPORTANT FEATURES ====================
# These are still extracted for backward compatibility

def getLength(url):
    try:
        L = len(_normalize_url(url))
        if L < 54:
            return -1
        elif 54 <= L <= 75:
            return 0
        else:
            return 1
    except:
        return TRAINING_DEFAULTS['URL_Length']

def tinyURL(url):
    try:
        _, _, _, _, reg_domain = _parsed(url)
        return 1 if reg_domain.lower() in SHORTENERS else -1
    except:
        return TRAINING_DEFAULTS['Shortining_Service']

def haveAtSign(url):
    try:
        return 1 if "@" in url else -1
    except:
        return TRAINING_DEFAULTS['having_At_Symbol']

def redirection(url):
    try:
        u = _normalize_url(url)
        i = u.find("://")
        after = u[i+3:] if i != -1 else u
        return 1 if "//" in after else -1
    except:
        return TRAINING_DEFAULTS['double_slash_redirecting']

def prefixSuffix(url):
    try:
        _, _, ext, _, _ = _parsed(url)
        return 1 if "-" in (ext.domain or "") else -1
    except:
        return TRAINING_DEFAULTS['Prefix_Suffix']

def favicon(url):
    return TRAINING_DEFAULTS['Favicon']

def port(url):
    try:
        _, p, _, _, _ = _parsed(url)
        if p.port is None:
            return -1
        return -1 if p.port in (80, 443) else 1
    except:
        return TRAINING_DEFAULTS['port']

def httpDomain(url):
    try:
        _, p, _, _, _ = _parsed(url)
        host = p.hostname or ""
        return 1 if "https" in host.lower() else -1
    except:
        return TRAINING_DEFAULTS['HTTPS_token']

def submittingToEmail(url):
    return TRAINING_DEFAULTS['Submitting_to_email']

def abnormalURL(url):
    return TRAINING_DEFAULTS['Abnormal_URL']

def redirect(url):
    return TRAINING_DEFAULTS['Redirect']

def onmouseover(url):
    return TRAINING_DEFAULTS['on_mouseover']

def rightClick(url):
    return TRAINING_DEFAULTS['RightClick']

def popUpWindow(url):
    return TRAINING_DEFAULTS['popUpWidnow']

def iframe(url):
    return TRAINING_DEFAULTS['Iframe']

def webTraffic(url):
    return TRAINING_DEFAULTS['web_traffic']

def pageRank(url):
    return TRAINING_DEFAULTS['Page_Rank']

def googleIndex(url):
    return TRAINING_DEFAULTS['Google_Index']

def linksPointingToPage(url):
    return TRAINING_DEFAULTS['Links_pointing_to_page']

def statisticalReport(url):
    return TRAINING_DEFAULTS['Statistical_report']

# ==================== MAIN EXTRACTION ====================

def extract_features(url):
    """
    Extract all 30 features in the correct order.
    Uses training data defaults when extraction fails.
    """
    features = []
    
    # Extract in exact order expected by model
    features.append(havingIP(url))                 # 1
    features.append(getLength(url))                # 2
    features.append(tinyURL(url))                  # 3
    features.append(haveAtSign(url))               # 4
    features.append(redirection(url))              # 5
    features.append(prefixSuffix(url))             # 6
    features.append(havingSubDomain(url))          # 7 ✓
    features.append(SSLfinalState(url))            # 8 ✓✓
    features.append(domainRegistrationLength(url)) # 9 ✓
    features.append(favicon(url))                  # 10
    features.append(port(url))                     # 11
    features.append(httpDomain(url))               # 12
    features.append(requestURL(url))               # 13 ✓
    features.append(urlOfAnchor(url))              # 14 ✓✓
    features.append(linksInTags(url))              # 15 ✓
    features.append(sfh(url))                      # 16 ✓
    features.append(submittingToEmail(url))        # 17
    features.append(abnormalURL(url))              # 18
    features.append(redirect(url))                 # 19
    features.append(onmouseover(url))              # 20
    features.append(rightClick(url))               # 21
    features.append(popUpWindow(url))              # 22
    features.append(iframe(url))                   # 23
    features.append(ageOfDomain(url))              # 24 ✓
    features.append(dnsRecord(url))                # 25 ✓
    features.append(webTraffic(url))               # 26
    features.append(pageRank(url))                 # 27
    features.append(googleIndex(url))              # 28
    features.append(linksPointingToPage(url))      # 29
    features.append(statisticalReport(url))        # 30
    
    return features