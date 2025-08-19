from urllib.parse import urlparse
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import requests


class DETECTION:
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|" \
                          r"u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|" \
                          r"filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net"

    def getDomain(self, url):
        domain = urlparse(url).netloc
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        return domain

    def havingIP(self, url):
        try:
            ipaddress.ip_address(url)
            return 1
        except:
            return 0

    def haveAtSign(self, url):
        return 1 if "@" in url else 0

    def getLength(self, url):
        return 0 if len(url) < 54 else 1

    def getDepth(self, url):
        path = urlparse(url).path.split('/')
        depth = sum(1 for p in path if p)
        return depth

    def redirection(self, url):
        pos = url.rfind('//')
        if pos > 6:
            return 1
        return 0

    def httpDomain(self, url):
        return 0 if 'https' in url else 1

    def tinyURL(self, url):
        return 1 if re.search(self.shortening_services, url) else 0

    def prefixSuffix(self, url):
        return 1 if '-' in url else 0

    def web_traffic(self, url):
        # Placeholder logic (real implementation would need Alexa API or similar)
        try:
            # You can replace this with actual ranking lookup later
            rank = 50000  # Simulating a safe rank
            return 1 if rank < 100000 else 0
        except:
            return 1

    def domainAge(self, domain_name):
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date

        try:
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            if isinstance(expiration_date, str):
                expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        except:
            return 1

        if creation_date is None or expiration_date is None:
            return 1
        if isinstance(creation_date, list) or isinstance(expiration_date, list):
            return 1

        age = abs((expiration_date - creation_date).days)
        return 1 if (age / 30) < 6 else 0

    def domainEnd(self, domain_name):
        expiration_date = domain_name.expiration_date
        try:
            if isinstance(expiration_date, str):
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1

        if expiration_date is None or isinstance(expiration_date, list):
            return 1

        today = datetime.now()
        end = abs((expiration_date - today).days)
        return 0 if (end / 30) < 6 else 1

    def iframe(self, response):
        if response is None:
            return 1
        if re.findall(r"<iframe|frameBorder", response.text, re.IGNORECASE):
            return 0
        return 1

    def mouseOver(self, response):
        if response is None:
            return 1
        if re.findall(r"<script>.+onmouseover.+</script>", response.text, re.IGNORECASE):
            return 1
        return 0

    def rightClick(self, response):
        if response is None:
            return 1
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        return 1

    def forwarding(self, response):
        if response is None:
            return 1
        return 0 if len(response.history) <= 2 else 1

    def featureExtractions(self, url):
        features = [
            self.getDomain(url),
            self.havingIP(url),
            self.haveAtSign(url),
            self.getLength(url),
            self.getDepth(url),
            self.redirection(url),
            self.httpDomain(url),
            self.prefixSuffix(url),
            self.tinyURL(url)
        ]

        # Domain-based features
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
            domain_name = None

        features.append(dns)
        features.append(self.web_traffic(url))
        features.append(1 if dns == 1 else self.domainAge(domain_name))
        features.append(1 if dns == 1 else self.domainEnd(domain_name))

        # HTML/JS-based features
        try:
            response = requests.get(url, timeout=5)
        except:
            response = None

        features.append(self.iframe(response))
        features.append(self.mouseOver(response))
        features.append(self.rightClick(response))
        features.append(self.forwarding(response))

        return features
