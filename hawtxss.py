import os
import requests
import subprocess
import concurrent.futures
import logging
import json
import argparse
from termcolor import colored
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
import time
import sys
from bs4 import BeautifulSoup
import random

LOCK_EMOJI = "\U0001F512"
WARNING_EMOJI = "\U000026A0"
INFO_EMOJI = "\U00002139"
SUCCESS_EMOJI = "\U0001F389"

logging.basicConfig(filename='xss_scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

CONFIG = {
    "log_level": logging.INFO,
    "max_threads": 10,
    "url_encode": False,
    "timeout": 5,
    "recursive_depth": 3,
    "payload_variations": 3,
    "dom_analysis": True
}

XSS_TEST_TOKEN = "XSS_TEST"

BANNER = """

 __  __     ______     __     __     ______      __  __     ______     ______    
/\ \_\ \   /\  __ \   /\ \  _ \ \   /\__  _\    /\_\_\_\   /\  ___\   /\  ___\   
\ \  __ \  \ \  __ \  \ \ \/ ".\ \  \/_/\ \/    \/_/\_\/_  \ \___  \  \ \___  \  
 \ \_\ \_\  \ \_\ \_\  \ \__/".~\_\    \ \_\      /\_\/\_\  \/\_____\  \/\_____\ 
  \/_/\/_/   \/_/\/_/   \/_/   \/_/     \/_/      \/_/\/_/   \/_____/   \/_____/ 
                                                                                 
Enjoy yourself :)

"""

class Logger:
    def __init__(self, log_level=logging.INFO):
        self.logger = logging.getLogger()
        self.logger.setLevel(log_level)

    def log(self, message, level=logging.INFO):
        self.logger.log(level, message)

    def console(self, message, color="yellow", delay=0):
        time.sleep(delay)
        sys.stdout.write(colored(message, color) + '\n')
        sys.stdout.flush()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self.console(BANNER, "blue")

class SubdomainFinder:
    def __init__(self, domain, logger):
        self.domain = domain
        self.logger = logger

    def run_assetfinder(self):
        self.logger.console(f"{INFO_EMOJI} Running assetfinder for {self.domain}", "blue")
        try:
            # Assetfinder komutunu çalıştır
            result = subprocess.run(['assetfinder', self.domain], capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                self.logger.console(f"{WARNING_EMOJI} Assetfinder failed with return code {result.returncode}", "red")
                return []
            subdomains = result.stdout.splitlines()
            self.logger.console(f"{INFO_EMOJI} Found {len(subdomains)} subdomains", "blue")
            return subdomains
        except subprocess.TimeoutExpired:
            self.logger.console(f"{WARNING_EMOJI} Assetfinder command timed out", "red")
            return []
        except subprocess.CalledProcessError as e:
            self.logger.console(f"{WARNING_EMOJI} Error running assetfinder: {e}", "red")
            return []

    def run_httpx(self, subdomains):
        self.logger.console(f"{INFO_EMOJI} Running httpx to find live URLs", "blue")
        try:
            with open('subdomains.txt', 'w') as f:
                f.write("\n".join(subdomains))

            result = subprocess.run(['httpx', '-l', 'subdomains.txt', '-mc', '200'], capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                self.logger.console(f"{WARNING_EMOJI} Httpx failed with return code {result.returncode}", "red")
                return []
            live_urls = result.stdout.splitlines()
            self.logger.console(f"{INFO_EMOJI} Found {len(live_urls)} live URLs", "blue")
            return live_urls
        except subprocess.TimeoutExpired:
            self.logger.console(f"{WARNING_EMOJI} Httpx command timed out", "red")
            return []
        except subprocess.CalledProcessError as e:
            self.logger.console(f"{WARNING_EMOJI} Error running httpx: {e}", "red")
            return []

class URLFilter:
    def __init__(self, logger):
        self.logger = logger

    def run_katana(self, urls):
        self.logger.console(f"{INFO_EMOJI} Running katana on live URLs to find URLs with '='", "blue")
        filtered_urls = []
        for url in urls:
            command = f"katana -u {url} | grep '='"
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
                filtered_urls.extend(result.stdout.splitlines())
            except subprocess.TimeoutExpired:
                self.logger.console(f"{WARNING_EMOJI} Katana command timed out", "red")
            except subprocess.CalledProcessError as e:
                self.logger.console(f"{WARNING_EMOJI} Error running katana: {e}", "red")
                continue

        self.logger.console(f"{INFO_EMOJI} Found {len(filtered_urls)} URLs with '=' character", "blue")
        return filtered_urls

class XSSScanner:
    def __init__(self, urls, payloads, logger, config=CONFIG):
        self.urls = urls
        self.payloads = payloads
        self.logger = logger
        self.config = config

    def run_xss_test(self):
        if not self.urls:
            self.logger.console(f"{WARNING_EMOJI} No URLs to test. Please check the input and try again.", "red")
            return

        self.logger.console(f"{INFO_EMOJI} Testing {len(self.urls)} URLs for XSS vulnerabilities with {self.config['max_threads']} threads\n", "blue")

        unique_urls = list(set(self.urls))
        unique_payloads = list(set(self.payloads))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            futures = []
            for url in unique_urls:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                if not params and '?' not in url:
                    continue
                for param in params or ['']:
                    for payload in unique_payloads:
                        futures.append(executor.submit(self.check_xss, url, payload, param, 0))
                        time.sleep(0.5)
            for future in concurrent.futures.as_completed(futures):
                future.result()

    def check_xss(self, url, payload, param, depth):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            if '?' in url:
                test_url = f"{url}{payload}{XSS_TEST_TOKEN}"
            else:
                test_url = f"{url}?{payload}{XSS_TEST_TOKEN}"
        else:
            if self.config["url_encode"]:
                query_params[param] = f"{payload}{XSS_TEST_TOKEN}"
                new_query = urlencode(query_params, doseq=True)
            else:
                new_query = '&'.join([f"{key}={value[0]}" for key, value in query_params.items()])
                new_query = new_query.replace(f"{param}={query_params[param][0]}", f"{param}={payload}{XSS_TEST_TOKEN}")

            test_url = urlunparse(parsed_url._replace(query=new_query))

        try:
            response = requests.get(test_url, timeout=self.config['timeout'])
            response.encoding = response.apparent_encoding

            if self.check_for_xss_in_response(response.text, payload):
                message = f"\n-----------------------------------------\n[+] FOUND XSS : {test_url}\n\n[+] PAYLOAD : {payload}\n-----------------------------------------\n"
                self.logger.log(message, level=logging.INFO)
                self.logger.console(message, "green", delay=0.5)

                if depth < self.config["recursive_depth"]:
                    new_payload = self.mutate_payload(payload)
                    self.check_xss(url, new_payload, param, depth + 1)
                return True

            if self.config["dom_analysis"]:
                if self.dom_based_xss_check(response.text):
                    message = f"\n-----------------------------------------\n[+] FOUND DOM-BASED XSS : {test_url}\n\n[+] PAYLOAD : {payload}\n-----------------------------------------\n"
                    self.logger.log(message, level=logging.INFO)
                    self.logger.console(message, "green", delay=0.5)
                    return True

            return False
        except requests.exceptions.Timeout:
            return False
        except Exception as e:
            return False

    def check_for_xss_in_response(self, response_text, payload):
        if XSS_TEST_TOKEN in response_text:
            return True

        patterns = [
            re.escape(f"<script>{XSS_TEST_TOKEN}</script>"),
            re.escape(f"<img src=x onerror={XSS_TEST_TOKEN}>"),
            re.escape(f"<body onload={XSS_TEST_TOKEN}>")
        ]
        for pattern in patterns:
            if re.search(pattern, response_text):
                return True

        return False

    def dom_based_xss_check(self, response_text):
        soup = BeautifulSoup(response_text, "html.parser")
        scripts = soup.find_all("script")
        for script in scripts:
            if XSS_TEST_TOKEN in script.get_text():
                return True
        return False

    def mutate_payload(self, payload):
        variations = []
        for _ in range(self.config["payload_variations"]):
            mutated_payload = ''.join(random.choice((str.upper, str.lower))(char) for char in payload)
            variations.append(mutated_payload)
        return random.choice(variations)

def main():
    parser = argparse.ArgumentParser(description='XSS Scanner Tool')
    parser.add_argument('-u', '--url', help='Single target URL (with parameters)')
    parser.add_argument('-f', '--file', help='File containing list of URLs (with parameters)')
    parser.add_argument('-l', '--list', required=True, help='XSS payload list file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use (default: 10)')
    parser.add_argument('-c', '--config', help='Configuration file (JSON format)')

    args = parser.parse_args()

    logger = Logger(log_level=CONFIG['log_level'])

    logger.clear_screen()

    if args.config:
        with open(args.config, 'r') as f:
            CONFIG.update(json.load(f))

    payload_file = args.list
    max_threads = args.threads

    url_encode = CONFIG['url_encode']

    with open(payload_file, 'r') as file:
        payloads = file.read().splitlines()

    if args.url:
        parsed_url = urlparse(args.url)
        params = parse_qs(parsed_url.query)
        if params or '?' in args.url:
            filtered_urls = [args.url]
        else:
            logger.console(f"{INFO_EMOJI} No parameters found in the URL. Starting subdomain discovery and filtering process.\n", "blue")
            subdomain_finder = SubdomainFinder(parsed_url.netloc, logger)
            subdomains = subdomain_finder.run_assetfinder()
            live_urls = subdomain_finder.run_httpx(subdomains)
            url_filter = URLFilter(logger)
            filtered_urls = url_filter.run_katana(live_urls)
            if not filtered_urls:
                logger.console(f"{WARNING_EMOJI} No URLs with '=' character found after filtering. Using live URLs for XSS testing.\n", "yellow")
                filtered_urls = live_urls
    elif args.file:
        with open(args.file, 'r') as f:
            urls = f.read().splitlines()
        filtered_urls = urls
    else:
        logger.console(f"{WARNING_EMOJI} Error: Either --url, --file, or a domain must be specified.", "red")
        parser.print_help()
        return

    scanner = XSSScanner(filtered_urls, payloads, logger, config=CONFIG)
    scanner.run_xss_test()

if __name__ == '__main__':
    main()
    