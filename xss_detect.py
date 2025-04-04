#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import argparse
import time

# Default XSS payloads for different contexts
PAYLOADS = {
    "html_text": "<script>window.xss_detected = true;</script>",
    "attribute": "\"><script>window.xss_detected = true;</script><\""
}

def find_context(soup, unique_string):
    """Determine where the unique string appears in the HTML."""
    for element in soup.find_all(text=True):
        if unique_string in element:
            return "html_text"
    for element in soup.find_all():
        for attr, value in element.attrs.items():
            if isinstance(value, str) and unique_string in value:
                return "attribute"
    return None

def static_scan(url):
    """Perform static analysis to find potential XSS vulnerabilities."""
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = parse_qs(parsed_url.query)

    # Step 1: Send request with unique strings
    test_params = {key: f"test_{key}" for key in params.keys()}
    test_url = f"{base_url}?{urlencode(test_params)}"
    response = requests.get(test_url)
    soup = BeautifulSoup(response.text, "html.parser")

    results = []
    for param, unique_string in test_params.items():
        context = find_context(soup, unique_string)
        if context:
            payload = PAYLOADS.get(context, PAYLOADS["html_text"])
            # Step 2: Test with payload
            test_params[param] = payload
            payload_url = f"{base_url}?{urlencode(test_params)}"
            resp = requests.get(payload_url)
            if payload in resp.text:
                results.append((param, context, payload))
            # Reset parameter for next iteration
            test_params[param] = params.get(param, [""])[0]
    return results

def verify_vulnerability(url, param, payload):
    """Verify if the payload executes using Selenium."""
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    driver = webdriver.Chrome(options=options)

    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    params = parse_qs(parsed_url.query)
    params[param] = payload
    test_url = f"{base_url}?{urlencode(params)}"

    try:
        driver.get(test_url)
        time.sleep(1)  # Wait for scripts to execute
        detected = driver.execute_script("return window.xss_detected || false")
        return detected
    finally:
        driver.quit()

def main():
    parser = argparse.ArgumentParser(description="XSS-Detect: XSS Vulnerability Scanner for Kali Linux")
    parser.add_argument("-u", "--url", required=False, help="Target URL with parameters (e.g., 'http://example.com/?param=value')")
    parser.add_argument("--verify", action="store_true", help="Enable dynamic verification with Selenium")
    args = parser.parse_args()

    if not args.url:
        print("Error: The '-u' or '--url' argument is required.")
        parser.print_help()
        return

    print(f"Scanning {args.url} for XSS vulnerabilities...")
    potential_vulns = static_scan(args.url)

    if not potential_vulns:
        print("No potential XSS vulnerabilities found.")
        return

    for param, context, payload in potential_vulns:
        print(f"\nPotential vulnerability found:")
        print(f"Parameter: {param}")
        print(f"Context: {context}")
        print(f"Payload: {payload}")

        if args.verify:
            print("Verifying with headless browser...")
            if verify_vulnerability(args.url, param, payload):
                print(f"CONFIRMED: XSS vulnerability in parameter '{param}' with payload '{payload}'")
            else:
                print("Not exploitable or false positive.")
        else:
            print("Run with --verify to confirm exploitability.")

if __name__ == "__main__":
    main()