from urllib.parse import urlparse, parse_qs
import socket
import dns.resolver
import whois
from datetime import datetime
from joblib import load
import pandas as pd
import requests
import os

from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.preprocessing import StandardScaler
import numpy as np

col_order = ['qty_mx_servers', 'qty_vowels_domain', 'time_domain_activation', 'time_response', 'ttl_hostname', 'qty_redirects', 'asn_ip', 'domain_length', 'qty_slash_directory', 'qty_nameservers', 'domain_spf', 'qty_dot_domain', 'time_domain_expiration', 'tls_ssl_certificate', 'qty_dot_url', 'qty_dot_file', 'file_length', 'length_url', 'qty_slash_url', 'qty_dot_directory']

class AveragingModel(BaseEstimator, ClassifierMixin):
    def __init__(self, models):
        self.models = models
        self.scaler = StandardScaler()  # Initialize the scaler
    
    def fit(self, X, y):
        # Fit each of the models with the scaled training data
        for model in self.models:
            model.fit(X, y)
        return self
    
    def predict_proba(self, X):
        # Get predictions from each model and average them
        avg_proba = np.mean([model.predict_proba(X) for model in self.models], axis=0)
        return avg_proba
    
    def predict(self, X):
        # Convert averaged probabilities into final predictions
        avg_proba = self.predict_proba(X)
        final_predictions = np.argmax(avg_proba, axis=1)
        return final_predictions

def split_url(url):
    # Parse the URL
    parsed_url = urlparse(url)
    split_path = parsed_url.path.split('/')
    
    # Initialize components with -1 (indicating "does not exist")
    components = {
        "domain": -1,
        "directory": -1,
        "file": -1,
        "parameters": -1
    }
    
    # Extract domain
    if parsed_url.netloc:
        components["domain"] = parsed_url.netloc
    
    # Extract file and directory
    if split_path:
        if len(split_path) > 1:
            # Join all parts except the last one as directory
            components["directory"] = '/'.join(split_path[:-1])
            if split_path[-1]:  # Check if the last part is not empty, indicating a file
                components["file"] = split_path[-1]
        elif split_path[0]:  # Only one part, could be either directory or file
            components["file"] = split_path[0]
    
    # Extract parameters (query string)
    if parsed_url.query:
        # Parse query string into a dictionary
        components["parameters"] = parse_qs(parsed_url.query)
    
    return components

def calculate_url_attributes(url):
    components = split_url(url)  # Use your split_url function
    domain = components['domain']
    directory = components['directory']
    file = components['file']
    
    # Initialize dictionary to store attributes
    attributes = {
        'qty_slash_url': url.count('/'),
        'qty_dot_url': url.count('.'),
        'length_url': len(url),
        'file_length': len(file) if file != -1 else 0,
        'qty_dot_directory': directory.count('.') if directory != -1 else 0,
        'qty_dot_file': file.count('.') if file != -1 and '.' in file else 0,
        'qty_slash_directory': directory.count('/') if directory != -1 else 0,
        'qty_dot_domain': domain.count('.') if domain != -1 else 0,
        'domain_length': len(domain) if domain else -1,
        'qty_vowels_domain': sum(map(domain.lower().count, "aeiou")) if domain else -1
    }

    return attributes

def get_asn(ip_address, access_token='dbf71fc14e52e2'):
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json?token={access_token}')
        data = response.json()
        org_field = data.get('org', 'N/A')
        asn = org_field.split(' ')[0] if org_field != 'N/A' else -1
        
        return asn[2:]
    except Exception as e:
        print(f"Error retrieving ASN for IP {ip_address}: {e}")
        return -1

def perform_external_lookups(url):
    features = {}
    domain = split_url(url)['domain']
    
    # Initialize features to handle errors individually
    features['time_domain_activation'] = -1
    features['time_domain_expiration'] = -1
    features['qty_mx_servers'] = 0
    features['qty_nameservers'] = 0
    features['ttl_hostname'] = -1
    features['asn_ip'] = -1  # Placeholder for ASN lookup
    features['time_response'] = -1
    features['qty_redirects'] = -1
    features['tls_ssl_certificate'] = -1
    features['domain_spf'] = -1

    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):  # Handle multiple creation dates
                w.creation_date = w.creation_date[0]
            features['time_domain_activation'] = (datetime.now() - w.creation_date).days
        if w.expiration_date:
            if isinstance(w.expiration_date, list):  # Handle multiple expiration dates
                w.expiration_date = w.expiration_date[0]
            features['time_domain_expiration'] = (w.expiration_date - datetime.now()).days
    except Exception as e:
        print(f"Error during WHOIS lookup: {e}")
    
    try:
        dns_resolver = dns.resolver.Resolver()
        mx_records = dns_resolver.resolve(domain, 'MX')
        features['qty_mx_servers'] = len(mx_records)
    except:
        pass  # Feature remains -1 if error occurs

    try:
        ns_records = dns_resolver.resolve(domain, 'NS')
        features['qty_nameservers'] = len(ns_records)
    except:
        pass  # Feature remains -1 if error occurs

    try:
        features['ttl_hostname'] = dns_resolver.resolve(domain, 'A').rrset.ttl
    except:
        pass  # Feature remains -1 if error occurs

    try:
        start_time = datetime.now()
        response = requests.get(url, timeout=100)
        end_time = datetime.now()
        features['time_response'] = (end_time - start_time).total_seconds()
        features['qty_redirects'] = len(response.history)
        features['tls_ssl_certificate'] = 1 if response.url.startswith('https') else 0
    except Exception as e:
        print(f"Error making HTTP request: {e}")

    try:
        txt_records = dns_resolver.resolve(domain, 'TXT')
        spf_record = any(record.to_text().startswith('"v=spf1') for record in txt_records)
        features['domain_spf'] = 1 if spf_record else 0
    except:
        pass

    try:
        # Resolve the domain to an IP address for the ASN lookup
        ip_address = socket.gethostbyname(domain)
        features['asn_ip'] = get_asn(ip_address)
    except Exception as e:
        print(f"Error resolving domain to IP for ASN lookup: {e}")
        features['asn_ip'] = -1  # Set to -1 if there's an error
        
    return features

def retrieveData(URL: str) -> pd.DataFrame:
    url_attributes = calculate_url_attributes(URL)
    
    # Get the external lookups using the domain
    external_lookups = perform_external_lookups(URL)
    data = {**url_attributes, **external_lookups}
    df = pd.DataFrame([data])
    
    return df

def predict(loaded_model, df: pd.DataFrame) -> str:
    # Make predictions
    predictions = loaded_model.predict(df)

    # Or get probability predictions
    probability_predictions = loaded_model.predict_proba(df)

    if probability_predictions[0][1] < 0.52 and probability_predictions[0][1] > 0.48:
        # If the probability is close to 0.5, the model is uncertain
        print("\n\033[93m" + "The model is uncertain about the URL" + "\033[0m")

    elif probability_predictions[0][1] >= 0.52:
        print("\n\033[91m" + "The URL is likely a phishing URL" + "\033[0m")
        print ("The probability of the URL being a phishing URL is:", f"{round(probability_predictions[0][1] * 100)}%")
    else:
        print("\n\033[92m" + "The URL is likely not a phishing URL" + "\033[0m")
        print ("The probability of the URL being a phishing URL is:", f"{round(probability_predictions[0][1] * 100)}%")

def initTUI():
    print("\nPlease enter the URL you would like to evaluate")
    URL = input("URL: ")
    
    # Check if the URL is valid
    try:
        response = requests.get(URL, timeout=10) 
    except requests.RequestException as e:
        print("The URL is not valid")
        return initTUI()
    
    return URL

def main():
    # Clear the terminal
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Welcome to the Phishing URL Detector")
    
    # Load the model
    loaded_model = load('Models/averaging_model.joblib')
    
    # Load the scaler
    scaler = load('Models/scaler.joblib')
    
    while True:
        # Clear the terminal
        os.system('cls' if os.name == 'nt' else 'clear')
        
        URL = initTUI()
        df = retrieveData(URL)
        
        # Reorder the columns to match the order used during training
        df = df[col_order]
        
        # Scale the data
        df_scaled = scaler.transform(df)
        
        # Add labels to the scaled data
        df_scaled = pd.DataFrame(df_scaled, columns=col_order)
        
        predict(loaded_model, df_scaled)
        print("\nWould you like to evaluate another URL? (y/n)")
        response = input()
        if response.lower() == 'n':
            break
        
if __name__ == "__main__":
    main()