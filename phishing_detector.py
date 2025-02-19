import numpy as np
import pandas as pd
import tldextract
from urllib.parse import urlparse, parse_qs
import ipaddress
from gensim.models import Word2Vec
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
import re

class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'update', 'account', 'secure', 'banking',
            'signin', 'confirm', 'password', 'credential', 'security'
        ]
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']

    def extract_features(self, url):
        features = {}
        parsed_url = urlparse(url.lower())

        # Basic URL Characteristics
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed_url.netloc)
        features['path_length'] = len(parsed_url.path)
        features['is_https'] = 1 if parsed_url.scheme == 'https' else 0

        # Special characters count
        features['special_char_count'] = sum(url.count(c) for c in "@#$%^&*()+=[]{}|;:,.<>?")

        # Check if domain is an IP address
        features['is_ip_address'] = self._is_ip_address(parsed_url.netloc)

        # Suspicious Keywords Count
        features['suspicious_keyword_count'] = self._count_suspicious_keywords(url)

        # Top-level domain check for suspicious TLDs
        features['has_suspicious_tld'] = self._check_suspicious_tld(parsed_url.netloc)

        # URL structure features
        features['directory_depth'] = parsed_url.path.count('/')
        features['query_param_count'] = len(parse_qs(parsed_url.query))
        features['fragment_length'] = len(parsed_url.fragment)

        # Additional features
        features['has_subdomain'] = 1 if parsed_url.netloc.count('.') > 1 else 0
        features['domain_has_numbers'] = 1 if any(char.isdigit() for char in parsed_url.netloc) else 0
        features['query_param_length'] = sum(len(val) for key, val in parse_qs(parsed_url.query).items())
        features['subdomain_count'] = parsed_url.netloc.count('.') - 1
        features['uses_ip_in_url'] = 1 if parsed_url.netloc.replace('.', '').isdigit() else 0
        features['long_path'] = 1 if len(parsed_url.path) > 50 else 0
        features['has_hyphens_in_domain'] = 1 if '-' in parsed_url.netloc else 0
        features['has_at_symbol'] = 1 if '@' in url else 0

        # Synthetic phishing-specific patterns
        features['has_misspelled_domain'] = self._has_misspelled_domain(parsed_url.netloc)
        features['is_shortened_url'] = self._is_shortened_url(url)

        # Domain extraction without status code
        features['domain_name'], features['tld'] = self._extract_domain_tld(url)

        return features

    def _is_ip_address(self, domain):
        try:
            ipaddress.ip_address(domain.split(':')[0])
            return 1
        except ValueError:
            return 0

    def _count_suspicious_keywords(self, url):
        return sum(1 for keyword in self.suspicious_keywords if keyword in url)

    def _check_suspicious_tld(self, domain):
        return int(any(domain.endswith(tld) for tld in self.suspicious_tlds))

    def _has_misspelled_domain(self, domain):
        misspelled_patterns = [
            r"0{1,}o", r"1{1,}l", r"3{1,}e", r"1{1,}i", r"(.)\1{2,}",
            r"faecbook", r"gogle", r"(o{2,}|g{2,}|e{2,})", r"ht{1,}:\/\/",
            r"g{2,}le", r"fa{2,}cebook", r"0o{1,}gle", r"t{1,}witter",
        ]
        return int(any(re.search(pattern, domain) for pattern in misspelled_patterns))

    def _is_shortened_url(self, url):
        shortened_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'
        ]
        domain = urlparse(url).netloc
        return int(domain in shortened_domains)

    def _extract_domain_tld(self, url):
        extracted = tldextract.extract(url)
        domain_name = extracted.domain
        tld = extracted.suffix
        return domain_name, tld

class PhishingURLDetector:
    def __init__(self):
        self.word2vec_model = None
        self.classifier = None
        self.label_encoder = None
        self.feature_extractor = URLFeatureExtractor()
        self.label_encoder = LabelEncoder()
        self.label_map = {0: 'phishing', 1: 'safe'}
        self.vector_size = 100
        self.tld_encoder = LabelEncoder()

    def train(self, urls, labels):
        """Train the complete model pipeline"""
        if not isinstance(urls, (pd.Series, list)) or not isinstance(labels, (pd.Series, list, np.ndarray)):
            raise ValueError("URLs and labels must be pandas Series, lists, or numpy arrays")

        # Convert inputs to numpy arrays
        urls = np.array(urls)
        labels = np.array(labels)

        # Fit label encoder
        self.label_encoder.fit(labels)
        labels_encoded = self.label_encoder.transform(labels)

        # Train Word2Vec model on domains
        tokenized_domains = [list(str(tldextract.extract(url).domain).lower())
                           for url in urls]
        self.word2vec_model = Word2Vec(
            sentences=tokenized_domains,
            vector_size=self.vector_size,
            window=5,
            min_count=1,
            workers=4
        )

        # Extract and encode TLDs
        tlds = [tldextract.extract(url).suffix for url in urls]
        self.tld_encoder.fit(tlds)

        # Prepare features
        X = self._prepare_features(urls)

        # Train stacking classifier
        base_models = [
            ('rf', RandomForestClassifier(
                n_estimators=183,
                max_depth=21,
                min_samples_split=7,
                min_samples_leaf=4,
                max_features='sqrt',
                random_state=42
            )),
            ('gb', GradientBoostingClassifier(
                n_estimators=50,
                random_state=42
            ))
        ]

        meta_model = LogisticRegression(random_state=42)
        self.classifier = StackingClassifier(
            estimators=base_models,
            final_estimator=meta_model,
            cv=3
        )

        try:
            self.classifier.fit(X, labels_encoded)
        except Exception as e:
            raise ValueError(f"Error training classifier: {str(e)}")

    def _prepare_features(self, urls):
        """Prepare features for a list of URLs"""
        features_list = []
        for url in urls:
            try:
                features = self._prepare_single_url_features(url)
                features_list.append(features)
            except Exception as e:
                print(f"Warning: Error processing URL {url}: {str(e)}")
                continue

        if not features_list:
            raise ValueError("No valid features could be extracted from URLs")

        return pd.concat(features_list, ignore_index=True)


    def save_models(self, model_path='phishing_detector.joblib'):
        if not all([self.word2vec_model, self.classifier, self.label_encoder, self.tld_encoder]):
            raise ValueError("Models not trained! Call train() first.")

        models = {
            'word2vec': self.word2vec_model,
            'classifier': self.classifier,
            'label_encoder': self.label_encoder,
            'tld_encoder': self.tld_encoder
        }
        joblib.dump(models, model_path)

    def load_models(self, model_path='phishing_detector.joblib'):
        try:
            models = joblib.load(model_path)
            self.word2vec_model = models['word2vec']
            self.classifier = models['classifier']
            self.label_encoder = models['label_encoder']
            self.tld_encoder = models['tld_encoder']
        except Exception as e:
            raise ValueError(f"Error loading models: {str(e)}")

    def predict(self, url):
        if not all([self.word2vec_model, self.classifier, self.label_encoder, self.tld_encoder]):
            raise ValueError("Models not trained! Call train() or load_models() first.")

        try:
            # Prepare features for the single URL
            features = self._prepare_single_url_features(url)

            # Make prediction
            prediction = self.classifier.predict(features)[0]
            probability = self.classifier.predict_proba(features)[0]

            # Map prediction to label
            label = self.label_map.get(prediction, 'Unknown')

            return {
                'url': url,
                'prediction': label,
                'is_phishing': label == 'phishing',
                'confidence': max(probability),
                'probability_phishing': probability[0],
                'probability_safe': probability[1]
            }
        except Exception as e:
            raise ValueError(f"Error making prediction: {str(e)}")

    def _prepare_single_url_features(self, url):
        try:
            # Extract base features
            features = self.feature_extractor.extract_features(url)

            # Get domain embedding
            domain = str(features['domain_name']).lower()
            domain_tokens = list(domain)

            # Calculate domain embedding
            valid_tokens = [token for token in domain_tokens if token in self.word2vec_model.wv]
            if valid_tokens:
                domain_embedding = np.mean([self.word2vec_model.wv[token] for token in valid_tokens], axis=0)
            else:
                domain_embedding = np.zeros(self.vector_size)

            # Prepare feature dictionary
            feature_dict = {
                'url_length': features['url_length'],
                'domain_length': features['domain_length'],
                'path_length': features['path_length'],
                'is_https': features['is_https'],
                'special_char_count': features['special_char_count'],
                'is_ip_address': features['is_ip_address'],
                'suspicious_keyword_count': features['suspicious_keyword_count'],
                'has_suspicious_tld': features['has_suspicious_tld'],
                'directory_depth': features['directory_depth'],
                'query_param_count': features['query_param_count'],
                'fragment_length': features['fragment_length'],
                'has_subdomain': features['has_subdomain'],
                'domain_has_numbers': features['domain_has_numbers'],
                'query_param_length': features['query_param_length'],
                'subdomain_count': features['subdomain_count'],
                'uses_ip_in_url': features['uses_ip_in_url'],
                'long_path': features['long_path'],
                'has_hyphens_in_domain': features['has_hyphens_in_domain'],
                'has_at_symbol': features['has_at_symbol'],
                'has_misspelled_domain': features['has_misspelled_domain'],
                'is_shortened_url': features['is_shortened_url']
            }

            # Add TLD encoding
            feature_dict['tld_encoded'] = self._encode_tld(features['tld'])

            # Add embedding features
            for i, val in enumerate(domain_embedding):
                feature_dict[f'embedding_{i}'] = val

            return pd.DataFrame([feature_dict])

        except Exception as e:
            raise ValueError(f"Error preparing features: {str(e)}")

    def _encode_tld(self, tld):
        try:
            return self.tld_encoder.transform([str(tld)])[0]
        except ValueError:
            return -1