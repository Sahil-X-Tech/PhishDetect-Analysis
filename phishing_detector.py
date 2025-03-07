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
        self.legitimate_domains = {
            'google': 'google',
            'facebook': 'facebook',
            'instagram': 'instagram', 
            'twitter': 'twitter', 
            'amazon': 'amazon', 
            'microsoft': 'microsoft', 
            'apple': 'apple',
            'github': 'github',
            'youtube': 'youtube',
            'netflix': 'netflix',
            'linkedin': 'linkedin',
            'yahoo': 'yahoo',
            'paypal': 'paypal',
            'dropbox': 'dropbox',
            'gmail': 'gmail',
            'outlook': 'outlook',
            'hotmail': 'hotmail',
            'ebay': 'ebay',
            'walmart': 'walmart',
            'adobe': 'adobe',
            'wordpress': 'wordpress',
            'chatgpt': 'chatgpt',
            'openai': 'openai'
        }

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
        # Extract domain name without TLD
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain.lower()

        # Known legitimate domains for direct comparison
        legitimate_domains = {
            'google': 'google',
            'facebook': 'facebook',
            'instagram': 'instagram', 
            'twitter': 'twitter', 
            'amazon': 'amazon', 
            'microsoft': 'microsoft', 
            'apple': 'apple',
            'github': 'github',
            'youtube': 'youtube',
            'netflix': 'netflix',
            'linkedin': 'linkedin',
            'yahoo': 'yahoo',
            'paypal': 'paypal',
            'dropbox': 'dropbox',
            'gmail': 'gmail',
            'outlook': 'outlook',
            'hotmail': 'hotmail',
            'ebay': 'ebay',
            'walmart': 'walmart',
            'adobe': 'adobe',
            'wordpress': 'wordpress',
            'chatgpt': 'chatgpt',
            'openai': 'openai'
        }

        # Common misspellings dictionary - maps misspelled versions to their correct forms
        common_misspellings = {
            'gogle': 'google',
            'goggle': 'google',
            'googel': 'google',
            'gooogle': 'google',
            'g00gle': 'google',
            'googlle': 'google',
            'goole': 'google',
            'faceboook': 'facebook',
            'facebok': 'facebook',
            'facbook': 'facebook',
            'fcebook': 'facebook',
            'faebook': 'facebook',
            'faceb00k': 'facebook',
            'twiter': 'twitter',
            'twitted': 'twitter',
            'twiteer': 'twitter',
            'twutter': 'twitter',
            'amazn': 'amazon',
            'amzon': 'amazon',
            'ammazon': 'amazon',
            'amazom': 'amazon',
            'amaz0n': 'amazon',
            'microsft': 'microsoft',
            'micosoft': 'microsoft',
            'micorsoft': 'microsoft',
            'mircosoft': 'microsoft',
            'paypl': 'paypal',
            'paypall': 'paypal',
            'paypai': 'paypal',
            'linkedln': 'linkedin',
            'linkeldn': 'linkedin',
            'youtub': 'youtube',
            'yutube': 'youtube',
            'yuotube': 'youtube',
            'instagarm': 'instagram',
            'insatgram': 'instagram',
            'instagrm': 'instagram'
        }

        # Direct check for known misspellings
        if domain_name in common_misspellings:
            return 1

        # If it's an exact match to a legitimate domain, it's not misspelled
        if domain_name in legitimate_domains.values():
            return 0

        # Check for common misspellings of popular domains
        for genuine, canonical in legitimate_domains.items():
            # Skip short domains to avoid false positives
            if len(genuine) <= 3:
                continue

            # Exact match
            if domain_name == canonical:
                extracted = tldextract.extract(domain)
                if extracted.suffix in ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'ai', 'app']:
                    return 0

            # Levenshtein distance check for similar domains
            # Calculate simple edit distance
            if len(domain_name) > 3 and len(canonical) > 3:
                # Simple homoglyph check (similar looking characters)
                homoglyph_domain = domain_name.replace('0', 'o').replace('1', 'l').replace('1', 'i').replace('3', 'e')

                # If the domain contains the canonical name but isn't exactly it
                if canonical in domain_name and domain_name != canonical:
                    return 1

                # Check if it's a common typo (character swapped)
                chars = list(canonical)
                for i in range(len(chars) - 1):
                    swapped = chars.copy()
                    swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
                    if ''.join(swapped) == domain_name:
                        return 1

                # Check for deleted character
                for i in range(len(canonical)):
                    if canonical[:i] + canonical[i+1:] == domain_name:
                        return 1

                # Check for inserted character
                if len(domain_name) == len(canonical) + 1:
                    for i in range(len(domain_name)):
                        if domain_name[:i] + domain_name[i+1:] == canonical:
                            return 1

                # Check for substituted character
                differences = sum(1 for a, b in zip(canonical, domain_name) if a != b)
                if len(canonical) == len(domain_name) and differences == 1:
                    return 1

                # Check for homoglyph substitution
                if homoglyph_domain == canonical:
                    return 1

                # Check for repeated characters (e.g., googgle)
                if len(domain_name) > len(canonical) and re.search(r'(.)\1{2,}', domain_name):
                    compressed = re.sub(r'(.)\1+', r'\1\1', domain_name)
                    if compressed == canonical or compressed == canonical + canonical[-1]:
                        return 1

        # Check other patterns for misspellings
        misspelled_patterns = [
            # Character substitutions
            r"0{1}o", r"1{1}l", r"3{1}e", r"1{1}i", r"5{1}s", r"6{1}b", r"8{1}b", 
            # Excessive repetition (3+ same character)
            r"(.)\1{2,}",
            # Domain-specific patterns
            r"g0+gle", r"goo+gle", r"g0ogle", r"goog1e", r"gogle",
            r"face(b0+k|bo{2,}k)", r"faceb00k",
            r"(a|4)m(a|4)z(o|0)n", 
            r"micr(o|0)(s|5)(o|0)ft",
            r"y(o|0)utub(e|3)",
            r"inst(a|4)gr(a|4)m",
            r"l(i|1)nk(e|3)d(i|1)n",
            r"tw(i|1)tt(e|3)r",
            # Protocol typos
            r"htt+p(s)?:/+", r"ht{2,}p://"
        ]

        # Check for 3+ consecutive repeating patterns that might indicate keyboard mashing
        if re.search(r'(.{2,})\1{2,}', domain_name):
            return 1

        # Check for excessive numbers in domain (phishing sites often use many numbers)
        digit_count = sum(c.isdigit() for c in domain_name)
        if digit_count > len(domain_name) * 0.4 and len(domain_name) > 5:
            return 1

        # Check for random-looking strings (high entropy domains)
        consonant_groups = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', domain_name)
        if consonant_groups and len(consonant_groups[0]) > 4:
            return 1

        return int(any(re.search(pattern, domain_name) for pattern in misspelled_patterns))

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
        # Define canonical forms of trusted domains
        self.trusted_domains_map = {
            'google': ['google.com', 'www.google.com'],
            'facebook': ['facebook.com', 'www.facebook.com'],
            'twitter': ['twitter.com', 'www.twitter.com'],
            'instagram': ['instagram.com', 'www.instagram.com'],
            'amazon': ['amazon.com', 'www.amazon.com'],
            'microsoft': ['microsoft.com', 'www.microsoft.com'],
            'apple': ['apple.com', 'www.apple.com'],
            'github': ['github.com', 'www.github.com'],
            'youtube': ['youtube.com', 'www.youtube.com'],
            'netflix': ['netflix.com', 'www.netflix.com'],
            'linkedin': ['linkedin.com', 'www.linkedin.com'],
            'chatgpt': ['chatgpt.com', 'www.chatgpt.com'],
            'openai': ['openai.com', 'www.openai.com']
        }

        # Flatten for backwards compatibility
        self.trusted_domains = []
        for domains in self.trusted_domains_map.values():
            self.trusted_domains.extend(domains)

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
            # Parse the URL and extract domain
            parsed_url = urlparse(url.lower())
            domain = parsed_url.netloc

            # Extract domain parts
            extracted = tldextract.extract(url.lower())
            domain_name = extracted.domain

            # Check if it's a known legitimate domain (exact match only)
            is_exact_trusted = domain in self.trusted_domains

            # For common domains like Google, check for exact match only
            # This prevents misspellings like "gogle.com" from being considered legitimate
            if is_exact_trusted:
                return {
                    'url': url,
                    'prediction': 'safe',
                    'is_phishing': False,
                    'confidence': 0.99,
                    'probability_phishing': 0.01,
                    'probability_safe': 0.99
                }
                
            # Get the legitimate domains from the feature extractor
            legitimate_domains = self.feature_extractor.legitimate_domains
            
            # Check if this is a legitimate domain by domain name alone (for chatgpt.com, etc.)
            # This ensures domains like "chatgpt.com" that might not be in the exact match list are still detected
            if domain_name.lower() in legitimate_domains.values():
                extracted = tldextract.extract(url.lower())
                if extracted.suffix in ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'ai', 'app']:
                    return {
                        'url': url,
                        'prediction': 'safe',
                        'is_phishing': False,
                        'confidence': 0.95,
                        'probability_phishing': 0.05,
                        'probability_safe': 0.95
                    }

            # Use the improved _has_misspelled_domain method to check for misspellings
            is_misspelled = self.feature_extractor._has_misspelled_domain(domain) == 1

            # If the domain is detected as misspelled, mark as suspicious
            if is_misspelled:
                is_suspicious_variant = True
            else:
                # Additional checks for misspelled versions of popular domains
                is_suspicious_variant = False
                for genuine, variants in self.trusted_domains_map.items():
                    # Skip very short domain names to prevent false positives
                    if len(genuine) <= 3:
                        continue

                    # Check for typosquatting techniques with more sophisticated rules
                    if len(genuine) > 4:
                        # Check for homoglyphs (similar looking characters)
                        homoglyph_domain = domain_name.replace('0', 'o').replace('1', 'l').replace('1', 'i').replace('3', 'e')
                        if homoglyph_domain == genuine and domain_name != genuine:
                            is_suspicious_variant = True
                            break

                        # Check for character swaps (transposition errors)
                        chars = list(genuine)
                        for i in range(len(chars) - 1):
                            swapped = chars.copy()
                            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
                            if ''.join(swapped) == domain_name:
                                is_suspicious_variant = True
                                break

                        # Check for added/removed characters
                        if abs(len(domain_name) - len(genuine)) == 1:
                            # Check if removing any one character from the longer string results in the shorter string
                            if len(domain_name) > len(genuine):
                                for i in range(len(domain_name)):
                                    if domain_name[:i] + domain_name[i+1:] == genuine:
                                        is_suspicious_variant = True
                                        break
                            else:
                                for i in range(len(genuine)):
                                    if genuine[:i] + genuine[i+1:] == domain_name:
                                        is_suspicious_variant = True
                                        break

                    if is_suspicious_variant:
                        break

            # If it looks like a misspelled version of a trusted domain, mark as phishing
            if is_suspicious_variant:
                return {
                    'url': url,
                    'prediction': 'phishing',
                    'is_phishing': True,
                    'confidence': 0.98,
                    'probability_phishing': 0.98,
                    'probability_safe': 0.02
                }

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