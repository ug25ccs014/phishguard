import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml_core.features import FEATURE_NAMES, FEATURE_VERSION, canonicalize_url, extract_features


class FeatureTests(unittest.TestCase):
    def test_feature_schema_is_stable(self):
        features = extract_features('https://example.com/account/login?x=1')
        values = features.to_dict()
        self.assertEqual(len(FEATURE_NAMES), 27)
        self.assertEqual(set(FEATURE_NAMES), set(values))
        self.assertEqual(FEATURE_VERSION, 'url-lexical-v1')

    def test_ip_and_punycode_signals(self):
        ip = extract_features('http://192.0.2.1/login')
        puny = extract_features('https://xn--paypa1-9za.example/verify')
        self.assertEqual(ip.has_ip_hostname, 1)
        self.assertEqual(puny.has_punycode, 1)

    def test_canonicalization_removes_fragment_and_normalizes_host(self):
        self.assertEqual(canonicalize_url('HTTPS://Example.COM/path#token'), 'https://example.com/path')

    def test_query_and_encoding_features(self):
        f = extract_features('https://example.com/a/b?next=%2Flogin&id=123')
        self.assertEqual(f.path_depth, 2)
        self.assertEqual(f.query_parameter_count, 2)
        self.assertEqual(f.percent_encoded_count, 1)


if __name__ == '__main__':
    unittest.main()
