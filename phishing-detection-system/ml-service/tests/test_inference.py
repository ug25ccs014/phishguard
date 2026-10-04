import unittest
import sys
import json
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml_core.model import MODEL, predict_url


class InferenceTests(unittest.TestCase):
    @unittest.skipUnless(MODEL is not None, 'trained model artifact not present')
    def test_model_manifest_pins_artifact_hash(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / 'models' / 'model_manifest.json').read_text())
        digest = hashlib.sha256((root / 'models' / 'phishing_model.joblib').read_bytes()).hexdigest()
        self.assertEqual(digest, manifest['model_sha256'])
        self.assertEqual(manifest['model_version'], 'url-lexical-0.2.0')

    def test_model_catches_explicit_ip_host_fixture(self):
        result = predict_url('http://192.0.2.44/account/verify')
        self.assertEqual(result['label'], 'PHISHING')
        self.assertGreaterEqual(result['phishingProbability'], 0.5)

    def test_prediction_contract(self):
        result = predict_url('https://github.com/docs')
        self.assertIn(result['label'], {'LEGITIMATE', 'PHISHING'})
        self.assertGreaterEqual(result['phishingProbability'], 0.0)
        self.assertLessEqual(result['phishingProbability'], 1.0)
        self.assertEqual(len(result['features']), 27)
        self.assertTrue(result['modelVersion'])
        self.assertTrue(result['featureVersion'])
        self.assertIn('probabilityCalibrated', result)
        self.assertIsInstance(result['probabilityCalibrated'], bool)
        metadata = json.loads((Path(__file__).resolve().parents[1] / 'models' / 'metrics.json').read_text())
        importances = metadata.get('feature_importance', [])
        self.assertLessEqual(abs(sum(item['importance'] for item in importances) - 1.0), 0.01)


if __name__ == '__main__':
    unittest.main()
