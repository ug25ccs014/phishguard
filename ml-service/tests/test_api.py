import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from app import app


class ApiContractTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_reports_loaded_model(self):
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body['modelLoaded'])
        self.assertEqual(body['stage'], 'final-release')

    def test_predict_contract(self):
        response = self.client.post('/predict', json={'url': 'https://github.com/docs'})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn(body['label'], {'LEGITIMATE', 'PHISHING'})
        self.assertAlmostEqual(body['phishingProbability'] + body['legitimateProbability'], 1.0, places=6)
        self.assertEqual(len(body['features']), 27)
        self.assertEqual(body['featureVersion'], 'url-lexical-v1')


    def test_credential_url_rejected(self):
        response = self.client.post('/predict', json={'url': 'https://user:password@example.com/login'})
        self.assertEqual(response.status_code, 422)

    def test_invalid_scheme_rejected(self):
        response = self.client.post('/predict', json={'url': 'ftp://example.com/file'})
        self.assertEqual(response.status_code, 422)

    def test_oversized_request_rejected(self):
        response = self.client.post('/predict', content=b'{"url":"https://example.com"}', headers={'Content-Length': str(70 * 1024), 'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 413)


if __name__ == '__main__':
    unittest.main()
