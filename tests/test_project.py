import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from data_cleaning import clean_dataset
from k8s_features import extract_features, image_is_floating, load_workloads
from scan_parser import parse_kubescape, parse_kubescape_data



def setUpModule():
    # Tests reference project files by relative path; make that independent
    # of where the test runner was started.
    os.chdir(ROOT)


class FeatureTests(unittest.TestCase):
    def test_hardened_deployment_has_expected_controls(self):
        with open('manifests/secure/hardened-deployment.yaml', encoding='utf-8') as f:
            docs = list(yaml.safe_load_all(f))
        workload = next(d for d in docs if isinstance(d, dict) and d.get('kind') == 'Deployment')
        features = extract_features(workload)
        self.assertEqual(features['privileged'], 0)
        self.assertEqual(features['run_as_root'], 0)
        self.assertEqual(features['allow_priv_esc'], 0)
        self.assertEqual(features['rw_root_fs'], 0)
        self.assertEqual(features['automount_sa_token'], 0)

    def test_floating_image_detection_registry_port(self):
        self.assertTrue(image_is_floating('nginx'))
        self.assertTrue(image_is_floating('nginx:latest'))
        self.assertFalse(image_is_floating('registry.example:5000/team/app:v1'))
        self.assertFalse(image_is_floating('team/app@sha256:abcdef'))

    def test_load_workloads_handles_multiple_documents(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'multi.yaml'
            p.write_text('''apiVersion: v1\nkind: Pod\nmetadata:\n  name: one\nspec:\n  containers:\n  - name: c\n    image: nginx:1.27\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: two\nspec:\n  containers:\n  - name: c\n    image: nginx:1.27\n''', encoding='utf-8')
            self.assertEqual([name for name, _ in load_workloads(p)], ['one', 'two'])


class ParsingAndCleaningTests(unittest.TestCase):
    def test_scan_parser_empty_report(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'scan.json'
            p.write_text(json.dumps({'summaryDetails': {'complianceScore': 75, 'statusCounters': {'failed': 2, 'passed': 5, 'skipped': 1}}, 'results': [{'status': 'failed', 'baseScore': 9.8}, {'status': 'failed', 'baseScore': 7.5}, {'status': 'passed', 'baseScore': 10}]}), encoding='utf-8')
            result = parse_kubescape(p)
            self.assertEqual(result['kubescape_compliance'], 75)
            self.assertEqual(result['kubescape_critical'], 1)
            self.assertEqual(result['kubescape_high'], 1)

    def test_scan_parser_control_based_report(self):
        report = {
            'summaryDetails': {
                'complianceScore': 61.234,
                'controls': {
                    'C-0001': {'status': 'failed', 'scoreFactor': 9},
                    'C-0002': {'status': 'failed', 'scoreFactor': 7},
                    'C-0003': {'status': 'failed', 'scoreFactor': 5},
                    'C-0004': {'status': 'failed', 'scoreFactor': 2},
                    'C-0005': {'status': 'passed', 'scoreFactor': 10},
                    'C-0006': {'status': 'skipped', 'scoreFactor': 3},
                },
            },
            'results': [{'resourceID': 'x', 'controls': [{'status': {'status': 'failed'}}]}],
        }
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'scan.json'
            p.write_text(json.dumps(report), encoding='utf-8')
            result = parse_kubescape(p)
        self.assertEqual(result['kubescape_compliance'], 61.23)
        self.assertEqual((result['kubescape_failed'], result['kubescape_passed'], result['kubescape_skipped']), (4, 1, 1))
        self.assertEqual(
            (result['kubescape_critical'], result['kubescape_high'], result['kubescape_medium'], result['kubescape_low']),
            (1, 1, 1, 1),
        )

    def test_parse_from_file_and_from_data_agree(self):
        report = {
            'summaryDetails': {'complianceScore': 80, 'statusCounters': {'failed': 1, 'passed': 4, 'skipped': 0}},
            'results': [{'status': 'failed', 'baseScore': 8.0}],
        }
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'scan.json'
            p.write_text(json.dumps(report), encoding='utf-8')
            from_file = parse_kubescape(p)
        self.assertEqual(from_file, parse_kubescape_data(report))
        with self.assertRaisesRegex(ValueError, 'my-scan'):
            parse_kubescape_data([], source='my-scan')

    def test_scan_parser_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'scan.json'
            p.write_text('[]', encoding='utf-8')
            with self.assertRaises(ValueError):
                parse_kubescape(p)

    def test_clean_dataset_bounds_and_dedup(self):
        import pandas as pd
        df = pd.DataFrame({'id': ['a', 'a', 'b'], 'count': [-2, -2, None], 'score': [120, 120, None]})
        cleaned, report = clean_dataset(df, count_columns=['count'], bounded_columns={'score': (0, 100)}, key_columns=['id'], dedup_subset=['id'])
        self.assertEqual(len(cleaned), 2)
        self.assertEqual(cleaned.loc[0, 'count'], 0)
        self.assertEqual(cleaned.loc[0, 'score'], 100)
        self.assertEqual(report.duplicate_rows_dropped, 1)

    def test_clean_dataset_advanced_techniques(self):
        import numpy as np
        import pandas as pd
        df = pd.DataFrame({
            'snapshot': [' s1 ', 's2', '   ', 's4'],
            'environment': [' SECURE ', 'Insecure', 'secure', 'secure'],
            'risk_level': ['low', 'HIGH', 'medium', 'Low'],
            'cve_count': [float('inf'), 5, -3, 1000000],
            'score': [float('-inf'), 85.5, 50.0, 95.0],
            'vuln_type': ['Access', None, 'Network', 'Resource'],
        })
        cleaned, report = clean_dataset(
            df,
            count_columns=['cve_count'],
            bounded_columns={'score': (0, 100)},
            key_columns=['snapshot'],
            max_count_cap=10000,
        )
        # s1 stripped, '   ' empty key dropped -> 3 rows remaining
        self.assertEqual(len(cleaned), 3)
        self.assertEqual(cleaned.loc[0, 'snapshot'], 's1')
        self.assertEqual(cleaned.loc[0, 'environment'], 'secure')
        self.assertEqual(cleaned.loc[0, 'risk_level'], 'Low')
        self.assertEqual(cleaned.loc[1, 'risk_level'], 'High')
        # inf replaced and capped to max_count_cap or 0
        self.assertEqual(cleaned.loc[0, 'cve_count'], 0)
        self.assertEqual(cleaned.loc[2, 'cve_count'], 10000)
        # -inf in bounded column filled with low (0)
        self.assertEqual(cleaned.loc[0, 'score'], 0)
        # None string filled with default
        self.assertEqual(cleaned.loc[1, 'vuln_type'], 'Unknown')
        self.assertEqual(report.dropped_missing_key, 1)
        self.assertIn('cve_count', report.infinite_replaced)
        self.assertIn('snapshot', report.whitespace_stripped)


if __name__ == '__main__':
    unittest.main()
