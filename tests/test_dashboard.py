import unittest
from pathlib import Path
from streamlit.testing.v1 import AppTest


class DashboardTests(unittest.TestCase):
    def test_initial_dashboard_and_settings(self):
        app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run(timeout=20)
        self.assertFalse(app.exception)
        self.assertEqual(app.title[0].value, 'ThreatLocker Hash Manager')
        self.assertTrue(next(b for b in app.button if b.label.startswith('Validate connection')).disabled)
        self.assertEqual(app.text_input[1].value, '')
        app.selectbox[0].set_value('Bulk').run()
        self.assertFalse(app.exception)
        self.assertEqual(app.selectbox[0].value, 'Bulk')


if __name__ == '__main__':
    unittest.main()
