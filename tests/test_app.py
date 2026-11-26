import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import storage
import ui_data
from test_chain import scan as chained_scan
from test_migration import make_v2_db

HAS_STREAMLIT = importlib.util.find_spec("streamlit") is not None
APP = str(ROOT / "app.py")

HOSTILE_BANNER = "<script>alert(1)</script> ![x](http://evil.example/x.png) [click](http://evil.example)"


@unittest.skipUnless(HAS_STREAMLIT, "Streamlit is not installed (python -m pip install -r requirements-ui.txt)")
class TestApp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = os.path.join(self.tmp.name, "portwatch.db")
        self._old_env = os.environ.get(ui_data.ENV_DB)
        os.environ[ui_data.ENV_DB] = self.path

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop(ui_data.ENV_DB, None)
        else:
            os.environ[ui_data.ENV_DB] = self._old_env
        self.tmp.cleanup()

    def fill(self, scans=2, banner=None):
        db = storage.connect(self.path)
        for i in range(scans):
            s = chained_scan(started=f"2026-11-0{i + 1}T10:00:00+00:00")
            if banner and i == scans - 1:
                for r in s["results"]:
                    if r["state"] == "OPEN":
                        r["banner"] = banner
            storage.save_scan(db, s)
        db.close()

    def start(self):
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP, default_timeout=60)
        return at.run()

    def go_to(self, at, page):
        at.sidebar.radio[0].set_value(page).run()
        return at

    def test_history_page_shows_the_scans_and_a_passing_history(self):
        self.fill()
        at = self.start()
        self.assertEqual(list(at.exception), [])
        self.assertTrue(any("History verification passed" in s.value for s in at.success))
        self.assertEqual(len(at.dataframe), 1)
        frame = at.dataframe[0].value
        self.assertEqual(list(frame["ID"]), [2, 1])
        self.assertEqual(list(frame["History"]), ["verified", "verified"])

    def test_results_page_shows_the_newest_scan_first(self):
        self.fill()
        at = self.go_to(self.start(), "Results")
        self.assertEqual(list(at.exception), [])
        self.assertEqual(at.selectbox[0].value, 2)
        metrics = {m.label: m.value for m in at.metric}
        self.assertEqual(metrics["Open"], "1")
        self.assertEqual(metrics["Closed"], "2")
        self.assertEqual(metrics["Exposure score"], "1.0")
        self.assertTrue(any("LOW EXPOSURE" in s.value for s in at.subheader))
        self.assertTrue(any("passed history verification" in s.value for s in at.success))
        findings = at.dataframe[0].value
        self.assertEqual(list(findings["Port"]), [8000])
        self.assertEqual(list(findings["Service"]), ["http"])

    def test_another_scan_can_be_chosen(self):
        self.fill(scans=3)
        at = self.go_to(self.start(), "Results")
        at.selectbox[0].select(1).run()
        self.assertEqual(list(at.exception), [])
        self.assertEqual(at.selectbox[0].value, 1)

    def test_untrusted_banner_text_is_never_rendered_as_markdown_or_html(self):
        self.fill(banner=HOSTILE_BANNER)
        at = self.go_to(self.start(), "Results")
        self.assertEqual(list(at.exception), [])
        self.assertIn(HOSTILE_BANNER, [c.value for c in at.code])        # shown as plain code text
        for element in list(at.markdown) + list(at.caption) + list(at.subheader):
            self.assertNotIn("evil.example", element.value)               # never reaches markdown
            self.assertNotIn("<script>", element.value)

    def test_a_missing_database_is_explained_and_not_created(self):
        at = self.start()
        self.assertEqual(list(at.exception), [])
        self.assertTrue(any("No database found" in e.value for e in at.error))
        self.assertEqual(len(at.dataframe), 0)
        self.assertFalse(os.path.exists(self.path))

    def test_an_empty_database_says_there_are_no_scans(self):
        storage.connect(self.path).close()
        at = self.start()
        self.assertEqual(list(at.exception), [])
        self.assertTrue(any("No saved scans" in i.value for i in at.info))
        at = self.go_to(at, "Results")
        self.assertEqual(list(at.exception), [])
        self.assertTrue(any("No saved scans" in i.value for i in at.info))

    def test_an_old_database_is_not_upgraded_by_viewing_it(self):
        make_v2_db(self.path)
        before = Path(self.path).read_bytes()
        at = self.start()
        self.assertTrue(any("python storage.py" in e.value for e in at.error))
        self.assertEqual(Path(self.path).read_bytes(), before)
        self.assertEqual(os.listdir(self.tmp.name), ["portwatch.db"])

    def test_viewing_never_changes_the_database(self):
        self.fill()
        before = Path(self.path).read_bytes()
        at = self.start()
        at = self.go_to(at, "Results")
        self.go_to(at, "History")
        self.assertEqual(Path(self.path).read_bytes(), before)

    def test_a_tampered_history_is_called_out_on_both_pages(self):
        self.fill(scans=3)
        import sqlite3
        raw = sqlite3.connect(self.path)
        raw.execute("UPDATE port_results SET state='CLOSED' WHERE scan_id=2 AND state='OPEN'")
        raw.commit()
        raw.close()
        at = self.start()
        self.assertTrue(any("FAILED" in e.value and "scan #2" in e.value for e in at.error))
        self.assertIn("BROKEN", list(at.dataframe[0].value["History"]))
        at = self.go_to(at, "Results")
        at.selectbox[0].select(2).run()
        self.assertTrue(any("FAILED history verification" in e.value for e in at.error))


if __name__ == "__main__":
    unittest.main()
