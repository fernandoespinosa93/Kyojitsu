from pathlib import Path
import unittest

from kyojitsu.studio_ui import STUDIO_HTML
from kyojitsu.report_ui import render_report_html

ROOT = Path(__file__).resolve().parents[1]
REPORT_CSS = (ROOT / "src/kyojitsu/web/report.css").read_text(encoding="utf-8")
REPORT_JS = (ROOT / "src/kyojitsu/web/report.js").read_text(encoding="utf-8")
STUDIO_CSS = (ROOT / "src/kyojitsu/web/studio.css").read_text(encoding="utf-8")
STUDIO_JS = (ROOT / "src/kyojitsu/web/studio.js").read_text(encoding="utf-8")

class Release37Tests(unittest.TestCase):
    def test_version_and_logo_present(self):
        self.assertIn("3.8.1", STUDIO_HTML)
        self.assertIn("brand-logo", STUDIO_HTML)
        self.assertIn("brand-lockup", STUDIO_CSS)

    def test_origin_reveals_edges_and_nodes_progressively(self):
        self.assertIn("lineage-edge-reveal", REPORT_JS)
        self.assertIn("lineage-edge-flow", REPORT_JS)
        self.assertIn("getTotalLength()", REPORT_JS)
        self.assertIn("prepareOriginStory", REPORT_JS)
        self.assertIn("playOriginStory", REPORT_JS)
        self.assertIn("renderOriginGraph();restartOriginAnimation()", REPORT_JS)

    def test_tables_use_plum_not_blue_headers(self):
        self.assertIn(".assessment-table th,.evidence-table th", REPORT_CSS)
        self.assertIn("background:#16121a!important", REPORT_CSS)
        self.assertIn("th,.live-table th,.tech-table th", STUDIO_CSS)

    def test_unverified_state_uses_lavender(self):
        self.assertIn("accepted_unverified:'#b88be8'", STUDIO_JS)
        self.assertIn("unverified:'#aa78ef'", REPORT_JS)

    def test_engine_motion_remains_after_completed_run(self):
        self.assertIn("motionActive=!reduced&&(isRunning||recentRows.length>0)", STUDIO_JS)
        self.assertIn("idleNodeBreath", STUDIO_CSS)

if __name__ == "__main__":
    unittest.main()
