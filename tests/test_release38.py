from pathlib import Path
import unittest

from kyojitsu.studio_ui import STUDIO_HTML

ROOT = Path(__file__).resolve().parents[1]
REPORT_CSS = (ROOT / 'src/kyojitsu/web/report.css').read_text(encoding='utf-8')
REPORT_JS = (ROOT / 'src/kyojitsu/web/report.js').read_text(encoding='utf-8')
STUDIO_CSS = (ROOT / 'src/kyojitsu/web/studio.css').read_text(encoding='utf-8')
STUDIO_JS = (ROOT / 'src/kyojitsu/web/studio.js').read_text(encoding='utf-8')


class Release38Tests(unittest.TestCase):
    def test_guided_wizard_has_five_steps(self):
        self.assertIn('id="wizardProgress"', STUDIO_HTML)
        self.assertIn('data-wizard-step="reviewPanel"', STUDIO_HTML)
        self.assertIn("const WIZARD=[", STUDIO_JS)
        self.assertIn("Paso ${index+1} de ${WIZARD.length}", STUDIO_JS)
        self.assertIn('.wizard-controls', STUDIO_CSS)

    def test_report_charts_reanimate_when_navigating(self):
        self.assertIn("viewTimer=setTimeout", REPORT_JS)
        self.assertIn("if(route==='overview')renderExecutiveCharts()", REPORT_JS)
        self.assertIn("if(route==='framework')renderFrameworkCharts()", REPORT_JS)
        self.assertIn('.rview.view-enter', REPORT_CSS)
        self.assertIn('.chart-line.ready', REPORT_CSS)

    def test_replay_rebuilds_lineage_before_case_playback(self):
        self.assertIn('playOriginStory', REPORT_JS)
        self.assertIn('prepareOriginStory', REPORT_JS)
        self.assertIn('originStoryAnimations', REPORT_JS)
        self.assertIn('getTotalLength()', REPORT_JS)
        self.assertIn('origin-story-playing', REPORT_JS)

    def test_report_has_mobile_specific_rules(self):
        self.assertIn('@media(max-width:560px)', REPORT_CSS)
        self.assertIn('.origin-graph{min-width:700px}', REPORT_CSS)
        self.assertIn('.filterbar{grid-template-columns:1fr}', REPORT_CSS)


if __name__ == '__main__':
    unittest.main()
