from pathlib import Path
import unittest

from kyojitsu.studio_ui import STUDIO_HTML

ROOT = Path(__file__).resolve().parents[1]
REPORT_CSS = (ROOT / 'src/kyojitsu/web/report.css').read_text(encoding='utf-8')
REPORT_JS = (ROOT / 'src/kyojitsu/web/report.js').read_text(encoding='utf-8')
STUDIO_CSS = (ROOT / 'src/kyojitsu/web/studio.css').read_text(encoding='utf-8')


class Release381Tests(unittest.TestCase):
    def test_lineage_story_is_javascript_orchestrated(self):
        self.assertIn('function playOriginStory', REPORT_JS)
        self.assertIn('function prepareOriginStory', REPORT_JS)
        self.assertIn('getTotalLength()', REPORT_JS)
        self.assertIn('data-generation=', REPORT_JS)
        self.assertIn('origin-story-playing', REPORT_JS)

    def test_dotted_lineage_visual_is_preserved(self):
        self.assertIn('radial-gradient(#3c3144 .75px,transparent .75px)', REPORT_CSS)
        self.assertIn('background-size:18px 18px', REPORT_CSS)
        self.assertIn('.lineage-edge-flow', REPORT_CSS)

    def test_report_charts_use_explicit_motion(self):
        self.assertIn('function animateEl', REPORT_JS)
        self.assertIn('function animatePath', REPORT_JS)
        self.assertIn('function animateSvgRect', REPORT_JS)
        self.assertIn("strokeDasharray:'0 100'", REPORT_JS)
        self.assertIn('transform:\'scaleX(0)\'', REPORT_JS)

    def test_wizard_panels_take_full_width(self):
        self.assertIn('#configView .layout:not(.review-step){grid-template-columns:minmax(0,1fr)}', STUDIO_CSS)
        self.assertIn('.wizard-controls.first-step', STUDIO_CSS)
        self.assertIn('first-step', (ROOT / 'src/kyojitsu/web/studio.js').read_text(encoding='utf-8'))

    def test_github_handoff_docs_exist(self):
        for name in ['README.md', 'AGENTS.md', 'CONTRIBUTING.md', 'SECURITY.md']:
            self.assertTrue((ROOT / name).exists(), name)
        self.assertTrue((ROOT / 'docs' / 'ARCHITECTURE.md').exists())
        self.assertTrue((ROOT / 'docs' / 'DEVELOPMENT.md').exists())


if __name__ == '__main__':
    unittest.main()
