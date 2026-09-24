from pathlib import Path
import unittest

from kyojitsu.studio_ui import STUDIO_HTML

ROOT = Path(__file__).resolve().parents[1]
STUDIO_CSS = (ROOT/'src/kyojitsu/web/studio.css').read_text(encoding='utf-8')
STUDIO_JS = (ROOT/'src/kyojitsu/web/studio.js').read_text(encoding='utf-8')
REPORT_CSS = (ROOT/'src/kyojitsu/web/report.css').read_text(encoding='utf-8')
REPORT_JS = (ROOT/'src/kyojitsu/web/report.js').read_text(encoding='utf-8')

class Release36Tests(unittest.TestCase):
    def test_version_and_crisp_visual_system_present(self):
        self.assertIn('3.8.1', STUDIO_HTML)
        self.assertIn('Kyojitsu 3.6 - Fortexa-inspired premium visual system', STUDIO_CSS)
        self.assertIn('backdrop-filter:none', STUDIO_CSS)
        self.assertIn('--cyan:#e056c9', STUDIO_CSS)

    def test_live_motion_uses_real_canvas_and_event_bursts(self):
        self.assertIn('flowParticles', STUDIO_HTML)
        self.assertIn('particleBurstAt', STUDIO_JS)
        self.assertIn('flowSample', STUDIO_JS)
        self.assertIn('requestAnimationFrame(drawParticles)', STUDIO_JS)

    def test_origin_motion_tracks_real_parent_child_edges(self):
        self.assertIn('originParticles', REPORT_JS)
        self.assertIn('originEdges.forEach', REPORT_JS)
        self.assertIn('lineage-node.selected', REPORT_CSS)
        self.assertIn("n.dataset.node===r.id", REPORT_JS)

    def test_semantic_state_colors_remain_available(self):
        for token in ('--green:#63b991','--amber:#d5a04f','--coral:#d96679'):
            self.assertIn(token, STUDIO_CSS)

if __name__ == '__main__':
    unittest.main()
