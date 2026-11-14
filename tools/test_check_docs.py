#!/usr/bin/env python3
"""Focused adversarial tests for the offline documentation checker."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_docs import extract_links, heading_anchors, validate


class DocsCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, path, text=""):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        return destination

    def codes(self, result):
        return {item["code"] for item in result["issues"]}

    def test_relative_redirects_and_bidirectional_navigation_are_valid(self):
        self.write("README.md", "[Start](docs/README.md)")
        self.write("docs/README.md", "[Moved guide](guides/intro.md)\n[Home](../README.md)")
        self.write("docs/guides/intro.md", "# Intro\n[Return](../README.md)\n[Source](../../core/example.kt)")
        self.write("core/example.kt", "// source")
        result = validate(self.root)
        self.assertTrue(result["ok"], result["issues"])
        self.assertEqual(result["navigation"]["unreachableDocs"], 0)

    def test_url_encoded_paths_images_titles_and_parentheses(self):
        self.write("README.md", '[Guide](docs/space%20guide.md#中文标题 "Read (carefully)")\n![Diagram](<images/diagram (2).svg> \'Title\')\n[Other](notes(a).txt (a title))')
        self.write("docs/space guide.md", "# 中文标题")
        self.write("images/diagram (2).svg", "<svg/>")
        self.write("notes(a).txt")
        result = validate(self.root)
        self.assertTrue(result["ok"], result["issues"])
        self.assertEqual(result["counts"]["images"], 1)
        self.assertEqual(result["counts"]["anchorsChecked"], 1)

    def test_exact_case_is_checked_on_windows_and_linux(self):
        self.write("README.md", "[Guide](docs/guide.md)")
        self.write("docs/Guide.md", "# Guide")
        result = validate(self.root)
        self.assertIn("case_mismatch", self.codes(result))
        self.assertNotIn("missing_target", self.codes(result))

    def test_missing_files_and_anchors_are_distinct(self):
        self.write("README.md", "[Guide](docs/guide.md#missing)\n![Image](missing.png)")
        self.write("docs/guide.md", "# Real")
        result = validate(self.root)
        self.assertEqual(self.codes(result), {"missing_target", "missing_anchor"})

    def test_duplicate_headings_and_explicit_anchor(self):
        self.write("README.md", "[A](docs/guide.md#hello-world-1)\n[B](docs/guide.md#legacy)\n[C](docs/guide.md#code-label)")
        self.write("docs/guide.md", '# Hello, World!\n# Hello, World!\n<a id="legacy"></a>\n## `Code` label')
        self.assertTrue(validate(self.root)["ok"])
        self.assertIn("setext", heading_anchors("Setext\n======"))

    def test_fenced_and_inline_code_do_not_generate_links(self):
        self.write("README.md", "# Readme\n```md\n[bad](missing.md)\n```\n~~~\n![bad](missing.png)\n~~~\n`[bad](none)` and ``[bad](more) ` inner``\n")
        result = validate(self.root)
        self.assertTrue(result["ok"], result["issues"])
        self.assertEqual(result["counts"]["links"], 0)

    def test_references_full_collapsed_shortcut_and_images(self):
        self.write("README.md", '[Guide][key]\n[key][]\n[key]\n![image][img]\n[key]: docs/guide.md "Guide title"\n[img]: images/a.svg\n')
        self.write("docs/guide.md", "# Guide")
        self.write("images/a.svg", "<svg/>")
        result = validate(self.root)
        self.assertTrue(result["ok"], result["issues"])
        self.assertEqual(result["counts"]["localLinks"], 4)

    def test_external_urls_are_counted_without_network(self):
        self.write("README.md", '[Web](https://example.invalid/a#x)\n[Mail](mailto:a@example.invalid)\n[CDN](//example.invalid/a)\n<https://another.invalid/>\n[Angle](<https://angle.invalid/a> "title")')
        result = validate(self.root)
        self.assertTrue(result["ok"])
        self.assertEqual(result["counts"]["externalLinks"], 5)
        self.assertEqual(result["counts"]["localLinks"], 0)

    def test_generated_evidence_and_third_party_trees_are_not_scanned(self):
        self.write("README.md", "# Home")
        for folder in ["app/build", ".gradle", ".local", "dist", "verification", "fixtures", "vendor", "third_party"]:
            self.write(folder + "/bad.md", "[Missing](no.md)")
        result = validate(self.root)
        self.assertTrue(result["ok"])
        self.assertEqual(result["counts"]["markdownFiles"], 1)

    def test_orphan_docs_fail_but_navigation_cycles_pass(self):
        self.write("README.md", "# Home")
        self.write("docs/README.md", "[A](a.md)")
        self.write("docs/a.md", "[Back](README.md)")
        self.write("docs/orphan.md", "# Orphan")
        result = validate(self.root)
        self.assertEqual(self.codes(result), {"unreachable_document"})
        self.assertEqual(result["navigation"]["unreachableDocs"], 1)

    def test_migration_retained_original_allowed_target_and_hash_checked(self):
        self.write("README.md", "[New](docs/new.md)")
        self.write("old.md", "Original retained")
        self.write("docs/new.md", "# Rewritten")
        manifest = self.write("migration.json", json.dumps({"entries": [{"originalPath": "old.md", "targetPath": "docs/new.md", "action": "rewrite", "originalSha256": "a" * 64}]}))
        self.assertTrue(validate(self.root, manifest)["ok"])
        manifest.write_text(json.dumps({"entries": [{"targetPath": "missing.md", "originalSha256": "bad"}]}))
        self.assertEqual(self.codes(validate(self.root, manifest)), {"migration_target_missing", "invalid_original_hash"})

    def test_cli_json_and_failure_exit(self):
        self.write("README.md", "[Missing](no.md)")
        output = self.root / "result.json"
        completed = subprocess.run([sys.executable, str(Path(__file__).with_name("check_docs.py")), "--root", str(self.root), "--json", str(output)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(output.read_text(encoding="utf-8"))["ok"])

    def test_linked_image_checks_image_and_link(self):
        self.write("README.md", "[![Logo](logo.svg)](guide.md)")
        self.write("guide.md", "# Guide")
        result = validate(self.root)
        self.assertIn("missing_target", self.codes(result))
        self.assertEqual(result["counts"]["links"], 2)

    def test_code_mask_preserves_link_line_numbers(self):
        links, problems = extract_links("```\n[none](bad)\n```\n`code`\n[real](ok.md)")
        self.assertFalse(problems)
        self.assertEqual([(item.target, item.line) for item in links], [("ok.md", 5)])

    def test_html_comment_fake_links_are_ignored(self):
        links, problems = extract_links("<!-- [bad](missing.md) -->\n[real](ok.md)")
        self.assertFalse(problems)
        self.assertEqual([(item.target, item.line) for item in links], [("ok.md", 2)])

    def test_drive_and_file_links_are_not_mistaken_for_external_urls(self):
        self.write("README.md", "[A](D:/machine/file.md)\n[B](file:///D:/machine/file.md)")
        result = validate(self.root)
        self.assertEqual(self.codes(result), {"absolute_local_path"})
        self.assertEqual(result["counts"]["externalLinks"], 0)


if __name__ == "__main__":
    unittest.main()
