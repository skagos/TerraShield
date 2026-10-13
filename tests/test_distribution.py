"""Run against an installed wheel, including from outside the checkout."""

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch
from zipfile import ZipFile

from fastapi.testclient import TestClient

from app.main import app
from app.terraform_parser import parse_tf_content, parse_tf_directory, parse_tf_from_zip


TERRAFORM = 'resource "aws_s3_bucket" "example" { bucket = "example-bucket" }'


class DistributionTests(unittest.TestCase):
    def test_parser_inputs(self):
        resources = parse_tf_content(TERRAFORM)
        self.assertEqual(resources[0].resource_type, "aws_s3_bucket")
        self.assertEqual(resources[0].config["bucket"], "example-bucket")
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "main.tf").write_text(TERRAFORM)
            self.assertEqual(len(parse_tf_directory(Path(directory))), 1)
        archive = io.BytesIO()
        with ZipFile(archive, "w") as zipped:
            zipped.writestr("infra/main.tf", TERRAFORM)
        self.assertEqual(parse_tf_from_zip(archive.getvalue())[0].resource_name, "example")

    def test_api_and_packaged_frontend(self):
        with TestClient(app) as client:
            self.assertEqual(client.get("/health").json(), {"status": "ok"})
            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(client.get("/static/app.js").status_code, 200)
            self.assertEqual(client.get("/openapi.json").status_code, 200)
            response = client.post(
                "/analyze/file", files={"tf_file": ("main.tf", TERRAFORM, "text/plain")}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["resource_count"], 1)

    def test_installed_command(self):
        executable = shutil.which("tfreader")
        self.assertIsNotNone(executable)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [executable, "--help"], cwd=directory, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run(
                [executable, "scan", "missing.tf"], cwd=directory, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 2)

    def test_scan_reports_without_external_scanners(self):
        from app.cli import main

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "main.tf")
            target.write_text(TERRAFORM)
            report = Path(directory, "security.json")
            markdown = Path(directory, "security.md")
            with patch("app.security_analyzer.shutil.which", return_value=None) as lookup:
                code = main([
                    "scan", str(target), "--out-json", str(report), "--out-md", str(markdown)
                ])
            self.assertEqual(lookup.call_args_list, [call("checkov"), call("tfsec")])
            self.assertEqual(code, 0)
            payload = json.loads(report.read_text())
            self.assertEqual(payload["findings_count"], 0)
            self.assertTrue(payload["scanner_errors"])
            self.assertTrue(markdown.read_text())
            self.assertEqual(set(payload["scanner_status"]), {"checkov", "tfsec"})
            self.assertNotIn("terrascan", markdown.read_text().lower())

    def test_security_api_uses_only_supported_scanners(self):
        checkov = {"results": {"failed_checks": [{
            "resource": "aws_s3_bucket.example", "check_id": "CKV_TEST",
            "check_name": "Public bucket", "severity": "HIGH",
        }]}}
        tfsec = {"results": [{
            "resource": "aws_s3_bucket.example", "long_id": "TFSEC_TEST",
            "description": "Bucket encryption", "severity": "MEDIUM",
        }]}
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("app.security_analyzer.shutil.which", side_effect=lambda name: name) as lookup,
                patch("app.security_analyzer.SecurityAnalyzer._run_command", side_effect=[
                    (1, json.dumps(checkov), ""), (1, json.dumps(tfsec), ""),
                ]) as commands,
                TestClient(app) as client,
            ):
                response = client.post("/security/resources", json={
                    "resources": [], "scan_dir": directory,
                })
            self.assertEqual(response.status_code, 200)
            self.assertEqual(lookup.call_args_list, [call("checkov"), call("tfsec")])
            self.assertEqual([item.args[0][0] for item in commands.call_args_list], ["checkov", "tfsec"])
            payload = response.json()
            self.assertEqual(payload["scanner_status"], {"checkov": "ok", "tfsec": "ok"})
            self.assertEqual(payload["findings_count"], 2)
            self.assertEqual(payload["score"]["score"], 82)
            self.assertNotIn("terrascan", json.dumps(payload).lower())


if __name__ == "__main__":
    unittest.main()
