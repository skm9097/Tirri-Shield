"""Tests for the CLI interface."""

from click.testing import CliRunner

from tirri_shield.cli import main


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_version(self):
        result = self.runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "tirri-shield" in result.output
        assert "0.1.0" in result.output

    def test_help(self):
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Tirri-Shield" in result.output
        assert "scan" in result.output
        assert "monitor" in result.output
        assert "web" in result.output
        assert "info" in result.output

    def test_scan_help(self):
        result = self.runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--duration" in result.output
        assert "--deep" in result.output

    def test_monitor_help(self):
        result = self.runner.invoke(main, ["monitor", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output
        assert "--interval" in result.output

    def test_web_help(self):
        result = self.runner.invoke(main, ["web", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--port" in result.output

    def test_info_command(self):
        result = self.runner.invoke(main, ["info"])
        assert result.exit_code == 0
        assert "BAT-BMS" in result.output
        assert "protect" in result.output.lower()
