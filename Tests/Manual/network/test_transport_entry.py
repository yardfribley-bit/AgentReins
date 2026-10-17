import importlib.util
import os
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path('tools/transport-audit').resolve()))

path = pathlib.Path("tools/transport-audit/auto.py")
spec = importlib.util.spec_from_file_location("transport_auto", path)
auto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auto)


class TransportEntryTests(unittest.TestCase):
    def test_any_safe_tool_name_is_an_entry(self):
        self.assertTrue(auto.entry_allowed("curl"))
        self.assertTrue(auto.entry_allowed("nc"))
        self.assertTrue(auto.entry_allowed("custom-tool"))
        self.assertFalse(auto.entry_allowed("auto.py"))
        self.assertFalse(auto.entry_allowed("../curl"))
        self.assertFalse(auto.entry_allowed(""))

    def test_destination_is_the_requested_peer(self):
        self.assertEqual(auto.destination_from_args(["-fsS", "https://example.com/a"]), "https://example.com/a")
        self.assertEqual(auto.destination_from_args(["git@github.com:org/repo.git"]), "git@github.com:org/repo.git")
        self.assertEqual(auto.destination_from_args(["example.com:443"]), "example.com:443")
        self.assertEqual(auto.destination_from_args(["127.0.0.1:8766"]), "127.0.0.1:8766")
        self.assertIsNone(auto.destination_from_args(["-fsS", "-o", "out"]))

    def test_gh_uses_hostname_and_repo_when_no_url_is_present(self):
        args = ["pr", "list", "--hostname", "github-tajleonbennis", "--repo", "owner/name", "--json", "url"]
        self.assertEqual(auto.command_destination("gh", args, {}), "github-tajleonbennis/owner/name")
        self.assertEqual(auto.command_destination("gh", ["api", "user"], {}), "api.github.com")
        self.assertIsNone(auto.command_destination("gh", ["--version"], {}))


class OutboundNameTests(unittest.TestCase):
    def test_download_paths_name_the_file_a_command_was_asked_to_write(self):
        from results import brew_download_host, brew_formulas, download_paths, download_record, session_http_lines
        self.assertEqual(download_paths('wget', ['https://downloads.example.com/pkg.tgz'], '/tmp/work'), ['/tmp/work/pkg.tgz'])
        self.assertEqual(download_paths('wget', ['-O', 'out.bin', 'https://downloads.example.com/pkg.tgz'], '/tmp/work'), ['/tmp/work/out.bin'])
        self.assertEqual(download_paths('wget', ['-O', '-', 'https://downloads.example.com/pkg.tgz'], '/tmp/work'), [])
        self.assertEqual(download_paths('curl', ['-O', 'https://downloads.example.com/pkg.tgz'], '/tmp/work'), ['/tmp/work/pkg.tgz'])
        self.assertEqual(brew_formulas(['install', 'wget']), ['wget'])
        self.assertEqual(brew_formulas(['--version']), [])
        missing = download_record('/tmp/agentreins-missing-download.bin')
        self.assertEqual(missing['state'], 'unavailable')
        request, response = session_http_lines('GET /pkg.tgz HTTP/1.1\nHost: downloads.example.com\nHTTP/1.1 200 Connection established\nHTTP/1.1 200 OK\n')
        self.assertEqual(request, ['GET /pkg.tgz HTTP/1.1', 'Host: downloads.example.com'])
        self.assertEqual(response, ['HTTP/1.1 200 OK'])
        self.assertEqual(brew_download_host('==> Downloading https://ghcr.io/v2/homebrew/core/wget/blobs/sha256:abc'), 'ghcr.io')
        import auto
        self.assertEqual(auto.destination_from_args(['-O', 'probe.html', 'https://example.com/']), 'https://example.com/')

    def test_upload_names_keep_the_file_name(self):
        from results import upload_names
        self.assertEqual(upload_names('curl', ['-T', 'secrets/token.txt', 'https://example.com']), ['token.txt'])
        self.assertEqual(upload_names('scp', ['-q', 'reports/special.bin', 'git@github.com:org/repo.git']), ['special.bin'])

    def test_push_names_come_from_commits_ahead_of_the_remote(self):
        import subprocess, tempfile
        from results import pushed_paths
        with tempfile.TemporaryDirectory() as directory:
            repo = pathlib.Path(directory)
            env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            env.update(GIT_AUTHOR_NAME='Audit', GIT_AUTHOR_EMAIL='audit@example.com', GIT_COMMITTER_NAME='Audit', GIT_COMMITTER_EMAIL='audit@example.com')
            subprocess.check_call(['git', 'init', '-q', '-b', 'main'], cwd=repo, env=env)
            (repo / 'keep.txt').write_text('old')
            subprocess.check_call(['git', 'add', 'keep.txt'], cwd=repo, env=env)
            subprocess.check_call(['git', 'commit', '-q', '-m', 'base'], cwd=repo, env=env)
            base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True, env=env).strip()
            subprocess.check_call(['git', 'update-ref', 'refs/remotes/origin/main', base], cwd=repo, env=env)
            (repo / 'special-file.txt').write_text('new')
            subprocess.check_call(['git', 'add', 'special-file.txt'], cwd=repo, env=env)
            subprocess.check_call(['git', 'commit', '-q', '-m', 'add special'], cwd=repo, env=env)
            head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True, env=env).strip()
            before = {'state': 'observed', 'branch': 'main', 'commit': head, 'refs': f'refs/heads/main {head}\nrefs/remotes/origin/main {base}'}
            self.assertEqual(pushed_paths(str(repo), before, ['push', 'origin', 'main']), ['special-file.txt'])


if __name__ == "__main__":
    unittest.main()
