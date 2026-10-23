"""Offline security regressions. No TV, live download, or installer is invoked."""
import base64
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from urllib.request import Request

import slopbro

ROOT = Path(__file__).resolve().parents[1]


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.session = slopbro.SecureSession({'index.html': b'page', 'main.js': b'code'}, '127.0.0.1')

    def test_transfers_are_not_an_install_result(self):
        for name in self.session.assets:
            self.session.tracker.mark_seen(name)
        with self.assertRaisesRegex(RuntimeError, 'no terminal'):
            self.session.wait(0.001)

    def test_success_requires_root_check_and_all_transfers(self):
        for payload in ({'ok': True, 'root_verified': True, 'phase': 'complete'},
                        {'ok': True, 'root_verified': False, 'phase': 'complete'}):
            with self.assertRaises(ValueError):
                self.session.receive_result(payload)
        for name in self.session.assets:
            self.session.tracker.mark_seen(name)
        self.session.receive_result({'ok': True, 'root_verified': True, 'phase': 'complete'})
        self.assertFalse(self.session.wait(0.01)['reboot_verified'])
        with self.assertRaises(ValueError):
            self.session.receive_result({'ok': True, 'root_verified': True, 'phase': 'complete'})

    def test_negative_result_before_any_download(self):
        self.session.receive_result({'ok': False, 'root_verified': False, 'phase': 'page', 'error': 'download failed'})
        with self.assertRaisesRegex(RuntimeError, 'page: download failed'):
            self.session.wait(0.01)

    def test_receipt_schema_is_strict(self):
        for value in (None, [], {}, {'ok': 1, 'root_verified': True, 'phase': 'complete'},
                      {'ok': False, 'root_verified': False, 'phase': 'x', 'extra': 1},
                      {'ok': False, 'root_verified': False, 'phase': 'x', 'error': 'x' * 501}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.session.receive_result(value)

    def test_manifest_snapshots_bytes_and_session_is_unpredictable(self):
        other = slopbro.SecureSession(self.session.assets, '127.0.0.1')
        self.assertNotEqual(self.session.token, other.token)
        manifest = json.loads(self.session.manifest())
        self.assertEqual(manifest['files'], ['main.js'])
        self.assertEqual(manifest['sha256']['main.js'], hashlib.sha256(b'code').hexdigest())
        url = slopbro.build_self_hosted_url('payload.example', 8443, self.session)
        self.assertTrue(url.startswith('https://payload.example:8443/' + self.session.token + '/index.html?'))


class TLSHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.directory.name) / 'cert.pem'
        cls.key = Path(cls.directory.name) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(cls.key), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-addext', 'basicConstraints=critical,CA:TRUE'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.context = ssl.create_default_context(cafile=str(cls.cert))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.session = slopbro.SecureSession({'index.html': b'page', 'main.js': b'code'}, '127.0.0.1')
        self.server = slopbro.start_http_server(self.session, '127.0.0.1', self.cert, self.key, preferred_port=0)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def request(self, method, path=None, body=None, headers=None):
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port, context=self.context, timeout=2)
        connection.request(method, path or '/' + self.session.token + '/index.html', body, headers or {})
        response = connection.getresponse()
        result = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return result

    def test_capability_paths_and_source_ip(self):
        for path in ('/index.html', '/' + '0' * 64 + '/index.html', '/' + self.session.token + '/../main.js',
                     '/' + self.session.token + '/%69ndex.html', '/' + self.session.token + '/missing'):
            self.assertEqual(self.request('GET', path)[0], 404)
        self.session.peer_ip = '192.0.2.1'
        self.assertEqual(self.request('GET')[0], 404)

    def test_head_does_not_count_and_assets_are_not_mutable(self):
        status, body, headers = self.request('HEAD')
        self.assertEqual((status, body), (200, b''))
        self.assertEqual(self.session.tracker.missing_files(), ['index.html', 'main.js'])
        status, body, headers = self.request('GET')
        self.assertEqual((status, body), (200, b'page'))
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.session.tracker.missing_files(), ['main.js'])

    def test_result_endpoint_checks_body_and_completion(self):
        path = '/' + self.session.token + '/result'
        good = {'ok': True, 'root_verified': True, 'phase': 'complete'}
        self.assertEqual(self.request('POST', path, json.dumps(good), {'Content-Type': 'application/json'})[0], 400)
        self.request('GET')
        self.request('GET', '/' + self.session.token + '/main.js')
        # Sending files alone still leaves the launcher waiting.
        self.assertIsNone(self.session.result)
        for body, content_type in (('not json', 'application/json'), ('{}', 'text/plain'), ('x' * 2049, 'application/json')):
            self.assertEqual(self.request('POST', path, body, {'Content-Type': content_type})[0], 400)
        self.assertEqual(self.request('POST', path, json.dumps(good), {'Content-Type': 'application/json'})[0], 204)
        self.assertTrue(self.session.wait(0.01)['ok'])

    def test_stalled_client_does_not_block_other_clients(self):
        raw = socket.create_connection(('127.0.0.1', self.server.server_port), 2)
        try:
            self.assertEqual(self.request('GET')[0], 200)
        finally:
            raw.close()

    def test_certificate_chain_and_hostname_must_be_trusted(self):
        with patch.dict(os.environ, {'SSL_CERT_FILE': str(self.cert)}):
            slopbro.verify_payload_certificate(self.server, '127.0.0.1', 'localhost')
            with self.assertRaises(ssl.SSLCertVerificationError):
                slopbro.verify_payload_certificate(self.server, '127.0.0.1', 'wrong.example')
        with self.assertRaises(ssl.SSLCertVerificationError):
            slopbro.verify_payload_certificate(self.server, '127.0.0.1', 'localhost')

    def test_plain_http_cannot_read_payload(self):
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        try:
            with self.assertRaises((ConnectionError, http.client.HTTPException)):
                client.request('GET', '/' + self.session.token + '/main.js')
                client.getresponse()
        finally:
            client.close()

    def test_missing_certificate_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'certificate'):
            slopbro.start_http_server(self.session, '127.0.0.1', None, None)


class DownloadAndKeyTests(unittest.TestCase):
    def test_local_package_digest_is_mandatory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'hbc.ipk'
            path.write_bytes(b'tampered')
            with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
                slopbro.load_hbchannel_ipk(path)
            # Test a valid fixture without downloading or redistributing HBC.
            with patch.object(slopbro, 'HBC_SHA256', hashlib.sha256(b'tampered').hexdigest()):
                self.assertEqual(slopbro.load_hbchannel_ipk(path), b'tampered')

    def test_package_error_pages_and_downgrade_are_rejected(self):
        response = Mock(status=404)
        response.geturl.return_value = slopbro.HBC_URL
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch.object(slopbro, 'build_opener') as build:
            build.return_value.open.return_value = response
            with self.assertRaisesRegex(RuntimeError, 'HTTPS 200'):
                slopbro.load_hbchannel_ipk()
            response.read.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'non-HTTPS'):
            slopbro.HTTPSOnlyRedirectHandler().redirect_request(Request(slopbro.HBC_URL), None, 302, '', {}, 'http://evil.example/file')

    def test_invalid_package_stops_before_pairing_or_listener(self):
        with patch.object(slopbro, 'load_hbchannel_ipk', side_effect=RuntimeError('bad package')):
            with patch.object(slopbro.WebSocket, 'connect') as connect, patch.object(slopbro, 'start_http_server') as server:
                with self.assertRaisesRegex(RuntimeError, 'bad package'):
                    slopbro.run('127.0.0.1', 'cert', 'key', 'localhost', '0' * 64, asset_source='dir', webos_version_override='9')
                connect.assert_not_called()
                server.assert_not_called()

    def test_keys_are_private_and_symlinks_are_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path, victim = Path(directory) / 'tv.key', Path(directory) / 'victim'
            victim.write_text('untouched')
            path.symlink_to(victim)
            with patch.object(slopbro, 'key_path', return_value=str(path)):
                slopbro.save_client_key('tv', 'secret')
                self.assertEqual(slopbro.load_client_key('tv'), 'secret')
            self.assertFalse(path.is_symlink())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(victim.read_text(), 'untouched')

    def test_embedded_assets_round_trip_and_include_security_policy(self):
        spec = importlib.util.spec_from_file_location('packager', ROOT / 'tools/package_single_file.py')
        packager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packager)
        assets = packager._build_asset_map(ROOT / 'wwwroot', packager.DEFAULT_FILES)
        self.assertEqual(set(assets), set(slopbro.required_files()))
        for name, meta in assets.items():
            self.assertEqual(base64.b64decode(meta['data']), (ROOT / 'wwwroot' / name).read_bytes())
        self.assertIn('Permission is hereby granted', base64.b64decode(assets['hbchannel-startup.sh']['data']).decode())


class WebSocketTests(unittest.TestCase):
    def socket_for(self, frames):
        sock = Mock()
        sock.recv.side_effect = [frames]
        return sock, slopbro.WebSocket(sock)

    def test_fragmented_utf8_with_interleaved_ping(self):
        sock, client = self.socket_for(b'\x01\x01\xc3\x89\x01?\x80\x01\xa9')
        self.assertEqual(client.recv_text(timeout=1), 'é')
        self.assertTrue(sock.sendall.called)  # Pong was sent.

    def test_bad_fragmentation_masking_and_oversized_frames(self):
        frames = (b'\x80\x01a', b'\x81\x80', b'\x09\x00', b'\xc1\x00',
                  b'\x81\x7f' + struct.pack('!Q', slopbro.MAX_WS_BYTES + 1), b'\x81\x01\xff')
        for frame in frames:
            with self.subTest(frame=frame), self.assertRaises(slopbro.WebSocketError):
                self.socket_for(frame)[1].recv_text(timeout=1)

    def test_aggregate_fragment_limit(self):
        with patch.object(slopbro, 'MAX_WS_BYTES', 3):
            with self.assertRaisesRegex(slopbro.WebSocketError, 'message exceeds'):
                self.socket_for(b'\x01\x02ab\x80\x02cd')[1].recv_text(timeout=1)

    def test_ping_stream_cannot_extend_deadline(self):
        sock = Mock()
        client = slopbro.WebSocket(sock)
        with patch.object(client, '_read_frame', return_value=(True, 9, b'')):
            with patch.object(slopbro.time, 'monotonic', side_effect=[0, 0.2, 1.1]):
                with self.assertRaises(socket.timeout):
                    client.recv_text(timeout=1)

    def test_certificate_pin_checked_before_handshake(self):
        with patch.object(slopbro.socket, 'create_connection') as connect:
            with patch.object(ssl.SSLContext, 'wrap_socket', autospec=True) as wrap:
                wrap.return_value.getpeercert.return_value = b'actual cert'
                with patch.object(slopbro.WebSocket, '_handshake') as handshake:
                    with self.assertRaisesRegex(slopbro.WebSocketError, 'fingerprint mismatch'):
                        slopbro.WebSocket.connect('tv', 3001, fingerprint='0' * 64)
                    handshake.assert_not_called()
                    good = hashlib.sha256(b'actual cert').hexdigest()
                    client = slopbro.WebSocket.connect('tv', 3001, fingerprint=good)
                    handshake.assert_called_once()
                    context = wrap.call_args.args[0]
                    self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
                    client.close()

    def test_no_pin_or_plaintext_refused_before_connection(self):
        with patch.object(slopbro.socket, 'create_connection') as connect:
            for kwargs in ({}, {'secure': False, 'fingerprint': '0' * 64}):
                with self.assertRaises(slopbro.WebSocketError):
                    slopbro.WebSocket.connect('tv', 3000, **kwargs)
            connect.assert_not_called()

    def test_launch_payload_failure_is_rejected(self):
        for response in ({'type': 'error'}, {'type': 'response', 'payload': {'returnValue': False}},
                         {'type': 'response', 'payload': {}}):
            with self.subTest(response=response), self.assertRaises(slopbro.SSAPError):
                slopbro.launch_app(Mock(request=Mock(return_value=response)), 'app', {})


class CLITests(unittest.TestCase):
    def test_unsafe_or_incomplete_cli_is_rejected_without_side_effects(self):
        invalid = [[], ['tv'], ['--curl-insecure', 'tv'], ['--telnet', 'tv'],
                   ['--tv-cert-sha256', 'bad'], ['--fake-service-path', '/a/../b'],
                   ['--fake-service-path', '/a;id'], ['--payload-host', 'https://example'],
                   ['--operation-timeout', 'nan'], ['--operation-timeout', '0']]
        with patch.object(slopbro, 'run') as run, patch.object(slopbro, 'run_test_payload') as payload:
            for args in invalid:
                with self.subTest(args=args), patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit) as caught:
                    slopbro.main(args)
                self.assertEqual(caught.exception.code, 2)
            run.assert_not_called()
            payload.assert_not_called()

    def test_simple_diagnostic_needs_no_credentials(self):
        with patch.object(slopbro, 'run_test_connection') as run:
            self.assertEqual(slopbro.main(['--test-server', 'simple']), 0)
            run.assert_called_once()

    def test_failure_returns_nonzero(self):
        args = ['tv', '--tls-cert', 'cert', '--tls-key', 'key', '--payload-host', 'example.test',
                '--tv-cert-sha256', 'a' * 64, '--webos-version', '9']
        with patch.object(slopbro, 'run', side_effect=RuntimeError('installer failed')), patch('sys.stderr', new=io.StringIO()):
            self.assertEqual(slopbro.main(args), 1)


if __name__ == '__main__':
    unittest.main()
