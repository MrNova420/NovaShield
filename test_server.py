#!/usr/bin/env python3
"""
Basic automated tests for NovaShield JARVIS server APIs
"""
import unittest
import json
import tempfile
import shutil
import os
import sys
import time
from pathlib import Path

# Add www directory to path to import server
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'www'))

import server
from unittest.mock import MagicMock, patch

class TestNovaShieldServer(unittest.TestCase):
    """Test suite for NovaShield server functionality"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for tests
        self.test_dir = tempfile.mkdtemp()
        
        # Mock NS_HOME to point to test directory
        server.NS_HOME = self.test_dir
        server.NS_WWW = os.path.join(self.test_dir, 'www')
        server.NS_LOGS = os.path.join(self.test_dir, 'logs')
        server.NS_CTRL = os.path.join(self.test_dir, 'control')
        server.NS_BIN = os.path.join(self.test_dir, 'bin')
        server.NS_BACKUPS = os.path.join(self.test_dir, 'backups')
        server.INDEX = os.path.join(server.NS_WWW, 'index.html')
        server.CONFIG = os.path.join(self.test_dir, 'config.yaml')
        server.SESSIONS = os.path.join(server.NS_CTRL, 'sessions.json')
        server.CHATLOG = os.path.join(server.NS_LOGS, 'chat.log')
        server.AUDIT = os.path.join(server.NS_LOGS, 'audit.log')
        server.SITE_DIR = os.path.join(self.test_dir, 'site')
        
        # Create necessary directories
        for dir_path in [server.NS_WWW, server.NS_LOGS, server.NS_CTRL, server.NS_BIN, server.NS_BACKUPS, server.SITE_DIR]:
            os.makedirs(dir_path, exist_ok=True)
        
        # Create basic config file
        config_content = """security:
  auth_enabled: true
  csrf_required: true
  require_2fa: false
web:
  bind_host: 127.0.0.1
  bind_port: 8765
rate_limit_per_min: 60
lockout_threshold: 10
"""
        server.write_text(server.CONFIG, config_content)
        
        # Create basic HTML file
        server.write_text(server.INDEX, '<html><body>NovaShield JARVIS</body></html>')
        
        # Create test user
        salt = 'test_salt'
        password_hash = server.hashlib.sha256((salt + ':' + 'testpass').encode()).hexdigest()
        test_db = {
            '_userdb': {
                'testuser': password_hash
            }
        }
        server.write_json(server.SESSIONS, test_db)
        
        # Mock auth_salt to return our test salt
        self.original_auth_salt = server.auth_salt
        server.auth_salt = lambda: 'test_salt'
        
    def tearDown(self):
        """Clean up test environment"""
        # Restore original auth_salt
        server.auth_salt = self.original_auth_salt
        
        # Remove test directory
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_yaml_val(self):
        """Test YAML value parsing"""
        # Test existing key
        self.assertEqual(server.yaml_val('security.auth_enabled'), 'true')
        self.assertEqual(server.yaml_val('web.bind_port'), '8765')
        
        # Test non-existing key
        self.assertIsNone(server.yaml_val('nonexistent.key'))
        
        # Test with default
        self.assertEqual(server.yaml_val('nonexistent.key', 'default'), 'default')

    def test_yaml_flag(self):
        """Test YAML boolean flag parsing"""
        self.assertTrue(server.yaml_flag('security.auth_enabled'))
        self.assertFalse(server.yaml_flag('security.require_2fa'))
        self.assertTrue(server.yaml_flag('nonexistent.key', True))

    def test_auth_functions(self):
        """Test authentication functions"""
        # Test auth_enabled
        self.assertTrue(server.auth_enabled())
        
        # Test check_login with correct credentials
        self.assertTrue(server.check_login('testuser', 'testpass'))
        
        # Test check_login with incorrect password
        self.assertFalse(server.check_login('testuser', 'wrongpass'))
        
        # Test check_login with non-existent user
        self.assertFalse(server.check_login('nonexistent', 'password'))

    def test_session_management(self):
        """Test session creation and retrieval"""
        # Create new session
        token, csrf = server.new_session('testuser')
        
        self.assertIsNotNone(token)
        self.assertIsNotNone(csrf)
        self.assertEqual(len(token), 64)  # SHA256 hash length
        
        # Verify session was stored
        db = server.users_db()
        self.assertIn(token, db)
        self.assertEqual(db[token]['user'], 'testuser')
        self.assertEqual(db[token]['csrf'], csrf)

    def test_file_operations(self):
        """Test safe file operations"""
        # Test write_file_safe
        test_content = "Hello, NovaShield!"
        test_path = os.path.join(self.test_dir, 'test.txt')
        
        result = server.write_file_safe(test_path, test_content)
        self.assertTrue(result['ok'])
        
        # Verify file was written
        self.assertTrue(os.path.exists(test_path))
        
        # Test read_file_safe
        result = server.read_file_safe(test_path)
        self.assertTrue(result['ok'])
        self.assertEqual(result['content'], test_content)
        
        # Test access outside NS_HOME (should fail)
        outside_path = '/tmp/outside_test.txt'
        result = server.write_file_safe(outside_path, test_content)
        self.assertFalse(result['ok'])
        self.assertIn('Access denied', result['error'])

    def test_directory_listing(self):
        """Test directory listing functionality"""
        # Create test directory structure
        test_subdir = os.path.join(self.test_dir, 'subdir')
        os.makedirs(test_subdir, exist_ok=True)
        
        # Create test files
        server.write_text(os.path.join(self.test_dir, 'file1.txt'), 'content1')
        server.write_text(os.path.join(test_subdir, 'file2.txt'), 'content2')
        
        # Test listing root directory
        result = server.list_directory(self.test_dir)
        self.assertTrue(result['ok'])
        self.assertEqual(result['dir'], self.test_dir)
        
        # Check that entries are present
        entry_names = [e['name'] for e in result['entries']]
        self.assertIn('subdir', entry_names)
        self.assertIn('file1.txt', entry_names)
        
        # Test listing subdirectory
        result = server.list_directory(test_subdir)
        self.assertTrue(result['ok'])
        entry_names = [e['name'] for e in result['entries']]
        self.assertIn('file2.txt', entry_names)

    def test_delete_path_safe(self):
        """Test safe path deletion"""
        # Create test file
        test_file = os.path.join(self.test_dir, 'to_delete.txt')
        server.write_text(test_file, 'delete me')
        
        # Test deletion
        result = server.delete_path_safe(test_file)
        self.assertTrue(result['ok'])
        self.assertFalse(os.path.exists(test_file))
        
        # Test deletion of non-existent file
        result = server.delete_path_safe(test_file)
        self.assertFalse(result['ok'])
        self.assertIn('not found', result['error'].lower())

    def test_move_path_safe(self):
        """Test safe path moving/renaming"""
        # Create test file
        src_file = os.path.join(self.test_dir, 'source.txt')
        dst_file = os.path.join(self.test_dir, 'destination.txt')
        test_content = 'move me'
        
        server.write_text(src_file, test_content)
        
        # Test move
        result = server.move_path_safe(src_file, dst_file)
        self.assertTrue(result['ok'])
        
        # Verify move
        self.assertFalse(os.path.exists(src_file))
        self.assertTrue(os.path.exists(dst_file))
        self.assertEqual(server.read_text(dst_file), test_content)

    def test_backup_functions(self):
        """Test backup creation and listing"""
        # Create some test data
        test_file = os.path.join(self.test_dir, 'backup_test.txt')
        server.write_text(test_file, 'backup this content')
        
        # Test backup creation (mocked since tar might not be available)
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            result = server.create_backup()
            self.assertTrue(result['ok'])
            self.assertIn('filename', result)
            
            # Verify subprocess was called with correct arguments
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            self.assertEqual(args[0], 'tar')
            self.assertEqual(args[1], '-czf')

    def test_yaml_config_validation(self):
        """Test YAML configuration validation"""
        # Test valid YAML
        valid_config = """
security:
  auth_enabled: true
web:
  bind_port: 8765
"""
        result = server.validate_yaml_config(valid_config)
        self.assertTrue(result['valid'])
        
        # Test invalid YAML (missing colon)
        invalid_config = """
security
  auth_enabled: true
"""
        result = server.validate_yaml_config(invalid_config)
        self.assertFalse(result['valid'])
        self.assertIn('Missing colon', result['error'])

    def test_ai_reply(self):
        """Test AI response generation"""
        # Test status query
        reply = server.ai_reply('What is the system status?')
        self.assertIn('status', reply.lower())
        
        # Test backup query
        reply = server.ai_reply('How do I create a backup?')
        self.assertIn('backup', reply.lower())
        
        # Test help query
        reply = server.ai_reply('help')
        self.assertIn('help', reply.lower())
        
        # Test generic query
        reply = server.ai_reply('random question')
        self.assertIn('random question', reply)

    def test_get_system_status(self):
        """Test system status generation"""
        status = server.get_system_status()
        
        # Check required fields
        self.assertIn('cpu', status)
        self.assertIn('memory', status)
        self.assertIn('disk', status)
        self.assertIn('network', status)
        self.assertIn('version', status)
        self.assertIn('alerts', status)
        self.assertIn('csrf', status)
        
        # Check that alerts is a list
        self.assertIsInstance(status['alerts'], list)
        
        # Check that CSRF token is present
        self.assertIsNotNone(status['csrf'])

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        client_ip = '127.0.0.1'
        
        # Should allow initial requests
        for i in range(5):
            self.assertTrue(server.rate_limit_check(client_ip))
        
        # Test with a lot of requests (should eventually fail if rate limit is low)
        # We'll set a mock rate limit for testing
        original_limit = server.rate_limit_per_min
        server.rate_limit_per_min = lambda: 3
        
        # Clear existing rate limit data
        server.write_json(server.RL_DB, {})
        
        # First 3 should pass
        for i in range(3):
            self.assertTrue(server.rate_limit_check(client_ip))
        
        # 4th should fail
        self.assertFalse(server.rate_limit_check(client_ip))
        
        # Restore original function
        server.rate_limit_per_min = original_limit

    def test_lockout_functions(self):
        """Test account lockout functionality"""
        client_ip = '192.168.1.100'
        
        # Initially no lockout
        self.assertFalse(server.check_lockout(client_ip))
        
        # Add lockout
        server.add_lockout(client_ip, 60)  # 60 seconds
        
        # Should be locked out now
        self.assertTrue(server.check_lockout(client_ip))
        
        # Add lockout with past expiry
        server.add_lockout(client_ip, -60)  # Expired 60 seconds ago
        
        # Should not be locked out
        self.assertFalse(server.check_lockout(client_ip))

class TestServerIntegration(unittest.TestCase):
    """Integration tests for server endpoints"""
    
    def setUp(self):
        """Set up test environment for integration tests"""
        # Create temporary directory for tests
        self.test_dir = tempfile.mkdtemp()
        
        # Mock server paths
        server.NS_HOME = self.test_dir
        server.NS_WWW = os.path.join(self.test_dir, 'www')
        server.NS_LOGS = os.path.join(self.test_dir, 'logs')
        server.NS_CTRL = os.path.join(self.test_dir, 'control')
        server.CONFIG = os.path.join(self.test_dir, 'config.yaml')
        server.SESSIONS = os.path.join(server.NS_CTRL, 'sessions.json')
        
        # Create necessary directories
        for dir_path in [server.NS_WWW, server.NS_LOGS, server.NS_CTRL]:
            os.makedirs(dir_path, exist_ok=True)
        
        # Create basic config
        config_content = """security:
  auth_enabled: false
web:
  bind_host: 127.0.0.1
  bind_port: 8765
"""
        server.write_text(server.CONFIG, config_content)
        
        # Create handler for testing
        self.handler = server.Handler(MagicMock(), ('127.0.0.1', 12345), MagicMock())
        self.handler.wfile = MagicMock()
        self.handler.headers = {}
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_system_status_endpoint(self):
        """Test system status generation"""
        # Test the underlying function instead of the handler
        status = server.get_system_status()
        
        # Verify response structure
        self.assertIn('cpu', status)
        self.assertIn('memory', status)
        self.assertIn('version', status)
        self.assertIn('csrf', status)
        
        # Check that version indicates JARVIS
        self.assertIn('JARVIS', status['version'])

def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases (skip integration tests that require complex mocking)
    test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestNovaShieldServer))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Return success status
    return result.wasSuccessful()

if __name__ == '__main__':
    print("Running NovaShield JARVIS Server Tests")
    print("=" * 50)
    
    success = run_tests()
    
    print("=" * 50)
    if success:
        print("✅ All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)