#!/usr/bin/env python3
"""
Basic tests for NovaShield JARVIS Edition APIs
"""
import json
import unittest
import requests
import subprocess
import time
import os
import signal
from threading import Thread

class NovaShieldAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Start the server for testing"""
        cls.server_process = subprocess.Popen(
            ['python3', 'server.py'],
            cwd='www',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(2)  # Wait for server to start
        cls.base_url = 'http://127.0.0.1:8765'
        cls.session = requests.Session()
        
        # Login to get session
        login_data = {'user': 'admin', 'pass': 'admin123'}
        response = cls.session.post(f'{cls.base_url}/api/login', json=login_data)
        if response.status_code == 200:
            cls.csrf = response.json().get('csrf', '')
        else:
            cls.csrf = ''

    @classmethod
    def tearDownClass(cls):
        """Stop the server"""
        if cls.server_process:
            cls.server_process.terminate()
            cls.server_process.wait()

    def test_server_running(self):
        """Test that server is responding"""
        response = requests.get(f'{self.base_url}/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('NovaShield', response.text)

    def test_login_success(self):
        """Test successful login"""
        login_data = {'user': 'admin', 'pass': 'admin123'}
        response = requests.post(f'{self.base_url}/api/login', json=login_data)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get('ok'))

    def test_login_failure(self):
        """Test failed login"""
        login_data = {'user': 'admin', 'pass': 'wrongpass'}
        response = requests.post(f'{self.base_url}/api/login', json=login_data)
        self.assertEqual(response.status_code, 401)

    def test_status_api(self):
        """Test status API"""
        headers = {'X-CSRF': self.csrf}
        response = self.session.get(f'{self.base_url}/api/status', headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('ts', data)
        self.assertIn('cpu', data)
        self.assertIn('memory', data)
        self.assertIn('disk', data)
        self.assertIn('network', data)

    def test_config_api(self):
        """Test config API"""
        headers = {'X-CSRF': self.csrf}
        response = self.session.get(f'{self.base_url}/api/config', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('security', response.text)

    def test_chat_api(self):
        """Test Jarvis chat API"""
        headers = {'X-CSRF': self.csrf, 'Content-Type': 'application/json'}
        chat_data = {'prompt': 'status'}
        response = self.session.post(f'{self.base_url}/api/chat', json=chat_data, headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get('ok'))
        self.assertIn('reply', data)

    def test_file_operations(self):
        """Test file manager APIs"""
        headers = {'X-CSRF': self.csrf, 'Content-Type': 'application/json'}
        
        # List files
        response = self.session.get(f'{self.base_url}/api/fs?dir=/tmp', headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('dir', data)
        self.assertIn('entries', data)

    def test_user_management(self):
        """Test admin user management APIs"""
        headers = {'X-CSRF': self.csrf, 'Content-Type': 'application/json'}
        
        # List users
        response = self.session.get(f'{self.base_url}/api/admin/users', headers=headers)
        self.assertEqual(response.status_code, 200)
        users = response.json()
        self.assertIsInstance(users, list)
        
        # Test add user
        user_data = {'username': 'testuser', 'password': 'testpass123'}
        response = self.session.post(f'{self.base_url}/api/admin/add_user', json=user_data, headers=headers)
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_access(self):
        """Test that unauthorized requests are blocked"""
        response = requests.get(f'{self.base_url}/api/status')
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()