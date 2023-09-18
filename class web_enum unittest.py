import unittest
import requests
import tkinter as tk
from unittest.mock import patch, MagicMock
from web_and_ip_enumeration_toolkit import web_enum

class TestWebEnum(unittest.TestCase):

    def setUp(self):
        self.root = MagicMock()
        self.app = web_enum(self.root)
    
    def tearDown(self):
        self.root.destroy()

    def test_web_enum_init(self):
        app = web_enum(self.root)
        self.assertIsNotNone(app)

    @patch("requests.get")
    def test_fetch_info_valid_url(self, mock_get):
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.content = "<html><title>Test Title</title></html>".encode('utf-8')
        
        app = web_enum(self.root)
        response, soup, title = app.fetch_info("http://example.com")
        
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(soup)
        self.assertEqual(title, "Test Title")

    @patch("requests.get")
    def test_fetch_info_invalid_url(self, mock_get):
        mock_get.side_effect = requests.ConnectionError()
        
        app = web_enum(self.root)
        response, soup, title = app.fetch_info("http://invalid-url.com")
        
        self.assertIsNone(response)
        self.assertIsNone(soup)
        self.assertIsNone(title)

    @patch("socket.socket")
    def test_scan_ports(self, mock_socket):
        mock_socket_instance = mock_socket.return_value
        mock_socket_instance.connect_ex.return_value = 0

        app = web_enum(self.root)
        open_ports = app.scan_ports("test-domain.com")

        self.assertTrue(80 in open_ports)
    
    @patch('builtwith.builtwith')
    def test_fetch_technologies(self, mock_builtwith):
        mock_builtwith.return_value = {'technology': ['sample tech']}
        app = web_enum(self.root)
        result = app.fetch_technologies("http://test.com")
        self.assertEqual(result, {'technology': ['sample tech']})

    @patch('requests.get')
    def test_scrape_emails(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = 'test1@gmail.com test2@gmail.com'
        mock_get.return_value = mock_response
        app = web_enum(self.root)
        result = app.scrape_emails("http://test.com")
        self.assertIn('test1@gmail.com', result)
        self.assertIn('test2@gmail.com', result)

    @patch('requests.get')
    def test_fetch_server_info(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'TestServer'}
        mock_get.return_value = mock_response
        app = web_enum(self.root)
        result = app.fetch_server_info(mock_response)
        self.assertEqual(result, 'TestServer')
    
    @patch("tkinter.messagebox.showerror")
    def test_empty_target_error_message(self, mock_showerror):
        self.app.target_entry.get = MagicMock(return_value="")
        self.app.start_scan()
        mock_showerror.assert_called_once_with("Error", "Please enter a valid URL.")


if __name__ == "__main__":
    unittest.main()

