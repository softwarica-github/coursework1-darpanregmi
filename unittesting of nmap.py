import unittest
from unittest.mock import patch, Mock
import tkinter as tk
from web_and_ip_enumeration_toolkit import CustomMessagebox, web_enum, NmapWindow 

def dummy_mainloop():
    pass

class TestNmapToolkit(unittest.TestCase):

    def setUp(self):
        self.root = tk.Tk()

    def tearDown(self):
        self.root.destroy()

    def test_CustomMessagebox_creation(self):
        with patch("tkinter.Toplevel") as mock_toplevel:
            mock_instance = Mock()
            mock_instance.title = Mock()
            mock_instance.configure = Mock()
            mock_instance.destroy = Mock()
            mock_toplevel.return_value = mock_instance

            box = CustomMessagebox("TestTitle", "TestMessage", "red")
            self.assertEqual(box.message, "TestMessage")
            self.assertEqual(box.color, "red")

    def test_web_enum_setup(self):
        enum_instance = web_enum(self.root)
        self.assertEqual(enum_instance.master, self.root)

    def test_NmapWindow_scan_without_target_or_command(self):
        with patch("tkinter.messagebox.showerror") as mock_showerror:
            app = NmapWindow(self.root)
            app.target_entry.delete(0, tk.END)
            app.run_scan()
            self.assertTrue(mock_showerror.called)
    
    def test_NmapWindow_scan_with_valid_target(self):
        app = NmapWindow(self.root)
        app.target_entry.insert(0, "192.168.56.1")
        app.run_scan()
        scan_output_content = app.scan_output.get("1.0", tk.END) 
        self.assertNotEqual(scan_output_content.strip(), "") 
        
    def test_NmapWindow_scan_with_invalid_hostname(self):
        with patch("tkinter.messagebox.showerror") as mock_showerror:
            app = NmapWindow(self.root)
            app.target_entry.insert(0, "invalid_!hostname")
            app.run_scan()
            self.assertTrue(mock_showerror.called)
        
    def test_NmapWindow_scan_with_invalid_command(self):
        with patch("tkinter.messagebox.showerror") as mock_showerror:
            app = NmapWindow(self.root)
            app.command_entry.insert(0, "-invalidCommand")
            app.run_scan()
            self.assertTrue(mock_showerror.called)
    
    def test_NmapWindow_scan_with_disallowed_command(self):
        with patch("tkinter.messagebox.showerror") as mock_showerror:
            app = NmapWindow(self.root)
            app.command_entry.insert(0, "rm")
            app.run_scan()
            self.assertTrue(mock_showerror.called)

if __name__ == "__main__":
    unittest.main()