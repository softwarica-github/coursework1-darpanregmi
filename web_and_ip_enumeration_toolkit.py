import nmap
import subprocess
import sys
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import scrolledtext
from bs4 import BeautifulSoup, Comment
from tkinter import filedialog
from getmac import get_mac_address
from tkinter import messagebox
import logging
import requests
from bs4 import BeautifulSoup, Comment
import threading
import builtwith
import re
import ipaddress
import requests.exceptions
from urllib.parse import urlsplit
from collections import deque
import socket
from tkinter import filedialog

logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class CustomMessagebox:
    def __init__(self, title, message, color):
        self.box = Toplevel()
        self.box.title(title)
        self.message = message
        self.color = color
        self.setup()

    def setup(self):
        self.box.configure(bg=self.color)
        self.text_area = scrolledtext.ScrolledText(self.box, width=40, height=10, bg=self.color)
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, self.message)
        self.text_area.config(state='disabled')
        self.text_area.pack()
        Button(self.box, text="OK", command=self.box.destroy).pack()

  
class web_enum:
    def __init__(self, master):
        self.master = master
        self.setup_gui()
    
    def setup_gui(self):
        self.large_font = ('Verdana', 9)
        
        style = ttk.Style()
        style.configure('TButton', font=self.large_font)

        self.frame = ttk.Frame(self.master, padding="18")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.scrape_emails_var = tk.BooleanVar(value=True)
        self.subdomains_from_list_var = tk.BooleanVar(value=True)
        self.brute_force_dirs_var = tk.BooleanVar(value=True)
        self.fetch_wayback_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(self.frame, text="Scrape Emails", variable=self.scrape_emails_var).grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Checkbutton(self.frame, text="Fetch Subdomains", variable=self.subdomains_from_list_var).grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Checkbutton(self.frame, text="Brute Force Directories                              Choose a wordlist:", variable=self.brute_force_dirs_var).grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Checkbutton(self.frame, text="Fetch Wayback URLs", variable=self.fetch_wayback_var).grid(row=4, column=0, sticky=tk.W, pady=5)

        dir_files = ["./apache-users-namelist.txt", "./directory-list-1.0.txt", "./directory-list-2.3-medium.txt", "./directory-list-2.3-small_edited.txt", "./directory-list-2.3-small_original.txt", "./directory-list-lowercase-2.3-medium.txt", "./directory-list-lowercase-2.3-small.txt"]
        self.dir_combobox = ttk.Combobox(self.frame, values=dir_files)
        self.dir_combobox.bind("<<ComboboxSelected>>", self.load_directory_file)
        self.dir_combobox.grid(row=3, column=1, pady=6, sticky=tk.W)

        ttk.Label(self.frame, text="Target URL:", font=self.large_font).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(self.frame, width=30, font=self.large_font)
        self.target_entry.grid(row=0, column=1, pady=6)

        scan_btn = ttk.Button(self.frame, text="Scan", command=self.start_scan, style='TButton')
        scan_btn.grid(row=4, column=1, columnspan=2, pady=5)

        self.progress_bar = ttk.Progressbar(self.frame, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.grid(row=5, column=0, columnspan=2, pady=9)

        self.output_area = scrolledtext.ScrolledText(self.frame, width=60, height=24, font=self.large_font)
        self.output_area.grid(row=6, column=0, columnspan=2, pady=9)
        self.output_area.config(state=tk.DISABLED)
        
        save_button = ttk.Button(self.frame, text="Save Output", command=self.save_output)
        save_button.grid(row=7, column=0, pady=5, padx=5)

        clear_button = ttk.Button(self.frame, text="Clear Output", command=self.clear_output)
        clear_button.grid(row=7, column=1, pady=5, padx=5)

        exit_button = ttk.Button(self.frame, text="Exit", command=self.exit_app)
        exit_button.grid(row=8, column=0, columnspan=2, pady=5, padx=5)

        
    def save_output(self):
        content = self.output_area.get("1.0", tk.END)
        file_name = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text file", "*.txt")])
        if file_name:
            with open(file_name, 'w') as file:
                file.write(content)
            logging.info("Output saved to %s", file_name)

    def clear_output(self):
        self.output_area.config(state=tk.NORMAL)
        self.output_area.delete("1.0", tk.END)
        self.output_area.config(state=tk.DISABLED)
        logging.info("Output cleared")

    def exit_app(self):
        logging.info("Exiting web_enum class")
        self.master.destroy()

    def update_output_area(self, content):
        self.output_area.config(state=tk.NORMAL)
        self.output_area.insert(tk.END, content)
        self.output_area.config(state=tk.DISABLED)

    def scan_ports(self, domain):
        open_ports = []
        for port in range(1, 81):  # Scanning ports 1 to 1024
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            try:
                result = s.connect_ex((domain, port))  # Returns 0 if port is open
                if result == 0:
                    open_ports.append(port)
            except socket.gaierror:
                logging.error(f"Failed to resolve domain: {domain}")
                self.update_output_area(f"Failed to resolve domain: {domain}\n")
                break
            except Exception as e:
                logging.error(f"Error connecting to {domain} on port {port}: {e}")
            finally:
                s.close()
        logging.info("Scanned ports for domain: %s. Open ports: %s", domain, open_ports)
        return open_ports


    def brute_force_directories(self, target, dir_list):
        found_directories = []
        for dir_name in dir_list:
            directory_url = f"{target}/{dir_name}"
            try:
                response = requests.get(directory_url, timeout=5)
                if response.status_code == 200:
                    found_directories.append(directory_url)
                    self.update_output_area(f"Found directory: {directory_url}\n")  # Update the output area immediately
            except requests.RequestException:
                continue
        logging.info("Directories found for target %s: %s", target, found_directories)
        return found_directories


    def load_directory_file(self, event):
        '''Load the selected directory file into common_directories'''
        global common_directories
        file_path = self.dir_combobox.get()
        try:
            with open(file_path, 'r') as f:
                self.common_directories = [line.strip() for line in f.readlines()]
                logging.info("Loaded directory file: %s", file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")


    def fetch_subdomains_from_list(self, target):
        subdomains_found = []

        # Remove 'https://www.' or 'http://www.' from the domain
        clean_domain = target.replace("https://www.", "").replace("http://www.", "")

        # Ensure that the subdomains file can be opened and read
        try:
            with open("subdomains-10000.txt", "r") as f:
                subdoms = f.read().splitlines()
        except FileNotFoundError:
            logging.error("Subdomains file not found.")
            return []
        except IOError:
            logging.error("Error reading subdomains file.")
            return []

        for sub in subdoms:
            # Combine subdomain with cleaned domain
            sub_domain = f"{sub}.{clean_domain}"

            try:
                # Since we stripped the protocol (https:// or http://), we need to add it back
                protocol = "https://" if "https://" in target else "http://"
                full_url = protocol + sub_domain
                
                requests.get(full_url, timeout=5)  # Added a timeout for efficiency
            except (requests.ConnectionError, requests.Timeout):
                logging.warning(f"Failed to connect to {full_url} due to connection issues or timeout.")
                continue
            except Exception as e:  # Handle other exceptions
                logging.error(f"Error connecting to {full_url}. Error: {e}")
                continue
            else:
                subdomains_found.append(sub_domain)
                self.update_output_area(f"Found subdomain: {sub_domain}\n")  # Update the output area immediately

        return subdomains_found



    def scrape_emails(self, url):
        # Limit to 20 emails
        EMAIL_LIMIT = 20

        # a queue of urls to be crawled
        unprocessed_urls = deque([url])

        # set of already crawled urls for email
        processed_urls = set()

        # a set of fetched emails
        emails = set()

        while len(unprocessed_urls) and len(emails) < EMAIL_LIMIT:
            # move next url from the queue to the processed urls set
            current_url = unprocessed_urls.popleft()
            processed_urls.add(current_url)

            # extract base url to resolve relative links
            parts = urlsplit(current_url)
            base_url = "{0.scheme}://{0.netloc}".format(parts)
            path = current_url[:current_url.rfind('/')+1] if '/' in parts.path else current_url

            # get url's content
            try:
                response = requests.get(current_url, timeout=5)
                new_emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text, re.I))
                emails.update(new_emails)
            except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                continue  # skip the error and continue

            # if the limit has been reached, break
            if len(emails) >= EMAIL_LIMIT:
                break

            # create a BeautifulSoup object for the html document
            soup = BeautifulSoup(response.text, 'html.parser')

            # find and process all the anchors i.e. linked urls in this document
            for anchor in soup.find_all("a"):
                # extract link url from the anchor
                link = anchor.attrs["href"] if "href" in anchor.attrs else ''
                # resolve relative links (starting with /)
                if link.startswith('/'):
                    link = base_url + link
                elif not link.startswith('http'):
                    link = path + link
                # add the new url to the queue if it was not in unprocessed list nor in processed list yet
                if not link in unprocessed_urls and not link in processed_urls:
                    unprocessed_urls.append(link)

        logging.info("Scraped emails for URL %s: %s", url, emails)
        return list(emails)[:EMAIL_LIMIT]  # just to be safe, slice the list to 200


    def fetch_wayback_urls(self, domain):
        try:
            response = requests.get(f'https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey', timeout=10)
            if response.status_code == 200:
                return [entry[2] for entry in response.json()[1:]]  # Return list of URLs
            return []
        except:
            return []

    def fetch_robots_txt(self, url):
        try:
            response = requests.get(url + '/robots.txt', timeout=5)
            if response.status_code == 200:
                return response.text.splitlines()
            else:
                return None
        except:
            return None

    def fetch_server_info(self, response):
        return response.headers.get('Server', 'Unknown')

    def fetch_content_length(self, response):
        return response.headers.get('Content-Length', 'Unknown')

    def fetch_technologies(self, url):
        return builtwith.builtwith(url)

    def fetch_comments(self, soup):
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        return [comment for comment in comments]


    def fetch_info(self, url):
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')
            title = soup.title.string if soup.title else "No title"
            return response, soup, title
        except requests.exceptions.RequestException:
            return None, None, None

    def scan_target(self):
        target = self.target_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a valid URL.")
            return 
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self.progress_bar['value'] = 30
        root.update_idletasks()

        response, soup, title = self.fetch_info(target)

        self.progress_bar['value'] = 60
        root.update_idletasks()

        if response:
            status_code = response.status_code
            self.update_output_area(f'URL: {target}\n')
            self.update_output_area(f'Status Code: {status_code}\n')
            self.update_output_area(f'Title: {title}\n\n')
        else:
            self.update_output_area(f'Failed to reach {target}\n\n')
            return
        
        self.progress_bar['value'] = 100
        
        robots_content = self.fetch_robots_txt(target)
        if robots_content:
            self.update_output_area(f"Robots.txt for {target}:\n")
            for line in robots_content:
                self.update_output_area(f'{line}\n')
            self.update_output_area("\n")
        
        server_info = self.fetch_server_info(response)
        self.update_output_area(f'Server: {server_info}\n')
        
        content_length = self.fetch_content_length(response)
        self.update_output_area(f'Content-Length: {content_length}\n')
        
        technologies = self.fetch_technologies(target)
        self.update_output_area(f'Technologies used:\n')
        for tech, details in technologies.items():
            self.update_output_area(f'{tech}: {", ".join(details)}\n')
            
        comments = self.fetch_comments(soup)
        if comments:
            self.update_output_area("Comments Found:\n")
            for comment in comments:
                self.update_output_area(f'{comment}\n')
                
        ports_open = self.scan_ports(target.split("//")[-1])  # Remove the http:// or https:// prefix
        if ports_open:
            self.update_output_area("Open Ports Found:\n")
            for port in ports_open:
                self.update_output_area(f'{port}\n')
        else:
            self.update_output_area("No Open Ports Found.\n")
        
        if self.subdomains_from_list_var.get():
            subdomains_from_list = self.fetch_subdomains_from_list(target)
            if subdomains_from_list:
                self.update_output_area("\n\n\n\nSubdomains Found from List:\n")
                for sub in subdomains_from_list:
                    self.update_output_area(f'{sub}\n')
            
        if self.scrape_emails_var.get():
            emails = self.scrape_emails(target)
            if emails:
                self.update_output_area("Emails Found:\n")
                for email in emails:
                    self.update_output_area(f'{email}\n')
            
        if self.fetch_wayback_var.get():
            wayback_urls = self.fetch_wayback_urls(target)
            if wayback_urls:
                self.update_output_area("Wayback Machine URLs:\n")
                for url in wayback_urls:
                    self.update_output_area(f'{url}\n')
            
        if self.brute_force_dirs_var.get():
            directories = self.brute_force_directories(target, self.common_directories)
            if directories:
                self.update_output_area("Directories Found:\n")
                for directory in directories:
                    self.update_output_area(f'{directory}\n')
            else:
                self.update_output_area("No Directories were found.\n")

    def start_scan(self):
        self.progress_bar['value'] = 0
        thread = threading.Thread(target=self.scan_target)
        logging.info("Started scan for web_enum class")
        thread.start()
        
class NmapWindow:
    def __init__(self, master):
        self.master = master
        logging.info("Initializing NmapWindow class")
        self.master.title('IP and Web Enumeration Toolkit')
        self.master.configure(bg="grey10")
        
        self.main_menu = Menu(self.master)
        self.master.config(menu=self.main_menu)

        self.more_menu = Menu(self.main_menu, tearoff=0)
        self.main_menu.add_cascade(label="More...", menu=self.more_menu)
        self.more_menu.add_command(label="Web Enumeration Tool", command=self.launch_web_enum)
        self.more_menu.add_command(label="Available Targets", command=self.display_network_info)
        self.more_menu.add_command(label="Exit", command=self.exit_application)
        
        self.help_menu = Menu(self.main_menu, tearoff=0)
        self.main_menu.add_cascade(label="Help", menu=self.help_menu)
        
        # Add commands to the 'Help' menu
        self.help_menu.add_command(label="How to type targets", command=self.help_targets)
        self.help_menu.add_command(label="How to type manual commands", command=self.help_manual_commands)

        self.setup_gui()
    
    def help_targets(self):
        messagebox.showinfo("How to Type Targets", "Enter the target IP addresses or hostnames. If you have multiple targets, separate them with a comma.")

    def help_manual_commands(self):
        messagebox.showinfo("Manual Commands", "Enter the desired Nmap commands manually. Ensure they are correct and safe to avoid unexpected behaviors. Ex: nmap <scan arguments like -sT, etc>")
    
    def display_network_info(self):
        try:
            # Check the system's OS to decide which command to run
            if sys.platform == "win32":
                command = "ipconfig"
            else:  # For Linux and macOS
                command = "ifconfig"
            
            # Execute the command and get its output
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, error = process.communicate()
            
            # Display the output in a messagebox
            messagebox.showinfo("Available Targets", output.decode('utf-8'))

        except Exception as e:
            logging.error(f"Error while fetching network info: {e}")
            messagebox.showerror("Error", "Unable to fetch network information.")

    
    def setup_gui(self):
        
        logging.info("Setting up GUI for NmapWindow")
        Label(self.master, text='Enter Target (if multiple\nseparate with a comma)', bg='grey36', fg='white').grid(row=0, column=0, padx=10, pady=10)
        self.target_entry = Entry(self.master, width=40)
        self.target_entry.grid(row=0, column=1, padx=10, pady=10)

        
        Label(self.master, text='Manual Command:', bg='grey36', fg='white').grid(row=1, column=0, padx=10, pady=10)
        self.command_entry = Entry(self.master, width=50)
        self.command_entry.grid(row=1, column=1, padx=10, pady=10)

        
        self.scan_types = ['---Scan Techniques---','TCP Connect Scan', 'SYN Scan', 'UDP Scan', 'Ping Scan', 'FIN Scan', 
                    'Fast Scan', 'Idle Scan','---Scan Commands---','IP Protocol Scan', 'NULL Scan', 'XMAS Scan', 'FTP Bounce Attack Scan',
                    'Version Detection', 'OS Detection Scan', 'Hostlists', 'Subnet Scan', 'Firewall rule detection: ACK scan', 'Dns-brute-script', '---Scan Discovery---',
                    'No ping scan','Liveness detection: no port scan','ARP scan: local network only','Disable DNS resolution: reduces noise',
                    'Aggressive OS detection','Advanced detection: OS detection and Version detection, Script scanning and Traceroute',
                    'Advanced detection: with stealth scan mode', 'Advanced detection: verbose', 'Advanced detection: scan with no DNS resolution',
                    'Advanced detection: combined with packet fragmentation', 'Aggressive service detection', 'Aggressive service detection: with version-intensity 3',
                    'Number version detection', 'OS detection with port selection', '--- Zenmap Profiles ---', 'Intense scan', 'Intense scan plus UDP', 
                    'Intense scan, all TCP ports', 'Intense scan, no ping', 'Quick scan', 'Quick scan plus', 'Quick traceroute', 'Regular scan', 'Slow comprehensive scan',
                    '---Miscellaneous---', 'IPV6 scan', 'sCV scan','SMB Discovery', 'Banner Grabbing', 'Vuln Scan', 'Default Script Scan', 'Safe Script Scan', 
                    'All Script Scan']

        self.scan_type_var = tk.StringVar()
        Label(self.master, text='Select Profiled Scans\n(optional)', bg='grey36', fg='white').grid(row=2, column=0, padx=10, pady=10)
        self.scan_type_var = tk.StringVar()
        self.combobox = ttk.Combobox(self.master, textvariable=self.scan_type_var, values=self.scan_types, width=60)
        self.combobox.grid(row=2, column=1, padx=10, pady=10)

        # Scan Button
        self.scan_button = Button(self.master, text='Scan', command=self.run_scan)
        self.scan_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)
        self.scan_button.bind("<Enter>", self.on_enter)  # Assuming on_enter() is defined
        self.scan_button.bind("<Leave>", self.on_leave)  # Assuming on_leave() is defined

        # Command Preview
        Label(self.master, text='Command Preview:', bg='grey36', fg='white').grid(row=4, column=0, padx=10, pady=10)
        self.command_preview = tk.Text(self.master, height=1, width=50, bg='white', fg='black')
        self.command_preview.grid(row=4, column=1, columnspan=2, padx=10, pady=10)

        # Label and ScrolledText for Scan Output
        Label(self.master, text='Scan Output:', bg='grey36', fg='white').grid(row=5, column=0, padx=10, pady=10)
        self.scan_output = scrolledtext.ScrolledText(self.master, bg='snow2', fg='green')
        self.scan_output.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

        # Clear and Save Output Buttons
        self.clear_button = Button(self.master, text='Clear Output', command=self.clear_output)
        self.clear_button.grid(row=7, column=0, columnspan=1, padx=10, pady=10)
        self.clear_button.bind("<Enter>", self.on_enter)  # Assuming on_enter() is defined
        self.clear_button.bind("<Leave>", self.on_leave)  # Assuming on_leave() is defined

        self.save_button = Button(self.master, text='Save Output', command=self.save_output)  # Assuming save_output() is defined
        self.save_button.grid(row=7, column=1, columnspan=2, padx=10, pady=10)
        self.save_button.bind("<Enter>", self.on_enter)  # Assuming on_enter() is defined
        self.save_button.bind("<Leave>", self.on_leave)  # Assuming on_leave() is defined
    
    def launch_web_enum(self):
        logging.info("Launching web enumeration tool from NmapWindow")
        new_window = tk.Toplevel(self.master)  # Create a new window
        app = web_enum(new_window)
    
    @staticmethod
    def is_valid_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    @staticmethod
    def is_valid_hostname(hostname):
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]  # strip the trailing dot
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))
    
    def exit_application(self):
        logging.info("Exiting NmapWindow class")
        self.master.destroy()

    def on_enter(self, e):
        logging.debug("Mouse entered a button in NmapWindow GUI")
        e.widget['background'] = 'snow4'

    def on_leave(self, e):
        logging.debug("Mouse left a button in NmapWindow GUI")
        e.widget['background'] = 'azure2'
    
    def clear_output(self):
        # Clear the scan output
        self.scan_output.config(state='normal')
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.config(state='disabled')
        logging.info("Cleared the scan output")
    
    def save_output(self):
        output = self.scan_output.get("1.0", tk.END)  # get text from the widget
        file_name = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text file", "*.txt")])
        if file_name:  # if the user didn't cancel the dialog
            with open(file_name, 'w') as f:  # open file in write mode
                f.write(output)  # write output to file
                logging.info("Saved the scan output to %s", file_name)
    
    def run_scan(self):
        targets = self.target_entry.get().split(",")
        logging.info("Scan started for targets: %s", self.target_entry.get())

        if not self.target_entry.get():
           print("No target provided!")  # Debugging print
           messagebox.showerror("Error", "No target provided!")
           logging.warning("No target provided for scanning!")
           return

        for target in targets:  # iterating over each host
            target = target.strip()
            logging.info("Checking validity of target: %s", target)
            if not (self.is_valid_ip(target) or self.is_valid_hostname(target)):
                messagebox.showerror("Error", f"Invalid target: {target}")
                logging.error("Invalid target provided: %s", target)
                continue
            # remove leading/trailing whitespaces
            manual_command = self.command_entry.get().strip()
            disallowed_commands = ['rm', 'shutdown', 'reboot']
            if any(bad_cmd in manual_command for bad_cmd in disallowed_commands):
                logging.error("Detected potentially harmful manual command: %s", manual_command)
                messagebox.showerror("Error", "Invalid or potentially harmful command detected.")
                return
            if not manual_command:
                scan_type = self.scan_type_var.get()
                logging.info("Setting scan arguments based on selected scan type: %s", scan_type)
                scan_arguments = ''
                
                if scan_type == 'TCP Connect Scan':
                    scan_arguments += '-sT'
                elif scan_type == 'SYN Scan':
                    scan_arguments += '-sS'
                elif scan_type == 'UDP Scan':
                    scan_arguments += '-sU'
                elif scan_type == 'Ping Scan':
                    scan_arguments += '-sn'
                elif scan_type == 'NULL Scan':
                    scan_arguments += '-sN'
                elif scan_type == 'FIN Scan':
                    scan_arguments += '-sF'
                elif scan_type == 'XMAS Scan':
                    scan_arguments += '-sX'
                elif scan_type == 'Fast Scan':
                    scan_arguments += '-F'
                elif scan_type == 'Version Detection':
                    scan_arguments += '-sV'
                elif scan_type == 'IP Protocol Scan':
                    scan_arguments += '-sO'
                elif scan_type == 'Idle Scan':
                    scan_arguments += '-sI'
                elif scan_type == 'FTP Bounce Attack Scan':
                    scan_arguments += '-b'
                elif scan_type == 'OS Detection Scan':
                    scan_arguments += '-O'
                elif scan_type == 'No Ping Scan':
                    scan_arguments += '-Pn'
                elif scan_type == 'Liveness detection: no port scan':
                    scan_arguments += '-sn'
                elif scan_type == 'ARP scan: local network only':
                    scan_arguments += '-PR'
                elif scan_type == 'Disable DNS resolution: reduces noise':
                    scan_arguments += '-n'
                elif scan_type == 'Aggressive OS Detection':
                    scan_arguments += '-Pn -O --osscan-guess'
                elif scan_type == 'Advanced detection: OS detection and Version detection, Script scanning and Traceroute':
                    scan_arguments += '-Pn -A'
                elif scan_type == 'Advanced detection: with stealth scan mode':
                    scan_arguments += '-Pn -A -T2'
                elif scan_type == 'Advanced detection: verbose':
                    scan_arguments += '-Pn -A -v'
                elif scan_type == 'Advanced detection: scan with no DNS resolution':
                    scan_arguments +=  '-Pn -n -A'
                elif scan_type == 'Advanced detection: combined with packet fragmentation':
                    scan_arguments += '-Pn -f -A'
                elif scan_type == 'Aggressive service detection':
                    scan_arguments += '-Pn -T4 -sV'
                elif scan_type == 'Aggressive service detection: with version-intensity 3':
                    scan_arguments += '-Pn -T4 -sV --version-intensity 3'
                elif scan_type == 'Number version detection':
                    scan_arguments += '-Pn -n -V'
                elif scan_type == 'OS detection with port selection':
                    scan_arguments += '-Pn -O --osscan-guess -p'
                elif scan_type == 'Firewall rule detection: ACK scan':
                    scan_arguments += '-sA'
                elif scan_type == 'SCTP: Advanced silent scan for top20 ports':
                    scan_arguments += '20 -sZ'
                elif scan_type == 'Top ports scan (1000 ports)':
                    scan_arguments += '--top-ports'
                elif scan_type == 'Dns-brute-script':
                    scan_arguments += '-script dns-brute'
                elif scan_type == 'Hostlists':
                    scan_arguments += '-sL'
                elif scan_type == 'Subnet scan':
                    scan_arguments += '-p-'
                elif scan_type == 'IPV6 scan':
                    scan_arguments += '-6'
                elif scan_type == 'sCV scan':
                    scan_arguments += '-sCV'
                elif scan_type == "Intense scan":
                    scan_arguments = '-T4 -A -v'
                elif scan_type == "Intense scan plus UDP":
                    scan_arguments = '-T4 -A -v -sU'
                elif scan_type == "Intense scan, all TCP ports":
                    scan_arguments = '-T4 -A -v -p 1-65535'
                elif scan_type == "Intense scan, no ping":
                    scan_arguments = '-T4 -A -v -Pn'
                elif scan_type == "Quick scan":
                    scan_arguments = '-T4 -F'
                elif scan_type == "Quick scan plus":
                    scan_arguments = '-T4 -A -v -F'
                elif scan_type == "Quick traceroute":
                    scan_arguments = '-sn --traceroute'
                elif scan_type == "Regular scan":
                    scan_arguments = ''
                elif scan_type == "Slow comprehensive scan":
                    scan_arguments = '-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 -script "default or (discovery and safe)"'
                elif scan_type == 'SMB Discovery':
                    scan_arguments += '-p 445 --script smb-os-discovery'
                elif scan_type == 'Banner Grabbing':
                    scan_arguments += '-sV --version-intensity 5'
                elif scan_type == 'Vuln Scan':
                    scan_arguments += '--script vuln'
                elif scan_type == 'Default Script Scan':
                    scan_arguments += '-sC'
                elif scan_type == 'Safe Script Scan':
                    scan_arguments += '--script "safe"'
                elif scan_type == 'All Script Scan':
                    scan_arguments += '--script "all"'
                
                command = f"nmap {scan_arguments} {target}"
            else:
                command = f"{manual_command} {target}"
            
            logging.debug("Generated scan command: %s", command)
            
            self.command_preview.delete(1.0, tk.END)
            self.command_preview.insert(tk.END, command)
            logging.info("Executing scan command for target: %s", target)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, error = process.communicate()
            
            logging.debug("Scan output for target %s: %s", target, output.decode('utf-8'))
            

            self.scan_output.config(state='normal')
            self.scan_output.insert(tk.END, '----------------------------------------------------\n')
            self.scan_output.insert(tk.END, output.decode('utf-8'))
            self.scan_output.insert(tk.END, 'Target : {}\n'.format(target))
            logging.info("Scan completed for target: %s", target)
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments=manual_command)
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    logging.debug("Detected protocol for host %s: %s", host, proto)
                    self.scan_output.insert(tk.END, '----------\n')
                    self.scan_output.insert(tk.END, 'Protocol : %s\n' % proto)
            mac_address = get_mac_address(ip=target)
            if mac_address:
                logging.debug("Detected MAC Address for target %s: %s", target, mac_address)
                self.scan_output.insert(tk.END, 'MAC Address : {}\n'.format(mac_address))
            self.scan_output.config(state='disabled')
            
        logging.info("Finished scanning for targets")

def exit_application():
    root.destroy()

if __name__ == "__main__":
    logging.info("Launching main application window")
    root = tk.Tk()
    app = NmapWindow(root)
    root.mainloop()
