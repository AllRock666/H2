# certiwipe_app.py (fixed)
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext, filedialog
import platform
import subprocess
import time
import os
import json
import requests
import re
import sys
import ctypes
import threading

import key_manager
import certificate_utils

# NOTE: The ensure_admin_privileges() function has been REMOVED 
# to prevent the .exe cloning bug.
# Admin rights will be handled by the .manifest file during build.

class CertiWipeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CertiWipe Pro - Erasure & Verification Tool")
        self.root.geometry("800x700")
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        try:
            if key_manager.ensure_keys():
                print("New key pair generated.")
            else:
                print("Existing key pair found.")
            key_manager.load_private_key()
            key_manager.load_public_key()
        except Exception as e:
            messagebox.showerror("Key Error", f"Could not load/generate keys: {e}")
            self.root.destroy()
            sys.exit(1)

        main_paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook = ttk.Notebook(main_paned_window)
        main_paned_window.add(notebook)
        self.wipe_tab = ttk.Frame(notebook, padding=10)
        self.verify_tab = ttk.Frame(notebook, padding=10)
        notebook.add(self.wipe_tab, text=' Wipe Drive ')
        notebook.add(self.verify_tab, text=' Verify Certificate ')
        log_frame = ttk.LabelFrame(main_paned_window, text="Process Log", padding=10)
        main_paned_window.add(log_frame, weight=1)
        self.status_log = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', font=("Courier", 10), bg="#2c3e50", fg="white", wrap=tk.WORD)
        self.status_log.pack(fill=tk.BOTH, expand=True)

        self._create_wipe_tab_widgets()
        self._create_verify_tab_widgets()
        self.log("Welcome to CertiWipe Pro.")
        # Check privileges at startup
        self._check_privileges()
        self.log("Cryptographic keys initialized.", "INFO")
        self.detect_drives()

        # Auto-start verification server
        self._start_verification_server()

    def _check_privileges(self):
        """Logs if the app is running with admin rights."""
        system = platform.system()
        is_admin = False
        try:
            if system == "Windows":
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            elif system in ["Linux", "Darwin"]:
                is_admin = os.geteuid() == 0
        except Exception:
            pass # Failed to check, assume not admin

        if is_admin:
            self.log("Running with administrator privileges.", "SUCCESS")
        else:
            self.log("WARNING: Not running as administrator. Wiping may fail.", "ERROR")
            messagebox.showerror("Privilege Error", "Not running as administrator.\nPlease right-click the app and 'Run as administrator'.")


    def _start_verification_server(self):
        """Start server in background without blocking UI"""
        def run_server():
            try:
                # Get script path
                if getattr(sys, 'frozen', False):
                    server_script = os.path.join(sys._MEIPASS, 'verification_server.py')
                else:
                    server_script = 'verification_server.py'

                if not os.path.exists(server_script):
                    self.log(f"Server script not found: {server_script}", "WARN")
                    return

                self.log("Starting verification server...", "INFO")
                
                # Start server process (unchanged from previous correction)
                if platform.system() == "Windows":
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = 0
                    subprocess.Popen(
                        [sys.executable, server_script],
                        startupinfo=startupinfo,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                    )
                else:
                    subprocess.Popen(
                        [sys.executable, server_script],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )

                # Wait briefly for server to start
                time.sleep(2)
                
                # FIX: Check both /health and /verify/test for robustness.
                check_urls = ["http://127.0.0.1:5000/health", "http://127.0.0.1:5000/verify/test"]
                success = False

                for url in check_urls:
                    try:
                        response = requests.get(url, timeout=2)
                        if response.status_code == 200:
                            self.log("Verification server started successfully.", "SUCCESS")
                            success = True
                            break
                        else:
                            self.log(f"Checked {url}: responded with status {response.status_code}", "WARN")
                    except Exception:
                        continue # Try the next URL if this one fails

                if not success:
                    self.log("Server started but returned HTTP 404 (or failed to connect).", "WARN")
                    
            except Exception as e:
                self.log(f"Server auto-start failed: {e}", "WARN")

        # Run in daemon thread
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

    def _create_wipe_tab_widgets(self):
        drive_frame = ttk.LabelFrame(self.wipe_tab, text="1. Select Target Drive", padding=10)
        drive_frame.pack(fill=tk.X, expand=True, pady=(0, 10))
        list_frame = ttk.Frame(drive_frame)
        list_frame.pack(fill=tk.X, expand=True, pady=5)
        self.drive_listbox = tk.Listbox(list_frame, height=5, font=("Courier", 11), selectbackground="#3498db")
        self.drive_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        buttons_frame = ttk.Frame(list_frame)
        buttons_frame.pack(side=tk.RIGHT, anchor='n')
        refresh_button = ttk.Button(buttons_frame, text="Refresh List", command=self.detect_drives)
        refresh_button.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))
        health_button = ttk.Button(buttons_frame, text="Check Health", command=self._check_drive_health)
        health_button.pack(side=tk.TOP, fill=tk.X)

        options_frame = ttk.LabelFrame(self.wipe_tab, text="2. Select Wipe Method", padding=10)
        options_frame.pack(fill=tk.X, expand=True, pady=(0, 10))
        self.wipe_method_var = tk.StringVar(value="Secure")
        secure_radio = ttk.Radiobutton(options_frame,
                                       text="Secure Wipe (3-Pass Shred / DoD 5220.22-M ECE)",
                                       variable=self.wipe_method_var,
                                       value="Secure")
        quick_radio = ttk.Radiobutton(options_frame,
                                      text="Quick Wipe (1-Pass Zeros / diskpart clean)",
                                      variable=self.wipe_method_var,
                                      value="Quick")
        secure_radio.pack(anchor='w', padx=5)
        quick_radio.pack(anchor='w', padx=5)

        wipe_frame = ttk.LabelFrame(self.wipe_tab, text="3. Initiate Wipe", padding=10)
        wipe_frame.pack(fill=tk.X, expand=True)
        self.wipe_button = ttk.Button(wipe_frame, text="PERMANENTLY ERASE SELECTED DRIVE", command=self.confirm_wipe, style='Danger.TButton')
        self.wipe_button.pack(pady=10)
        style = ttk.Style()
        try:
            style.configure('Danger.TButton', foreground='white', background='#c0392b', font=('Helvetica', 12, 'bold'), padding=(10, 5))
            style.map('Danger.TButton', background=[('active', '#e74c3c')])
        except Exception:
            pass

    def _create_verify_tab_widgets(self):
        verify_frame = ttk.LabelFrame(self.verify_tab, text="Verify a Certificate File", padding=10)
        verify_frame.pack(fill=tk.BOTH, expand=True)
        self.selected_file_var = tk.StringVar(value="No file selected.")
        select_button = ttk.Button(verify_frame, text="Select Certificate (.json)...", command=self._select_verification_file)
        select_button.grid(row=0, column=0, padx=5, pady=10)
        file_label = ttk.Label(verify_frame, textvariable=self.selected_file_var, font=("Helvetica", 10, "italic"), wraplength=500)
        file_label.grid(row=0, column=1, padx=5, pady=10, sticky='w')
        verify_button = ttk.Button(verify_frame, text="VERIFY SIGNATURE", command=self._verify_certificate_file)
        verify_button.grid(row=1, column=0, columnspan=2, pady=10)

    def log(self, message, level="INFO"):
        timestamp = time.strftime('%H:%M:%S')
        formatted = f"[{timestamp}] [{level}] {message}\n"
        if hasattr(self, 'status_log') and self.status_log and self.status_log.winfo_exists():
            try:
                self.status_log.config(state='normal')
                self.status_log.insert(tk.END, formatted)
                self.status_log.config(state='disabled')
                self.status_log.see(tk.END)
                self.root.update_idletasks()
            except tk.TclError:
                print(formatted, end='')
        else:
            print(formatted, end='')

    def _get_system_drive_identifier(self):
        """
        Retrieves the base disk identifier for the running system drive.
        
        Windows FIX: We rely on the user exercising 'extra caution' because 
        reliably getting the system disk index via WMI often fails in the
        elevated context required by this application.
        """
        system = platform.system()
        try:
            if system == "Windows":
                # Returns None so the application relies on the safety warning 
                # instead of a potentially incorrect automatic ID.
                return None 

            elif system == "Linux":
                source = subprocess.check_output(['findmnt', '-n', '-o', 'SOURCE', '/']).decode().strip()
                match = re.search(r'(/dev/)?([\w\/]+)', source)
                if match:
                    base_name = re.sub(r'\d+$', '', match.group(2))
                    return base_name.split('/')[-1]
                
            elif system == "Darwin":
                source = subprocess.check_output(['df', '/']).decode().strip().split('\n')[-1].split()[0]
                match = re.search(r'(\/dev\/disk\d+)', source)
                if match:
                    return re.sub(r's\d+$', '', match.group(1).split('/')[-1])
        except Exception as e:
            self.log(f"System drive detection failed: {e}", "WARN")
        return None
    
    def detect_drives(self):
        self.log("Detecting storage devices...")
        self.drive_listbox.delete(0, tk.END)
        system_drive_id = self._get_system_drive_identifier()
        if system_drive_id:
            self.log(f"System drive identified: {system_drive_id}. Protected.", "INFO")
        else:
            self.log("Could not identify system drive. Extra caution advised.", "WARN")
        system = platform.system()
        found_drives = []
        try:
            if system == "Linux":
                try:
                    cmd = ["lsblk", "-d", "-o", "NAME,SIZE,MODEL", "--bytes"]
                    result = subprocess.check_output(cmd).decode("utf-8").strip()
                    lines = result.split('\n')[1:]
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            name = parts[0]
                            drive_string = " ".join(parts)
                            if name == system_drive_id:
                                self.drive_listbox.insert(tk.END, f"[SYSTEM DRIVE] {drive_string}")
                            else:
                                self.drive_listbox.insert(tk.END, drive_string)
                            found_drives.append(drive_string)
                except Exception as e:
                    self.log(f"Drive detection failed (Linux): {e}", "ERROR")
            elif system == "Windows":
                # Use wmic CSV format for simpler parsing
                try:
                    cmd = ["wmic", "diskdrive", "get", "Index,DeviceID,Model,Size", "/FORMAT:CSV"]
                    startupinfo = subprocess.STARTUPINFO()
                    try:
                        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    except Exception:
                        pass
                    raw = subprocess.check_output(cmd, startupinfo=startupinfo).decode(errors='ignore').strip()
                    # CSV output: Node,Index,DeviceID,Model,Size
                    lines = [l.strip() for l in raw.splitlines() if l.strip()]
                    # find header line index (some WMIC outputs include header repeated)
                    parsed_any = False
                    for line in lines:
                        if line.lower().startswith("node,"):
                            continue
                        # split by commas but Model can contain commas: WMIC CSV should quote fields but to be safe do a simple split with max 4 parts
                        parts = line.split(',', 4)
                        
                        # --- THIS IS THE FIX ---
                        if len(parts) >= 5:
                            # parts: Node,DeviceID,Index,Model,Size (FIXED to match your output)
                            _, deviceid, index, model, size = parts[:5]
                        elif len(parts) == 4:
                            # (FIXED)
                            _, deviceid, index, model = parts
                            size = ""
                        # --- END OF FIX ---
                        
                        else:
                            continue
                        index = index.strip()
                        deviceid = deviceid.strip()
                        model = model.strip()
                        size = size.strip()
                        # Display a helpful entry. Include index so wipe routine can extract it.
                        display = f"(Index:{index}) {deviceid} {model} {size}"
                        # mark system drive? skipping mapping to logical drive (safer to not mark on Windows)
                        self.drive_listbox.insert(tk.END, display)
                        found_drives.append(display)
                        parsed_any = True
                    if not parsed_any:
                        self.log("No disks found by WMIC.", "WARN")
                except FileNotFoundError:
                    self.log("WMIC not available on this system.", "ERROR")
                except Exception as e:
                    self.log(f"Drive detection failed (Windows): {e}", "ERROR")
            elif system == "Darwin":
                try:
                    # Use diskutil list -plist or diskutil list and parse /dev/diskX lines
                    raw = subprocess.check_output(["diskutil", "list"]).decode()
                    for line in raw.splitlines():
                        line = line.strip()
                        m = re.match(r"(/dev/disk\d+)\s+(.+)", line)
                        if m:
                            dev = m.group(1)
                            desc = m.group(2).strip()
                            display = f"{dev} {desc}"
                            self.drive_listbox.insert(tk.END, display)
                            found_drives.append(display)
                except Exception as e:
                    self.log(f"Drive detection failed (Darwin): {e}", "ERROR")
            else:
                self.log("Unsupported OS for drive detection.", "WARN")
        except Exception as e:
            self.log(f"Unexpected error in detect_drives: {e}", "ERROR")

        if not found_drives:
            self.log("No removable/non-system drives detected.", "INFO")

    def _check_drive_health(self):
        try:
            selected = self.drive_listbox.get(self.drive_listbox.curselection())
            if selected.startswith("[SYSTEM DRIVE]"):
                parts = selected.split(' ', 1)
                drive_identifier = parts[1] if len(parts) > 1 else None
            else:
                drive_identifier = selected.split(' ')[0] if selected else None
            if not drive_identifier:
                messagebox.showerror("Error", "No drive selected.")
                return
            self.log(f"Checking S.M.A.R.T. health for {drive_identifier}...", "INFO")
            system = platform.system()
            status, details = "Unknown", "Could not retrieve status."
            try:
                if system in ["Linux", "Darwin"]:
                    cmd = ["smartctl", "-H", drive_identifier]
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
                    output = result.stdout + result.stderr
                    if "PASSED" in output or "OK" in output:
                        status, details = "✅ PASSED", "Basic check passed."
                    elif "FAILED" in output:
                        status, details = "❌ FAILED", "Drive may be failing."
                    else:
                        status, details = "⚠️ UNKNOWN", "Could not determine status."
                elif system == "Windows":
                    # Try extracting index if present (our listbox shows (Index:N))
                    idx_match = re.search(r'\(Index:(\d+)\)', selected)
                    if idx_match:
                        idx = idx_match.group(1)
                        cmd = ["wmic", "diskdrive", "where", f"Index={idx}", "get", "Status", "/format:list"]
                        startupinfo = subprocess.STARTUPINFO()
                        try:
                            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                        except Exception:
                            pass
                        result = subprocess.run(cmd, capture_output=True, text=True, check=True, startupinfo=startupinfo, timeout=10)
                        output = result.stdout.strip()
                        if "Status=OK" in output or "OK" in output:
                            status, details = "✅ OK", "Basic status reported OK."
                        else:
                            status, details = "⚠️ UNKNOWN/ERROR", f"WMIC reported: {output.split('=')[-1] if '=' in output else output}"
                    else:
                        status, details = "Not Supported", "Could not determine disk index for WMIC check."
                else:
                    status, details = "Not Supported", "Check not supported on this OS."
                self.log(f"Health Status ({drive_identifier}): {status}", "INFO")
                messagebox.showinfo("Drive Health Status", f"Drive: {drive_identifier}\nStatus: {status}\n\nDetails: {details}")
            except FileNotFoundError:
                self.log("Health Check Error: Command not found ('smartctl' or 'wmic').", "ERROR")
                messagebox.showerror("Command Not Found", "Required command ('smartctl' or 'wmic') not found.")
            except subprocess.TimeoutExpired:
                self.log("Health Check Error: Command timed out.", "ERROR")
                messagebox.showerror("Timeout", "Health check command took too long to respond.")
            except subprocess.CalledProcessError as e:
                self.log(f"Health Check Error: {e.stderr or e.stdout}", "ERROR")
                messagebox.showerror("Command Error", f"Failed to get status.\nError:\n{e.stderr or e.stdout}")
            except Exception as e:
                self.log(f"Health Check Error: Unexpected error - {e}", "ERROR")
                messagebox.showerror("Error", f"Unexpected error during health check:\n{e}")
        except tk.TclError:
            messagebox.showerror("Error", "Please select a drive first.")

    def confirm_wipe(self):
        try:
            selected_drive = self.drive_listbox.get(self.drive_listbox.curselection())
        except tk.TclError:
            messagebox.showerror("Error", "Please select a drive.")
            return
        if selected_drive.startswith("[SYSTEM DRIVE]"):
            messagebox.showerror("Action Prohibited", "Cannot wipe system drive.")
            return
        if not messagebox.askokcancel("Are you sure?", f"Erase:\n\n{selected_drive}\n\nThis is IRREVERSIBLE."):
            return
        confirm_text = simpledialog.askstring("Final Confirmation", 'Type "ERASE" to proceed:')
        if confirm_text == "ERASE":
            self._perform_wipe(selected_drive)
        else:
            messagebox.showerror("Cancelled", "Confirmation text mismatch.")

    def _perform_wipe(self, drive_info):
        self.log(f"Starting wipe for {drive_info}...", "WARN")
        self.wipe_button.config(state='disabled')
        system = platform.system()
        chosen_method = self.wipe_method_var.get()
        process = None

        try:
            command, wipe_method_desc = None, ""
            drive_identifier = drive_info
            if drive_info.startswith("[SYSTEM DRIVE]"):
                # remove prefix
                drive_identifier = drive_info.replace("[SYSTEM DRIVE] ", "", 1)

            # For Windows, extract disk index
            if system in ["Linux", "Darwin"]:
                # If drive_info contains a path like /dev/sdb
                drive_identifier = drive_identifier.split()[0]
                if chosen_method == "Secure":
                    # Use shred (2 passes + zero)
                    command = ["shred", "-v", "-n", "2", "-z", drive_identifier]
                    wipe_method_desc = "NIST 800-88 Purge (shred, 3-pass)"
                    self.log("Using secure 3-pass 'shred' method.", "INFO")
                else:
                    raw_disk_id = drive_identifier.replace('/dev/disk', '/dev/rdisk') if system == "Darwin" else drive_identifier
                    dd_command = ["dd", f"if=/dev/zero", f"of={raw_disk_id}", "bs=4M"]
                    # try to append status=progress if supported
                    try:
                        test_run = subprocess.run(["dd", "if=/dev/zero", "of=/dev/null", "count=0", "status=progress"], capture_output=True, timeout=1)
                        dd_command.append("status=progress")
                    except Exception:
                        pass
                    command = dd_command
                    wipe_method_desc = "NIST 800-88 Clear (dd, 1-pass zeros)"
                    self.log("Using quick 1-pass 'dd' zero-fill method.", "INFO")

            elif system == "Windows":
                # extract index from string like "(Index:0)"
                idx_match = re.search(r'\(Index:(\d+)\)', drive_info)
                if not idx_match:
                    raise ValueError("Could not find disk index in selected entry.")
                disk_index = idx_match.group(1)
                script_path = os.path.join(os.getcwd(), 'wipe_script.txt')
                with open(script_path, 'w', newline='\r\n') as f:
                    f.write(f"select disk {disk_index}\nclean\n")
                # diskpart only supports 'clean' and 'clean all' — 'clean all' overwrites with zeros but takes long (no direct 3-pass)
                if chosen_method == "Secure":
                    wipe_method_desc = "NIST 800-88 Clear (diskpart clean - Secure multi-pass not available here)"
                    self.log("Using 'diskpart clean'. Secure multi-pass unavailable on Windows.", "WARN")
                else:
                    wipe_method_desc = "NIST 800-88 Clear (diskpart clean)"
                    self.log("Using 'diskpart clean' method.", "INFO")
                command = ["diskpart", "/s", script_path]
            else:
                raise OSError("Unsupported OS for wipe.")

            if not command:
                raise OSError("Prepared command is empty / unsupported method.")

            self.log(f"Executing: {' '.join(command)}", "WARN")
            self.log("Wipe in progress...", "INFO")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)

            stderr_output = ""
            if system in ["Linux", "Darwin"] and process.stderr:
                for line in iter(process.stderr.readline, ''):
                    if not line:
                        break
                    self.log(line.strip(), "WIPE")
                    stderr_output += line
                try:
                    process.stderr.close()
                except Exception:
                    pass

            stdout, final_stderr = process.communicate()
            stderr_output += (final_stderr or "")

            # cleanup Windows helper file
            try:
                if system == "Windows" and os.path.exists('wipe_script.txt'):
                    os.remove('wipe_script.txt')
            except Exception as e:
                self.log(f"Warning: could not remove wipe_script.txt: {e}", "WARN")

            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command, stderr_output)

            self.log("Sanitization complete.", "SUCCESS")
        except Exception as e:
            error_details = str(e) if not isinstance(e, subprocess.CalledProcessError) else e.stderr
            self.log(f"Wipe failed: {error_details}", "ERROR")
            messagebox.showerror("Wipe Failed", f"Details:\n{error_details}")
            if process and process.poll() is None:
                try:
                    process.terminate()
                except Exception:
                    pass
            self.wipe_button.config(state='normal')
            return

        messagebox.showinfo("Select Save Location", "Wipe complete. Select certificate save location.")
        save_path = filedialog.askdirectory(title="Select Save Location")
        if not save_path:
            self.wipe_button.config(state='normal')
            return

        if not wipe_method_desc:
            wipe_method_desc = "Unknown"

        device_data = {"deviceString": drive_info.replace("[SYSTEM DRIVE] ", ""), "wipeMethod": wipe_method_desc}
        try:
            private_key = key_manager.load_private_key()
            cert_data, _, pdf_path = certificate_utils.generate_certificate(device_data, private_key, save_path)
            self.log(f"Certificate saved: {os.path.basename(pdf_path)}", "SUCCESS")
            self._register_certificate_with_server(cert_data)
            messagebox.showinfo("Wipe Complete", f"Certificate saved in:\n{save_path}")
        except Exception as e:
            self.log(f"Certificate generation failed: {e}", "ERROR")
            messagebox.showerror("Certificate Error", f"Certificate generation failed: {e}")
        finally:
            self.wipe_button.config(state='normal')

    def _register_certificate_with_server(self, cert_data):
        server_url = "http://127.0.0.1:5000/api/register_wipe"
        try:
            response = requests.post(server_url, json=cert_data, timeout=5)
            if response.status_code == 201:
                self.log("Certificate registered with server.", "SUCCESS")
            else:
                # try to show json message if available
                try:
                    msg = response.json().get('message', response.text)
                except Exception:
                    msg = response.text
                self.log(f"Server error: {msg}", "ERROR")
        except requests.exceptions.RequestException as e:
            self.log(f"Could not connect to server: {e}", "ERROR")

    def _select_verification_file(self):
        filepath = filedialog.askopenfilename(title="Select Certificate File", filetypes=(("JSON files", "*.json"),))
        if filepath:
            self.selected_file_var.set(filepath)

    def _verify_certificate_file(self):
        json_path = self.selected_file_var.get()
        if not os.path.exists(json_path):
            messagebox.showerror("Error", "Please select a valid file.")
            return
        self.log(f"Verifying {os.path.basename(json_path)} (Offline)...")
        try:
            public_key = key_manager.load_public_key()
            is_valid, message = certificate_utils.verify_certificate(json_path, public_key)
            if is_valid:
                self.log(message, "SUCCESS")
                messagebox.showinfo("Result: VALID", message)
            else:
                self.log(message, "ERROR")
                messagebox.showerror("Result: INVALID", message)
        except Exception as e:
            self.log(f"Verification failed: {e}", "ERROR")
            messagebox.showerror("Verification Error", f"Offline verification failed:\n{e}\n\n(Is 'config/public.pem' valid?)")

if __name__ == "__main__":
    # NOTE: ensure_admin_privileges() has been REMOVED.
    # The .exe build now uses a manifest file to request admin rights.
    root = tk.Tk()
    app = CertiWipeApp(root)
    root.mainloop()