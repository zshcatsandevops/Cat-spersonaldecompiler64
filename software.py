import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import queue
import logging
from pathlib import Path

class N64DecompilerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("N64 ROM Decompiler")
        self.root.geometry("800x600")
        
        # Configure logging (no file, console only)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Initialize queue for thread communication
        self.queue = queue.Queue()
        
        # Configuration settings
        self.config = {
            'tools_dir': './tools',
            'output_dir': './decomp_output',
            'compiler': 'gcc',
            'optimization': '-O2'
        }
        
        self.rom_path = None
        self.create_widgets()
        self.setup_periodic_queue_check()
        self.log_message("Ready. Select a ROM (.z64/.n64/.v64) and hit Decompile.", dim=True)

    def create_widgets(self):
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(
            self.main_frame, 
            text="N64 ROM Decompiler",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=10)

        # ROM Selection Frame
        rom_frame = ttk.LabelFrame(self.main_frame, text="ROM Selection", padding="10")
        rom_frame.pack(fill=tk.X, padx=5, pady=5)

        # ROM path entry and browse button
        self.rom_path_var = tk.StringVar()
        rom_entry = ttk.Entry(rom_frame, textvariable=self.rom_path_var, width=50)
        rom_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        browse_button = ttk.Button(
            rom_frame,
            text="Browse",
            command=self.browse_rom
        )
        browse_button.pack(side=tk.LEFT, padx=5)

        # Options Frame
        options_frame = ttk.LabelFrame(self.main_frame, text="Decompilation Options", padding="10")
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        # Checkboxes for options
        self.debug_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame, 
            text="Generate Debug Info", 
            variable=self.debug_var
        ).pack(anchor=tk.W)

        self.symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame, 
            text="Extract Symbols", 
            variable=self.symbols_var
        ).pack(anchor=tk.W)

        # Control frame
        control_frame = ttk.LabelFrame(self.main_frame, text="Decompilation Controls", padding="10")
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Decompilation button with progress bar
        self.create_action_section(control_frame, "Decompile", self.start_decompilation)

        # Add Test button for mock run
        self.create_action_section(control_frame, "Test Mode", self.start_test_mode)

        # Output frame
        output_frame = ttk.LabelFrame(self.main_frame, text="Decompilation Output", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Output text with scrollbar
        self.output_text = tk.Text(
            output_frame,
            height=15,
            width=80,
            wrap=tk.WORD,
            font=("Consolas", 10)
        )
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scrollbar.set)
        
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Configure tags once
        self.output_text.tag_config("error", foreground="red")
        self.output_text.tag_config("success", foreground="green")
        self.output_text.tag_config("dim", foreground="gray")

    def create_action_section(self, parent, name, command):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=5)
        
        button = ttk.Button(frame, text=name, command=command)
        button.pack(side=tk.LEFT, padx=5)
        
        progress = ttk.Progressbar(
            frame,
            mode='indeterminate',
            length=300
        )
        progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        setattr(self, f"{name.lower().replace(' ', '_')}_button", button)
        setattr(self, f"{name.lower().replace(' ', '_')}_progress", progress)

    def browse_rom(self):
        filename = filedialog.askopenfilename(
            title="Select N64 ROM",
            filetypes=[("N64 ROMs", "*.z64 *.v64 *.n64"), ("All files", "*.*")]
        )
        if filename:
            self.rom_path = filename
            self.rom_path_var.set(filename)
            self.log_message(f"Selected ROM: {filename}")

    def standardize_rom(self, rom_path, output_dir):
        with open(rom_path, 'rb') as f:
            header = f.read(4)
        
        if header == b'\x80\x37\x12\x40':
            self.log_message("ROM format: .z64 (big-endian) - no conversion needed.")
            return rom_path
        elif header == b'\x37\x80\x40\x12':
            self.log_message("ROM format: .v64 (byte-swapped) - converting to .z64.")
            format_type = 'v64'
        elif header == b'\x40\x12\x37\x80':
            self.log_message("ROM format: .n64 (little-endian) - converting to .z64.")
            format_type = 'n64'
        else:
            raise ValueError("Unknown N64 ROM format - cannot proceed.")
        
        with open(rom_path, 'rb') as f:
            data = bytearray(f.read())
        
        if format_type == 'v64':
            for i in range(0, len(data), 2):
                data[i], data[i+1] = data[i+1], data[i]
        elif format_type == 'n64':
            for i in range(0, len(data), 4):
                data[i:i+4] = data[i:i+4][::-1]
        
        std_path = output_dir / 'standardized.z64'
        with open(std_path, 'wb') as f:
            f.write(data)
        
        self.log_message(f"Standardized ROM saved to: {std_path}")
        return str(std_path)

    def run_command(self, cmd, working_dir=None):
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=working_dir
            )
            
            while True:
                output = process.stdout.readline()
                if output:
                    self.queue.put(('output', output.strip()))
                    
                if process.poll() is not None:
                    break
                    
            returncode = process.wait()
            
            if returncode != 0:
                error = process.stderr.read()
                raise subprocess.CalledProcessError(returncode, cmd, error)
                
            return True
            
        except Exception as e:
            self.queue.put(('error', str(e)))
            return False

    def start_decompilation(self):
        if not self.rom_path:
            messagebox.showerror("Error", "Please select a ROM file first.")
            return

        def decompile():
            try:
                self.decompile_button.state(['disabled'])
                self.decompile_progress.start()
                
                # Create output directory
                output_dir = Path(self.config['output_dir'])
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # Standardize ROM format
                self.queue.put(('output', "Standardizing ROM format..."))
                std_rom = self.standardize_rom(self.rom_path, output_dir)
                
                # Disassemble as fallback
                self.queue.put(('output', "Disassembling ROM..."))
                disasm_cmd = f"mips64-elf-objdump -D -b binary -m mips:4300 -EB {std_rom} > {output_dir}/disasm.s"
                self.run_command(disasm_cmd)
                
                if self.symbols_var.get():
                    self.queue.put(('output', "Note: Raw N64 ROMs have no symbols - skipping extraction."))
                
                # Decompile to C
                self.queue.put(('output', "Decompiling to C code..."))
                debug_flag = "--debug" if self.debug_var.get() else ""
                cmd = f"mips_decompiler {debug_flag} {std_rom} -o {output_dir}/output.c"
                success = self.run_command(cmd)
                
                if success:
                    self.queue.put(('success', 'Decompilation completed successfully'))
                    
            except Exception as e:
                self.queue.put(('error', f"Decompilation failed: {str(e)}"))
                
            finally:
                self.queue.put(('build_complete', 'decompile'))

        threading.Thread(target=decompile, daemon=True).start()

    def start_test_mode(self):
        def test():
            try:
                self.test_mode_button.state(['disabled'])
                self.test_mode_progress.start()
                
                self.queue.put(('output', "Running test mode (mock standardization)..."))
                # Mock ROM path for test
                mock_rom = Path('mock_rom.z64')
                with open(mock_rom, 'wb') as f:
                    f.write(b'\x80\x37\x12\x40')  # Mock header
                
                output_dir = Path(self.config['output_dir'])
                output_dir.mkdir(parents=True, exist_ok=True)
                
                std_rom = self.standardize_rom(str(mock_rom), output_dir)
                self.queue.put(('output', f"Mock standardized: {std_rom}"))
                self.queue.put(('success', 'Test mode completed'))
                
                os.remove(mock_rom)  # Cleanup
                
            except Exception as e:
                self.queue.put(('error', f"Test failed: {str(e)}"))
                
            finally:
                self.queue.put(('build_complete', 'test mode'))

        threading.Thread(target=test, daemon=True).start()

    def setup_periodic_queue_check(self):
        def check_queue():
            while True:
                try:
                    msg_type, message = self.queue.get_nowait()
                    
                    if msg_type == 'output':
                        self.log_message(message)
                    elif msg_type == 'error':
                        self.log_message(f"Error: {message}", error=True)
                    elif msg_type == 'success':
                        self.log_message(message, success=True)
                    elif msg_type == 'build_complete':
                        if message == 'decompile':
                            self.decompile_button.state(['!disabled'])
                            self.decompile_progress.stop()
                        elif message == 'test mode':
                            self.test_mode_button.state(['!disabled'])
                            self.test_mode_progress.stop()
                            
                except queue.Empty:
                    break
                    
            self.root.after(100, check_queue)
            
        self.root.after(100, check_queue)

    def log_message(self, message, error=False, success=False, dim=False):
        self.output_text.insert(tk.END, f"{message}\n")
        
        # Calculate indices for the last inserted line
        start_index = "end-1l linestart"
        end_index = "end-1c"
        
        if error:
            self.output_text.tag_add("error", start_index, end_index)
        elif success:
            self.output_text.tag_add("success", start_index, end_index)
        elif dim:
            self.output_text.tag_add("dim", start_index, end_index)
        logging.info(message) if not error else logging.error(message)
            
        self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = N64DecompilerApp(root)
    root.mainloop()
