#!/usr/bin/env python3
"""
Web Application Security Scanner - GUI Frontend
PyQt5 based frontend that calls bash scripts for functionality
"""

import sys
import os
import subprocess
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTabWidget,
    QGroupBox, QCheckBox, QComboBox, QProgressBar, QFileDialog,
    QMessageBox, QSpinBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QStatusBar, QMenuBar, QAction
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QIcon, QFont, QColor


class BashWorkerThread(QThread):
    """Thread to execute bash scripts without blocking GUI"""
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    progress_signal = pyqtSignal(int)
    
    def __init__(self, script_path, args=None):
        super().__init__()
        self.script_path = script_path
        self.args = args or []
        self.is_running = True
    
    def run(self):
        """Execute bash script and capture output"""
        try:
            cmd = ['bash', self.script_path] + self.args
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            # Read output line by line
            for line in process.stdout:
                if not self.is_running:
                    process.terminate()
                    break
                self.output_signal.emit(line.strip())
            
            process.wait()
            
            if process.returncode == 0:
                self.finished_signal.emit(True, "Scan completed successfully")
            else:
                error = process.stderr.read()
                self.finished_signal.emit(False, f"Error: {error}")
                
        except Exception as e:
            self.finished_signal.emit(False, f"Exception: {str(e)}")
    
    def stop(self):
        """Stop the running thread"""
        self.is_running = False


class WebSecurityScannerGUI(QMainWindow):
    """Main GUI Application"""
    
    def __init__(self):
        super().__init__()
        self.worker_thread = None
        self.scan_results = {}
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Web Application Security Scanner v1.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Target Configuration Section
        target_group = self.create_target_section()
        main_layout.addWidget(target_group)
        
        # Scan Configuration Section
        config_group = self.create_config_section()
        main_layout.addWidget(config_group)
        
        # Control Buttons
        control_layout = self.create_control_buttons()
        main_layout.addLayout(control_layout)
        
        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        # Tabs for Results
        self.tabs = self.create_tabs()
        main_layout.addWidget(self.tabs)
        
        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Apply styling
        self.apply_styles()
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu("File")
        
        load_config_action = QAction("Load Configuration", self)
        load_config_action.triggered.connect(self.load_configuration)
        file_menu.addAction(load_config_action)
        
        save_config_action = QAction("Save Configuration", self)
        save_config_action.triggered.connect(self.save_configuration)
        file_menu.addAction(save_config_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Scan Menu
        scan_menu = menubar.addMenu("Scan")
        
        start_action = QAction("Start Scan", self)
        start_action.triggered.connect(self.start_scan)
        scan_menu.addAction(start_action)
        
        stop_action = QAction("Stop Scan", self)
        stop_action.triggered.connect(self.stop_scan)
        scan_menu.addAction(stop_action)
        
        # Report Menu
        report_menu = menubar.addMenu("Report")
        
        generate_html_action = QAction("Generate HTML Report", self)
        generate_html_action.triggered.connect(self.generate_html_report)
        report_menu.addAction(generate_html_action)
        
        generate_json_action = QAction("Generate JSON Report", self)
        generate_json_action.triggered.connect(self.generate_json_report)
        report_menu.addAction(generate_json_action)
        
        # Help Menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        docs_action = QAction("Documentation", self)
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)
    
    def create_header(self):
        """Create header section"""
        header_label = QLabel("🔒 Web Application Security Scanner")
        header_label.setAlignment(Qt.AlignCenter)
        font = QFont()
        font.setPointSize(18)
        font.setBold(True)
        header_label.setFont(font)
        header_label.setStyleSheet("""
            background-color: #2b2b2b;
            color: #ffffff;
            padding: 15px;
            border-radius: 5px;
        """)
        return header_label
    
    def create_target_section(self):
        """Create target configuration section"""
        group = QGroupBox("Target Configuration")
        layout = QVBoxLayout()
        
        # URL Input
        url_layout = QHBoxLayout()
        url_label = QLabel("Target URL:")
        url_label.setMinimumWidth(100)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://testphp.vulnweb.com")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        
        # Validate URL Button
        validate_btn = QPushButton("🔍 Validate Target")
        validate_btn.clicked.connect(self.validate_target)
        layout.addWidget(validate_btn)
        
        group.setLayout(layout)
        return group
    
    def create_config_section(self):
        """Create scan configuration section"""
        group = QGroupBox("Scan Configuration")
        layout = QVBoxLayout()
        
        # Test Modules
        modules_layout = QHBoxLayout()
        modules_label = QLabel("Test Modules:")
        self.xss_check = QCheckBox("XSS Detection")
        self.xss_check.setChecked(True)
        self.sqli_check = QCheckBox("SQL Injection")
        self.sqli_check.setChecked(True)
        self.header_check = QCheckBox("Security Headers")
        self.header_check.setChecked(True)
        
        modules_layout.addWidget(modules_label)
        modules_layout.addWidget(self.xss_check)
        modules_layout.addWidget(self.sqli_check)
        modules_layout.addWidget(self.header_check)
        modules_layout.addStretch()
        layout.addLayout(modules_layout)
        
        # Scan Intensity
        intensity_layout = QHBoxLayout()
        intensity_label = QLabel("Scan Intensity:")
        intensity_label.setMinimumWidth(100)
        self.intensity_combo = QComboBox()
        self.intensity_combo.addItems(["Low", "Medium", "High"])
        self.intensity_combo.setCurrentText("Medium")
        intensity_layout.addWidget(intensity_label)
        intensity_layout.addWidget(self.intensity_combo)
        intensity_layout.addStretch()
        layout.addLayout(intensity_layout)
        
        # Request Delay
        delay_layout = QHBoxLayout()
        delay_label = QLabel("Request Delay (ms):")
        delay_label.setMinimumWidth(100)
        self.delay_spinbox = QSpinBox()
        self.delay_spinbox.setMinimum(0)
        self.delay_spinbox.setMaximum(5000)
        self.delay_spinbox.setValue(100)
        delay_layout.addWidget(delay_label)
        delay_layout.addWidget(self.delay_spinbox)
        delay_layout.addStretch()
        layout.addLayout(delay_layout)
        
        group.setLayout(layout)
        return group
    
    def create_control_buttons(self):
        """Create control buttons"""
        layout = QHBoxLayout()
        
        self.start_btn = QPushButton("▶ Start Scan")
        self.start_btn.setMinimumHeight(40)
        self.start_btn.clicked.connect(self.start_scan)
        
        self.stop_btn = QPushButton("⏹ Stop Scan")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        
        self.clear_btn = QPushButton("🗑 Clear Results")
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.clicked.connect(self.clear_results)
        
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.clear_btn)
        
        return layout
    
    def create_tabs(self):
        """Create tabs for different result views"""
        tabs = QTabWidget()
        
        # Console Output Tab
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: monospace;")
        tabs.addTab(self.console_output, "📟 Console Output")
        
        # XSS Results Tab
        self.xss_results = QTextEdit()
        self.xss_results.setReadOnly(True)
        tabs.addTab(self.xss_results, "🔴 XSS Vulnerabilities")
        
        # SQLi Results Tab
        self.sqli_results = QTextEdit()
        self.sqli_results.setReadOnly(True)
        tabs.addTab(self.sqli_results, "🔴 SQL Injection")
        
        # Header Results Tab
        self.header_results = QTextEdit()
        self.header_results.setReadOnly(True)
        tabs.addTab(self.header_results, "🔒 Security Headers")
        
        # Summary Tab
        self.summary_table = QTableWidget()
        self.summary_table.setColumnCount(3)
        self.summary_table.setHorizontalHeaderLabels(["Vulnerability Type", "Severity", "Count"])
        self.summary_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        tabs.addTab(self.summary_table, "📊 Summary")
        
        return tabs
    
    def apply_styles(self):
        """Apply custom styles to the application"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #444444;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #ffffff;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:pressed {
                background-color: #004578;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #555555;
                border-radius: 3px;
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QComboBox {
                padding: 5px;
                border: 1px solid #555555;
                border-radius: 3px;
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QComboBox::drop-down {
                border: none;
                background-color: #0078d4;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid white;
            }
            QSpinBox {
                padding: 5px;
                border: 1px solid #555555;
                border-radius: 3px;
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QCheckBox {
                color: #ffffff;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #555555;
                border-radius: 3px;
                background-color: #1e1e1e;
            }
            QCheckBox::indicator:checked {
                background-color: #0078d4;
                border-color: #0078d4;
            }
            QLabel {
                color: #ffffff;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                text-align: center;
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
            }
            QTabWidget::pane {
                border: 1px solid #444444;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #1e1e1e;
                color: #ffffff;
                padding: 8px 16px;
                border: 1px solid #444444;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0078d4;
                color: #ffffff;
            }
            QTabBar::tab:hover {
                background-color: #333333;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 3px;
            }
            QTableWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                gridline-color: #444444;
            }
            QHeaderView::section {
                background-color: #2b2b2b;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #444444;
                font-weight: bold;
            }
            QStatusBar {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QMenuBar {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QMenuBar::item:selected {
                background-color: #0078d4;
            }
            QMenu {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #444444;
            }
            QMenu::item:selected {
                background-color: #0078d4;
            }
        """)
    
    # Button Actions (Connected to Bash Scripts)
    
    def validate_target(self):
        """Validate target URL - calls validate_target.sh"""
        target_url = self.url_input.text().strip()
        
        if not target_url:
            QMessageBox.warning(self, "Input Error", "Please enter a target URL")
            return
        
        self.status_bar.showMessage("Validating target...")
        self.append_console(f"[*] Validating target: {target_url}")
        
        # Call bash script: bash/validate_target.sh <url>
        self.execute_bash_script("bash/validate_target.sh", [target_url])
    
    def start_scan(self):
        """Start security scan - calls main_scan.sh"""
        target_url = self.url_input.text().strip()
        
        if not target_url:
            QMessageBox.warning(self, "Input Error", "Please enter a target URL")
            return
        
        # Prepare scan parameters
        modules = []
        if self.xss_check.isChecked():
            modules.append("xss")
        if self.sqli_check.isChecked():
            modules.append("sqli")
        if self.header_check.isChecked():
            modules.append("headers")
        
        if not modules:
            QMessageBox.warning(self, "Configuration Error", "Please select at least one test module")
            return
        
        intensity = self.intensity_combo.currentText().lower()
        delay = str(self.delay_spinbox.value())
        modules_str = ",".join(modules)
        
        # Update UI state
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.clear_results()
        
        self.status_bar.showMessage("Scan in progress...")
        self.append_console(f"[*] Starting scan on: {target_url}")
        self.append_console(f"[*] Modules: {modules_str}")
        self.append_console(f"[*] Intensity: {intensity}")
        
        # Call bash script: bash/main_scan.sh <url> <modules> <intensity> <delay>
        self.execute_bash_script("bash/main_scan.sh", 
                                [target_url, modules_str, intensity, delay])
    
    def stop_scan(self):
        """Stop running scan"""
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.stop()
            self.append_console("[!] Scan stopped by user")
            self.status_bar.showMessage("Scan stopped")
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def clear_results(self):
        """Clear all results"""
        self.console_output.clear()
        self.xss_results.clear()
        self.sqli_results.clear()
        self.header_results.clear()
        self.summary_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_bar.showMessage("Results cleared")
    
    def generate_html_report(self):
        """Generate HTML report - calls generate_report.sh"""
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", "", "HTML Files (*.html)"
        )
        
        if save_path:
            self.append_console(f"[*] Generating HTML report: {save_path}")
            # Call bash script: bash/generate_report.sh html <output_file>
            self.execute_bash_script("bash/generate_report.sh", 
                                    ["html", save_path])
    
    def generate_json_report(self):
        """Generate JSON report - calls generate_report.sh"""
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Report", "", "JSON Files (*.json)"
        )
        
        if save_path:
            self.append_console(f"[*] Generating JSON report: {save_path}")
            # Call bash script: bash/generate_report.sh json <output_file>
            self.execute_bash_script("bash/generate_report.sh", 
                                    ["json", save_path])
    
    def load_configuration(self):
        """Load scan configuration - calls load_config.sh"""
        config_file, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", "Config Files (*.conf *.cfg)"
        )
        
        if config_file:
            self.append_console(f"[*] Loading configuration: {config_file}")
            # Call bash script: bash/load_config.sh <config_file>
            self.execute_bash_script("bash/load_config.sh", [config_file])
    
    def save_configuration(self):
        """Save scan configuration - calls save_config.sh"""
        config_file, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", "", "Config Files (*.conf)"
        )
        
        if config_file:
            # Prepare config data
            target = self.url_input.text()
            modules = f"{self.xss_check.isChecked()},{self.sqli_check.isChecked()},{self.header_check.isChecked()}"
            intensity = self.intensity_combo.currentText()
            delay = str(self.delay_spinbox.value())
            
            self.append_console(f"[*] Saving configuration: {config_file}")
            # Call bash script: bash/save_config.sh <file> <target> <modules> <intensity> <delay>
            self.execute_bash_script("bash/save_config.sh", 
                                    [config_file, target, modules, intensity, delay])
    
    # Helper Methods
    
    def execute_bash_script(self, script_path, args=None):
        """Execute a bash script in a separate thread"""
        if not os.path.exists(script_path):
            self.append_console(f"[ERROR] Script not found: {script_path}")
            QMessageBox.warning(self, "Script Error", 
                              f"Bash script not found: {script_path}\n\nPlease create the script first.")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            return
        
        self.worker_thread = BashWorkerThread(script_path, args)
        self.worker_thread.output_signal.connect(self.handle_script_output)
        self.worker_thread.finished_signal.connect(self.handle_script_finished)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.start()
    
    def handle_script_output(self, output):
        """Handle output from bash script"""
        self.append_console(output)
        
        # Parse output and update relevant tabs
        if "[XSS]" in output:
            self.xss_results.append(output)
        elif "[SQLI]" in output or "[SQL]" in output:
            self.sqli_results.append(output)
        elif "[HEADER]" in output:
            self.header_results.append(output)
    
    def handle_script_finished(self, success, message):
        """Handle script completion"""
        self.append_console(f"\n{'='*60}")
        self.append_console(f"[*] {message}")
        self.append_console(f"{'='*60}\n")
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        
        if success:
            self.status_bar.showMessage("Scan completed successfully")
            QMessageBox.information(self, "Scan Complete", message)
        else:
            self.status_bar.showMessage("Scan failed")
            QMessageBox.warning(self, "Scan Error", message)
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
    
    def append_console(self, text):
        """Append text to console output"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console_output.append(f"[{timestamp}] {text}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>Web Application Security Scanner</h2>
        <p><b>Version:</b> 1.0</p>
        <p><b>Description:</b> A focused web security scanner for testing OWASP Top 10 vulnerabilities in lab environments.</p>
        <p><b>Modules:</b></p>
        <ul>
            <li>Reflected XSS Detection</li>
            <li>SQL Injection Testing</li>
            <li>Security Header Analysis</li>
        </ul>
        <p><b>⚠️ Legal Notice:</b> Only scan applications you own or have explicit permission to test.</p>
        """
        QMessageBox.about(self, "About", about_text)
    
    def show_documentation(self):
        """Show documentation"""
        docs_text = """
        <h3>Quick Start Guide</h3>
        <ol>
            <li>Enter target URL in the Target Configuration section</li>
            <li>Select test modules (XSS, SQLi, Headers)</li>
            <li>Choose scan intensity (Low/Medium/High)</li>
            <li>Click "Start Scan" button</li>
            <li>View results in respective tabs</li>
            <li>Generate reports from Report menu</li>
        </ol>
        
        <h3>Bash Scripts Required</h3>
        <ul>
            <li><b>bash/validate_target.sh</b> - Validates target URL</li>
            <li><b>bash/main_scan.sh</b> - Main scanning script</li>
            <li><b>bash/generate_report.sh</b> - Report generator</li>
            <li><b>bash/load_config.sh</b> - Load configuration</li>
            <li><b>bash/save_config.sh</b> - Save configuration</li>
        </ul>
        """
        QMessageBox.information(self, "Documentation", docs_text)


def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look
    
    window = WebSecurityScannerGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
