import sys
import ctypes
import winreg
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QSystemTrayIcon
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl, pyqtSlot, QObject
from PyQt6.QtGui import QIcon
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEngineSettings, QWebEnginePage

# Windows API Setup (for titlebar color changes)
DWM_API = ctypes.windll.dwmapi
DWMWA_USE_IMMERSIVE_DARK_MODE = 20  # Dark Mode Toggle
DWMWA_BORDER_COLOR = 34             # Titlebar Border Color
DWMWA_CAPTION_COLOR = 35            # Titlebar Background Color
DWMWA_TEXT_COLOR = 36               # Titlebar Text Color

###########################################################################
# 1. Create a Python object to manage startup registration via the Windows registry
###########################################################################

from PyQt6.QtWebEngineCore import QWebEnginePage

class CustomWebEnginePage(QWebEnginePage):
    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        print(f"JS Console: {message} (line: {lineNumber}, source: {sourceID})")


class StartupManager(QObject):
    @pyqtSlot(result=bool)
    def isStartupEnabled(self):
        """Check if our app is in the Windows startup registry."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_READ)
            try:
                winreg.QueryValueEx(key, "FutureNotes")
                winreg.CloseKey(key)
                return True
            except FileNotFoundError:
                winreg.CloseKey(key)
                return False
        except Exception:
            return False

    @pyqtSlot(result=bool)
    def toggleStartup(self):
        """Toggle our app’s startup registry entry."""
        import os
        if getattr(sys, 'frozen', False):
            app_path = sys.executable
        else:
            app_path = os.path.join(os.path.dirname(__file__), "main.py")
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_ALL_ACCESS)
        except Exception:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Run")
        try:
            # If already registered, remove it.
            winreg.QueryValueEx(key, "FutureNotes")
            winreg.DeleteValue(key, "FutureNotes")
            new_status = False
        except FileNotFoundError:
            # Not registered yet: add it.
            winreg.SetValueEx(key, "FutureNotes", 0, winreg.REG_SZ, f'"{app_path}"')
            new_status = True

        winreg.CloseKey(key)
        return new_status

###########################################################################
# 2. The Main Window: our web app viewer with JS injection support
###########################################################################

class WebAppViewer(QMainWindow):
    def __init__(self, base_url):
        super().__init__()

        self.base_url = base_url
        self.setWindowTitle("Future Notes")
        self.setGeometry(100, 100, 1024, 768)
        self.setWindowIcon(QIcon("icon.ico"))  # Replace with your .ico file path

        # --- IMPORTANT: Configure QWebEngineProfile BEFORE creating the QWebEngineView ---
        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
        # Set an absolute path or ensure the relative path exists
        self.profile.setPersistentStoragePath("./web_storage")
        # (Optional) Explicitly enable localStorage
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)

        # Set a unique AppUserModelID for Windows taskbar grouping
        app_id = "futurenotes.futurenotesapp.1.0"  # Change to a unique name
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)

        tray_icon = QSystemTrayIcon(QIcon("icon.ico"), app)
        tray_icon.show()

        # Create a central widget for styling
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        layout = QVBoxLayout()
        self.central_widget.setLayout(layout)

        # --- Create the QWebEngineView AFTER configuring the profile ---
        self.browser = QWebEngineView()
        # Create a new QWebEnginePage with the specified profile.
        page = CustomWebEnginePage(self.profile, self.browser)
        # Set the custom page to the browser.
        self.browser.setPage(page)
        self.browser.setUrl(QUrl(self.base_url + "/login_page"))
        layout.addWidget(self.browser)

        # Set up QWebChannel for JS ⇄ Python communication
        self.channel = QWebChannel()
        self.startup_manager = StartupManager()
        self.channel.registerObject("startupManager", self.startup_manager)
        self.browser.page().setWebChannel(self.channel)

        # When a page loads, check for theme-color and for account/settings page injection.
        self.browser.loadFinished.connect(self.on_page_load)

    @pyqtSlot()
    def on_page_load(self):
        # --- 1. Update the window theme based on the page's <meta name="theme-color"> ---
        js_theme = """
        (function() {
            var meta = document.querySelector('meta[name="theme-color"]');
            return meta ? meta.getAttribute("content") : "";
        })();
        """
        self.browser.page().runJavaScript(js_theme, self.update_theme_color)

        # Hide scrollbars
        self.browser.page().runJavaScript("""
            (function() {
                var css = '*::-webkit-scrollbar { display: none; }';
                var style = document.createElement('style');
                style.innerHTML = css;
                document.head.appendChild(style);
            })();
        """)
        print("Hiding scrollbars")
        
        # Test localStorage functionality
        self.browser.page().runJavaScript("""
            localStorage.setItem("testKey", "testValue");
            console.log("Stored value in localStorage:", localStorage.getItem("testKey"));
        """)

        # --- 2. If we are on the account/settings page, inject our startup toggle button ---
        current_url = self.browser.url().toString()
        if current_url == self.base_url + "/account_page":
            self.inject_startup_button()

    def update_theme_color(self, color):
        if color and color.startswith("#"):
            print(f"Applying theme color: {color}")
            self.central_widget.setStyleSheet(f"background-color: {color};")
            self.set_titlebar_color(color)
        else:
            print("No valid theme color found.")

    def set_titlebar_color(self, hex_color):
        # Convert hex (e.g. "#RRGGBB") to COLORREF format for Windows.
        r, g, b = self.hex_to_rgb(hex_color)
        color = (b << 16) | (g << 8) | r
        hwnd = self.winId().__int__()  # Updated for PyQt6
        DWM_API.DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR,
                                      ctypes.byref(ctypes.c_int(color)),
                                      ctypes.sizeof(ctypes.c_int))
        DWM_API.DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR,
                                      ctypes.byref(ctypes.c_int(color)),
                                      ctypes.sizeof(ctypes.c_int))
        DWM_API.DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR,
                                      ctypes.byref(ctypes.c_int(0xFFFFFF)),
                                      ctypes.sizeof(ctypes.c_int))

    def hex_to_rgb(self, hex_color):
        hex_color = hex_color.lstrip("#")
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    def inject_startup_button(self):
        """
        Injects HTML, CSS and JavaScript into the account page that:
          - Adds a fixed-position button labeled according to the startup registry state.
          - Uses QWebChannel to call Python methods when clicked.
        """
        js_code = """
        (function() {
            // Function to insert the button if it doesn't already exist.
            function injectButton() {
                if (document.getElementById('startupToggleBtn')) return;
                var btn = document.createElement('button');
                btn.id = 'startupToggleBtn';
                btn.style.position = 'fixed';
                btn.style.bottom = '20px';
                btn.style.right = '20px';
                btn.style.padding = '10px 20px';
                btn.style.zIndex = '10000';
                // When clicked, call the exposed Python method to toggle startup.
                btn.onclick = function() {
                    window.startupManager.toggleStartup(function(new_status) {
                        btn.innerText = new_status ? "Don't start on system startup"
                                                  : "Start on system startup";
                    });
                };
                document.body.appendChild(btn);
                // Set the initial button text based on whether startup is enabled.
                window.startupManager.isStartupEnabled(function(enabled) {
                    btn.innerText = enabled ? "Don't start on system startup"
                                            : "Start on system startup";
                });
            }
            // Ensure QWebChannel is loaded, then initialize it.
            if (typeof QWebChannel === 'undefined') {
                var script = document.createElement('script');
                script.src = 'qrc:///qtwebchannel/qwebchannel.js';
                script.onload = function() {
                    new QWebChannel(qt.webChannelTransport, function(channel) {
                        window.startupManager = channel.objects.startupManager;
                        injectButton();
                    });
                };
                document.head.appendChild(script);
            } else {
                new QWebChannel(qt.webChannelTransport, function(channel) {
                    window.startupManager = channel.objects.startupManager;
                    injectButton();
                });
            }
        })();
        """
        self.browser.page().runJavaScript(js_code)

###########################################################################
# 3. Run the Application
###########################################################################

if __name__ == "__main__":
    app = QApplication(sys.argv)
    base_url = "http://127.0.0.1:5000"  # Change to your actual app URL
    window = WebAppViewer(base_url)
    window.show()
    sys.exit(app.exec())