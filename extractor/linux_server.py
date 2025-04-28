import socket
import sys
import json
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTreeView, QVBoxLayout, QWidget, QMenu, QAction,
                            QInputDialog, QMessageBox, QFileDialog, QToolBar, QPushButton, QLineEdit,
                            QTextEdit, QDialog, QSplitter, QLabel, QStatusBar, QHeaderView)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QFont, QCursor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize

# تنظیمات سرور
HOST = '51.77.109.238'
PORT = 65432
BUFFER_SIZE = 1024 * 1024 * 10  # 10MB buffer for large files

def get_system_icon(file_path, is_dir):
    """Returns appropriate icon for file/directory"""
    try:
        if is_dir:
            return QIcon.fromTheme("folder")
        
        file_extension = os.path.splitext(file_path)[1].lower()
        icon_mapping = {
            '.txt': "text-x-generic",
            '.py': "text-x-python",
            '.sh': "text-x-script",
            '.c': "text-x-csrc",
            '.cpp': "text-x-c++src",
            '.h': "text-x-chdr",
            '.jpg': "image-jpeg",
            '.jpeg': "image-jpeg",
            '.png': "image-png",
            '.gif': "image-gif",
            '.bmp': "image-bmp",
            '.mp3': "audio-x-generic",
            '.wav': "audio-x-wav",
            '.ogg': "audio-x-vorbis+ogg",
            '.mp4': "video-x-generic",
            '.avi': "video-x-msvideo",
            '.mkv': "video-x-matroska",
            '.pdf': "application-pdf",
            '.zip': "application-zip",
            '.tar': "application-x-tar",
            '.gz': "application-x-gzip",
            '.rar': "application-x-rar",
            '.html': "text-html",
            '.htm': "text-html",
            '.doc': "application-msword",
            '.docx': "application-vnd.openxmlformats-officedocument.wordprocessingml.document",
            '.xls': "application-vnd.ms-excel",
            '.xlsx': "application-vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            '.ppt': "application-vnd.ms-powerpoint",
            '.pptx': "application-vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        return QIcon.fromTheme(icon_mapping.get(file_extension, "text-x-generic"))
    except Exception:
        return QIcon.fromTheme("folder" if is_dir else "text-x-generic")

class ServerConnectionThread(QThread):
    """Thread for establishing server connection"""
    connected = pyqtSignal(socket.socket)
    error = pyqtSignal(str)
    
    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout
            sock.connect((HOST, PORT))
            self.connected.emit(sock)
        except Exception as e:
            self.error.emit(f"Connection error: {str(e)}")

class CommandThread(QThread):
    """Thread for sending commands to server"""
    response_received = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)  # For tracking progress
    
    def __init__(self, sock, command):
        super().__init__()
        self.sock = sock
        self.command = command
    
    def run(self):
        try:
            # Send command
            self.sock.sendall(json.dumps(self.command).encode('utf-8'))
            
            # Receive response
            response = b""
            while True:
                data = self.sock.recv(BUFFER_SIZE)
                if not data:
                    break
                response += data
                # Emit progress (simple implementation)
                self.progress.emit(len(response))
            
            try:
                parsed_response = json.loads(response.decode('utf-8'))
                self.response_received.emit(parsed_response)
            except json.JSONDecodeError:
                self.error.emit("Invalid server response format")
        except Exception as e:
            self.error.emit(f"Command error: {str(e)}")

class FileTransferDialog(QDialog):
    """Dialog for showing file transfer progress"""
    def __init__(self, parent=None, operation="Uploading", filename=""):
        super().__init__(parent)
        self.setWindowTitle(f"{operation} File")
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        self.status_label = QLabel(f"{operation} {filename}...")
        layout.addWidget(self.status_label)
        
        self.progress_label = QLabel("Progress: 0%")
        layout.addWidget(self.progress_label)
        
        self.setLayout(layout)
    
    def update_progress(self, progress):
        """Update progress display"""
        self.progress_label.setText(f"Progress: {progress}%")

class TextEditor(QDialog):
    """Text file editor dialog"""
    def __init__(self, parent=None, file_content="", file_path=""):
        super().__init__(parent)
        self.setWindowTitle(f"Editing: {os.path.basename(file_path)}")
        self.resize(800, 600)
        
        layout = QVBoxLayout()
        
        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Monospace", 10))
        self.text_edit.setText(file_content)
        layout.addWidget(self.text_edit)
        
        # Buttons
        button_layout = QVBoxLayout()
        
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.accept)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def get_content(self):
        """Get edited content"""
        return self.text_edit.toPlainText()

class RemoteFileExplorer(QMainWindow):
    """Main application window"""
    def __init__(self):
        super().__init__()
        self.sock = None
        self.current_path = "/"
        self.file_list = []
        
        self.setWindowTitle("Remote File Explorer")
        self.resize(1000, 700)
        
        # Main widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Layout
        main_layout = QVBoxLayout(self.central_widget)
        
        # Create toolbar
        self.create_toolbar()
        
        # Current path display
        path_layout = QVBoxLayout()
        path_label = QLabel("Current Path:")
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        path_layout.addWidget(path_label)
        path_layout.addWidget(self.path_edit)
        main_layout.addLayout(path_layout)
        
        # File tree view
        self.tree_view = QTreeView()
        self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self.show_context_menu)
        self.tree_view.doubleClicked.connect(self.item_double_clicked)
        
        # Model for tree view
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modified'])
        self.tree_view.setModel(self.model)
        
        # Configure columns
        header = self.tree_view.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        main_layout.addWidget(self.tree_view)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Connect to server
        self.connect_to_server()

    def create_toolbar(self):
        """Create the main toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        # Reload button
        reload_action = QAction(QIcon.fromTheme("view-refresh"), "Reload", self)
        reload_action.setShortcut("F5")
        reload_action.triggered.connect(self.reload_current_directory)
        toolbar.addAction(reload_action)
        
        # Go up button
        up_action = QAction(QIcon.fromTheme("go-up"), "Go Up", self)
        up_action.setShortcut("Alt+Up")
        up_action.triggered.connect(self.go_up)
        toolbar.addAction(up_action)
        
        toolbar.addSeparator()
        
        # New folder
        new_folder_action = QAction(QIcon.fromTheme("folder-new"), "New Folder", self)
        new_folder_action.setShortcut("Ctrl+N")
        new_folder_action.triggered.connect(self.create_new_folder)
        toolbar.addAction(new_folder_action)
        
        # Upload
        upload_action = QAction(QIcon.fromTheme("document-send"), "Upload", self)
        upload_action.setShortcut("Ctrl+U")
        upload_action.triggered.connect(self.upload_file)
        toolbar.addAction(upload_action)
        
        # Download
        download_action = QAction(QIcon.fromTheme("document-save"), "Download", self)
        download_action.setShortcut("Ctrl+S")
        download_action.triggered.connect(self.download_selected)
        toolbar.addAction(download_action)

    def connect_to_server(self):
        """Establish connection to the remote server"""
        self.status_bar.showMessage("Connecting to server...")
        
        self.connection_thread = ServerConnectionThread()
        self.connection_thread.connected.connect(self.on_connected)
        self.connection_thread.error.connect(self.on_connection_error)
        self.connection_thread.start()

    def on_connected(self, sock):
        """Handle successful connection"""
        self.sock = sock
        self.status_bar.showMessage("Connected to server")
        self.list_directory(self.current_path)

    def on_connection_error(self, error_message):
        """Handle connection errors"""
        self.status_bar.showMessage(f"Connection failed: {error_message}")
        QMessageBox.critical(self, "Connection Error", 
                            f"Failed to connect to server:\n{error_message}\n\n"
                            "Please check your network connection and try again.")

    def list_directory(self, path):
        """List directory contents from server"""
        if not self.sock:
            QMessageBox.warning(self, "Error", "Not connected to server")
            return
            
        self.current_path = os.path.normpath(path).replace("\\", "/")
        self.path_edit.setText(self.current_path)
        
        command = {
            "command": "list",
            "path": self.current_path
        }
        
        self.status_bar.showMessage(f"Loading: {self.current_path}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(self.on_list_response)
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()

    def on_list_response(self, response):
        """Handle directory listing response"""
        if response.get("status") == "success":
            self.file_list = response.get("files", [])
            self.update_file_view()
            self.status_bar.showMessage(f"Loaded: {self.current_path}")
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to list directory:\n{error_message}")

    def update_file_view(self):
        """Update the file tree view"""
        self.model.clear()
        self.model.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modified'])
        
        # Add parent directory entry (..)
        if self.current_path != "/":
            parent_item = QStandardItem("..")
            parent_item.setIcon(QIcon.fromTheme("go-up"))
            parent_item.setData({"name": "..", "is_dir": True}, Qt.UserRole)
            self.model.appendRow([parent_item, QStandardItem(""), QStandardItem("Parent Directory"), QStandardItem("")])
        
        # Add files and directories
        for file_info in sorted(self.file_list, key=lambda x: (not x['is_dir'], x['name'].lower())):
            name = file_info.get("name", "")
            is_dir = file_info.get("is_dir", False)
            size = file_info.get("size", 0)
            modified = file_info.get("modified", "")
            
            # Name column
            name_item = QStandardItem(name)
            name_item.setIcon(get_system_icon(name, is_dir))
            name_item.setData(file_info, Qt.UserRole)
            
            # Size column (formatted)
            size_str = self.format_size(size) if not is_dir else ""
            size_item = QStandardItem(size_str)
            
            # Type column
            type_item = QStandardItem("Folder" if is_dir else "File")
            
            # Modified column
            modified_item = QStandardItem(modified)
            
            self.model.appendRow([name_item, size_item, type_item, modified_item])
        
        self.tree_view.sortByColumn(0, Qt.AscendingOrder)

    def format_size(self, size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def on_command_error(self, error_message):
        """Handle command execution errors"""
        QMessageBox.critical(self, "Error", f"Operation failed:\n{error_message}")
        self.status_bar.showMessage(f"Error: {error_message}")

    def item_double_clicked(self, index):
        """Handle double-click on items"""
        item = self.model.itemFromIndex(index)
        if not item:
            return
            
        file_info = item.data(Qt.UserRole)
        if not file_info:
            return
            
        name = file_info.get("name", "")
        is_dir = file_info.get("is_dir", False)
        
        if name == "..":
            self.go_up()
        elif is_dir:
            new_path = os.path.join(self.current_path, name).replace("\\", "/")
            self.list_directory(new_path)
        else:
            self.open_file(file_info)

    def open_file(self, file_info):
        """Open a file for viewing/editing"""
        name = file_info.get("name", "")
        full_path = os.path.join(self.current_path, name).replace("\\", "/")
        
        command = {
            "command": "get_file",
            "path": full_path
        }
        
        self.status_bar.showMessage(f"Opening: {name}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(lambda r: self.on_file_downloaded(r, name))
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()

    def on_file_downloaded(self, response, filename):
        """Handle downloaded file"""
        if response.get("status") != "success":
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to download file:\n{error_message}")
            return
            
        file_content = response.get("content", "")
        extension = os.path.splitext(filename)[1].lower()
        
        # Text files - open in editor
        if extension in ['.txt', '.py', '.sh', '.c', '.cpp', '.h', 
                        '.html', '.htm', '.css', '.js', '.json', '.xml', '.md']:
            full_path = os.path.join(self.current_path, filename).replace("\\", "/")
            self.edit_text_file(file_content, full_path)
        else:
            # Binary files - save to temp and open with default app
            self.save_and_open_temp_file(filename, file_content)

    def save_and_open_temp_file(self, filename, content):
        """Save file to temp location and open with default app"""
        temp_dir = os.path.join(os.path.expanduser("~"), ".remote_explorer_temp")
        os.makedirs(temp_dir, exist_ok=True)
        
        temp_file = os.path.join(temp_dir, filename)
        try:
            mode = 'wb' if isinstance(content, bytes) else 'w'
            with open(temp_file, mode) as f:
                f.write(content)
            
            # Open with default application
            if sys.platform == 'linux':
                os.system(f"xdg-open '{temp_file}'")
            elif sys.platform == 'darwin':
                os.system(f"open '{temp_file}'")
            elif sys.platform == 'win32':
                os.startfile(temp_file)
            
            self.status_bar.showMessage(f"Opened: {filename}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open file:\n{str(e)}")

    def edit_text_file(self, content, file_path):
        """Open text file in editor"""
        dialog = TextEditor(self, content, file_path)
        if dialog.exec_() == QDialog.Accepted:
            self.save_file(file_path, dialog.get_content())

    def save_file(self, file_path, content):
        """Save file to server"""
        command = {
            "command": "save_file",
            "path": file_path,
            "content": content
        }
        
        self.status_bar.showMessage(f"Saving: {os.path.basename(file_path)}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(self.on_file_saved)
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()

    def on_file_saved(self, response):
        """Handle file save response"""
        if response.get("status") == "success":
            self.status_bar.showMessage("File saved successfully")
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to save file:\n{error_message}")

    def show_context_menu(self, position):
        """Show context menu for file operations"""
        index = self.tree_view.indexAt(position)
        if not index.isValid():
            return
            
        item = self.model.itemFromIndex(index)
        if not item:
            return
            
        file_info = item.data(Qt.UserRole)
        if not file_info:
            return
            
        name = file_info.get("name", "")
        is_dir = file_info.get("is_dir", False)
        
        menu = QMenu(self)
        
        # Open action
        open_action = QAction("Open", self)
        open_action.triggered.connect(lambda: self.item_double_clicked(index))
        menu.addAction(open_action)
        
        if not is_dir:
            # Edit action for files
            edit_action = QAction("Edit", self)
            edit_action.triggered.connect(lambda: self.item_double_clicked(index))
            menu.addAction(edit_action)
            
            # Download action
            download_action = QAction("Download", self)
            download_action.triggered.connect(lambda: self.download_file(file_info))
            menu.addAction(download_action)
        
        menu.addSeparator()
        
        # Rename action
        rename_action = QAction("Rename", self)
        rename_action.triggered.connect(lambda: self.rename_item(file_info))
        menu.addAction(rename_action)
        
        # Delete action
        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(lambda: self.delete_item(file_info))
        menu.addAction(delete_action)
        
        menu.exec_(self.tree_view.viewport().mapToGlobal(position))

    def download_file(self, file_info):
        """Download file from server"""
        name = file_info.get("name", "")
        full_path = os.path.join(self.current_path, name).replace("\\", "/")
        
        save_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Save File", 
            name,
            "All Files (*)"
        )
        
        if not save_path:
            return
            
        command = {
            "command": "get_file",
            "path": full_path
        }
        
        self.status_bar.showMessage(f"Downloading: {name}")
        
        # Show progress dialog
        progress_dialog = FileTransferDialog(self, "Downloading", name)
        progress_dialog.show()
        
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(
            lambda r: self.on_download_complete(r, save_path, progress_dialog))
        self.command_thread.error.connect(
            lambda e: self.on_download_error(e, progress_dialog))
        self.command_thread.progress.connect(
            lambda p: progress_dialog.update_progress(min(100, p // (1024 * 1024))))
        self.command_thread.start()

    def on_download_complete(self, response, save_path, dialog):
        """Handle completed download"""
        dialog.close()
        
        if response.get("status") != "success":
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Download failed:\n{error_message}")
            return
            
        file_content = response.get("content", "")
        try:
            mode = 'wb' if isinstance(file_content, bytes) else 'w'
            with open(save_path, mode) as f:
                f.write(file_content)
            self.status_bar.showMessage(f"Downloaded: {os.path.basename(save_path)}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save file:\n{str(e)}")

    def on_download_error(self, error_message, dialog):
        """Handle download error"""
        dialog.close()
        QMessageBox.critical(self, "Error", f"Download failed:\n{error_message}")

    def rename_item(self, file_info):
        """Rename file/folder"""
        old_name = file_info.get("name", "")
        old_path = os.path.join(self.current_path, old_name).replace("\\", "/")
        
        new_name, ok = QInputDialog.getText(
            self, 
            "Rename", 
            "New name:", 
            text=old_name
        )
        
        if not ok or not new_name or new_name == old_name:
            return
            
        new_path = os.path.join(self.current_path, new_name).replace("\\", "/")
        
        command = {
            "command": "rename",
            "old_path": old_path,
            "new_path": new_path
        }
        
        self.status_bar.showMessage(f"Renaming: {old_name} to {new_name}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(self.on_rename_response)
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()

    def on_rename_response(self, response):
        """Handle rename response"""
        if response.get("status") == "success":
            self.status_bar.showMessage("Renamed successfully")
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Rename failed:\n{error_message}")

    def delete_item(self, file_info):
        """Delete file/folder"""
        name = file_info.get("name", "")
        is_dir = file_info.get("is_dir", False)
        path = os.path.join(self.current_path, name).replace("\\", "/")
        
        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete {'folder' if is_dir else 'file'} '{name}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            return
            
        command = {
            "command": "delete",
            "path": path,
            "is_dir": is_dir
        }
        
        self.status_bar.showMessage(f"Deleting: {name}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(self.on_delete_response)
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()

    def on_delete_response(self, response):
        """Handle delete response"""
        if response.get("status") == "success":
            self.status_bar.showMessage("Deleted successfully")
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Delete failed:\n{error_message}")

    def upload_file(self):
        """Upload file to server"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select File to Upload",
            "",
            "All Files (*)"
        )
        
        if not file_path:
            return
            
        filename = os.path.basename(file_path)
        dest_path = os.path.join(self.current_path, filename).replace("\\", "/")
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Show progress dialog
            progress_dialog = FileTransferDialog(self, "Uploading", filename)
            progress_dialog.show()
            
            command = {
                "command": "upload_file",
                "path": dest_path,
                "content": content.decode('latin1') if isinstance(content, bytes) else content
            }
            
            self.status_bar.showMessage(f"Uploading: {filename}")
            
            self.command_thread = CommandThread(self.sock, command)
            self.command_thread.response_received.connect(
                lambda r: self.on_upload_response(r, progress_dialog))
            self.command_thread.error.connect(
                lambda e: self.on_upload_error(e, progress_dialog))
            self.command_thread.progress.connect(
                lambda p: progress_dialog.update_progress(min(100, p // (1024 * 1024))))
            self.command_thread.start()
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to read file:\n{str(e)}")

    def on_upload_response(self, response, dialog):
        """Handle upload response"""
        dialog.close()
        if response.get("status") == "success":
            self.status_bar.showMessage("Uploaded successfully")
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Upload failed:\n{error_message}")

    def on_upload_error(self, error_message, dialog):
        """Handle upload error"""
        dialog.close()
        QMessageBox.critical(self, "Error", f"Upload failed:\n{error_message}")

    def create_new_folder(self):
        """Create new directory on server"""
        name, ok = QInputDialog.getText(
            self,
            "New Folder",
            "Enter folder name:"
        )
        
        if not ok or not name:
            return
            
        new_path = os.path.join(self.current_path, name).replace("\\", "/")
        
        command = {
            "command": "create_dir",
            "path": new_path
        }
        
        self.status_bar.showMessage(f"Creating folder: {name}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(self.on_new_folder_response)
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()

    def on_new_folder_response(self, response):
        """Handle new folder creation response"""
        if response.get("status") == "success":
            self.status_bar.showMessage("Folder created successfully")
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to create folder:\n{error_message}")

    def go_up(self):
        """Navigate to parent directory"""
        if self.current_path == "/":
            return
            
        parent_path = os.path.dirname(self.current_path)
        if not parent_path:  # Handle root case
            parent_path = "/"
            
        self.list_directory(parent_path)

    def reload_current_directory(self):
        """Reload current directory"""
        self.list_directory(self.current_path)

    def download_selected(self):
        """Download currently selected file"""
        index = self.tree_view.currentIndex()
        if not index.isValid():
            QMessageBox.warning(self, "Warning", "No file selected")
            return
            
        item = self.model.itemFromIndex(index)
        if not item:
            return
            
        file_info = item.data(Qt.UserRole)
        if not file_info or file_info.get("is_dir", False):
            QMessageBox.warning(self, "Warning", "Please select a file to download")
            return
            
        self.download_file(file_info)

    def closeEvent(self, event):
        """Handle window close event"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RemoteFileExplorer()
    window.show()
    sys.exit(app.exec_())
