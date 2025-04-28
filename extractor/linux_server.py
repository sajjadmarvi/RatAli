import socket
import sys
import json
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTreeView, QVBoxLayout, QWidget, QMenu, QAction,
                            QInputDialog, QMessageBox, QFileDialog, QToolBar, QPushButton, QLineEdit,
                            QTextEdit, QDialog, QSplitter, QLabel, QStatusBar, QHeaderView)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QFont, QCursor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize

HOST = '51.77.109.238'
PORT = 65432

def get_system_icon(file_path, is_dir):
    """
    جایگزین تابع آیکون ویندوزی با نسخه سازگار با لینوکس
    """
    try:
        if is_dir:
            # استفاده از آیکون پیش‌فرض برای پوشه‌ها
            return QIcon.fromTheme("folder")
        else:
            # تشخیص نوع فایل براساس پسوند
            file_extension = os.path.splitext(file_path)[1].lower()
            
            # تخصیص آیکون براساس پسوند فایل
            if file_extension in ['.txt', '.py', '.sh', '.c', '.cpp', '.h']:
                return QIcon.fromTheme("text-x-generic")
            elif file_extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                return QIcon.fromTheme("image-x-generic")
            elif file_extension in ['.mp3', '.wav', '.ogg']:
                return QIcon.fromTheme("audio-x-generic")
            elif file_extension in ['.mp4', '.avi', '.mkv']:
                return QIcon.fromTheme("video-x-generic")
            elif file_extension in ['.pdf']:
                return QIcon.fromTheme("application-pdf")
            elif file_extension in ['.zip', '.tar', '.gz', '.rar']:
                return QIcon.fromTheme("package-x-generic")
            elif file_extension in ['.html', '.htm']:
                return QIcon.fromTheme("text-html")
            elif file_extension in ['.doc', '.docx']:
                return QIcon.fromTheme("x-office-document")
            elif file_extension in ['.xls', '.xlsx']:
                return QIcon.fromTheme("x-office-spreadsheet")
            elif file_extension in ['.ppt', '.pptx']:
                return QIcon.fromTheme("x-office-presentation")
            else:
                return QIcon.fromTheme("text-x-generic")
    except Exception:
        # آیکون پیش‌فرض در صورت بروز خطا
        return QIcon.fromTheme("folder" if is_dir else "text-x-generic")

class ServerConnectionThread(QThread):
    """
    کلاس برای اتصال به سرور در یک ترد جداگانه
    """
    connected = pyqtSignal(socket.socket)
    error = pyqtSignal(str)
    
    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            self.connected.emit(sock)
        except Exception as e:
            self.error.emit(str(e))

class CommandThread(QThread):
    """
    کلاس برای ارسال دستورات به سرور در یک ترد جداگانه
    """
    response_received = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, sock, command):
        super().__init__()
        self.sock = sock
        self.command = command
    
    def run(self):
        try:
            # ارسال دستور به سرور
            self.sock.sendall(json.dumps(self.command).encode('utf-8'))
            
            # دریافت پاسخ
            data = self.sock.recv(1024 * 1024)  # بافر بزرگ برای فایل‌های بزرگ
            response = json.loads(data.decode('utf-8'))
            self.response_received.emit(response)
        except Exception as e:
            self.error.emit(str(e))

class FileTransferDialog(QDialog):
    """
    دیالوگ نمایش پیشرفت انتقال فایل
    """
    def __init__(self, parent=None, operation="Uploading"):
        super().__init__(parent)
        self.setWindowTitle(f"{operation} File")
        self.setMinimumWidth(300)
        
        layout = QVBoxLayout()
        self.status_label = QLabel(f"{operation} in progress...")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)

class TextEditor(QDialog):
    """
    دیالوگ ویرایش فایل متنی
    """
    def __init__(self, parent=None, file_content="", file_path=""):
        super().__init__(parent)
        self.setWindowTitle(f"Edit: {os.path.basename(file_path)}")
        self.resize(800, 600)
        
        layout = QVBoxLayout()
        
        self.text_edit = QTextEdit()
        self.text_edit.setText(file_content)
        layout.addWidget(self.text_edit)
        
        # دکمه‌های ذخیره و لغو
        buttons_layout = QVBoxLayout()
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        
        buttons_layout.addWidget(save_button)
        buttons_layout.addWidget(cancel_button)
        
        layout.addLayout(buttons_layout)
        self.setLayout(layout)
    
    def get_content(self):
        return self.text_edit.toPlainText()

class RemoteFileExplorer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sock = None
        self.current_path = "/"
        self.file_list = []
        
        self.setWindowTitle("Remote File Explorer")
        self.resize(900, 600)
        
        # ایجاد ویجت اصلی
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # چیدمان اصلی
        main_layout = QVBoxLayout(self.central_widget)
        
        # ایجاد نوار ابزار
        self.create_toolbar()
        
        # مسیر فعلی
        path_layout = QVBoxLayout()
        path_label = QLabel("Current Path:")
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        path_layout.addWidget(path_label)
        path_layout.addWidget(self.path_edit)
        main_layout.addLayout(path_layout)
        
        # نمای درختی فایل‌ها
        self.tree_view = QTreeView()
        self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self.show_context_menu)
        self.tree_view.doubleClicked.connect(self.item_double_clicked)
        
        # مدل داده‌ها برای نمایش درختی
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modified'])
        self.tree_view.setModel(self.model)
        
        # تنظیم ستون‌های نمای درختی
        header = self.tree_view.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        main_layout.addWidget(self.tree_view)
        
        # نوار وضعیت
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # اتصال به سرور
        self.connect_to_server()

    def create_toolbar(self):
        """
        ایجاد نوار ابزار با دکمه‌های مختلف
        """
        toolbar = QToolBar("File Operations")
        self.addToolBar(toolbar)
        
        # دکمه بارگذاری مجدد
        reload_action = QAction(QIcon.fromTheme("view-refresh"), "Reload", self)
        reload_action.triggered.connect(self.reload_current_directory)
        toolbar.addAction(reload_action)
        
        # دکمه رفتن به دایرکتوری بالاتر
        up_action = QAction(QIcon.fromTheme("go-up"), "Go Up", self)
        up_action.triggered.connect(self.go_up)
        toolbar.addAction(up_action)
        
        toolbar.addSeparator()
        
        # دکمه ایجاد پوشه جدید
        new_folder_action = QAction(QIcon.fromTheme("folder-new"), "New Folder", self)
        new_folder_action.triggered.connect(self.create_new_folder)
        toolbar.addAction(new_folder_action)
        
        # دکمه آپلود فایل
        upload_action = QAction(QIcon.fromTheme("document-send"), "Upload", self)
        upload_action.triggered.connect(self.upload_file)
        toolbar.addAction(upload_action)

    def connect_to_server(self):
        """
        اتصال به سرور راه دور
        """
        self.status_bar.showMessage("Connecting to server...")
        
        # اتصال در ترد جداگانه برای جلوگیری از مسدود شدن رابط کاربری
        self.connection_thread = ServerConnectionThread()
        self.connection_thread.connected.connect(self.on_connected)
        self.connection_thread.error.connect(self.on_connection_error)
        self.connection_thread.start()
    
    def on_connected(self, sock):
        """
        هنگامی که اتصال موفقیت‌آمیز برقرار شد، این تابع فراخوانی می‌شود
        """
        self.sock = sock
        self.status_bar.showMessage("Connected to server")
        self.list_directory(self.current_path)
    
    def on_connection_error(self, error_message):
        """
        هنگام خطا در اتصال، این تابع فراخوانی می‌شود
        """
        self.status_bar.showMessage(f"Connection error: {error_message}")
        QMessageBox.critical(self, "Connection Error", f"Failed to connect to server: {error_message}")
    
    def list_directory(self, path):
        """
        فهرست کردن محتویات یک دایرکتوری از سرور
        """
        self.current_path = path
        self.path_edit.setText(self.current_path)
        
        command = {
            "command": "list",
            "path": path
        }
        
        self.status_bar.showMessage(f"Loading directory: {path}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(self.on_list_response)
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()
    
    def on_list_response(self, response):
        """
        پردازش پاسخ سرور به درخواست فهرست دایرکتوری
        """
        if response.get("status") == "success":
            self.file_list = response.get("files", [])
            self.update_file_view()
            self.status_bar.showMessage(f"Directory loaded: {self.current_path}")
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to list directory: {error_message}")
            self.status_bar.showMessage(f"Error: {error_message}")
    
    def update_file_view(self):
        """
        به‌روزرسانی نمای فایل‌ها با استفاده از داده‌های دریافتی از سرور
        """
        self.model.clear()
        self.model.setHorizontalHeaderLabels(['Name', 'Size', 'Type', 'Modified'])
        
        for file_info in self.file_list:
            name = file_info.get("name", "")
            is_dir = file_info.get("is_dir", False)
            size = file_info.get("size", 0)
            file_type = "Folder" if is_dir else "File"
            modified = file_info.get("modified", "")
            
            # ایجاد آیتم نام فایل با آیکون مناسب
            name_item = QStandardItem(name)
            name_item.setIcon(get_system_icon(name, is_dir))
            name_item.setData(file_info, Qt.UserRole)  # ذخیره اطلاعات کامل فایل
            
            # ایجاد سایر ستون‌ها
            size_item = QStandardItem(str(size) if not is_dir else "")
            type_item = QStandardItem(file_type)
            modified_item = QStandardItem(modified)
            
            # افزودن ردیف به مدل
            self.model.appendRow([name_item, size_item, type_item, modified_item])
        
        # مرتب‌سازی: ابتدا پوشه‌ها، سپس فایل‌ها
        self.tree_view.sortByColumn(0, Qt.AscendingOrder)
    
    def on_command_error(self, error_message):
        """
        هنگام خطا در اجرای دستور، این تابع فراخوانی می‌شود
        """
        QMessageBox.critical(self, "Error", f"Command error: {error_message}")
        self.status_bar.showMessage(f"Error: {error_message}")
    
    def item_double_clicked(self, index):
        """
        رویداد دابل کلیک روی آیتم‌ها
        """
        # دریافت داده‌های آیتم از مدل
        item = self.model.itemFromIndex(index)
        if not item:
            return
        
        row = item.row()
        name_item = self.model.item(row, 0)
        if not name_item:
            return
        
        file_info = name_item.data(Qt.UserRole)
        if not file_info:
            return
        
        name = file_info.get("name", "")
        is_dir = file_info.get("is_dir", False)
        
        if is_dir:
            # اگر پوشه باشد، به آن دایرکتوری برو
            new_path = os.path.join(self.current_path, name).replace("\\", "/")
            self.list_directory(new_path)
        else:
            # اگر فایل باشد، آن را باز کن
            self.open_file(file_info)
    
    def open_file(self, file_info):
        """
        باز کردن فایل برای مشاهده یا ویرایش
        """
        name = file_info.get("name", "")
        full_path = os.path.join(self.current_path, name).replace("\\", "/")
        
        command = {
            "command": "get_file",
            "path": full_path
        }
        
        self.status_bar.showMessage(f"Downloading file: {full_path}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(lambda response: self.on_file_downloaded(response, name))
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()
    
    def on_file_downloaded(self, response, filename):
        """
        پردازش پاسخ سرور به درخواست دانلود فایل
        """
        if response.get("status") == "success":
            file_content = response.get("content", "")
            
            # بررسی نوع فایل و تصمیم‌گیری برای نحوه نمایش
            extension = os.path.splitext(filename)[1].lower()
            if extension in ['.txt', '.py', '.sh', '.c', '.cpp', '.h', '.html', '.htm', '.css', '.js', '.json', '.xml', '.md']:
                # فایل‌های متنی را در ویرایشگر نمایش بده
                full_path = os.path.join(self.current_path, filename).replace("\\", "/")
                self.edit_text_file(file_content, full_path)
            else:
                # سایر فایل‌ها را در مسیر موقت ذخیره کن و با برنامه پیش‌فرض باز کن
                temp_dir = os.path.join(os.path.expanduser("~"), ".remote_explorer_temp")
                if not os.path.exists(temp_dir):
                    os.makedirs(temp_dir)
                
                temp_file = os.path.join(temp_dir, filename)
                try:
                    with open(temp_file, 'wb') as f:
                        f.write(file_content.encode('latin1') if isinstance(file_content, str) else file_content)
                    
                    # باز کردن فایل با برنامه پیش‌فرض
                    # در لینوکس از xdg-open استفاده می‌کنیم
                    os.system(f"xdg-open '{temp_file}'")
                    self.status_bar.showMessage(f"File opened: {filename}")
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to open file: {str(e)}")
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to download file: {error_message}")
            self.status_bar.showMessage(f"Error: {error_message}")
    
    def edit_text_file(self, content, file_path):
        """
        ویرایش فایل متنی
        """
        dialog = TextEditor(self, content, file_path)
        if dialog.exec_() == QDialog.Accepted:
            new_content = dialog.get_content()
            self.save_file(file_path, new_content)
    
    def save_file(self, file_path, content):
        """
        ذخیره فایل در سرور
        """
        command = {
            "command": "save_file",
            "path": file_path,
            "content": content
        }
        
        self.status_bar.showMessage(f"Saving file: {file_path}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(self.on_file_saved)
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()
    
    def on_file_saved(self, response):
        """
        پردازش پاسخ سرور به درخواست ذخیره فایل
        """
        if response.get("status") == "success":
            self.status_bar.showMessage("File saved successfully")
            # بعد از ذخیره، دایرکتوری فعلی را دوباره بارگذاری کن
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to save file: {error_message}")
            self.status_bar.showMessage(f"Error: {error_message}")
    
    def show_context_menu(self, position):
        """
        نمایش منوی راست کلیک
        """
        indexes = self.tree_view.selectedIndexes()
        if not indexes:
            return
        
        # انتخاب آیتم اول از انتخاب‌ها (نام فایل)
        index = self.tree_view.model().index(indexes[0].row(), 0)
        item = self.model.itemFromIndex(index)
        if not item:
            return
        
        file_info = item.data(Qt.UserRole)
        if not file_info:
            return
        
        name = file_info.get("name", "")
        is_dir = file_info.get("is_dir", False)
        
        # ایجاد منو
        menu = QMenu(self)
        
        if is_dir:
            open_action = QAction("Open", self)
            open_action.triggered.connect(lambda: self.item_double_clicked(index))
            menu.addAction(open_action)
        else:
            open_action = QAction("Open", self)
            open_action.triggered.connect(lambda: self.item_double_clicked(index))
            menu.addAction(open_action)
            
            edit_action = QAction("Edit", self)
            edit_action.triggered.connect(lambda: self.item_double_clicked(index))
            menu.addAction(edit_action)
            
            download_action = QAction("Download", self)
            download_action.triggered.connect(lambda: self.download_file(file_info))
            menu.addAction(download_action)
        
        menu.addSeparator()
        
        rename_action = QAction("Rename", self)
        rename_action.triggered.connect(lambda: self.rename_item(file_info))
        menu.addAction(rename_action)
        
        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(lambda: self.delete_item(file_info))
        menu.addAction(delete_action)
        
        # نمایش منو
        menu.exec_(QCursor.pos())
    
    def download_file(self, file_info):
        """
        دانلود فایل از سرور به کامپیوتر محلی
        """
        name = file_info.get("name", "")
        full_path = os.path.join(self.current_path, name).replace("\\", "/")
        
        save_path, _ = QFileDialog.getSaveFileName(self, "Save File", name)
        if not save_path:
            return
        
        command = {
            "command": "get_file",
            "path": full_path
        }
        
        self.status_bar.showMessage(f"Downloading file: {full_path}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(lambda response: self.save_downloaded_file(response, save_path))
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()
    
    def save_downloaded_file(self, response, save_path):
        """
        ذخیره فایل دانلود شده در مسیر محلی
        """
        if response.get("status") == "success":
            file_content = response.get("content", "")
            try:
                with open(save_path, 'wb') as f:
                    f.write(file_content.encode('latin1') if isinstance(file_content, str) else file_content)
                self.status_bar.showMessage(f"File downloaded successfully: {save_path}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to save file: {str(e)}")
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to download file: {error_message}")
            self.status_bar.showMessage(f"Error: {error_message}")
    
    def rename_item(self, file_info):
        """
        تغییر نام فایل یا پوشه
        """
        old_name = file_info.get("name", "")
        old_path = os.path.join(self.current_path, old_name).replace("\\", "/")
        
        new_name, ok = QInputDialog.getText(self, "Rename", "New name:", text=old_name)
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
        """
        پردازش پاسخ سرور به درخواست تغییر نام
        """
        if response.get("status") == "success":
            self.status_bar.showMessage("Item renamed successfully")
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to rename item: {error_message}")
            self.status_bar.showMessage(f"Error: {error_message}")
    
    def delete_item(self, file_info):
        """
        حذف فایل یا پوشه
        """
        name = file_info.get("name", "")
        path = os.path.join(self.current_path, name).replace("\\", "/")
        is_dir = file_info.get("is_dir", False)
        
        item_type = "directory" if is_dir else "file"
        msg = f"Are you sure you want to delete this {item_type}?\n{name}"
        reply = QMessageBox.question(self, "Confirm Delete", msg, QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.No:
            return
        
        command = {
            "command": "delete",
            "path": path,
            "is_dir": is_dir
        }
        
        self.status_bar.showMessage(f"Deleting: {path}")
        self.command_thread = CommandThread(self.sock, command)
        self.command_thread.response_received.connect(self.on_delete_response)
        self.command_thread.error.connect(self.on_command_error)
        self.command_thread.start()
    
    def on_delete_response(self, response):
        """
        پردازش پاسخ سرور به درخواست حذف
        """
        if response.get("status") == "success":
            self.status_bar.showMessage("Item deleted successfully")
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to delete item: {error_message}")
            self.status_bar.showMessage(f"Error: {error_message}")
    
    def upload_file(self):
        """
        آپلود فایل به سرور
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if not file_path:
            return
        
        file_name = os.path.basename(file_path)
        destination_path = os.path.join(self.current_path, file_name).replace("\\", "/")
        
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # تبدیل محتوای باینری به رشته برای ارسال در JSON
            file_content_str = file_content.decode('latin1')
            
            command = {
                "command": "upload_file",
                "path": destination_path,
                "content": file_content_str
            }
            
            self.status_bar.showMessage(f"Uploading file: {file_name}")
            
            # نمایش دیالوگ پیشرفت آپلود
            progress_dialog = FileTransferDialog(self, "Uploading")
            progress_dialog.show()
            
            self.command_thread = CommandThread(self.sock, command)
            self.command_thread.response_received.connect(lambda response: self.on_upload_response(response, progress_dialog))
            self.command_thread.error.connect(lambda error: self.on_upload_error(error, progress_dialog))
            self.command_thread.start()
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to read file: {str(e)}")
    
    def on_upload_response(self, response, dialog):
        """
        پردازش پاسخ سرور به درخواست آپلود فایل
        """
        dialog.close()
        if response.get("status") == "success":
            self.status_bar.showMessage("File uploaded successfully")
            self.reload_current_directory()
        else:
            error_message = response.get("message", "Unknown error")
            QMessageBox.warning(self, "Error", f"Failed to upload file: {error_message}")
            self.status_bar.showMessage(