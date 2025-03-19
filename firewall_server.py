# www.theforage.com - Telstra Cyber Task 3
# Firewall Server Handler - Enhanced for Spring4Shell Protection

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

host = "localhost"
port = 8000

# Function to block requests
def block_request(self):
    self.send_response(403)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Blocked: Suspicious activity detected."}')
    print(f"[!] Blocked request from {self.client_address}")

# Function to allow safe requests
def handle_request(self):
    self.send_response(200)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Request received."}')

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_request(self)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode()

        # Suspicious Spring4Shell exploitation patterns
        blocked_patterns = [
            "class.module.classLoader",
            "Runtime.getRuntime().exec",
            "pipeline.first.pattern",
            "<%",
            "%>//"
        ]

        # Suspicious headers commonly used in the attack
        blocked_headers = ["suffix", "c1", "c2"]

        # Check if payload contains malicious patterns
        if any(pattern in post_data for pattern in blocked_patterns):
            print(f"[!] Detected malicious payload: {post_data[:100]}...")  # Log first 100 chars for visibility
            block_request(self)
            return  # Ensure the request is not processed further

        # Check if malicious headers are present
        for header in blocked_headers:
            if header in self.headers:
                print(f"[!] Detected malicious header: {header}")
                block_request(self)
                return  # Ensure the request is not processed further

        handle_request(self)  # Process request normally if no threats found

if __name__ == "__main__":        
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server is running")
    print(f"[+] Listening on {host}:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)
