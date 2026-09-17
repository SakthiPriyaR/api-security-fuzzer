"""
A tiny, deliberately vulnerable mock API used ONLY to validate that the
scanner correctly detects each vulnerability class. This stands in for
crAPI/vAPI so the test can run offline in any environment - swap this
out for real crAPI when you do your actual capstone validation run.

Vulnerabilities intentionally present:
  - GET /orders/{order_id}: no ownership check -> BOLA
  - GET /profile: works with NO auth at all -> Broken Auth
  - PUT /users/{user_id}/update: accepts an unlisted "isAdmin" field -> Mass Assignment
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

ORDERS = {"1": {"order_id": "1", "owner": "1", "item": "Widget"},
          "2": {"order_id": "2", "owner": "2", "item": "Gadget"}}

VALID_TOKENS = {"token-a": "1", "token-b": "2"}


class Handler(BaseHTTPRequestHandler):
    def _auth_user(self):
        auth = self.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "")
        return VALID_TOKENS.get(token)

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        if self.path.startswith("/orders/"):
            order_id = self.path.split("/orders/")[1]
            user = self._auth_user()
            if not user:
                self._send(401, {"error": "unauthorized"})
                return
            order = ORDERS.get(order_id)
            if not order:
                self._send(404, {"error": "not found"})
                return
            # VULNERABLE: no check that `user` == order["owner"]
            self._send(200, order)
            return

        if self.path == "/profile":
            # VULNERABLE: returns data with NO auth check at all
            self._send(200, {"name": "demo user", "email": "demo@example.com"})
            return

        self._send(404, {"error": "not found"})

    def do_PUT(self):
        if "/users/" in self.path and self.path.endswith("/update"):
            user = self._auth_user()
            if not user:
                self._send(401, {"error": "unauthorized"})
                return
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            # VULNERABLE: blindly reflects back any field sent, including isAdmin
            response = {"name": body.get("name", ""), "email": body.get("email", "")}
            for k, v in body.items():
                response[k] = v
            self._send(200, response)
            return
        self._send(404, {"error": "not found"})

    def log_message(self, format, *args):
        pass  # quiet


if __name__ == "__main__":
    server = HTTPServer(("localhost", 8123), Handler)
    print("Mock vulnerable API running on http://localhost:8123")
    server.serve_forever()
