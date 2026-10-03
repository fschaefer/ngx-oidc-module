from http.server import BaseHTTPRequestHandler, HTTPServer


class App(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            "Hello, %s!\nEmail: %s\nSub: %s\n"
            % (
                self.headers.get("X-OIDC-Name", ""),
                self.headers.get("X-OIDC-Email", ""),
                self.headers.get("X-OIDC-Sub", ""),
            )
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


HTTPServer(("", 8000), App).serve_forever()
