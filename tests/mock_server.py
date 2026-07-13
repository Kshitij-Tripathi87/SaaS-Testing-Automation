"""Lightweight mock server for running tests without external dependencies.

Serves:
- A login page at /login with credential validation
- A dashboard at /dashboard (only when authenticated via cookie)
- Projects list/detail pages with tenant-scoped data
- Projects CRUD API at /api/v1/projects
- Tenant-isolated data per X-Tenant-ID header
- Role-based UI elements (admin vs employee)

Run standalone: python tests/mock_server.py
"""

import json
import uuid
import http.cookies
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

VALID_USERS = {
    "admin@company1.com": {"password": "password123", "role": "admin", "company": "Acme Corp"},
    "manager@company1.com": {"password": "password123", "role": "manager", "company": "Acme Corp"},
    "employee@company1.com": {"password": "password123", "role": "employee", "company": "Acme Corp"},
    "user@company2.com": {"password": "password123", "role": "admin", "company": "Globex Inc"},
    "admin@company2.com": {"password": "password123", "role": "admin", "company": "Globex Inc"},
}

VALID_CREDENTIALS_JSON = """{"admin@company1.com":"password123","manager@company1.com":"password123","employee@company1.com":"password123","user@company2.com":"password123","admin@company2.com":"password123"}"""

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>WorkFlow Pro - Login</title></head><body>
<div data-testid="login-form" id="login-form">
  <input data-testid="email-input" id="email" type="email" />
  <input data-testid="password-input" id="password" type="password" />
  <button data-testid="login-btn" id="login-btn">Login</button>
  <div data-testid="login-error" id="login-error" style="display:none">Invalid credentials</div>
  <div data-testid="email-error" id="email-error" style="display:none">Email is required</div>
  <div data-testid="password-error" id="password-error" style="display:none">Password is required</div>
</div>
<script>
var USERS = """ + VALID_CREDENTIALS_JSON + """;
document.getElementById('login-btn').onclick = function() {
  var email = document.getElementById('email').value;
  var pass = document.getElementById('password').value;
  document.getElementById('email-error').style.display = 'none';
  document.getElementById('password-error').style.display = 'none';
  document.getElementById('login-error').style.display = 'none';
  if (!email) {
    document.getElementById('email-error').style.display = 'block';
  }
  if (!pass) {
    document.getElementById('password-error').style.display = 'block';
  }
  if (email && pass) {
    if (USERS[email] === pass) {
      document.cookie = 'session_email=' + email + '; path=/';
      window.location.href = '/dashboard';
    } else {
      document.getElementById('login-error').style.display = 'block';
    }
  }
};
</script>
</body></html>"""

DASHBOARD_PAGE_ADMIN = """<!DOCTYPE html>
<html><head><title>WorkFlow Pro - Dashboard</title></head><body>
<div data-testid="welcome-message" class="welcome-message">Welcome!</div>
<nav>
  <a data-testid="nav-projects" href="/projects">Projects</a>
  <button data-testid="create-project-btn">Create Project</button>
  <button data-testid="manage-users-btn">Manage Users</button>
</nav>
</body></html>"""

DASHBOARD_PAGE_EMPLOYEE = """<!DOCTYPE html>
<html><head><title>WorkFlow Pro - Dashboard</title></head><body>
<div data-testid="welcome-message" class="welcome-message">Welcome!</div>
<nav>
  <a data-testid="nav-projects" href="/projects">Projects</a>
  <button data-testid="create-project-btn" style="display:none">Create Project</button>
</nav>
</body></html>"""

PROJECTS_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>WorkFlow Pro - Projects</title></head><body>
<div data-testid="project-list">
  <div data-testid="loading-spinner" style="display:none">Loading...</div>
  <input data-testid="search-projects" placeholder="Search..." />
  {project_cards}
</div>
</body></html>"""

COMPANY_NAMES = {"company1": "Acme Corp", "company2": "Globex Inc"}

PROJECT_CARD_TEMPLATE = """<div data-testid="project-card" class="project-card">
  <a data-testid="project-link" href="/projects/{id}">{name}</a>
  <span data-testid="project-card-name">{name}</span>
  <span data-testid="project-card-status">{status}</span>
  <span data-testid="project-card-company">{company_name}</span>
</div>"""

PROJECT_DETAIL_PAGE = """<!DOCTYPE html>
<html><head><title>{name} - Project</title></head><body>
<h1 data-testid="project-name">{name}</h1>
<p data-testid="project-status">{status}</p>
<p data-testid="project-description">{description}</p>
</body></html>"""

_projects = {
    "company1": [
        {"id": "proj-a1b2", "name": "Q4 Marketing Campaign", "status": "active", "company": "company1", "description": "Marketing Q4", "team_members": []},
        {"id": "proj-c3d4", "name": "Product Launch v2", "status": "active", "company": "company1", "description": "Product launch", "team_members": []},
    ],
    "company2": [
        {"id": "proj-e5f6", "name": "Data Migration", "status": "active", "company": "company2", "description": "Migration project", "team_members": []},
    ],
}


class MockHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def _tenant_id(self):
        return self.headers.get("X-Tenant-ID", "company1")

    def _get_user_from_cookie(self):
        cookie_header = self.headers.get("Cookie", "")
        cookies = http.cookies.SimpleCookie(cookie_header)
        if "session_email" in cookies:
            email = cookies["session_email"].value
            if email in VALID_USERS:
                return VALID_USERS[email], email
        return None, None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/login", "/"):
            user, _ = self._get_user_from_cookie()
            if user:
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.end_headers()
                return
            self._send_html(LOGIN_PAGE)

        elif path == "/dashboard":
            user, email = self._get_user_from_cookie()
            if not user:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            if user["role"] == "employee":
                self._send_html(DASHBOARD_PAGE_EMPLOYEE)
            else:
                self._send_html(DASHBOARD_PAGE_ADMIN)

        elif path == "/projects":
            user, email = self._get_user_from_cookie()
            tenant = "company2" if email and "company2" in email else "company1"
            cards = ""
            for p in _projects.get(tenant, []):
                p_display = dict(p)
                p_display["company_name"] = COMPANY_NAMES.get(p["company"], p["company"])
                cards += PROJECT_CARD_TEMPLATE.format(**p_display)
            html = PROJECTS_PAGE_TEMPLATE.format(
                project_cards=cards or "<p>No projects</p>"
            )
            self._send_html(html)

        elif path.startswith("/projects/"):
            pid = path.split("/")[-1]
            user, _ = self._get_user_from_cookie()
            tenant = "company1"
            for t in ("company1", "company2"):
                for p in _projects.get(t, []):
                    if p["id"] == pid:
                        self._send_html(PROJECT_DETAIL_PAGE.format(**p))
                        return
            self._send_html("<h1>Not found</h1>", 404)

        elif path == "/api/v1/projects":
            tenant = self._tenant_id()
            all_projects = _projects.get(tenant, [])
            self._send_json({"projects": all_projects})

        elif path.startswith("/api/v1/projects/"):
            pid = path.split("/")[-1]
            tenant = self._tenant_id()
            intruder_tenant = None
            for t in ("company1", "company2"):
                for p in _projects.get(t, []):
                    if p["id"] == pid:
                        if t != tenant:
                            intruder_tenant = t
                        else:
                            self._send_json(p)
                            return
            if intruder_tenant:
                self._send_json({"error": "Forbidden"}, 403)
            else:
                self._send_json({"error": "Not found"}, 404)

        elif path == "/api/v1/auth/login":
            self._send_json({"token": "mock-token"})

        else:
            self._send_html("<h1>Not found</h1>", 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_body()

        if path == "/api/v1/projects":
            tenant = self._tenant_id()
            data = body if body else {}
            project = {
                "id": uuid.uuid4().hex[:12],
                "name": data.get("name", "Untitled"),
                "description": data.get("description", ""),
                "status": "active",
                "company": tenant,
                "team_members": data.get("team_members", []),
                "metadata": data.get("metadata", {}),
            }
            if tenant not in _projects:
                _projects[tenant] = []
            _projects[tenant].append(project)
            self._send_json(project, 201)

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/v1/projects/"):
            pid = path.split("/")[-1]
            tenant = self._tenant_id()
            for p in _projects.get(tenant, []):
                if p["id"] == pid:
                    self._send_json(p)
                    return
            self._send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/v1/projects/"):
            pid = path.split("/")[-1]
            tenant = self._tenant_id()
            for p in _projects.get(tenant, []):
                if p["id"] == pid:
                    _projects[tenant].remove(p)
                    self._send_json({"deleted": pid})
                    return
            self._send_json({"error": "Not found"}, 404)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            raw = self.rfile.read(length).decode()
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return json.loads(raw)
            return parse_qs(raw)
        return {}

    def log_message(self, format, *args):
        pass


def run_mock_server(host="127.0.0.1", port=8765):
    server = HTTPServer((host, port), MockHandler)
    print(f"Mock server running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    run_mock_server()
