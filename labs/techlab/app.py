"""TechLab: deterministic vulnerable/hardened twins of seven server stacks.

Each stack lives under its own path prefix (/wp, /php, /java, /cf, /node,
/iis, /apache) so one Flask process can stand in for seven virtual hosts:
detection reads the prefix's landing page headers/body, and the technology
modules probe under the same prefix.

LAB_MODE=vuln exposes the seeded weaknesses; LAB_MODE=hardened serves the same
stacks with the resources removed and the version banners silenced. Lab-only:
binds 127.0.0.1, fake credentials, no outbound traffic.
"""
import json
import os

from flask import Flask, Response, redirect, request

MODE = os.environ.get("LAB_MODE", "vuln")
VULN = MODE == "vuln"
PORT = int(os.environ.get("LAB_PORT", "8821" if VULN else "8822"))

app = Flask(__name__)

ROOT_BODY = {
    "wp": '<html><head><link rel="stylesheet" href="/wp/wp-content/themes/lab/style.css">'
          '<script src="/wp/wp-content/plugins/hello-dolly/hello.js"></script>'
          '<link rel="https://api.w.org/" href="/wp/wp-json/"></head>'
          "<body><h1>LabPress</h1></body></html>",
    "php": "<html><body><h1>Lab PHP application</h1></body></html>",
    "java": "<html><body><h1>Lab Spring application</h1></body></html>",
    "cf": "<html><body><h1>Lab ColdFusion application</h1></body></html>",
    "node": "<html><body><h1>Lab Express application</h1></body></html>",
    "iis": "<html><body><h1>Lab ASP.NET application</h1></body></html>",
    "apache": "<html><body><h1>Lab Apache/Nginx site</h1></body></html>",
}

# Detection markers stay in hardened mode (the stack is still identifiable);
# version disclosure and the vulnerable resources do not.
HEADERS = {
    "vuln": {
        "wp": {"X-Powered-By": "PHP/7.4.3", "Server": "Apache/2.4.41 (Ubuntu)"},
        "php": {"X-Powered-By": "PHP/7.4.3", "Server": "Apache/2.4.41 (Ubuntu)"},
        "java": {"Set-Cookie": "JSESSIONID=LABJSESSIONID123; Path=/"},
        "cf": {"Set-Cookie": "CFID=1234; CFTOKEN=5678; path=/"},
        "node": {"X-Powered-By": "Express"},
        "iis": {"Server": "Microsoft-IIS/10.0", "X-AspNet-Version": "4.0.30319"},
        "apache": {"Server": "Apache/2.4.41 (Ubuntu)"},
    },
    "hardened": {
        "wp": {"Server": "Apache/2.4.41 (Ubuntu)"},
        "php": {"Set-Cookie": "PHPSESSID=LABPHPSESSID123; Path=/"},
        "java": {"Set-Cookie": "JSESSIONID=LABJSESSIONID456; Path=/"},
        "cf": {"Set-Cookie": "CFID=9999; CFTOKEN=8888; path=/"},
        "node": {"X-Powered-By": "Express"},
        "iis": {"Server": "Microsoft-IIS/10.0"},
        "apache": {"Server": "Apache/2.4.41 (Ubuntu)"},
    },
}

WP_CONFIG_BAK = ("<?php\ndefine('DB_NAME', 'labwp');\n"
                 "define('DB_PASSWORD', 'lab-only-password');\n"
                 "define('AUTH_KEY', 'lab-only-salt');\n")

NODE_STACK = ("Error: Not Found\n    at Layer.handle [as handle_request] "
              "(/app/node_modules/express/lib/router/layer.js:95:5)\n"
              "    at next (/app/node_modules/express/lib/router/route.js:144:13)\n")

# (stack, path after the prefix) -> (status, body, extra headers)
EXPOSURES = {
    ("wp", "wp-config.php.bak"): (200, WP_CONFIG_BAK, {}),
    ("wp", "wp-config.php~"): (200, WP_CONFIG_BAK, {}),
    ("wp", "wp-content/plugins/"): (200, "<html><title>Index of /wp/wp-content/plugins</title>", {}),
    ("wp", "wp-content/plugins/hello-dolly/readme.txt"): (
        200, "=== Hello Dolly ===\nStable tag: 1.7.2\nRequires at least: 4.0\n", {}),
    ("wp", "wp-json/wp/v2/users"): (
        200, json.dumps([{"id": 1, "name": "admin", "slug": "admin"}]),
        {"Content-Type": "application/json"}),
    ("php", "phpinfo.php"): (200, "<html><body><h1>PHP Version 7.4.3</h1>"
                                 "<table><tr><td>DOCUMENT_ROOT</td><td>/var/www/lab</td></tr>"
                                 "</table></body></html>", {}),
    ("php", "index.php.bak"): (200, "<?php echo 'lab index'; ?>", {}),
    ("php", "config.php.bak"): (200, "<?php return ['db_pass' => 'lab-only']; ?>", {}),
    ("java", "actuator"): (200, json.dumps({"_links": {"self": {"href": "/java/actuator"}}}),
                           {"Content-Type": "application/json"}),
    ("java", "actuator/env"): (200, json.dumps({"activeProfiles": [],
                                                "propertySources": [{"name": "systemEnvironment"}]}),
                               {"Content-Type": "application/json"}),
    ("java", "actuator/heapdump"): (200, "JAVA PROFILE 1.0.2\nlab-only-heap",
                                    {"Content-Type": "application/octet-stream"}),
    ("java", "index.action"): (200, "<html><title>Struts Problem Report</title>"
                                    "<p>struts.devMode is enabled</p></html>", {}),
    ("cf", "CFIDE/administrator/"): (200, "<html><title>ColdFusion Administrator</title>"
                                          "<form action='enter.cfm'></form></html>", {}),
    ("cf", "CFIDE/componentutils/cfcexplorer.cfc"): (
        200, "<html><title>CFC Explorer</title><p>componentutils</p></html>", {}),
    ("node", ".env"): (200, "DB_PASSWORD=lab-only\nAPI_KEY=lab-only-key\n", {}),
    ("node", "package.json"): (200, json.dumps({"name": "lab", "dependencies":
                                                {"express": "4.18.2"}}),
                               {"Content-Type": "application/json"}),
    ("node", "debug"): (200, json.dumps({"environ": {"NODE_ENV": "production"},
                                         "secret": "lab-only"}), {}),
    ("iis", "web.config"): (200, "<configuration><connectionStrings><add "
                                 "connectionString='Server=lab;User Id=sa;Password=lab-only'/>"
                                 "</connectionStrings></configuration>", {}),
    ("iis", "trace.axd"): (200, "<html><title>Application Trace</title></html>", {}),
    ("iis", "libella~1.aspx"): (404, "<html><head><title>HTTP Error 404.0 - Not Found</title>"
                                     "</head><body></body></html>", {}),
    ("apache", "server-status"): (200, "<html><title>Apache Server Status for 127.0.0.1</title>"
                                       "</html>", {}),
    ("apache", ".htaccess"): (200, "RewriteEngine On\nAuthType Basic\n", {}),
    ("apache", "nginx.conf"): (200, "server {\n    listen 80;\n    server_name lab;\n}\n", {}),
    ("apache", "static../WEB-INF/web.xml"): (200, "<web-app><servlet/></web-app>", {}),
}

# Hardened twins keep the routes but refuse them the way the stack would.
HARDENED_OVERRIDES = {
    ("apache", ".htaccess"): (403, "<html><body>Forbidden</body></html>"),
    ("iis", "libella~1.aspx"): (400, "<html><body>Bad Request</body></html>"),
}


def _resp(body: str, status: int = 200, headers: dict | None = None) -> Response:
    return Response(body, status=status, headers=headers or {}, mimetype="text/html")


@app.get("/health")
def health():
    return {"status": "ok", "mode": MODE, "stacks": sorted(ROOT_BODY)}


@app.route("/<stack>/", defaults={"rest": ""}, methods=["GET", "POST"], strict_slashes=False)
@app.route("/<stack>/<path:rest>", methods=["GET", "POST"])
def serve(stack, rest):
    if stack not in ROOT_BODY:
        return _resp("unknown stack", 404)
    headers = dict(HEADERS[MODE][stack])
    if not rest:
        if stack == "wp" and VULN and "author" in request.args:
            return redirect(f"/wp/author/{request.args.get('author')}", code=301)
        return _resp(ROOT_BODY[stack], 200, headers)

    if stack == "wp" and rest == "xmlrpc.php":
        if not VULN:
            return _resp("Forbidden", 403, headers)
        if request.method == "POST":
            return _resp('<?xml version="1.0"?><methodResponse><params><param><value>'
                         "<array><data><value>system.listMethods</value></data></array>"
                         "</value></param></params></methodResponse>", 200,
                         {**headers, "Content-Type": "text/xml"})
        return _resp("XML-RPC server accepts POST requests only.", 405, headers)

    if not VULN:  # hardened: every seeded resource is gone
        status, body = HARDENED_OVERRIDES.get((stack, rest), (404, "Not Found"))
        return _resp(body, status, {k: v for k, v in headers.items()
                                    if k.lower() != "x-powered-by"})

    if (stack, rest) in EXPOSURES:
        status, body, extra = EXPOSURES[(stack, rest)]
        return _resp(body, status, {**headers, **extra})
    if stack == "node":  # unhandled route -> Express default error page with a stack trace
        return _resp(NODE_STACK, 404, headers)
    return _resp("Not Found", 404, headers)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
