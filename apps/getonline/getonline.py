"""
    Keep you connected when required to login to portal.
    Copyright (C) 2021    Magnus Sandin <magnus.sandin@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Arguments in config file:

DEBUG:                      O: yes | no (activate debug logging)
urls_to_check:              M: list of URLs to try to connect to
detect_redirect_to:         M: hostname and path received when login requested
get_cookies_from:           O: URL to pre load sessoin cookies
destination:
    send_to:                M: URL to POST or GET login data to
    data: "terms=true"      M: data to send in POST
    method: POST            M: Method to use POST|GET
"""


import appdaemon.plugins.hass.hassapi as hass

import re
import socket
import ssl
import time

DEFAULT_CHECK_CONNECTION_EVERY = 30
SOCKET_TIMEOUT = 7.5
BUFFER_SIZE = 4096

MAX_REDIRECTS = 10

# Number of loops to skip after failed login attempt
GRACE_TIMES = 10

# Log every hour
REPORT_EVERY = 60 * 60

VERSION = 0.53


class GetOnline(hass.Hass):
    time_between_checks = DEFAULT_CHECK_CONNECTION_EVERY

    def initialize(self):
        self.servers = {}
        self.cookie_store = {}
        self.force_debug = False
        self.grace_times = 0

        self.clear_report_data()

        self.detect_redirect_to = self.args["detect_redirect_to"].lower()
        self.max_redirects = (
            self.args["max_redirects"]
            if "max_redirects" in self.args
            else MAX_REDIRECTS
        )

        h, d = self.parse_url(self.args["destination"]["send_to"])
        self.send_to = d

        for s in self.args["urls_to_check"]:
            host, data = self.parse_url(s)
            self.servers[host] = data

        self.log(f"Loaded URLs: {self.servers}")

        server = "portal.valitron.se"

        self.run_every(
            callback=self.check_connection,
            start="now",
            interval=self.time_between_checks,
        )

    def terminate(self):
        pass

    def debug(self, text):
        if self.force_debug or ("DEBUG" in self.args and self.args["DEBUG"]):
            self.log(f"DEBUG: {text}")

    def parse_url(self, s):
        try:
            use_ssl = True if s.lower().startswith("https://") else False
            standard_port = 443 if use_ssl else 80

            m = re.search(
                "^https?://([^:|/]+){1}:?(\d+)?(\S*)?", s, re.IGNORECASE
            )

            host = m.group(1)
            port = standard_port if m.group(2) is None else int(m.group(2))
            path = "/" if len(m.group(3)) == 0 else m.group(3)

            data = {
                "line": s,
                "ssl": use_ssl,
                "server": host,
                "port": port,
                "path": path,
            }

            self.debug(f"Parsed URL: {data}")
            return host, data

        except Exception as e:
            self.error(f"Unexpected exception when parsing {s} ({e})")

    def check_connection(self, kwargs=None):
        last_report = self.report_data["last_report"]
        report = True if last_report + REPORT_EVERY <= time.time() else False

        if self.grace_times > 0:
            self.grace_times -= 1
            self.log(f"Skipping check... ({self.grace_times})")
            return

        self.debug("Checking connection....")
        self.report_data["number_of_checks_done"] += 1

        for k, v in self.servers.items():
            self.report_data["number_of_servers_checked"] += 1

            self.debug(f"Checking server {v['server']}")
            server = v["server"]

            try:
                sock = self.connect(server, v["port"], v["ssl"])
                self.send_request(sock, server, v["path"])
                headers = self.get_response_headers(server, sock)
                sock.close();

                location = self.get_header("location", headers)

                if (
                    len(location)
                    and self.detect_redirect_to in location[0].lower()
                ):
                    try_login = True

                    self.log(f"Redirect detected '{location[0]}'")

                    # TODO REMOVE
                    #self.force_debug = True

                    self.follow_redirects(location[0], v)

                    if "get_cookies_from" in self.args:
                        # Make sure we have the session cookies required
                        host, data = self.parse_url(
                            self.args["get_cookies_from"]
                        )

                        # Connect and get the request (will store session cookies)
                        sock = self.connect(host, data["port"], data["ssl"])
                        self.send_request(sock, host, data["path"])
                        headers = self.get_response_headers(host, sock)
                        sock.close();

                    self.report_data["number_of_login_attempts"] += 1

                    self.debug("Sending login data")

                    # Send login
                    self.login()

                    # Re validate connection
                    sock = self.connect(server, v["port"], v["ssl"])
                    self.send_request(sock, server, v["path"])
                    headers = self.get_response_headers(server, sock)
                    sock.close();

                    location = self.get_header("location", headers)

                    if (
                        len(location)
                        and self.detect_redirect_to in location[0].lower()
                    ):
                        self.report_data["number_of_failed_logins"] += 1
                        self.grace_times = GRACE_TIMES
                    else:
                        self.report_data["number_of_successful_logins"] += 1

                else:
                    self.debug(
                        f"Got normal reply from {server}, connection good..."
                    )
                    self.force_debug = False
                    self.grace_times = 0
                    break

            except Exception as e:
                if "try_login" in locals():
                    self.grace_times = GRACE_TIMES

                self.report_data["number_of_failed_connections"] += 1

                self.error(f"Unable to communicate with {server} ({e})")
                if "DEBUG" in self.args and self.args["DEBUG"]:
                    raise e

        if report:
            self.log_report()
            self.clear_report_data()

    def follow_redirects(self, location, server_data):
        redirects = 0

        while redirects < self.max_redirects:
            redirects += 1

            if location.startswith("/"):
                self.log(f"Following relative redirect to: {location}")

                data = server_data.copy()
                data["path"] = location
                host = data["server"]
            else:
                self.log(f"Following redirect to '{location}'")
                host, data = self.parse_url(location)

            # Connect and get the request (will store session cookies)
            sock = self.connect(host, data["port"], data["ssl"])
            self.send_request(sock, host, data["path"])
            headers = self.get_response_headers(host, sock)
            sock.close();

            header = self.get_header("location", headers)
            if len(header) == 0:
                self.log(f"No more redirects...")
                break
            else:
                location = header[0]


    def log_report(self):
        rd = self.report_data

        self.log(
            "REPORT: "
            + f"Checks performed: {rd['number_of_checks_done']}, "
            + f"Servers tested: {rd['number_of_servers_checked']}, "
            + f"Failed connections: {rd['number_of_failed_connections']}, "
            + f"Login attempts: {rd['number_of_login_attempts']}, "
            + f"Successful logins: {rd['number_of_successful_logins']}, "
            + f"Failed logins: {rd['number_of_failed_logins']} "
        )

    def clear_report_data(self):
        self.report_data = {
            "last_report": time.time(),
            "number_of_checks_done": 0,
            "number_of_servers_checked": 0,
            "number_of_failed_connections": 0,
            "number_of_login_attempts": 0,
            "number_of_successful_logins": 0,
            "number_of_failed_logins": 0,
        }

    def store_cookie(self, server, header):
        try:
            m = re.search("([^=]+){1}=([^;]+)+", header, re.IGNORECASE)
            self.debug(f"Got: {m.groups()} from {header}")

            cookie = m.group(1)
            value = m.group(2)

            self.debug(f"cookie: {cookie}, value: {value}")

            if server not in self.cookie_store:
                self.cookie_store[server] = {}

            self.debug(f"Storing cookie '{cookie}' = '{value}' for {server}")
            self.cookie_store[server][cookie] = value

        except Exception as e:
            self.error(
                f"Unable to parse cookie from '{header}' "
                f"in response from '{server}' ({e})"
            )

    def get_response_headers(self, server, sock):
        data = sock.recv(BUFFER_SIZE)

        lines = data.decode().split("\r\n")

        cookies = self.get_header("Set-Cookie", lines)
        for cookie in cookies:
            self.store_cookie(server, cookie)

        return lines

    def get_header(self, header, lines):
        headers = ()

        regexp = f"^{header}:\s+(.*)$"
        for line in lines:
            m = re.search(regexp, line, re.IGNORECASE)
            if m is not None and m.groups(1) is not None:
                headers += m.groups(1)

        return headers

    def connect(self, server, port, use_ssl):
        plain_socket = socket.socket(socket.AF_INET)

        if use_ssl:
            self.debug(f"Connecting to {server} over SSL/TLS")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            s = context.wrap_socket(plain_socket, server_hostname=server)
        else:
            self.debug(f"Connecting to {server} in plain text")
            s = plain_socket

        s.connect((server, port))
        s.settimeout(SOCKET_TIMEOUT)
        return s

    def get_stored_cookie_headers(self, server):
        cookie_headers = ""

        if server in self.cookie_store:
            cookies = self.cookie_store[server]
            for c in cookies:
                self.debug(f"Adding cookie '{c}'")
                cookie_headers += f"Cookie: {c}={cookies[c]}\r\n"

        return cookie_headers

    def send_request(self, sock, server, path="/"):
        cookie_headers = self.get_stored_cookie_headers(server)

        request = bytearray(
            (
                f"GET {path} HTTP/1.1\r\n"
                + f"Host: {server}\r\n"
                + "Accept: */*\r\n"
                + "Connection: close\r\n"
                + cookie_headers
                + "\r\n"
            ).encode()
        )

        self.debug(f"Will send: {request} to {server}")
        sock.send(request)

    def login(self):
        server = self.send_to["server"]
        port = self.send_to["port"]
        path = self.send_to["path"]
        use_ssl = self.send_to["ssl"]

        self.debug(f"Will try to login to {server}{path}")

        try:
            sock = self.connect(server, port, use_ssl)
            cookie_headers = self.get_stored_cookie_headers(server)
            data = self.args["destination"]["data"]

            if self.args["destination"]["method"].lower() == "post":
                request = bytearray(
                    (
                        f"POST {path} HTTP/1.1\r\n"
                        + f"Content-Length: {len(data)}\r\n"
                        + "Content-Type: application/x-www-form-urlencoded\r\n"
                        + f"Host: {server}\r\n"
                        + "Accept: */*\r\n"
                        + "Connection: close\r\n"
                        + cookie_headers
                        + "\r\n"
                        + data
                    ).encode()
                )
            else:
                request = bytearray(
                    (
                        f"GET {path}?{data} HTTP/1.1\r\n"
                        + f"Host: {server}\r\n"
                        + "Accept: */*\r\n"
                        + "Connection: close\r\n"
                        + cookie_headers
                        + "\r\n"
                    ).encode()
                )

            self.debug(f"Will send: {request} to {server}")
            sock.send(request)
            self.log(f"Login data sent...")

            headers = self.get_response_headers(server, sock)
            sock.close()

            location = self.get_header("location", headers)
            self.follow_redirects(location[0], self.send_to)
            self.debug(f"Got response: {headers}")


        except Exception as e:
            self.error(f"Exception when trying to login to {server} ({e})")
