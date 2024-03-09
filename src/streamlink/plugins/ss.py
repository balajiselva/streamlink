"""
$description Indian live TV channels and video on-demand service. OTT service from Simplysouth.tv.
$url simplysouth.tv
$type live, vod
$account Some streams require an account and subscription
"""

import logging
import re
import time

from streamlink.plugin import Plugin, pluginargument, pluginmatcher
from streamlink.plugin.api import useragents
from streamlink.stream.hls import HLSStream


log = logging.getLogger(__name__)


@pluginmatcher(re.compile(
    r"https?://(?:www\.)?simplysouth\.tv",
))
@pluginargument(
    "username",
    help="Your Simplysouth.tv username.",
)
@pluginargument(
    "password",
    sensitive=True,
    help="Your Simplysouth.tv password.",
)
@pluginargument(
    "purge-credentials",
    action="store_true",
    help="Purge cached Simplysouth.tv credentials to initiate a new session and reauthenticate.",
)
class SimplySouthTV(Plugin):
    _m3u8_re = re.compile(r"""['"](http.+\.m3u8.*?)['"]""")
    _cookie_expiry = 3600 * 24 * 365

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._authed = self.session.http.cookies.get("session")

    @staticmethod
    def _override_encoding(res, **kwargs):
        res.encoding = "utf-8"

    def _login(self, username, password):
        # Implement the login logic for Simplysouth.tv
        # This can include sending a POST request with the username and password to the login endpoint
        # and then setting the appropriate cookies if login is successful.
        # For demonstration purposes, let's assume a successful login sets a "session" cookie.
        time_now = time.time()

        self.session.http.cookies.set(
            "session",
            "example_session_token",  # Replace this with the actual session token received upon login
            domain="www.simplysouth.tv",
            path="/",
            expires=time_now + self._cookie_expiry,
        )

        self.save_cookies()
        log.info("Successfully logged in")

    def _get_streams(self):
        self.session.http.headers.update({"User-Agent": useragents.CHROME})
        self.session.http.headers.update({"Origin": "https://www.simplysouth.tv"})

        username = self.get_option("username")
        password = self.get_option("password")

        if self.options.get("purge_credentials"):
            self.clear_cookies()
            self._authed = False
            log.info("All credentials were successfully removed")

        if self._authed:
            log.debug("Already authenticated using cached session cookie")
        elif username and password:
            self._login(username, password)
            self._authed = True

        page = self.session.http.get(self.url)
        if not self._authed:
            log.error("Failed to authenticate")
            return

        match = self._m3u8_re.search(page.text)
        if match:
            stream_url = match.group(1)
            return HLSStream.parse_variant_playlist(self.session,
                                                    stream_url,
                                                    hooks={"response": self._override_encoding})
        else:
            log.error("No stream found on the page")


__plugin__ = SimplySouthTV
