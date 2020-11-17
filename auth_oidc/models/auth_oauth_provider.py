# -*- coding: utf-8 -*-
# Copyright© 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2020 Camptocamp
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import json
import logging
import re
from urllib.request import urlopen

from jose import jwt
from openerp import api, fields, models

_logger = logging.getLogger(__name__)


class AuthOauthProvider(models.Model):
    _inherit = "auth.oauth.provider"

    flow = fields.Selection(
        [("access_token", "OAuth2"), ("id_token", "OpenID Connect")],
        string="Auth Flow",
        required=True,
        default="access_token",
    )

    token_map = fields.Char(
        help="Some Oauth providers don't map keys in their responses "
        "exactly as required.  It is important to ensure user_id and "
        "email at least are mapped. For OpenID Connect user_id is "
        "the sub key in the standard."
    )

    auth_endpoint = fields.Char(
        help="OAuth / OIDC provider URL to authenticate users. "
        "For OIDC on Microsoft Azure, use the value of "
        "'OAuth2 autorization endpoint (v2)'"
    )
    validation_endpoint = fields.Char(
        help="OAuth provider URL to validate Endpoints. For OpenID "
        "Connect this should be the location for public keys. For "
        "OIDC on Microsoft Azure, use the value of "
        "'OAuth2 token endpoint (v2)'"
    )

    @api.model
    def _get_key(self, header):
        if self.flow != "id_token":
            return False
        try:
            response = urlopen(self.validation_endpoint)
            content_type = response.getheader(
                "Content-Type", "application/json; charset=utf-8"
            )
            try:
                charset = re.search(r'charset=([^;]*)', content_type).group(1)
            except IndexError:
                _logger.warn(
                    "No charset found in response content type. Assuming utf-8"
                )
                charset = "utf-8"
            response = json.loads(bytes.decode(charset))
            rsa_key = {}
            for key in response["keys"]:
                if key["kid"] == header.get("kid"):
                    rsa_key = key
            return rsa_key
        except Exception as exc:
            _logger.exception(
                "Error getting RSA key from %s: %s",
                self.validation_endpoint,
                exc,
            )
            raise

    @api.model
    def map_token_values(self, res):
        if self.token_map:

            for pair in self.token_map.split(" "):
                from_key, to_key = pair.split(":")
                if to_key not in res:
                    res[to_key] = res.get(from_key, "")
        return res

    @api.multi
    def _parse_id_token(self, id_token):
        self.ensure_one()
        res = {}
        header = jwt.get_unverified_header(id_token)
        res.update(
            jwt.decode(
                id_token,
                self._get_key(header),
                algorithms=["RS256"],
                audience=self.client_id,
            )
        )

        res.update(self.map_token_values(res))
        return res
