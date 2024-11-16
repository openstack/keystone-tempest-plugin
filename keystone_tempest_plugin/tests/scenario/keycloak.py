# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests


class KeycloakClient(object):
    def __init__(self, keycloak_url, keycloak_username, keycloak_password,
                 realm='master', ca_certs_file=False):
        self.keycloak_url = keycloak_url
        self.keycloak_username = keycloak_username
        self.keycloak_password = keycloak_password
        self.session = requests.session()
        self.realm = realm
        self.ca_certs_file = ca_certs_file
        self._admin_auth()

    @property
    def url_base(self):
        return self.keycloak_url + '/admin/realms'

    @property
    def token_endpoint(self):
        return self.keycloak_url + \
            f'/realms/{self.realm}/protocol/openid-connect/token'

    @property
    def discovery_endpoint(self):
        return self.keycloak_url + \
            f'/realms/{self.realm}/.well-known/openid-configuration'

    def _construct_url(self, path):
        return self.url_base + f'/{self.realm}/{path}'

    def _admin_auth(self):
        params = {
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': self.keycloak_username,
            'password': self.keycloak_password,
            'scope': 'openid',
        }
        r = requests.post(
            self.token_endpoint,
            data=params,
            verify=self.ca_certs_file).json()

        headers = {
            'Authorization': ("Bearer %s" % r['access_token']),
            'Content-Type': 'application/json'
        }
        self.session.headers.update(headers)
        return r

    def create_user(self, email, first_name, last_name):
        self._admin_auth()
        data = {
            'username': email,
            'email': email,
            'firstName': first_name,
            'lastName': last_name,
            'enabled': True,
            'emailVerified': True,
            'credentials': [{
                'value': 'secret',
                'type': 'password',
            }],
            'requiredActions': []
        }
        return self.session.post(
            self._construct_url('users'),
            json=data, verify=self.ca_certs_file)

    def delete_user(self, username):
        self._admin_auth()
        data = {
            'id': username,
        }
        return self.session.delete(
            self._construct_url('users'),
            json=data, verify=self.ca_certs_file)
