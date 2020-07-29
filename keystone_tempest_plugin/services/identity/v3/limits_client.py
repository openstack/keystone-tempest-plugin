# Copyright 2020 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json

import http.client
from tempest.lib.common import rest_client

from keystone_tempest_plugin.services.identity import clients


class RegisteredLimitsClient(clients.Identity):

    subpath_prefix = 'registered_limits'
    collection_url = subpath_prefix
    entity_url = subpath_prefix + '/%s'

    def create_registered_limits(self, payload):
        """Create a list of registered limits.

        :param body: A list of registered limits objects.
        """
        post_body = json.dumps({'registered_limits': payload})
        resp, body = super(RegisteredLimitsClient, self).post(
            self.collection_url, post_body)
        self.expected_success(http.client.CREATED, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def list_registered_limits(self, **kwargs):
        """List registered limits.

        :param kwargs: Filter by service_id, region_id, or resource_name
        """
        resp, body = super(RegisteredLimitsClient, self).get(
            self.collection_url, **kwargs)
        self.expected_success(http.client.OK, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def update_registered_limit(self, registered_limit_id, registered_limit):
        """Update a registered limit.

        :param registered_limit_id: ID of registered limit to update
        :param registered_limit: new registered limit object
        """
        patch_body = json.dumps({'registered_limit': registered_limit})
        resp, body = super(RegisteredLimitsClient, self).patch(
            self.entity_url % registered_limit_id, patch_body)
        self.expected_success(http.client.OK, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def show_registered_limit(self, registered_limit_id):
        """Get a registered limit.

        :param registered_limit_id: ID of registered limit to show
        """
        resp, body = super(RegisteredLimitsClient, self).get(
            self.entity_url % registered_limit_id)
        self.expected_success(http.client.OK, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def delete_registered_limit(self, registered_limit_id):
        """Delete a registered limit.

        :param registered_limit_id: ID of registered limit to delete.
        """
        resp, body = super(RegisteredLimitsClient, self).delete(
            self.entity_url % registered_limit_id)
        self.expected_success(http.client.NO_CONTENT, resp.status)
        return rest_client.ResponseBody(resp, body)


class LimitsClient(clients.Identity):

    subpath_prefix = 'limits'
    collection_url = subpath_prefix
    entity_url = subpath_prefix + '/%s'

    def limits_model(self):
        """Get limits model from server."""
        url = self.entity_url % 'model'
        resp, body = super(LimitsClient, self).get(url)
        self.expected_success(http.client.OK, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def create_limits(self, payload):
        """Create a list of project limits.

        :param body: A list of project limits objects.
        """
        post_body = json.dumps({'limits': payload})
        resp, body = super(LimitsClient, self).post(
            self.collection_url, post_body)
        self.expected_success(http.client.CREATED, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def list_limits(self, **kwargs):
        """List project limits.

        :param kwargs: Filter by service_id, region_id, resource_name,
            or project/domain ID
        """
        resp, body = super(LimitsClient, self).get(
            self.collection_url, **kwargs)
        self.expected_success(http.client.OK, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def update_limit(self, limit_id, limit):
        """Update a project limit.

        :param limit_id: ID of project limit to update
        :param limit: new project limit object
        """
        patch_body = json.dumps({'limit': limit})
        resp, body = super(LimitsClient, self).patch(
            self.entity_url % limit_id, patch_body)
        self.expected_success(http.client.OK, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def show_limit(self, limit_id):
        """Get a project limit.

        :param limit_id: ID of project limit to show
        """
        resp, body = super(LimitsClient, self).get(self.entity_url % limit_id)
        self.expected_success(http.client.OK, resp.status)
        body = json.loads(body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def delete_limit(self, limit_id):
        """Delete a project limit.

        :param limit_id: ID of project limit to delete.
        """
        resp, body = super(LimitsClient, self).delete(
            self.entity_url % limit_id)
        self.expected_success(http.client.NO_CONTENT, resp.status)
        return rest_client.ResponseBody(resp, body)
