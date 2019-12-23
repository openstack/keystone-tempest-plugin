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

import abc

from tempest.api.identity import base
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from keystone_tempest_plugin.tests.rbac.v3 import base as rbac_base


class IdentityV3RbacProjectTagTests(rbac_base.IdentityV3RbacBaseTests,
                                    metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacProjectTagTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.project_tags_client
        cls.admin_client = cls.os_system_admin
        cls.admin_project_tags_client = cls.admin_client.project_tags_client

    @abc.abstractmethod
    def test_identity_create_project_tag(self):
        """Test identity:create_project_tag policy.

        This test must check:
          * whether the persona can create a tag for an arbitrary project
          * whether the persona can create a tag for a project in their own
            domain
          * whether the persona can create a tag for a project in another
            domain
          * whether the persona can create a tag for their own project
        """
        pass

    @abc.abstractmethod
    def test_identity_get_project_tag(self):
        """Test identity:get_project_tag policy.

        This test must check:
          * whether the persona can get a tag for an arbitrary project
          * whether the persona can get a tag for a project in their own domain
          * whether the persona can get a tag for a project in another domain
          * whether the persona can get tag for their own project
        """
        pass

    @abc.abstractmethod
    def test_identity_list_project_tags(self):
        """Test identity:list_project_tags policy.

        This test must check:
          * whether the persona can list tags for an arbitrary project
          * whether the persona can list tags for a project in their own domain
          * whether the persona can list tags for a project in another domain
          * whether the persona can list tags for their own project
        """
        pass

    @abc.abstractmethod
    def test_identity_update_project_tags(self):
        """Test identity:update_project_tags policy.

        This test must check:
          * whether the persona can update all tags for an project
          * whether the persona can update all tags for a project in their own
            domain
          * whether the persona can update all tags for a project in another
            domain
          * whether the persona can update all tags for their own project
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_project_tag(self):
        """Test identity:delete_project_tag policy.

        This test must check
          * whether the persona can delete a single tag for an arbitrary
            project
          * whether the persona can delete a single tag for a project in their
            own domain
          * whether the persona can delete a single tag for a project in
            another domain
          * whether the persona can delete a single tag for their own project
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_project_tags(self):
        """Test identity:delete_project_tag policy.

        This test must check
          * whether the persona can delete all tags for an arbitrary project
          * whether the persona can delete all tags for a project in their own
            domain
          * whether the persona can delete all tags for a project in another
            domain
          * whether the persona can delete all tags for their own project
        """
        pass


class SystemAdminTests(IdentityV3RbacProjectTagTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def setUp(self):
        super(SystemAdminTests, self).setUp()
        self.project_id = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(
            self.admin_client.projects_client.delete_project, self.project_id)

    def test_identity_create_project_tag(self):
        self.do_request(
            'update_project_tag', expected_status=201,
            project_id=self.project_id,
            tag=data_utils.rand_uuid_hex()
        )

    def test_identity_get_project_tag(self):
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.project_id, tag=tag)
        self.do_request('check_project_tag_existence',
                        expected_status=204,
                        project_id=self.project_id, tag=tag)

    def test_identity_list_project_tags(self):
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.project_id, tag=tag)
        resp = self.do_request('list_project_tags', project_id=self.project_id)
        self.assertIn(tag, resp['tags'])

    def test_identity_update_project_tags(self):
        self.do_request('update_all_project_tags',
                        project_id=self.project_id,
                        tags=[data_utils.rand_uuid_hex()])

    def test_identity_delete_project_tag(self):
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.project_id, tag=tag)
        self.do_request('delete_project_tag', expected_status=204,
                        project_id=self.project_id,
                        tag=tag)

    def test_identity_delete_project_tags(self):
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.project_id, tag=tag)
        self.do_request('delete_all_project_tags', expected_status=204,
                        project_id=self.project_id)


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_project_tag(self):
        self.do_request(
            'update_project_tag', expected_status=exceptions.Forbidden,
            project_id=self.project_id,
            tag=data_utils.rand_uuid_hex()
        )

    def test_identity_update_project_tags(self):
        self.do_request('update_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.project_id,
                        tags=[data_utils.rand_uuid_hex()])

    def test_identity_delete_project_tag(self):
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.project_id, tag=tag)
        self.do_request('delete_project_tag',
                        expected_status=exceptions.Forbidden,
                        project_id=self.project_id,
                        tag=tag)

    def test_identity_delete_project_tags(self):
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.project_id, tag=tag)
        self.do_request('delete_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.project_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacProjectTagTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def setUp(self):
        super(DomainAdminTests, self).setUp()
        self.own_domain = self.persona.credentials.domain_id
        self.other_domain = self.admin_client.domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_client.domains_client.delete_domain,
                        self.other_domain)
        self.addCleanup(self.admin_client.domains_client.update_domain,
                        domain_id=self.other_domain, enabled=False)
        project_client = self.admin_client.projects_client
        self.own_project_id = project_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['project']['id']
        self.addCleanup(
            project_client.delete_project,
            self.own_project_id)
        self.other_project_id = project_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.other_domain)['project']['id']
        self.addCleanup(project_client.delete_project, self.other_project_id)

    def test_identity_create_project_tag(self):
        # user can add tags to project in own domain
        tag = data_utils.rand_uuid_hex()
        self.do_request(
            'update_project_tag', expected_status=201,
            project_id=self.own_project_id,
            tag=tag
        )
        # user cannot add tags to project in other domain
        tag = data_utils.rand_uuid_hex()
        self.do_request(
            'update_project_tag', expected_status=exceptions.Forbidden,
            project_id=self.other_project_id,
            tag=tag
        )

    def test_identity_get_project_tag(self):
        # user can get tag for project in own domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.do_request('check_project_tag_existence',
                        expected_status=204,
                        project_id=self.own_project_id, tag=tag)
        # user cannot get tag for project in other domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('check_project_tag_existence',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id, tag=tag)

    def test_identity_list_project_tags(self):
        # user can list tags for project in own domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        resp = self.do_request('list_project_tags',
                               project_id=self.own_project_id)
        self.assertIn(tag, resp['tags'])
        # user cannot list tags for project in other domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('list_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id)

    def test_identity_update_project_tags(self):
        # user can update tags for project in own domain
        tag = data_utils.rand_uuid_hex()
        self.do_request('update_all_project_tags',
                        project_id=self.own_project_id,
                        tags=[tag])
        # user cannot update tags for project in other domain
        tag = data_utils.rand_uuid_hex()
        self.do_request('update_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id,
                        tags=[tag])

    def test_identity_delete_project_tag(self):
        # user can delete tag for project in own domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.do_request('delete_project_tag', expected_status=204,
                        project_id=self.own_project_id,
                        tag=tag)
        # user cannot delete tag for project in other domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('delete_project_tag',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id,
                        tag=tag)

    def test_identity_delete_project_tags(self):
        # user can delete tags for project in own domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.do_request('delete_all_project_tags', expected_status=204,
                        project_id=self.own_project_id)
        # user cannot delete tags for project in other domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('delete_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id)


class DomainMemberTests(DomainAdminTests, base.BaseIdentityTest):

    credentials = ['domain_member', 'system_admin']

    def test_identity_create_project_tag(self):
        # user cannot add tags to project in own domain
        tag = data_utils.rand_uuid_hex()
        self.do_request(
            'update_project_tag', expected_status=exceptions.Forbidden,
            project_id=self.own_project_id,
            tag=tag
        )
        # user cannot add tags to project in other domain
        tag = data_utils.rand_uuid_hex()
        self.do_request(
            'update_project_tag', expected_status=exceptions.Forbidden,
            project_id=self.other_project_id,
            tag=tag
        )

    def test_identity_update_project_tags(self):
        # user cannot update tags for project in own domain
        tag = data_utils.rand_uuid_hex()
        self.do_request('update_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.own_project_id,
                        tags=[tag])
        # user cannot update tags for project in other domain
        tag = data_utils.rand_uuid_hex()
        self.do_request('update_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id,
                        tags=[tag])

    def test_identity_delete_project_tag(self):
        # user cannot delete tag for project in own domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.do_request('delete_project_tag',
                        expected_status=exceptions.Forbidden,
                        project_id=self.own_project_id,
                        tag=tag)
        # user cannot delete tag for project in other domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('delete_project_tag',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id,
                        tag=tag)

    def test_identity_delete_project_tags(self):
        # user cannot delete tags for project in own domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.do_request('delete_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.own_project_id)
        # user cannot delete tags for project in other domain
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('delete_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id)


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(IdentityV3RbacProjectTagTests, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
        self.own_project_id = self.persona.credentials.project_id
        project_client = self.admin_client.projects_client
        self.other_project_id = project_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(project_client.delete_project, self.other_project_id)

    def test_identity_create_project_tag(self):
        # user can add tags to own project
        tag = data_utils.rand_uuid_hex()
        self.do_request(
            'update_project_tag', expected_status=201,
            project_id=self.own_project_id,
            tag=tag
        )
        self.addCleanup(self.admin_project_tags_client.delete_project_tag,
                        project_id=self.own_project_id,
                        tag=tag)
        # user cannot add tags to arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.do_request(
            'update_project_tag', expected_status=exceptions.Forbidden,
            project_id=self.other_project_id,
            tag=tag
        )

    def test_identity_get_project_tag(self):
        # user can get tag for own project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.addCleanup(self.admin_project_tags_client.delete_project_tag,
                        project_id=self.own_project_id,
                        tag=tag)
        self.do_request('check_project_tag_existence',
                        expected_status=204,
                        project_id=self.own_project_id, tag=tag)
        # user cannot get tag for arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('check_project_tag_existence',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id, tag=tag)

    def test_identity_list_project_tags(self):
        # user can list tags for own project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.addCleanup(self.admin_project_tags_client.delete_project_tag,
                        project_id=self.own_project_id,
                        tag=tag)
        resp = self.do_request('list_project_tags',
                               project_id=self.own_project_id)
        self.assertIn(tag, resp['tags'])
        # user cannot list tags for arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('list_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id)

    def test_identity_update_project_tags(self):
        # user can update tags for own project
        tag = data_utils.rand_uuid_hex()
        self.do_request('update_all_project_tags',
                        project_id=self.own_project_id,
                        tags=[tag])
        self.addCleanup(self.admin_project_tags_client.delete_project_tag,
                        project_id=self.own_project_id,
                        tag=tag)
        # user cannot update tags for arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.do_request('update_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id,
                        tags=[tag])

    def test_identity_delete_project_tag(self):
        # user can delete tag for own project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.do_request('delete_project_tag', expected_status=204,
                        project_id=self.own_project_id,
                        tag=tag)
        # user cannot delete tag for arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('delete_project_tag',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id,
                        tag=tag)

    def test_identity_delete_project_tags(self):
        # user can delete tags for own project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.do_request('delete_all_project_tags', expected_status=204,
                        project_id=self.own_project_id)
        # user cannot delete tags for arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('delete_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id)


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']

    def test_identity_create_project_tag(self):
        # user cannot add tags to own project
        tag = data_utils.rand_uuid_hex()
        self.do_request(
            'update_project_tag', expected_status=exceptions.Forbidden,
            project_id=self.own_project_id,
            tag=tag
        )
        # user cannot add tags to arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.do_request(
            'update_project_tag', expected_status=exceptions.Forbidden,
            project_id=self.other_project_id,
            tag=tag
        )

    def test_identity_update_project_tags(self):
        # user cannot update tags for own project
        tag = data_utils.rand_uuid_hex()
        self.do_request('update_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.own_project_id,
                        tags=[tag])
        # user cannot update tags for arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.do_request('update_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id,
                        tags=[tag])

    def test_identity_delete_project_tag(self):
        # user cannot delete tag for own project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.addCleanup(self.admin_project_tags_client.delete_project_tag,
                        project_id=self.own_project_id,
                        tag=tag)
        self.do_request('delete_project_tag',
                        expected_status=exceptions.Forbidden,
                        project_id=self.own_project_id,
                        tag=tag)
        # user cannot delete tag for arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('delete_project_tag',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id,
                        tag=tag)

    def test_identity_delete_project_tags(self):
        # user cannot delete tags for own project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.own_project_id, tag=tag)
        self.addCleanup(self.admin_project_tags_client.delete_project_tag,
                        project_id=self.own_project_id,
                        tag=tag)
        self.do_request('delete_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.own_project_id)
        # user cannot delete tags for arbitrary project
        tag = data_utils.rand_uuid_hex()
        self.admin_project_tags_client.update_project_tag(
            project_id=self.other_project_id, tag=tag)
        self.do_request('delete_all_project_tags',
                        expected_status=exceptions.Forbidden,
                        project_id=self.other_project_id)


class ProjectReaderTests(ProjectMemberTests):

    credentials = ['project_reader', 'system_admin']
