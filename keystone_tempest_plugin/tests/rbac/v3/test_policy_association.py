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


class IdentityV3RbacPolicyAssociationTests(rbac_base.IdentityV3RbacBaseTests,
                                           metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacPolicyAssociationTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.policies_client
        cls.admin_client = cls.os_system_admin
        cls.admin_policies_client = cls.admin_client.policies_client

    @classmethod
    def resource_setup(cls):
        super(IdentityV3RbacPolicyAssociationTests, cls).resource_setup()
        cls.policy_id = cls.admin_policies_client.create_policy(
            blob=data_utils.rand_uuid_hex(),
            type=data_utils.rand_uuid_hex())['policy']['id']
        cls.addClassResourceCleanup(
            cls.admin_policies_client.delete_policy,
            policy_id=cls.policy_id)
        cls.region_id = cls.admin_client.regions_client.create_region(
            region_id=data_utils.rand_name())['region']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.regions_client.delete_region,
            cls.region_id)
        svc_client = cls.admin_client.identity_services_v3_client
        cls.service_id = svc_client.create_service(
            type=data_utils.rand_name())['service']['id']
        cls.addClassResourceCleanup(svc_client.delete_service, cls.service_id)
        cls.endpoint_id = cls.admin_client.endpoints_v3_client.create_endpoint(
            interface='public',
            url='http://localhost/foo',
            service_id=cls.service_id)['endpoint']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.endpoints_v3_client.delete_endpoint,
            endpoint_id=cls.endpoint_id)

    @abc.abstractmethod
    def test_identity_create_policy_association_for_endpoint(self):
        """Test identity:create_policy_association_for_endpoint policy.

        This test must check:
          * whether the persona can associate a policy with an endpoint
        """
        pass

    @abc.abstractmethod
    def test_identity_create_policy_association_for_service(self):
        """Test identity:create_policy_association_for_service policy.

        This test must check:
          * whether the persona can associate a policy with a service
        """
        pass

    @abc.abstractmethod
    def test_identity_create_policy_association_for_region_and_service(self):
        """Test identity:create_policy_association_for_region_and_service.

        This test must check:
          * whether the persona can associate a policy with a region and
            service
        """
        pass

    @abc.abstractmethod
    def test_identity_check_policy_association_for_endpoint(self):
        """Test identity:check_policy_association_for_endpoint policy.

        This test must check:
          * whether the persona can check a policy association for an endpoint
        """
        pass

    @abc.abstractmethod
    def test_identity_check_policy_association_for_service(self):
        """Test identity:check_policy_association_for_service policy.

        This test must check:
          * whether the persona can check a policy association for a service
        """
        pass

    @abc.abstractmethod
    def test_identity_check_policy_association_for_region_and_service(self):
        """Test identity:check_policy_association_for_region_and_service.

        This test must check:
          * whether the persona can check a policy association for a region and
            service
        """
        pass

    @abc.abstractmethod
    def test_identity_get_policy_for_endpoint(self):
        """Test identity:get_policy_for_endpoint policy.

        This test must check:
          * whether the persona can get a policy for an endpoint
        """
        pass

    @abc.abstractmethod
    def test_identity_list_endpoints_for_policy(self):
        """Test identity:list_endpoints_for_policy policy.

        This test must check:
          * whether the persona can list endpoints for a policy
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_policy_association_for_endpoint(self):
        """Test identity:delete_policy_association_for_endpoint policy.

        This test must check
          * whether the persona can delete a policy association for an endpoint
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_policy_association_for_service(self):
        """Test identity:delete_policy_association_for_service policy.

        This test must check
          * whether the persona can delete a policy association for a service
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_policy_association_for_region_and_service(self):
        """Test identity:delete_policy_association_for_region_and_service policy.

        This test must check
          * whether the persona can delete a policy association for a region
            and service
        """
        pass


class SystemAdminTests(
    IdentityV3RbacPolicyAssociationTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_policy_association_for_endpoint(self):
        self.do_request(
            'update_policy_association_for_endpoint',
            expected_status=204,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_endpoint,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)

    def test_identity_create_policy_association_for_service(self):
        self.do_request(
            'update_policy_association_for_service',
            expected_status=204,
            policy_id=self.policy_id, service_id=self.service_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_service,
            policy_id=self.policy_id, service_id=self.service_id)

    def test_identity_create_policy_association_for_region_and_service(self):
        self.do_request(
            'update_policy_association_for_region_and_service',
            expected_status=204,
            policy_id=self.policy_id, service_id=self.service_id,
            region_id=self.region_id)
        delete_fn = getattr(
            self.admin_policies_client,
            'delete_policy_association_for_region_and_service'
        )
        self.addCleanup(delete_fn,
                        policy_id=self.policy_id,
                        service_id=self.service_id,
                        region_id=self.region_id)

    def test_identity_check_policy_association_for_endpoint(self):
        self.admin_policies_client.update_policy_association_for_endpoint(
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_endpoint,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.do_request(
            'show_policy_association_for_endpoint',
            expected_status=204,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)

    def test_identity_check_policy_association_for_service(self):
        self.admin_policies_client.update_policy_association_for_service(
            policy_id=self.policy_id, service_id=self.service_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_service,
            policy_id=self.policy_id, service_id=self.service_id)
        self.do_request(
            'show_policy_association_for_service',
            expected_status=204,
            policy_id=self.policy_id, service_id=self.service_id)

    def test_identity_check_policy_association_for_region_and_service(self):
        update_fn = getattr(
            self.admin_policies_client,
            'update_policy_association_for_region_and_service'
        )
        update_fn(policy_id=self.policy_id,
                  service_id=self.service_id,
                  region_id=self.region_id)
        delete_fn = getattr(
            self.admin_policies_client,
            'delete_policy_association_for_region_and_service'
        )
        self.addCleanup(delete_fn,
                        policy_id=self.policy_id,
                        service_id=self.service_id,
                        region_id=self.region_id)
        self.do_request(
            'show_policy_association_for_region_and_service',
            expected_status=204,
            policy_id=self.policy_id,
            service_id=self.service_id,
            region_id=self.region_id)

    def test_identity_get_policy_for_endpoint(self):
        self.admin_policies_client.update_policy_association_for_endpoint(
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_endpoint,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.do_request(
            'show_policy_for_endpoint',
            expected_status=200,
            endpoint_id=self.endpoint_id)

    def test_identity_list_endpoints_for_policy(self):
        self.admin_policies_client.update_policy_association_for_endpoint(
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_endpoint,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.do_request(
            'list_endpoints_for_policy',
            expected_status=200,
            policy_id=self.policy_id)

    def test_identity_delete_policy_association_for_endpoint(self):
        self.admin_policies_client.update_policy_association_for_endpoint(
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.do_request(
            'delete_policy_association_for_endpoint',
            expected_status=204,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)

    def test_identity_delete_policy_association_for_service(self):
        self.admin_policies_client.update_policy_association_for_service(
            policy_id=self.policy_id, service_id=self.service_id)
        self.do_request(
            'delete_policy_association_for_service',
            expected_status=204,
            policy_id=self.policy_id, service_id=self.service_id)

    def test_identity_delete_policy_association_for_region_and_service(self):
        update_fn = getattr(
            self.admin_policies_client,
            'update_policy_association_for_region_and_service'
        )
        update_fn(policy_id=self.policy_id,
                  service_id=self.service_id,
                  region_id=self.region_id)
        self.do_request(
            'delete_policy_association_for_region_and_service',
            expected_status=204,
            policy_id=self.policy_id,
            service_id=self.service_id,
            region_id=self.region_id)


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_policy_association_for_endpoint(self):
        self.do_request(
            'update_policy_association_for_endpoint',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)

    def test_identity_create_policy_association_for_service(self):
        self.do_request(
            'update_policy_association_for_service',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id, service_id=self.service_id)

    def test_identity_create_policy_association_for_region_and_service(self):
        self.do_request(
            'update_policy_association_for_region_and_service',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id, service_id=self.service_id,
            region_id=self.region_id)

    def test_identity_delete_policy_association_for_endpoint(self):
        self.admin_policies_client.update_policy_association_for_endpoint(
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_endpoint,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.do_request(
            'delete_policy_association_for_endpoint',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)

    def test_identity_delete_policy_association_for_service(self):
        self.admin_policies_client.update_policy_association_for_service(
            policy_id=self.policy_id, service_id=self.service_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_service,
            policy_id=self.policy_id, service_id=self.service_id)
        self.do_request(
            'delete_policy_association_for_service',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id, service_id=self.service_id)

    def test_identity_delete_policy_association_for_region_and_service(self):
        update_fn = getattr(
            self.admin_policies_client,
            'update_policy_association_for_region_and_service'
        )
        update_fn(policy_id=self.policy_id,
                  service_id=self.service_id,
                  region_id=self.region_id)
        delete_fn = getattr(
            self.admin_policies_client,
            'delete_policy_association_for_region_and_service'
        )
        self.addCleanup(delete_fn,
                        policy_id=self.policy_id,
                        service_id=self.service_id,
                        region_id=self.region_id)
        self.do_request(
            'delete_policy_association_for_region_and_service',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id,
            service_id=self.service_id,
            region_id=self.region_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_check_policy_association_for_endpoint(self):
        self.admin_policies_client.update_policy_association_for_endpoint(
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_endpoint,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.do_request(
            'show_policy_association_for_endpoint',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)

    def test_identity_check_policy_association_for_service(self):
        self.admin_policies_client.update_policy_association_for_service(
            policy_id=self.policy_id, service_id=self.service_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_service,
            policy_id=self.policy_id, service_id=self.service_id)
        self.do_request(
            'show_policy_association_for_service',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id, service_id=self.service_id)

    def test_identity_check_policy_association_for_region_and_service(self):
        update_fn = getattr(
            self.admin_policies_client,
            'update_policy_association_for_region_and_service'
        )
        update_fn(policy_id=self.policy_id,
                  service_id=self.service_id,
                  region_id=self.region_id)
        delete_fn = getattr(
            self.admin_policies_client,
            'delete_policy_association_for_region_and_service'
        )
        self.addCleanup(delete_fn,
                        policy_id=self.policy_id,
                        service_id=self.service_id,
                        region_id=self.region_id)
        self.do_request(
            'show_policy_association_for_region_and_service',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id,
            service_id=self.service_id,
            region_id=self.region_id)

    def test_identity_get_policy_for_endpoint(self):
        self.admin_policies_client.update_policy_association_for_endpoint(
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_endpoint,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.do_request(
            'show_policy_for_endpoint',
            expected_status=exceptions.Forbidden,
            endpoint_id=self.endpoint_id)

    def test_identity_list_endpoints_for_policy(self):
        self.admin_policies_client.update_policy_association_for_endpoint(
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.addCleanup(
            self.admin_policies_client.delete_policy_association_for_endpoint,
            policy_id=self.policy_id, endpoint_id=self.endpoint_id)
        self.do_request(
            'list_endpoints_for_policy',
            expected_status=exceptions.Forbidden,
            policy_id=self.policy_id)


class DomainMemberTests(DomainAdminTests, base.BaseIdentityTest):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(DomainReaderTests, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
