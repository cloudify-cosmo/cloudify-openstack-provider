########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############

__author__ = 'barakm'

import unittest
import os
import tempfile
import cloudify_openstack.cloudify_openstack

TEST_DIR = tempfile.mkdtemp(".test", "openstack_provider")
TEST_WORK_DIR = TEST_DIR + "/cloudify"
THIS_DIR = os.path.dirname(os.path.realpath(__file__))


class OpenStackProviderTest(unittest.TestCase):

    def test_override_username_from_env(self):
        provider_config = {}
        provider_config["keystone"] = {}
        provider_config["keystone"]["auth_url"] = "http://nowhere"
        # provider_config["keystone"]["username"] = "NO_USER"
        provider_config["keystone"]["password"] = "NO_PASSWORD"

        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertEqual(provider_config["keystone"]["username"],
                         "MODIFIED_NAME")

    def test_no_override_username_from_env(self):
        provider_config = {}
        provider_config["keystone"] = {}
        provider_config["keystone"]["auth_url"] = "http://nowhere"
        provider_config["keystone"]["username"] = "NO_USER"
        provider_config["keystone"]["password"] = "NO_PASSWORD"

        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertEqual(provider_config["keystone"]["username"], "NO_USER")

    def test_override_all(self):
        provider_config = {}
        provider_config["keystone"] = {}

        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        os.environ["OS_PASSWORD"] = "MODIFIED_PASSWORD"
        os.environ["OS_TENANT_NAME"] = "MODIFIED_TENANT"
        os.environ["OS_AUTH_URL"] = "MODIFIED_URL"
        os.environ["OS_TENANT_ID"] = "MODIFIED_TENANT_ID"

        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertEqual(provider_config["keystone"]["username"],
                         "MODIFIED_NAME")
        self.assertEqual(provider_config["keystone"]["password"],
                         "MODIFIED_PASSWORD")
        self.assertEqual(provider_config["keystone"]["tenant_name"],
                         "MODIFIED_TENANT")
        self.assertEqual(provider_config["keystone"]["auth_url"],
                         "MODIFIED_URL")
        self.assertEqual(provider_config["keystone"]["tenant_id"],
                         "MODIFIED_TENANT_ID")

    def test_no_keystone_and_no_env(self):
        provider_config = {}
        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertFalse(provider_config.has_key('keystone'))

    def test_no_keystone_with_env(self):
        provider_config = {}
        os.environ["OS_USERNAME"] = "MODIFIED_NAME"

        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertTrue(provider_config.has_key('keystone'))
        self.assertEqual(os.environ["OS_USERNAME"],
                         provider_config['keystone']['username'])

    def test_override_default(self):
        provider_config = {}
        provider_config['keystone'] = {}
        provider_config['keystone']['username'] = 'Enter-Openstack-Username-Here'
        provider_config['keystone']['password'] = 'Enter-Openstack-Password-Here'
        provider_config['keystone']['tenant_name'] = 'Enter-Openstack-Tenant-Name-Here'

        os.environ["OS_USERNAME"] = "MODIFIED_NAME"
        os.environ["OS_PASSWORD"] = "MODIFIED_PASSWORD"
        os.environ["OS_TENANT_NAME"] = "MODIFIED_TENANT"

        cloudify_openstack.cloudify_openstack.ProviderManager(provider_config,
                                                              False)
        self.assertTrue(provider_config.has_key('keystone'))
        self.assertEqual(provider_config["keystone"]["username"],
                         "MODIFIED_NAME")
        self.assertEqual(provider_config["keystone"]["password"],
                         "MODIFIED_PASSWORD")
        self.assertEqual(provider_config["keystone"]["tenant_name"],
                         "MODIFIED_TENANT")

