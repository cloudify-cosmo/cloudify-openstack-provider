########
# Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

from setuptools import setup

setup(
    name='cloudify-openstack-provider',
    version='1.2a1',
    author='ran',
    author_email='ran@gigaspaces.com',
    packages=['cloudify_openstack'],
    license='LICENSE',
    description='Cloudify OpenStack provider',
    package_data={'cloudify_openstack': ['cloudify-config.yaml',
                                         'cloudify-config.defaults.yaml']},
    install_requires=[
        'python-novaclient==2.17.0',
        'python-keystoneclient==0.7.1',
        'python-neutronclient==2.3.9',
        'IPy==0.81',
        'cloudify==3.2a1',
    ]
)
