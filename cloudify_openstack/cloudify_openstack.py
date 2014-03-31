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

__author__ = 'ran'

# Standard
import os
import shutil
import inspect
import itertools
import time
import json
import tempfile
import paramiko
import socket
import errno
from os.path import expanduser
from scp import SCPClient
import logging
import logging.config
from schemas import PROVIDER_SCHEMA

from cosmo_cli.cosmo_cli import logger
from cosmo_cli.cosmo_cli import _set_global_verbosity_level
from cosmo_cli.cosmo_cli import BaseProviderClass

# Validator
from IPy import IP

# OpenStack
import keystoneclient.v2_0.client as keystone_client
import novaclient.v1_1.client as nova_client
import neutronclient.neutron.client as neutron_client


EP_FLAG = 'use_existing'

EXTERNAL_MGMT_PORTS = (22, 8100)  # SSH, REST service
INTERNAL_MGMT_PORTS = (5555, 5672, 53229)  # Riemann, RabbitMQ, FileServer

INTERNAL_AGENT_PORTS = (22,)

SSH_CONNECT_RETRIES = 12
SSH_CONNECT_SLEEP = 5
SSH_CONNECT_PORT = 22

verbose_output = False

# http://stackoverflow.com/questions/8144545/turning-off-logging-in-paramiko
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(
    logging.ERROR)

lgr, flgr = logger()


class ProviderManager(BaseProviderClass):

    def __init__(self, provider_config, is_verbose_output=False):
        self.provider_config = provider_config
        self.is_verbose_output = is_verbose_output

    def provision(self, keep_up=False):
        """
        provisions resources in the provider before bootstrapping
        the management server. This can include (for instance)
        network, keypairs, security groups and an instance.
        at the very least, an instance is required.
        This should return
        a hash containing the instance's attached ip, its private ip,
        its ssh key path and its ssh user.
        (upon error, this should return None)
        """
        _set_global_verbosity_level(self.is_verbose_output)
        # implement the resource provisioning process.
        connector = OpenStackConnector(self.provider_config)
        network_creator = OpenStackNetworkCreator(connector)
        subnet_creator = OpenStackSubnetCreator(connector)
        router_creator = OpenStackRouterCreator(connector)
        floating_ip_creator = OpenStackFloatingIpCreator(connector)
        keypair_creator = OpenStackKeypairCreator(connector)
        server_creator = OpenStackServerCreator(connector)
        server_killer = OpenStackServerKiller(connector)
        if self.provider_config['networking']['neutron_supported_region']:
            sg_creator = OpenStackNeutronSecurityGroupCreator(connector)
        else:
            sg_creator = OpenStackNovaSecurityGroupCreator(connector)
        provisioner = CosmoOnOpenStackProvisioner(
            self.provider_config, network_creator, subnet_creator,
            router_creator, sg_creator, floating_ip_creator, keypair_creator,
            server_creator, server_killer)
        params = provisioner._create_topology()
        if params is not None:
            mgmt_ip, private_ip, ssh_key, ssh_user = params
            if mgmt_ip is not None:
                r = provisioner._copy_files(mgmt_ip)
            if r is not None:
                return params
        return None

    def validate(self):
        """
        validates provider specific resources and configuration.
        This can, for instance, include quota validations, config file
        validations, access validations, etc...
        This should either retriesurn True if the validations were successful,
        or False, if they weren't.
        """
        _set_global_verbosity_level(self.is_verbose_output)

        global validated
        validated = True
        verifier = OpenStackValidator()

        self._validate_config_schema(PROVIDER_SCHEMA)
        lgr.debug('validating provider cidrs in config file...')
        verifier._validate_cidr('networking.subnet.cidr',
                                self.provider_config['networking']
                                ['subnet']['cidr'])
        verifier._validate_cidr('networking.management_security_group.cidr',
                                self.provider_config['networking']
                                ['management_security_group']['cidr'])

        if validated:
            return True
        else:
            return False

    def teardown(self, management_ip):
        """
        tears down whatever was provisioned in provision().
        must return True on successful teardown, and False otherwise.
        """
        _set_global_verbosity_level(self.is_verbose_output)
        lgr.info('NOTE: currently only instance teardown is implemented!')

        connector = OpenStackConnector(self.provider_config)
        # network_killer = OpenStackNetworkKiller(connector)
        # subnet_killer = OpenStackSubnetKiller(connector)
        # router_killer = OpenStackRouterKiller(connector)
        # floating_ip_killer = OpenStackFloatingIpKiller(connector)
        # keypair_killer = OpenStackKeypairKiller(connector)
        server_killer = OpenStackServerKiller(connector)
        # if provider_config['networking']['neutron_supported_region']:
        #     sg_killer = OpenStackNeutronSecurityGroupKiller(connector)
        # else:
        #     sg_killer = OpenStackNovaSecurityGroupKiller(connector)
        killer = CosmoOnOpenStackKiller(
            self.provider_config, management_ip, server_killer)
        killer._kill_topology()
        return True


class OpenStackValidator:

    def _validate_cidr(self, field, cidr):
        global validated
        try:
            IP(cidr)
        except ValueError as e:
            validated = False
            lgr.error('config file validation error found at key:'
                      ' {0}. {1}'.format(field, e.message))


class CosmoOnOpenStackProvisioner(object):
    """ Bootstraps Cosmo on OpenStack """

    def __init__(self, provider_config, network_creator, subnet_creator,
                 router_creator, sg_creator, floating_ip_creator,
                 keypair_creator, server_creator, server_killer):
        self.provider_config = provider_config
        self.network_creator = network_creator
        self.subnet_creator = subnet_creator
        self.router_creator = router_creator
        self.sg_creator = sg_creator
        self.floating_ip_creator = floating_ip_creator
        self.keypair_creator = keypair_creator
        self.server_creator = server_creator
        self.server_killer = server_killer

        global verbose_output
        self.verbose_output = verbose_output

    def _create_topology(self):
        compute_config = self.provider_config['compute']
        insconf = compute_config['management_server']['instance']

        is_neutron_supported_region = \
            self.provider_config['networking']['neutron_supported_region']
        if is_neutron_supported_region:
            nconf = self.provider_config['networking']['int_network']
            try:
                net_id = self.network_creator.create_or_ensure_exists(
                    nconf,
                    nconf['name'],
                    False)
            except Exception as exception:
                lgr.error('failed to create internal network ({0})'.format(
                    exception))
                return None

            sconf = self.provider_config['networking']['subnet']
            try:
                subnet_id = self.subnet_creator.create_or_ensure_exists(
                    sconf,
                    sconf['name'],
                    False,
                    sconf['ip_version'],
                    sconf['cidr'],
                    sconf['dns_nameservers'],
                    net_id)
            except Exception as exception:
                lgr.error('failed to create subnet ({0})'.format(
                    exception))
                return None

            enconf = self.provider_config['networking']['ext_network']
            try:
                enet_id = self.network_creator.create_or_ensure_exists(
                    enconf,
                    enconf['name'],
                    False,
                    ext=True)
            except Exception as exception:
                lgr.error('failed to create external network ({0})'.format(
                    exception))
                return None

            rconf = self.provider_config['networking']['router']
            try:
                self.router_creator.create_or_ensure_exists(
                    rconf,
                    rconf['name'],
                    False,
                    interfaces=[{'subnet_id': subnet_id}],
                    external_gateway_info={"network_id": enet_id})
            except Exception as exception:
                lgr.error('failed to create router ({0})'.format(
                    exception))
                return None

            insconf['nics'] = [{'net-id': net_id}]
        # Security group for Cosmo created instances
        asgconf = self.provider_config['networking']['agents_security_group']
        try:
            asg_id, agent_sg_created = self.sg_creator.create_or_ensure_exists(
                asgconf,
                asgconf['name'],
                True,
                'Cosmo created machines',
                [])
        except Exception as exception:
            lgr.error('failed to create agents security group ({0})'.format(
                exception))
            return None
        # Security group for Cosmo manager, allows created
        # instances -> manager communication
        try:
            msgconf = self.provider_config['networking']['management_security_group']  # NOQA
            sg_rules = \
                [{'port': p, 'group_id': asg_id}
                    for p in INTERNAL_MGMT_PORTS] + \
                [{'port': p, 'cidr': msgconf['cidr']}
                    for p in EXTERNAL_MGMT_PORTS]
            msg_id = self.sg_creator.create_or_ensure_exists(
                msgconf,
                msgconf['name'],
                False,
                'Cosmo Manager',
                sg_rules)
        except Exception as exception:
            lgr.error('failed to create mgmt security group ({0})'.format(
                exception))
            return None

        # Add rules to agent security group. (Happens here because we need
        # the management security group id)
        if agent_sg_created:
            try:
                self.sg_creator.add_rules(asg_id,
                                          [{'port': port, 'group_id': msg_id}
                                           for port in INTERNAL_AGENT_PORTS])
            except Exception as exception:
                lgr.error('failed to add agent sg rules ({0})'.format(
                    exception))
                return None

        # Keypairs setup
        try:
            mgr_kpconf = compute_config['management_server']['management_keypair']  # NOQA
            self.keypair_creator.create_or_ensure_exists(
                mgr_kpconf,
                mgr_kpconf['name'],
                False,
                private_key_target_path=
                mgr_kpconf['auto_generated']['private_key_target_path'] if
                'auto_generated' in mgr_kpconf else None,
                public_key_filepath=
                mgr_kpconf['provided']['public_key_filepath'] if
                'provided' in mgr_kpconf else None
            )
        except Exception as exception:
            lgr.error('failed to create mgmt keypair ({0})'.format(
                exception))
            return None

        try:
            agents_kpconf = compute_config['agent_servers']['agents_keypair']
            self.keypair_creator.create_or_ensure_exists(
                agents_kpconf,
                agents_kpconf['name'],
                False,
                private_key_target_path=agents_kpconf['auto_generated']
                ['private_key_target_path'] if 'auto_generated' in
                                               agents_kpconf else None,
                public_key_filepath=
                agents_kpconf['provided']['public_key_filepath'] if
                'provided' in agents_kpconf else None
            )
        except Exception as exception:
            lgr.error('failed to create agents keypair ({0})'.format(
                exception))
            return None

        try:
            server_id = self.server_creator.create_or_ensure_exists(
                insconf,
                insconf['name'],
                False,
                {k: v for k, v in insconf.iteritems() if k != EP_FLAG},
                mgr_kpconf['name'],
                msg_id if is_neutron_supported_region else msgconf['name']
            )
        except Exception as exception:
            lgr.error('failed to create mgmt server ({0})'.format(
                exception))
            return None
        if is_neutron_supported_region:
            network_name = nconf['name']
            if not insconf[EP_FLAG]:  # new server
                self._attach_floating_ip(
                    compute_config['management_server'],
                    enet_id, server_id)
            else:  # existing server
                ips = self.server_creator.get_server_ips_in_network(
                    server_id, nconf['name'])
                if len(ips) < 2:
                    self._attach_floating_ip(
                        compute_config['management_server'], enet_id,
                        server_id)
        else:
            network_name = 'private'

        ips = self.server_creator.get_server_ips_in_network(server_id,
                                                            network_name)
        private_ip, public_ip = ips[:2]

        ssh_key = mgr_kpconf['auto_generated']['private_key_target_path'] \
            if 'auto_generated' in mgr_kpconf else None
        ssh_user = compute_config['management_server']['user_on_management']

        # if ips is not None:
        return public_ip, private_ip, ssh_key, ssh_user

    def _copy_files(self, mgmt_ip):

        compute_config = self.provider_config['compute']
        management_server_config = compute_config['management_server']

        lgr.debug('creating ssh channel to machine...')
        try:
            ssh = self._create_ssh_channel_with_mgmt(
                mgmt_ip,
                self._get_private_key_path_from_keypair_config(
                    management_server_config['management_keypair']),
                management_server_config['user_on_management'])
            return True
        except:
            lgr.error('ssh channel creation failed. '
                      'your private and public keys might not be matching or '
                      'your security group might not be configured to allow '
                      'connections to port {0}.'.format(SSH_CONNECT_PORT))
            return False

        try:
            self._copy_files_to_manager(
                ssh,
                management_server_config['userhome_on_management'],
                self.provider_config['keystone'],
                self._get_private_key_path_from_keypair_config(
                    compute_config['agent_servers']['agents_keypair']),
                self.provider_config['networking'])
        except:
            lgr.error('failed to copy keystone files')
            return False

    def _create_ssh_channel_with_mgmt(self, mgmt_ip, management_key_path,
                                      user_on_management):
        ssh = paramiko.SSHClient()
        # TODO: support fingerprint in config json
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        #trying to ssh connect to management server. Using retries since it
        #might take some time to find routes to host
        for retry in range(0, SSH_CONNECT_RETRIES):
            try:
                ssh.connect(mgmt_ip, username=user_on_management,
                            key_filename=management_key_path,
                            look_for_keys=False, timeout=10)
                lgr.debug('ssh connection successful')
                return ssh
            except socket.error as err:
                lgr.debug(
                    "SSH connection to {0} failed ({1}). Waiting {2} seconds "
                    "before retrying".format(mgmt_ip, err, 5))
                time.sleep(5)
        lgr.error('Failed to ssh connect to management server ({0}'
                  .format(err))

    def _attach_floating_ip(self, mgmt_server_conf, enet_id, server_id):
        if 'floating_ip' in mgmt_server_conf:
            floating_ip = mgmt_server_conf['floating_ip']
        else:
            floating_ip = self.floating_ip_creator.allocate_ip(enet_id)

        lgr.info('attaching IP {0} to the instance'.format(
            floating_ip))
        self.server_creator.add_floating_ip(server_id, floating_ip)
        return floating_ip

    def _get_private_key_path_from_keypair_config(self, keypair_config):
        path = keypair_config['provided']['private_key_filepath'] if \
            'provided' in keypair_config else \
            keypair_config['auto_generated']['private_key_target_path']
        return expanduser(path)

    def _copy_files_to_manager(self, ssh, userhome_on_management,
                               keystone_config, agents_key_path,
                               networking):
        lgr.info('uploading keystone and neutron files to manager')
        scp = SCPClient(ssh.get_transport())

        tempdir = tempfile.mkdtemp()
        try:
            scp.put(agents_key_path, userhome_on_management + '/.ssh',
                    preserve_times=True)
            keystone_file_path = self._make_keystone_file(tempdir,
                                                          keystone_config)
            scp.put(keystone_file_path, userhome_on_management,
                    preserve_times=True)
            if networking['neutron_supported_region']:
                neutron_file_path = self._make_neutron_file(tempdir,
                                                            networking)
                scp.put(neutron_file_path, userhome_on_management,
                        preserve_times=True)
        finally:
            shutil.rmtree(tempdir)

    def _make_keystone_file(self, tempdir, keystone_config):
        # put default region in keystone_config file
        keystone_config['region'] = self.provider_config['compute']['region']
        keystone_file_path = os.path.join(tempdir, 'keystone_config.json')
        with open(keystone_file_path, 'w') as f:
            json.dump(keystone_config, f)
        return keystone_file_path

    def _make_neutron_file(self, tempdir, networking):
        neutron_file_path = os.path.join(tempdir, 'neutron_config.json')
        with open(neutron_file_path, 'w') as f:
            json.dump({'url': networking['neutron_url']}, f)
        return neutron_file_path

    def _exec_install_command_on_manager(self, ssh, install_command):
        command = 'DEBIAN_FRONTEND=noninteractive sudo -E {0}'.format(
            install_command)
        return self._exec_command_on_manager(ssh, command)

    def _exec_command_on_manager(self, ssh, command):
        lgr.info('EXEC START: {0}'.format(command))
        chan = ssh.get_transport().open_session()
        chan.exec_command(command)
        stdin = chan.makefile('wb', -1)
        stdout = chan.makefile('rb', -1)
        stderr = chan.makefile_stderr('rb', -1)

        try:
            exit_code = chan.recv_exit_status()
            if exit_code != 0:
                errors = stderr.readlines()
                raise RuntimeError('Error occurred when trying to run a '
                                   'command on the management machine. '
                                   'command was: {0} ; Error(s): {1}'
                                   .format(command, errors))

            response_lines = stdout.readlines()
            lgr.info('EXEC END: {0}'.format(command))
            return response_lines
        finally:
            stdin.close()
            stdout.close()
            stderr.close()
            chan.close()


class OpenStackLogicError(RuntimeError):
    pass


class CreateOrEnsureExists(object):

    def _create(self, name, *args, **kw):
        lgr.debug("Will create {0} '{1}'".format(
            self.__class__.WHAT, name))
        return self.create(name, *args, **kw)

    def _check(self, name, *args, **kw):
        lgr.debug("Checking to see if {0} '{1}' already exists".format(
            self.__class__.WHAT, name))
        if self.list_objects_with_name(name):
            lgr.debug("{0} '{1}' already exists".format(
                self.__class__.WHAT, name))
            return True
        else:
            lgr.debug("{0} '{1}' does not exist".format(
                self.__class__.WHAT, name))
            return False

    def create_or_ensure_exists(self, provider_config, name, return_created,
                                *args, **kw):
        """
        if resource exists:
            if resource is server:
                raise already exists
            use resource
        else:
            if use_existing:
                raise is configured to use_existing but does not exist
            create resource
        """
        if self._check(name, *args, **kw):
            if self.__class__.WHAT in ('server'):
                raise OpenStackLogicError("{0} '{1}' already exists".format(
                                          self.__class__.WHAT, name))
            the_id = self.ensure_exists(name, *args, **kw)
            created = False
        else:
            if EP_FLAG in provider_config and provider_config[EP_FLAG]:
                raise OpenStackLogicError("{0} '{1}' is configured to 'use_"
                                          "existing' but does not exist"
                                          .format(self.__class__.WHAT, name))
            the_id = self._create(name, *args, **kw)
            created = True
        if return_created:
            return the_id, created
        else:
            return the_id

    def ensure_exists(self, name, *args, **kw):
        lgr.debug("Will use existing {0} '{1}'"
                  .format(self.__class__.WHAT, name))
        ret = self.find_by_name(name)
        if not ret:
            raise OpenStackLogicError("{0} '{1}' was not found".format(
                self.__class__.WHAT, name))
        return ret['id']

    def find_by_name(self, name):
        matches = self.list_objects_with_name(name)

        if len(matches) == 0:
            return None
        if len(matches) == 1:
            return matches[0]
        raise OpenStackLogicError("Lookup of {0} named '{1}' failed. There "
                                  "are {2} matches."
                                  .format(self.__class__.WHAT, name,
                                          len(matches)))

    def _fail_on_missing_required_parameters(self, obj, required_parameters,
                                             hint_where):
        for k in required_parameters:
            if k not in obj:
                raise OpenStackLogicError("Required parameter '{0}' is "
                                          "missing (under {3}'s properties."
                                          "{1}). "
                                          "Required parameters are: {2}"
                                          .format(k, hint_where,
                                                  required_parameters,
                                                  self.__class__.WHAT))


class CreateOrEnsureExistsNova(CreateOrEnsureExists):
    def __init__(self, connector):
        CreateOrEnsureExists.__init__(self)
        self.nova_client = connector.get_nova_client()


class CreateOrEnsureExistsNeutron(CreateOrEnsureExists):
    def __init__(self, connector):
        CreateOrEnsureExists.__init__(self)
        self.neutron_client = connector.get_neutron_client()


class OpenStackNetworkCreator(CreateOrEnsureExistsNeutron):
    WHAT = 'network'

    def list_objects_with_name(self, name):
        return self.neutron_client.list_networks(name=name)['networks']

    def create(self, name, ext=False):
        n = {
            'network': {
                'name': name,
                'admin_state_up': True,
            }
        }
        if ext:
            n['router:external'] = ext
        ret = self.neutron_client.create_network(n)
        return ret['network']['id']


class OpenStackSubnetCreator(CreateOrEnsureExistsNeutron):
    WHAT = 'subnet'

    def list_objects_with_name(self, name):
        return self.neutron_client.list_subnets(name=name)['subnets']

    def create(self, name, ip_version, cidr, dns_nameservers, net_id):
        ret = self.neutron_client.create_subnet({
            'subnet': {
                'name': name,
                'ip_version': ip_version,
                'cidr': cidr,
                'dns_nameservers': dns_nameservers,
                'network_id': net_id
            }
        })
        return ret['subnet']['id']


class OpenStackFloatingIpCreator():
    def __init__(self, connector):
        self.neutron_client = connector.get_neutron_client()

    def allocate_ip(self, external_network_id):
        floating_ip = self.neutron_client.create_floatingip(
            {
                "floatingip":
                {
                    "floating_network_id": external_network_id,
                }
            })
        return floating_ip['floatingip']['floating_ip_address']


class OpenStackRouterCreator(CreateOrEnsureExistsNeutron):
    WHAT = 'router'

    def list_objects_with_name(self, name):
        return self.neutron_client.list_routers(name=name)['routers']

    def create(self, name, interfaces=None, external_gateway_info=None):
        args = {
            'router': {
                'name': name,
                'admin_state_up': True
            }
        }
        if external_gateway_info:
            args['router']['external_gateway_info'] = external_gateway_info
        router_id = self.neutron_client.create_router(args)['router']['id']
        if interfaces:
            for i in interfaces:
                self.neutron_client.add_interface_router(router_id, i)
        return router_id


class OpenStackNovaSecurityGroupCreator(CreateOrEnsureExistsNova):
    WHAT = 'nova security group'

    def list_objects_with_name(self, name):
        sgs = self.nova_client.security_groups.list()
        return [{'id': sg.id} for sg in sgs if sg.name == name]

    def create(self, name, description, rules):
        sg = self.nova_client.security_groups.create(name, description)
        for rule in rules:
            self.nova_client.security_group_rules.create(
                sg.id,
                ip_protocol="tcp",
                from_port=rule['port'],
                to_port=rule['port'],
                cidr=rule.get('cidr'),
                group_id=rule.get('group_id')
            )
        return sg.id


class OpenStackNeutronSecurityGroupCreator(CreateOrEnsureExistsNeutron):
    WHAT = 'neutron security group'

    def list_objects_with_name(self, name):
        return self.neutron_client.list_security_groups(
            name=name)['security_groups']

    def create(self, name, description, rules):
        sg = self.neutron_client.create_security_group({
            'security_group': {
                'name': name,
                'description': description,
            }
        })['security_group']
        self.add_rules(sg['id'], rules)
        return sg['id']

    def add_rules(self, sg_id, rules):
        for rule in rules:
            self.neutron_client.create_security_group_rule({
                'security_group_rule': {
                    'security_group_id': sg_id,
                    'direction': 'ingress',
                    'protocol': 'tcp',
                    'port_range_min': rule['port'],
                    'port_range_max': rule['port'],
                    'remote_ip_prefix': rule.get('cidr'),
                    'remote_group_id': rule.get('group_id'),
                }
            })


class OpenStackKeypairCreator(CreateOrEnsureExistsNova):
    WHAT = 'keypair'

    def list_objects_with_name(self, name):
        keypairs = self.nova_client.keypairs.list()
        return [{'id': keypair.id} for keypair in keypairs if
                keypair.id == name]

    def create(self, key_name, private_key_target_path=None,
               public_key_filepath=None, *args, **kwargs):
        if not private_key_target_path and not public_key_filepath:
            raise RuntimeError("Must provide either private key target path "
                               "or public key filepath to create keypair")

        if public_key_filepath:
            with open(public_key_filepath, 'r') as f:
                self.nova_client.keypairs.create(key_name, f.read())
        else:
            key = self.nova_client.keypairs.create(key_name)
            pk_target_path = expanduser(private_key_target_path)
            self._mkdir_p(os.path.dirname(private_key_target_path))
            with open(pk_target_path, 'w') as f:
                f.write(key.private_key)
                os.system('chmod 600 {0}'.format(pk_target_path))

    def _mkdir_p(path):
        try:
            lgr.debug('creating dir {0}'
                      .format(path))
            os.makedirs(path)
        except OSError, exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                return
            raise


class OpenStackServerCreator(CreateOrEnsureExistsNova):
    WHAT = 'server'

    def list_objects_with_name(self, name):
        servers = self.nova_client.servers.list(True, {'name': name})
        return [{'id': server.id} for server in servers]

    def create(self, name, server_config, management_server_keypair_name,
               sgm_id, *args, **kwargs):
        """
        Creates a server. Exposes the parameters mentioned in
        http://docs.openstack.org/developer/python-novaclient/api/novaclient
        .v1_1.servers.html#novaclient.v1_1.servers.ServerManager.create
        """

        self._fail_on_missing_required_parameters(
            server_config,
            ('name', 'flavor', 'image'),
            'compute.management_server.instance')

        # First parameter is 'self', skipping
        params_names = inspect.getargspec(
            self.nova_client.servers.create).args[1:]
        params_default_values = inspect.getargspec(
            self.nova_client.servers.create).defaults
        params = dict(itertools.izip(params_names, params_default_values))

        # Fail on unsupported parameters
        for k in server_config:
            if k not in params:
                raise ValueError("Parameter with name '{0}' must not be passed"
                                 " to openstack provisioner (under "
                                 "compute.management_server.instance)"
                                 .format(k))

        for k in params:
            if k in server_config:
                params[k] = server_config[k]

        server_name = server_config['name']
        if self.find_by_name(server_name):
            raise RuntimeError("Can not provision the server with name '{0}'"
                               " because server with such name "
                               "already exists"
                               .format(server_name))

        lgr.debug("Asking Nova to create server. Parameters: {0}"
                  .format(str(params)))

        configured_sgs = []
        if params['security_groups'] is not None:
            configured_sgs = params['security_groups']
        params['security_groups'] = [sgm_id] + configured_sgs

        params['key_name'] = management_server_keypair_name

        server = self.nova_client.servers.create(**params)
        server = self._wait_for_server_to_become_active(server_name, server)
        return server.id

    def add_floating_ip(self, server_id, ip):

        # Extra: detach floating ip from existng server
        while True:
            ls = self.nova_client.floating_ips.findall(ip=ip)
            if len(ls) == 0:
                raise OpenStackLogicError(
                    "Floating IP {0} does not exist so it can "
                    "not be attached to server {1}".format(ip, server_id))
            if len(ls) > 1:
                raise OpenStackLogicError(
                    "Floating IP {0} is attached to "
                    "{1} instances".format(ip, len(ls)))

            if not ls[0].instance_id:
                lgr.debug(
                    "Floating IP {0} is not attached to any instance. "
                    "Continuing.".format(ip))
                break

            lgr.debug(
                "Floating IP {0} is attached "
                "to instance {1}. Detaching.".format(ip, ls[0].instance_id))
            self.nova_client.servers.remove_floating_ip(ls[0].instance_id, ip)
            time.sleep(1)

        server = self.nova_client.servers.get(server_id)
        server.add_floating_ip(ip)

    def get_server_ips_in_network(self, server_id, network_name):
        server = self.nova_client.servers.get(server_id)
        if network_name not in server.networks:
            raise OpenStackLogicError(
                "Server {0} ({1}) does not have address in"
                " network {2}".format(server.name, server_id, network_name))
        return server.networks[network_name]

    def _wait_for_server_to_become_active(self, server_name, server):
        timeout = 100
        while server.status != "ACTIVE":
            timeout -= 5
            if timeout <= 0:
                raise RuntimeError('Server failed to start in time')
            time.sleep(5)
            server = self.nova_client.servers.get(server.id)

        return server


class CosmoOnOpenStackKiller(object):
    """ Kills Cosmo on OpenStack """

    def __init__(self, provider_config, mgmt_ip, server_killer):
        self.config = provider_config
        self.mgmt_ip = mgmt_ip
        self.server_killer = server_killer

        global verbose_output
        self.verbose_output = verbose_output

    def _kill_topology(self):
        lgr.debug('retrieving server object for ip: {0}'.format(self.mgmt_ip))
        server = self.server_killer.list_objects_by_ip(self.mgmt_ip)
        if server is not None:
            self.server_killer.kill(server)
        else:
            lgr.info('no servers found for ip: {0}'.format(self.mgmt_ip))


class OpenStackServerKiller(CreateOrEnsureExistsNova):
    WHAT = 'server'

    def list_objects_with_name(self, name):
        servers = self.nova_client.servers.list(True, {'name': name})
        return servers

    def list_objects_by_ip(self, ip):
        servers = self.nova_client.servers.list()
        for server in servers:
            if str(ip) in str(server.addresses):
                return server

    def kill(self, server):
        lgr.debug('killing server: {0}'.format(server.name))
        server.delete()
        self._wait_for_server_to_terminate(server)

    def _wait_for_server_to_terminate(self, server):
        timeout = 20
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                server = self.nova_client.servers.get(server.id)
                lgr.debug('server status: ' + server.status)
            except:
                lgr.info('server terminated')
                return
            time.sleep(2)
        else:
            raise RuntimeError('server failed to terminate in time')


class OpenStackConnector(object):
    # TODO: maybe lazy?
    def __init__(self, provider_config):
        self.config = provider_config
        self.keystone_client = keystone_client.Client(
            **self.config['keystone'])

        if self.config['networking']['neutron_supported_region']:
            self.neutron_client = \
                neutron_client.Client('2.0',
                                      endpoint_url=provider_config
                                      ['networking']
                                      ['neutron_url'],
                                      token=self.keystone_client.auth_token)
            self.neutron_client.format = 'json'
        else:
            self.neutron_client = None

        kconf = self.config['keystone']
        self.nova_client = nova_client.Client(
            kconf['username'],
            kconf['password'],
            kconf['tenant_name'],
            kconf['auth_url'],
            region_name=self.config['compute']['region'],
            http_log_debug=False
        )

    def get_keystone_client(self):
        return self.keystone_client

    def get_neutron_client(self):
        return self.neutron_client

    def get_nova_client(self):
        return self.nova_client
