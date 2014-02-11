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
import errno
import shutil
import inspect
import itertools
import time
import yaml
import json
import socket
import logging
import paramiko
import tempfile
from os.path import expanduser
from copy import deepcopy
from scp import SCPClient
from fabric.api import run, put
from fabric.context_managers import settings

# OpenStack
import keystoneclient.v2_0.client as keystone_client
import novaclient.v1_1.client as nova_client
import neutronclient.neutron.client as neutron_client


EP_FLAG = 'externally_provisioned'

EXTERNAL_PORTS = (22, 8100)  # SSH, REST service
INTERNAL_PORTS = (5555, 5672, 53229)  # Riemann, RabbitMQ, FileServer

SSH_CONNECT_RETRIES = 12
SSH_CONNECT_SLEEP = 5

SHELL_PIPE_TO_LOGGER = ' |& logger -i -t cosmo-bootstrap -p local0.info'

CONFIG_FILE_NAME = 'cloudify-config.yaml'
DEFAULTS_CONFIG_FILE_NAME = 'cloudify-config.defaults.yaml'

verbose_output = False

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def init(target_directory, reset_config, is_verbose_output=False):
    if not reset_config and os.path.exists(
            os.path.join(target_directory, CONFIG_FILE_NAME)):
        return False

    provider_dir = os.path.dirname(os.path.realpath(__file__))
    shutil.copy(os.path.join(provider_dir, CONFIG_FILE_NAME),
                target_directory)
    return True


def bootstrap(config_path=None, is_verbose_output=False, bootstrap_using_script=True):
    global verbose_output
    verbose_output = is_verbose_output

    config = _read_config(config_path)

    connector = OpenStackConnector(config)
    network_creator = OpenStackNetworkCreator(connector)
    subnet_creator = OpenStackSubnetCreator(connector)
    router_creator = OpenStackRouterCreator(connector)
    floating_ip_creator = OpenStackFloatingIpCreator(connector)
    keypair_creator = OpenStackKeypairCreator(connector)
    server_creator = OpenStackServerCreator(connector)
    if config['networking']['neutron_supported_region']:
        sg_creator = OpenStackNeutronSecurityGroupCreator(connector)
    else:
        sg_creator = OpenStackNovaSecurityGroupCreator(connector)
    bootstrapper = CosmoOnOpenStackBootstrapper(
        config, network_creator, subnet_creator, router_creator,
        sg_creator, floating_ip_creator, keypair_creator, server_creator)
    mgmt_ip = bootstrapper.do(bootstrap_using_script)
    return mgmt_ip


def teardown(management_ip, is_verbose_output=False):
    raise RuntimeError('NOT YET IMPLEMENTED')


def _read_config(config_file_path):
    if not config_file_path:
        config_file_path = CONFIG_FILE_NAME
    defaults_config_file_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        DEFAULTS_CONFIG_FILE_NAME)

    if not os.path.exists(config_file_path) or not os.path.exists(
            defaults_config_file_path):
        if not os.path.exists(defaults_config_file_path):
            raise ValueError('Missing the defaults configuration file; '
                             'expected to find it at {0}'.format(
                                 defaults_config_file_path))
        raise ValueError('Missing the configuration file; expected to find '
                         'it at {0}'.format(config_file_path))

    with open(config_file_path, 'r') as config_file, \
            open(defaults_config_file_path, 'r') as defaults_config_file:
        user_config = yaml.safe_load(config_file.read())
        defaults_config = yaml.safe_load(defaults_config_file.read())

    merged_config = _deep_merge_dictionaries(user_config, defaults_config) \
        if user_config else defaults_config
    return merged_config


def _deep_merge_dictionaries(overriding_dict, overridden_dict):
    merged_dict = deepcopy(overridden_dict)
    for k, v in overriding_dict.iteritems():
        if k in merged_dict and isinstance(v, dict):
            if isinstance(merged_dict[k], dict):
                merged_dict[k] = _deep_merge_dictionaries(v, merged_dict[k])
            else:
                raise RuntimeError('type conflict at key {0}'.format(k))
        else:
            merged_dict[k] = deepcopy(v)
    return merged_dict


def _output(level, message):
    if level >= logging.INFO or verbose_output:
        print message


def _mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        raise


class CosmoOnOpenStackBootstrapper(object):
    """ Bootstraps Cosmo on OpenStack """

    def __init__(self, config, network_creator, subnet_creator,
                 router_creator, sg_creator, floating_ip_creator,
                 keypair_creator, server_creator):
        self.config = config
        self.network_creator = network_creator
        self.subnet_creator = subnet_creator
        self.router_creator = router_creator
        self.sg_creator = sg_creator
        self.floating_ip_creator = floating_ip_creator
        self.keypair_creator = keypair_creator
        self.server_creator = server_creator

    def do(self, bootstrap_using_script):
        mgmt_ip = self._create_topology()
        self._bootstrap_manager(mgmt_ip, bootstrap_using_script)
        return mgmt_ip

    def _create_topology(self):
        compute_config = self.config['compute']
        insconf = compute_config['management_server']['instance']

        is_neutron_supported_region = \
            self.config['networking']['neutron_supported_region']
        if is_neutron_supported_region:
            nconf = self.config['networking']['int_network']
            net_id = self.network_creator.create_or_ensure_exists(
                nconf,
                nconf['name'])

            sconf = self.config['networking']['subnet']
            subnet_id = self.subnet_creator.create_or_ensure_exists(
                sconf,
                sconf['name'],
                sconf['ip_version'],
                sconf['cidr'], net_id)

            enconf = self.config['networking']['ext_network']
            enet_id = self.network_creator.create_or_ensure_exists(
                enconf,
                enconf['name'],
                ext=True)

            rconf = self.config['networking']['router']
            self.router_creator.create_or_ensure_exists(
                rconf,
                rconf['name'],
                interfaces=[{'subnet_id': subnet_id}],
                external_gateway_info={"network_id": enet_id})

            insconf['nics'] = [{'net-id': net_id}]

        # Security group for Cosmo created instances
        asgconf = self.config['networking']['agents_security_group']
        asg_id = self.sg_creator.create_or_ensure_exists(
            asgconf,
            asgconf['name'],
            'Cosmo created machines',
            [])

        # Security group for Cosmo manager, allows created
        # instances -> manager communication
        msgconf = self.config['networking']['management_security_group']
        sg_rules = \
            [{'port': p, 'group_id': asg_id} for p in INTERNAL_PORTS] + \
            [{'port': p, 'cidr': msgconf['cidr']} for p in EXTERNAL_PORTS]
        msg_id = self.sg_creator.create_or_ensure_exists(
            msgconf,
            msgconf['name'],
            'Cosmo Manager',
            sg_rules)

        # Keypairs setup
        mgr_kpconf = compute_config['management_server']['management_keypair']
        self.keypair_creator.create_or_ensure_exists(
            mgr_kpconf,
            mgr_kpconf['name'],
            private_key_target_path=
            mgr_kpconf['auto_generated']['private_key_target_path'] if
            'auto_generated' in mgr_kpconf else None,
            public_key_filepath=
            mgr_kpconf['provided']['public_key_filepath'] if
            'provided' in mgr_kpconf else None
        )
        agents_kpconf = compute_config['agent_servers']['agents_keypair']
        self.keypair_creator.create_or_ensure_exists(
            agents_kpconf,
            agents_kpconf['name'],
            private_key_target_path=agents_kpconf['auto_generated']
            ['private_key_target_path'] if 'auto_generated' in
                                           agents_kpconf else None,
            public_key_filepath=
            agents_kpconf['provided']['public_key_filepath'] if
            'provided' in agents_kpconf else None
        )

        server_id = self.server_creator.create_or_ensure_exists(
            insconf,
            insconf['name'],
            {k: v for k, v in insconf.iteritems() if k != EP_FLAG},
            mgr_kpconf['name'],
            msg_id if is_neutron_supported_region else msgconf['name'],
        )

        if is_neutron_supported_region:
            if not insconf[EP_FLAG]:  # new server
                return self._attach_floating_ip(
                    compute_config['management_server'], enet_id, server_id)
            else:  # existing server
                ips = self.server_creator.get_server_ips_in_network(
                    server_id, nconf['name'])
                if len(ips) > 0:
                    return ips[1]  # the floating ip
                else:  # there's no floating ip, attaching it.
                    return self._attach_floating_ip(
                        compute_config['management_server'], enet_id,
                        server_id)
        else:
            return self.server_creator.get_server_ips_in_network(
                server_id, 'private')[1]

    def _attach_floating_ip(self, mgmt_server_conf, enet_id, server_id):
        if 'floating_ip' in mgmt_server_conf:
            floating_ip = mgmt_server_conf['floating_ip']
        else:
            floating_ip = self.floating_ip_creator.allocate_ip(enet_id)

        _output(logging.INFO, 'Attaching IP {0} to the instance'.format(
                floating_ip))
        self.server_creator.add_floating_ip(server_id, floating_ip)
        return floating_ip

    def _get_private_key_path_from_keypair_config(self, keypair_config):
        path = keypair_config['provided']['private_key_filepath'] if \
            'provided' in keypair_config else \
            keypair_config['auto_generated']['private_key_target_path']
        return expanduser(path)

    def _download_packages(self, url, path):
        r = run('wget %s -P %s' % (path, url))
        return r

    def _unpack(self, path):
        r = run('sudo dpkg -i %s/*.deb' % path)
        return r

    def _run(self, command):
        r = run(command)
        return r

    def _put(self, this, there):
        r = put(this, there)
        return r

    def _bootstrap_manager(self, mgmt_ip, bootstrap_using_script):
        _output(logging.INFO, 'Initializing manager on the machine at {0}'
                .format(mgmt_ip))
        compute_config = self.config['compute']
        cosmo_config = self.config['cloudify']
        management_server_config = compute_config['management_server']

        ssh = self._create_ssh_channel_with_mgmt(
            mgmt_ip,
            self._get_private_key_path_from_keypair_config(
                management_server_config['management_keypair']),
            management_server_config['user_on_management'])

        if not bootstrap_using_script:
            try:
                self._put(
                    management_server_config['userhome_on_management'],
                    self.config['keystone'],
                    self._get_private_key_path_from_keypair_config(
                        compute_config['agent_servers']['agents_keypair']))

                with settings(host_string=mgmt_ip):
                    self._download_package(cosmo_config['cloudify_packages_path'],
                                           cosmo_config['cloudify_components_package_url'])
                    self._download_package(cosmo_config['cloudify_packages_path'],
                                           cosmo_config['cloudify_package_url'])
                    self._unpack(cosmo_config['cloudify_components_package_path'])
                    self._unpack(cosmo_config['cloudify_package_path'])
                    self._run('sudo %s/cloudify3-components-bootstrap.sh')
                    self._run('sudo %s/cloudify3-bootstrap.sh')
            except:
                raise RuntimeError('Failed to install Cloudify on %s' % mgmt_ip)
        else:
            try:
                self._copy_files_to_manager(
                    ssh,
                    management_server_config['userhome_on_management'],
                    self.config['keystone'],
                    self._get_private_key_path_from_keypair_config(
                        compute_config['agent_servers']['agents_keypair']))

                _output(logging.DEBUG, 'Installing required packages on manager')
                self._exec_command_on_manager(ssh, 'echo "127.0.0.1 '
                                                   '$(cat /etc/hostname)" | '
                                                   'sudo tee -a /etc/hosts')
                self._exec_command_on_manager(ssh, 'sudo apt-get -y -q update'
                                                   + SHELL_PIPE_TO_LOGGER)
                self._exec_install_command_on_manager(ssh,
                                                      'apt-get install -y -q '
                                                      'python-dev git rsync '
                                                      'openjdk-7-jdk maven '
                                                      'python-pip'
                                                      + SHELL_PIPE_TO_LOGGER)
                self._exec_install_command_on_manager(ssh, 'pip install -q '
                                                           'retrying '
                                                           'timeout-decorator')

                # use open sdk java 7
                self._exec_command_on_manager(
                    ssh,
                    'sudo update-alternatives --set java '
                    '/usr/lib/jvm/java-7-openjdk-amd64/jre/bin/java')

                # configure and clone cosmo-manager from github
                branch = cosmo_config['cloudify_branch']
                workingdir = '{0}/cosmo-work'.format(
                    management_server_config['userhome_on_management'])
                version = cosmo_config['cloudify_branch']
                configdir = '{0}/cosmo-manager/vagrant'.format(workingdir)

                _output(logging.DEBUG, 'cloning cosmo on manager')
                self._exec_command_on_manager(ssh, 'mkdir -p {0}'
                    .format(workingdir))
                self._exec_command_on_manager(ssh, 'git clone https://github.com/'
                                                   'CloudifySource/cosmo-manager'
                                                   '.git {0}/cosmo-manager'
                                                   ' --depth 1'
                    .format(workingdir))
                self._exec_command_on_manager(ssh, '( cd {0}/cosmo-manager ; '
                                                   'git checkout {1} )'
                    .format(workingdir, branch))

                _output(logging.DEBUG, 'running the manager bootstrap script '
                                       'remotely')
                run_script_command = 'DEBIAN_FRONTEND=noninteractive python2.7 ' \
                                     '{0}/cosmo-manager/vagrant/' \
                                     'bootstrap_lxc_manager.py --working_dir=' \
                                     '{0} --cosmo_version={1} ' \
                                     '--config_dir={2} ' \
                                     '--install_openstack_provisioner ' \
                                     '--install_logstash' \
                                     .format(workingdir, version, configdir)
                run_script_command += ' {0}'.format(SHELL_PIPE_TO_LOGGER)
                self._exec_command_on_manager(ssh, run_script_command)

                _output(logging.DEBUG, 'rebuilding cosmo on manager')
            finally:
                ssh.close()

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
                            look_for_keys=False)
                return ssh
            except socket.error:
                _output(logging.DEBUG,
                        "SSH connection to {0} failed. Waiting {1} seconds "
                        "before retrying".format(mgmt_ip, SSH_CONNECT_SLEEP))
                time.sleep(SSH_CONNECT_SLEEP)
        raise RuntimeError('Failed to ssh connect to management server')

    def _copy_files_to_manager(self, ssh, userhome_on_management,
                               keystone_config, agents_key_path):
        _output(logging.INFO, 'Uploading files to manager')
        scp = SCPClient(ssh.get_transport())

        tempdir = tempfile.mkdtemp()
        try:
            scp.put(agents_key_path, userhome_on_management + '/.ssh',
                    preserve_times=True)
            keystone_file_path = self._make_keystone_file(tempdir,
                                                          keystone_config)
            scp.put(keystone_file_path, userhome_on_management,
                    preserve_times=True)

        finally:
            shutil.rmtree(tempdir)

    def _make_keystone_file(self, tempdir, keystone_config):
        keystone_file_path = os.path.join(tempdir, 'keystone_config.json')
        with open(keystone_file_path, 'w') as f:
            json.dump(keystone_config, f)
        return keystone_file_path

    def _exec_install_command_on_manager(self, ssh, install_command):
        command = 'DEBIAN_FRONTEND=noninteractive sudo -E {0}'.format(
            install_command)
        return self._exec_command_on_manager(ssh, command)

    def _exec_command_on_manager(self, ssh, command):
        _output(logging.INFO, 'EXEC START: {0}'.format(command))
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
            _output(logging.INFO, 'EXEC END: {0}'.format(command))
            return response_lines
        finally:
            stdin.close()
            stdout.close()
            stderr.close()
            chan.close()


class OpenStackLogicError(RuntimeError):
    pass


class CreateOrEnsureExists(object):

    def create_or_ensure_exists(self, config, name, *args, **kw):
        # config hash is only used for 'externally_provisioned' attribute
        if EP_FLAG in config and config[EP_FLAG]:
            method = 'ensure_exists'
        else:
            method = 'check_and_create'
        return getattr(self, method)(name, *args, **kw)

    def check_and_create(self, name, *args, **kw):
        _output(logging.INFO, "Will create {0} '{1}'".format(
            self.__class__.WHAT, name))
        if self.list_objects_with_name(name):
            raise OpenStackLogicError("{0} '{1}' already exists".format(
                self.__class__.WHAT, name))
        return self.create(name, *args, **kw)

    def ensure_exists(self, name, *args, **kw):
        _output(logging.INFO, "Will use existing {0} '{1}'"
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

    def create(self, name, ip_version, cidr, net_id):
        ret = self.neutron_client.create_subnet({
            'subnet': {
                'name': name,
                'ip_version': ip_version,
                'cidr': cidr,
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

        for rule in rules:
            self.neutron_client.create_security_group_rule({
                'security_group_rule': {
                    'security_group_id': sg['id'],
                    'direction': 'ingress',
                    'protocol': 'tcp',
                    'port_range_min': rule['port'],
                    'port_range_max': rule['port'],
                    'remote_ip_prefix': rule.get('cidr'),
                    'remote_group_id': rule.get('group_id'),
                }
            })

        return sg['id']


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
            _mkdir_p(os.path.dirname(private_key_target_path))
            with open(pk_target_path, 'w') as f:
                f.write(key.private_key)
                os.system('chmod 600 {0}'.format(pk_target_path))


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

        _output(logging.INFO, "Asking Nova to create server. Parameters: {0}"
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
                _output(logging.DEBUG,
                        "Floating IP {0} is not attached to any instance. "
                        "Continuing.".format(ip))
                break

            _output(
                logging.DEBUG,
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


class OpenStackConnector(object):
    # TODO: maybe lazy?
    def __init__(self, config):
        self.config = config
        self.keystone_client = keystone_client.Client(
            **self.config['keystone'])

        if self.config['networking']['neutron_supported_region']:
            self.neutron_client = \
                neutron_client.Client('2.0',
                                      endpoint_url=config['networking']
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
