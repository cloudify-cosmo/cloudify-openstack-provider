cloudify-openstack-provider
===========================

DEPRACATED IN CLOUDIFY 3.1!

Beginning with Cloudify 3.1, bootstrapping a Cloudify Management Environment is done via a `manager blueprint`.
please refer to [Manager Blueprints](http://getcloudify.org/guide/3.1/installation-bootstrapping.html#manager-blueprints) for more info.


Cloudify 3.0 openstack CLI package
This Python project contains the code and configurations needed to bootstrap the Cloudify management netwrok &amp; manager VM on Openstack

##Requirements
The python-dev package is required (as it is used to compile the Crypto library used by Paramiko):
`apt-get install python-dev # or the equivalent *nix version of this command`

##Mandatory Configurations
In order to boostrap Cloudify manager on OpenStack you must edit the cloudify-config.yaml file and update the following propeties:

* username: The Openstack username you want to use vs. keystone authentication service

* password: The Openstack password you want to use vs. keystone authentication service

* tenant_name: The Openstack tenant name to which you want to use now.

##Cloudify OpenStack Configuration

The following configuration options are available in the cloudify-config.defaults.yaml file. You can edit this file if you need to change any of these defaults:

NOTE: the use_existing parameter follows this logic:
* if a resource exists and use_existing is true, it will use the resource.
* if a resource exists and use_existing is false, it will use the resource.
* if a resource does not exist and use_existing is true, it will raise an exception.
* if a resource does not exist and use_existing is false, it will create the resource.

* Keystone configuration

  * auth_url: The URL to Keystone authentication service

* Networking configuration
* Security Configuration
* Compute Configuration

##Sample Blueprint
You may download a sample "hello world" blueprint to test and expirement with [here](https://github.com/CloudifySource/cloudify-hello-world/tree/develop/openstack).



