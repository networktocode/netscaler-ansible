#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community"
}

DOCUMENTATION = '''
---
module: netscaler_servicegroup_server
version_added: "2.3"
short_description: Manages service group to server bindings.
description:
  - Manages Netscaler service group to server binding configurations using Nitro API.
author: Jacob McGill (@jmcgill298)
options:
  host:
    description:
      - The Netscaler's Address.
    required: true
    type: str
  partition:
    description:
      - The Netscaler's partition if not the "default" partition.
    required: false
    type: str
  password:
    description:
      - The password associated with the username account.
    required: false
    type: str
  port:
    description:
      - The TCP port used to connect to the Netscaler if other than the default used by the transport
        method(http=80, https=443).
    required: false
    type: int
  provider:
    description:
      - Dictionary which acts as a collection of arguments used to define the characteristics
        of how to connect to the device.
      - Arguments hostname, username, and password must be specified in either provider or local param.
      - Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.
    required: false
    type: dict
  state:
    description:
      - The desired state of the specified object.
      - Absent will delete resource.
      - Present will create resource.
    required: false
    default: present
    type: str
    choices: ["absent", "present"]
  use_ssl:
    description:
      - Determines whether to use HTTPS(True) or HTTP(False).
    required: false
    default: True
    type: bool
  username:
    description:
      - The username used to authenticate with the Netscaler.
    required: true
    type: str
  validate_certs:
    description:
      - Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)
    required: false
    default: False
    type: bool
  server_name:
    description:
      - The server name which is being bound to a service group.
    required: True
    type: str
  servicegroup_name:
    description:
      - The service group name which the server is being bound to.
    required: True
    type: str
  server_port:
    description:
      - The port the server is listening on to offer services.
    required: True
    type: str
  weight:
    description:
      - The weight to assing the servers in the Service Group.
    required: False
    type: str
'''

EXAMPLES = '''
- name: Bind Service Group to Server
  netscaler_lbvserver:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    server_name: server01
    server_port: 443
    servicegroup_name: svcgrp_app01
- name: Bind Service Group to Server in Lab Partition
  netscaler_lbvserver:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    server_name: server02
    server_port: 443
    servicegroup_name: svcgrp_app01
    partition: Lab
    port: 8443
    validate_certs: True
'''

RETURN = '''
all_existing:
    description: All existing server bindings for the service group.
    returned: always
    type: list
    sample: [{"server_name": "server01", "servicegroupname": "svcgrp_app01"},
             {"server_name": "server02", "servicegroupname": "svcgrp_app01"}]
config:
    description: The configuration that was sent to the the Netscaler API. Existing bindings return an empty dict.
    returned: always
    type: dict
    sample: {}
existing:
    description: The existing binding for the service group and server pair. New bindings return an empty dict.
    returned: always
    type: dict
    sample: {"server_name": "server02", "servicegroupname": "svcgrp_app01"}
'''


import requests
from ansible.module_utils.basic import AnsibleModule, env_fallback, return_values

requests.packages.urllib3.disable_warnings()


class Netscaler(object):
    """
    This is the Base Class for Netscaler modules. All methods common across several Netscaler Classes should be defined
    here and inherited by the sub-class.
    """

    def __init__(self, host, user, passw, use_ssl=True, verify=False, api_endpoint="", **kwargs):
        """
        :param host: Type str.
                     The IP or resolvable hostname of the Netscaler.
        :param user: Type str.
                     The username used to authenticate with the Netscaler.
        :param passw: Type str.
                      The password associated with the user account.
        :param use_ssl: Type bool.
                        The default is True, which uses HTTPS instead of HTTP.
        :param verify: Type bool.
                       The default is False, which does not verify the certificate against the list of trusted
                       certificates.
        :param api_endpoint: Type str.
                             The API endpoint used for a particular configuration section.
        :param headers: Type dict.
                        The headers to include in HTTP requests.
        :param kwargs: Type dict. Currently supports port.
        :param port: Type str.
                     Passing the port parameter will override the default HTTP(S) port when making requests.
        """
        self.host = host
        self.user = user
        self.passw = passw
        self.verify = verify
        self.api_endpoint = api_endpoint
        self.headers = {"Content-Type": "application/json"}
        self.port = kwargs.get("port", "")

        if use_ssl:
            self.url = "https:{port}//{lb}/nitro/v1/config/".format(port=self.port, lb=self.host)
            self.stat_url = "https:{port}//{lb}/nitro/v1/stat/".format(port=self.port, lb=self.host)
        else:
            self.url = "http:{port}//{lb}/nitro/v1/config/".format(port=self.port, lb=self.host)
            self.stat_url = "http:{port}//{lb}/nitro/v1/stat/".format(port=self.port, lb=self.host)

    def change_state(self, object_name, state):
        """
        The purpose of this method is to change the state of an object from either disabled to enabled, or enabled to
        disabled. This method assumes the object is referenced by "name." This is the most common reference key, but not
        universal; where the Nitro API uses another key, an overriding method must be created in the sub-class.
        :param object_name: Type str.
                            The name of the object to be deleted.
        :param state: Type str.
                      The state the object should be in after execution. Valid values are "enable" or "disable"
        :return: The response from the request to delete the object.
        """
        url = self.url + self.api_endpoint + "?action={}".format(state)
        body = {self.api_endpoint: {"name": object_name}}
        response = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return response

    def config_delete(self, module, object_name):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "absent." The
        delete_config method is used to delete the object from the Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param object_name: Type str.
                            The name of the object to be deleted.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.delete_config(object_name)
            if config_status.ok:
                config.append({"method": "delete", "url": config_status.url, "body": {}})
            else:
                module.fail_json(msg=config_status.content)
        else:
            url = self.url + self.api_endpoint + "/" + object_name
            config.append({"method": "delete", "url": url, "body": {}})

        return config

    def config_new(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and the
        proposed config is a new object. The post_config method is used to post the object's configuration to the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The configuration to send to the Nitro API.
        :return: A list with config dictionary corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.post_config(new_config)
            if config_status.ok:
                config.append({"method": "post", "url": config_status.url, "body": new_config})
            else:
                module.fail_json(msg=config_status.content)
        else:
            config.append({"method": "post", "url": self.url + self.api_endpoint, "body": new_config})

        return config

    def config_update(self, module, update_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and the
        proposed config modifies an existing object. If the object's state needs to be updated, the "state" key,value is
        popped from the update_config in order to prevent it from being included in a config update when there are
        updates besides state change. The change_state method is then used to modify the object's state. After the
        object's state matches the proposed state, a check is done to see if the update_config has any keys other than
        the "name" key (len > 1). If there are more updates to make, the put_config method is used to push those to the
        Netscaler. Note that this method uses the common "name" key to input to the change_state method; if the API
        Endpoint uses a different key, then an overriding method must be created in the sub-class.
        :param module: The AnsibleModule instance started by the task.
        :param update_config: Type dict.
                              The configuration to send to the Nitro API.
        :return: The list of config dictionaries corresponding to the config returned by the Ansible module.
        """
        config = []

        if "state" in update_config:
            config_state = update_config.pop("state")[:-1].lower()
            if not module.check_mode:
                config_status = self.change_state(update_config["name"], config_state)
                if config_status.ok:
                    config.append({"method": "post", "url": config_status.url, "body": {"name": update_config["name"]}})
                else:
                    module.fail_json(msg=config_status.content)
            else:
                url = self.url + self.api_endpoint + "?action={}".format(config_state)
                config.append({"method": "post", "url": url, "body": {"name": update_config["name"]}})

        if len(update_config) > 1:
            if not module.check_mode:
                config_status = self.put_update(update_config)
                if config_status.ok:
                    config.append({"method": "put", "url": self.url, "body": update_config})
                else:
                    module.fail_json(msg=config_status.content)
            else:
                config.append({"method": "put", "url": self.url, "body": update_config})

        return config

    def delete_config(self, object_name):
        """
        The purpose of this method is to remove an object from the Netscaler's configuration. Currently no checks are
        made to verify if the object is bound to another item.
        :param object_name: Type str.
                            The name of the object to be deleted.
        :return: The response from the request to delete the object.
        """
        url = self.url + self.api_endpoint + "/" + object_name
        response = self.session.delete(url, headers=self.headers, verify=self.verify)

        return response

    def get_all(self, api_endpoint):
        """
        The purpose of this method is to retrieve every object's configuration for the API endpoint.
        :param api_endpoint: Type str.
                             The API endpoint to use for data collection.
        :return: A list of configuration dictionaries returned by they Nitro API. An empty list means that their are
                 currently no objects configured, or the request was unsuccessful.
        """
        response = self.session.get(self.url + api_endpoint, headers=self.headers, verify=self.verify)

        return response.json().get(api_endpoint, [])

    def get_all_attrs(self, api_endpoint, attrs_list):
        """
        The purpose of this method is to retrieve every object's configuration for the API endpoint, but the
        collected data is restricted to the attributes in the attrs_list argument.
        :param api_endpoint: Type str.
                             The API endpoint to use for data collection.
        :param attrs_list: Type list,tuple
                           The list of attributes used to limit the scope of returned config data.
        :return: A list of configuration dictionaries returned by they Nitro API. An empty list means that their are
                 currently no objects configured, or the request was unsuccessful.
        """
        attrs = "?attrs=" + ",".join(attrs_list)
        url = self.url + api_endpoint + attrs

        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get(api_endpoint, [])

    def get_config(self, defaults="false"):
        """
        This method retrieves the running configuration from the Netscaler.
        :param defaults: Type str.
                         The default setting will retrieve configurations that do not have their default setting.
                         Setting this to "true" will retrieve the full configuration including defaults.
        :return: The configuration of the Netscaler as a str. An empty str is returned if the request is unsuccessful.
        """
        url = self.url + "nsrunningconfig?args=withdefaults:{}".format(defaults)
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get("nsrunningconfig", {"response": ""})["response"]

    @staticmethod
    def get_diff(proposed, existing):
        """
        This method is used to compare the proposed config with what currently exists on the Netscaler. Note that thi
        method uses the most common key used by Nitro, "name." Where Nitro uses a different key, the corresponding class
        must have an overriding method.
        :param proposed: Type dict.
                         A dictionary corresponding to the proposed configuration item. The dictionary must have a
                         "name" key.
        :param existing: Type dict.
                         A dictionary corresponding to the existing configuration for the object. This can be retrieved
                         using the get_existing_attrs method.
        :return: A tuple indicating whether the config is a new object, will update an existing object, or make no
                 changes, and a dict that corresponds to the body of a config request using the Nitro API.
        """
        diff = dict(set(proposed.items()).difference(existing.items()))

        if diff == proposed:
            return "new", diff
        elif diff:
            diff["name"] = proposed["name"]
            return "update", diff
        else:
            return "none", {}

    def get_existing_attrs(self, object_name, attrs):
        """
        This method is used to get a subset of a particular object's configuration for the given API Endpoint
        (configuration section). The configuration will be scoped to the list of values in attrs.
        :param object_name: Type str.
                            The name of the object.
        :param attrs: Type list.
                      The list of attributes to retrieve from the configuration.
        :return: A dictionary of the object's configuration. If the object doesn't exist or the request fails, then an
        empty dict is returned. Unexpected empty lists are likely caused by a mistyped API endpoint or an expired
        session.
        """
        attributes = ",".join(attrs)
        url = self.url + self.api_endpoint + "/" + object_name + "?attrs=" + attributes
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get(self.api_endpoint, [{}])[0]

    def get_hardware(self):
        """
        This method is used to retrieve basic hardware information about the Netscaler.
        :return: A dictionary of hardware information. An empty dictionary is returned if the request is unsuccessful.
        """
        response = self.session.get(self.url + "nshardware", headers=self.headers, verify=self.verify)

        return response.json().get("nshardware", {})

    def get_hostname(self):
        """
        This method is used to retrieve the hostname of the connected Netscaler
        :return: A dictionary of the hostname configuration. An empty dictionary is returned if the API request failed.
        """
        response = self.session.get(self.url + "nshostname", headers=self.headers, verify=self.verify)

        return response.json().get("nshostname", [{}])[0]

    def get_interfaces(self):
        """
        This method is used to get the interfaces and their stats from the Netscaler.
        :return: A list of interface dictionaries containing configuration and statistical info. An empty list is
                 returned if the request is unsuccessful.
        """
        response = self.session.get(self.url + "interface", headers=self.headers, verify=self.verify)

        return response.json().get("Interface", [])

    def get_lbvserver_stats(self):
        """
        This method is used to get the lbvserver statistical info for all vservers on the Netscaler.
        :return: A list of dictionaries for all statistical data for the lbvservers. An empty dictionary is returned if
                 the request is unsuccessful.
        """
        response = self.session.get(self.stat_url + "lbvserver", headers=self.headers, verify=self.verify)

        return response.json().get("lbvserver", [])

    def get_nsconfig(self):
        """
        This method is used to get the nsconfig data from the Netscaler.
        :return: A dictionary of the nsconfig data. An empty dictionary is returned if the request is unsuccessful.
        """
        response = self.session.get(self.url + "nsconfig", headers=self.headers, verify=self.verify)

        return response.json().get("nsconfig", {})

    def get_state(self, object_name):
        """
        This method is used to retrieve the current state of the object. The possibilities are enabled or disabled.
        :param object_name: Type str.
                            The name of the object.
        :return: A str representing the current state of the object. An empty string is returned when the object does
                 not exist.
        """
        url = self.url + self.api_endpoint + object_name + "attrs=state"
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get(self.api_endpoint, [{"state": ""}])[0]["state"]

    def get_system(self):
        """
        This method is used to retrieve the system or environment statistics from the Netscaler.
        :return: A dictionary of the systems statistics (fans, memory, cpu, temp, disk space). An empty dictionary is
        returned if the request is unsuccessful.
        """
        response = self.session.get(self.stat_url + "system", headers=self.headers, verify=self.verify)

        return response.json().get("system", {})

    def login(self):
        """
        The login method is used to establish a session with the Netscaler. All necessary parameters need to be
        established at class instantiation. The requests Session class is used to maintain session consistency for all
        subsequent requests. The Session class automatically stores the cookie returned from the login request, and
        passes the cookie on all requests after a successful login. This is important when using partitions since the
        Netscaler API (Nitro) does not support modifying partitions using basic auth. Note that using partitions still
        requires calling the switch_partition function; these are separated so as to separate the failure domains.
        :return: The response from the login request. A successful login also sets the instance session.
        """
        url = self.url + "login"
        body = {"login": {"username": self.user, "password": self.passw}}
        session = requests.Session()
        login = session.post(url, json=body, headers=self.headers, verify=self.verify)

        if login.ok:
            self.session = session

        return login

    def post_config(self, new_config):
        """
        This method is used to submit a configuration request to the Netscaler using the Nitro API.
        :param new_config: Type dict:
                           The new configuration item to be sent to the Netscaler. It is expected that you use the
                           get_diff method to generate the new_config data.
        :return: The response from the request to add the configuration.
        """
        url = self.url + self.api_endpoint
        body = {self.api_endpoint: new_config}
        response = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return response

    def put_update(self, update_config):
        """
        This method is used to update the configuration of an existing item on the Netscaler.
        :param update_config: Type dict:
                              The configuration item to be sent to the Netscaler in order to update existing object. It
                              is expected that you use the get_diff method to generate the update_config data.
        :return: The response from the request to add the configuration.
        """
        url = self.url + self.api_endpoint
        body = {self.api_endpoint: update_config}
        response = self.session.put(url, json=body, headers=self.headers, verify=self.verify)

        return response

    def save_config(self):
        """
        This method is used to save the config of the Netscaler.
        :return: The response from the request to save the config.
        """
        url = self.url + "nsconfig?action=save"
        response = self.session.post(url, json={"nsconfig": {}}, headers=self.headers, verify=self.verify)

        return response

    def switch_partition(self, partition):
        """
        This method will switch from the default partition to the specified partition.
        :param partition: Type str.
                          The partition to interact with for all subsequent requests.
        :return: The response from the request to switch partitions.
        """
        url = self.url + "nspartition?action=Switch"
        body = {"nspartition": {"partitionname": partition}}
        switch = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return switch

    @staticmethod
    def validate_ip(ip_address):
        """
        This method is used to validate that an IPv4 Address has 4 octets and that each octet is an int from 0 to 255.
        Note, "0.0.0.0" is a valid IP.
        :param ip_address: Type str.
                           An IPv4 address.
        :return: A valid IP returns True; otherwise, False.
        """
        octet_split = ip_address.split(".")
        if len(octet_split) != 4:
            return False

        for octet in octet_split:
            try:
                int_octet = int(octet)
            except ValueError:
                return False

            if 0 > int_octet or 255 < int_octet:
                return False

        return True


class ServiceGroup(Netscaler):
    """
    This is the class used for interacting with the "servicegroup" API endpoint. In addition to servicegroup specific
    methods, the api endpoint default value is set to "servicegroup."
    """

    def __init__(self, host, user, passw, secure=True, verify=False, api_endpoint="servicegroup", **kwargs):
        super(ServiceGroup, self).__init__(host, user, passw, secure, verify, api_endpoint, **kwargs)

    def add_monitor_binding(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and the
        proposed binding is new. The bind_monitor method is used to post the binding configuration to the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The binding configuration to send to the Nitro API.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.bind_server(new_config)
            if config_status.ok:
                config.append({"method": "post", "url": config_status.url, "body": new_config})
            else:
                module.fail_json(msg=config_status.content)
        else:
            config.append({"method": "post", "url": self.url + self.api_endpoint + "_lbmonitor_binding",
                           "body": new_config})

        return config

    def add_server_binding(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and the
        proposed binding is new. The bind_server method is used to post the binding configuration to the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The binding configuration to send to the Nitro API.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.bind_server(new_config)
            if config_status.ok:
                config.append({"method": "post", "url": config_status.url, "body": new_config})
            else:
                module.fail_json(msg=config_status.content)
        else:
            config.append({"method": "post", "url": self.url + self.api_endpoint + "_servicegroupmember_binding",
                           "body": new_config})

        return config

    def bind_monitor(self, new_config):
        """
        This method is used to submit a binding request to the Netscaler using the Nitro API. It is expected that you
        compare the new_config with the results from get_monitor_bindings method before submitting the request.
        :param new_config: Type dict:
                           The new binding configuration to be sent to the Netscaler.
        :return: The response from the request to add the binding.
        """
        url = self.url + self.api_endpoint + "_lbmonitor_binding"
        body = {self.api_endpoint + "_lbmonitor_binding": new_config}
        response = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return response

    def bind_server(self, new_config):
        """
        This method is used to submit a binding request to the Netscaler using the Nitro API. It is expected that you
        compare the new_config with the results from get_server_bindings method before submitting the request.
        :param new_config: Type dict:
                           The new binding configuration to be sent to the Netscaler.
        :return: The response from the request to add the binding.
        """
        url = self.url + self.api_endpoint + "_servicegroupmember_binding"
        body = {self.api_endpoint + "_servicegroupmember_binding": new_config}
        response = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return response

    def change_state(self, object_name, state):
        """
        The purpose of this method is to change the state of a servicegroup object from either disabled to enabled, or
        enabled to disabled.
        :param object_name: Type str.
                            The name of the servicegroup object to be deleted.
        :param state: Type str.
                      The state the object should be in after execution. Valid values are "enable" or "disable"
        :return: The response from the request to delete the object.
        """
        url = self.url + self.api_endpoint + "?action={}".format(state)
        body = {self.api_endpoint: {"servicegroupname": object_name}}
        response = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return response

    def config_update(self, module, update_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and the
        proposed config modifies an existing servicegroup object. If the object's state needs to be updated, the "state"
        key,value is popped from the update_config in order to prevent it from being included in a config update when
        there are updates besides state change. The change_state method is then used to modify the object's state. After
        the object's state matches the proposed state, a check is done to see if the update_config has any keys other
        than the "name" key (len > 1). If there are more updates to make, the put_config method is used to push those to
        the Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param update_config: Type dict.
                              The configuration to send to the Nitro API.
        :return: The list of config dictionaries corresponding to the config returned by the Ansible module.
        """
        config = []

        if "state" in update_config:
            config_state = update_config.pop("state")[:-1].lower()
            if not module.check_mode:
                config_status = self.change_state(update_config["servicegroupname"], config_state)
                if config_status.ok:
                    config.append({"method": "post", "url": config_status.url,
                                   "body": {"servicegroupname": update_config["servicegroupname"]}})
                else:
                    module.fail_json(msg=config_status.content)
            else:
                url = self.url + self.api_endpoint + "?action={}".format(config_state)
                config.append({"method": "post", "url": url,
                               "body": {"servicegroupname": update_config["servicegroupname"]}})

        if len(update_config) > 1:
            if not module.check_mode:
                config_status = self.put_update(update_config)
                if config_status.ok:
                    config.append({"method": "put", "url": self.url, "body": update_config})
                else:
                    module.fail_json(msg=config_status.content)
            else:
                config.append({"method": "put", "url": self.url, "body": update_config})

        return config

    def get_all(self):
        """
        The purpose of this method is to retrieve every object's configuration for the instance's API endpoint.
        :return: A list of configuration dictionaries returned by they Nitro API. An empty list means that their are
                 currently no objects configured, or the request was unsuccessful.
        """
        response = self.session.get(self.url + self.api_endpoint, headers=self.headers, verify=self.verify)

        return response.json().get(self.api_endpoint, [])

    def get_all_attrs(self, attrs_list):
        """
        The purpose of this method is to retrieve every object's configuration for the instance's API endpoint, but the
        collected data is restricted to the attributes in the attrs_list argument.
        :param attrs_list: Type list,tuple
                           The list of attributes used to limit the scope of returned config data.
        :return: A list of configuration dictionaries returned by they Nitro API. An empty list means that their are
                 currently no objects configured, or the request was unsuccessful.
        """
        attrs = "?attrs=" + ",".join(attrs_list)
        url = self.url + self.api_endpoint + attrs

        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get(self.api_endpoint, [])

    @staticmethod
    def get_diff(proposed, existing):
        """
        This method is used to compare the proposed config with what currently exists on the Netscaler.
        :param proposed: Type dict.
                         A dictionary corresponding to the proposed configuration item. The dictionary must have a
                         "name" key.
        :param existing: Type dict.
                         A dictionary corresponding to the existing configuration for the object. This can be retrieved
                         using the get_existing_attrs method.
        :return: A tuple indicating whether the config is a new object, will update an existing object, or make no
                 changes, and a dict that corresponds to the body of a config request using the Nitro API.
        """
        diff = dict(set(proposed.items()).difference(existing.items()))

        if diff == proposed:
            return "new", proposed
        elif diff:
            diff["servicegroupname"] = proposed["servicegroupname"]
            return "update", diff
        else:
            return "none", {}

    def get_monitor_bindings(self, object_name):
        """
        This method is used to get the servicegroup's current monitor bindings.
        :param object_name: Type str.
                            The name of the servicegroup object.
        :return: A list of dictionaries of the current servers bound to the servicegroup object. If no bindings
                 exist, then an empty dictionary is returned.
        """
        url = self.url + self.api_endpoint + "_lbmonitor_binding/" + object_name + \
              "?attrs=servicegroupname,monitor_name,weight"
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get("servicegroup_lbmonitor_binding", [])

    def get_server_bindings(self, object_name):
        """
        This method is used to get the servicegroup's current server bindings.
        :param object_name: Type str.
                            The name of the servicegroup object.
        :return: A list of dictionaries of the current servers bound to the servicegroup object. If no bindings
                 exist, then an empty dictionary is returned.
        """
        url = self.url + self.api_endpoint + "_servicegroupmember_binding/" + object_name + \
              "?attrs=servicegroupname,servername,port,weight"
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get("servicegroup_servicegroupmember_binding", [])

    def remove_monitor_binding(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "absent" and the
        proposed binding exists. The unbind_monitor method is used to post the binding configuration to the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The binding configuration to build the Nitro API url.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.unbind_monitor(new_config)
            if config_status.ok:
                config.append({"method": "delete", "url": config_status.url, "body": {}})
            else:
                module.fail_json(msg=config_status.content)
        else:
            url = self.url + self.api_endpoint + \
                  "_lbmonitor_binding?args=servicegroupname:{},monitor_name:{}".format(
                      new_config["servicegroupname"], new_config["monitor_name"]
                  )

            config.append({"method": "delete", "url": url, "body": {}})

        return config

    def remove_server_binding(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "absent" and the
        proposed binding exists. The unbind_server method is used to post the binding configuration to the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The binding configuration to build the Nitro API url.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.unbind_server(new_config)
            if config_status.ok:
                config.append({"method": "delete", "url": config_status.url, "body": {}})
            else:
                module.fail_json(msg=config_status.content)
        else:
            url = self.url + self.api_endpoint + \
                  "_servicegroupmember_binding?args=servicegroupname:{},servername:{},port:{}".format(
                      new_config["servicegroupname"], new_config["servername"], new_config["port"]
                  )

            config.append({"method": "delete", "url": url, "body": {}})

        return config

    def unbind_monitor(self, binding_config):
        """
        This method is used to remove a monitor binding from a servicegroup object. It is expected that you check
        that the binding currently exists with the get_monitor_bindings method.
        :param binding_config: Type dict.
                               The current binding config that needs to be removed.
        :return: The response from the request to unbind the server from the servicegroup.
        """
        url = self.url + self.api_endpoint + \
              "_lbmonitor_binding?args=servicegroupname:{},monitor_name:{}".format(
                  binding_config["servicegroupname"], binding_config["monitor_name"]
              )
        response = self.session.delete(url, headers=self.headers, verify=self.verify)

        return response

    def unbind_server(self, binding_config):
        """
        This method is used to remove a server binding from a servicegroup object. It is expected that you check
        that the binding currently exists with the get_server_bindings method.
        :param binding_config: Type dict.
                               The current binding config that needs to be removed.
        :return: The response from the request to unbind the server from the servicegroup.
        """
        url = self.url + self.api_endpoint + \
              "_servicegroupmember_binding?args=servicegroupname:{},servername:{},port:{}".format(
                  binding_config["servicegroupname"], binding_config["servername"], binding_config["port"]
              )
        response = self.session.delete(url, headers=self.headers, verify=self.verify)

        return response


def main():
    argument_spec = dict(
        host=dict(required=True, type="str"),
        port=dict(required=False, type="int"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        use_ssl=dict(default=True, type="bool"),
        validate_certs=dict(default=False, type="bool"),
        provider=dict(required=False, type="dict"),
        state=dict(choices=["absent", "present"], default="present", type="str"),
        partition=dict(required=False, type="str"),
        server_name=dict(required=True, type="str"),
        server_port=dict(required=True, type="str"),
        servicegroup_name=dict(required=True, type="str"),
        weight=dict(required=False, type="str")
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    provider = module.params["provider"] or {}

    no_log = ["password"]
    for param in no_log:
        if provider.get(param):
            module.no_log_values.update(return_values(provider[param]))

    # allow local params to override provider
    for param, pvalue in provider.items():
        if module.params.get(param) is None:
            module.params[param] = pvalue
            
    host = module.params["host"]
    partition = module.params["partition"]
    password = module.params["password"]
    port = module.params["port"]
    state = module.params["state"]
    use_ssl = module.params["use_ssl"]
    username = module.params["username"]
    validate_certs = module.params["validate_certs"]
    service_port = module.params["server_port"]
    if service_port == "*":
        service_port = 65535
    else:
        try:
            service_port = int(service_port)
        except ValueError:
            module.fail_json(msg="'server_port' Must be a Number from 0 to 65535, or '*'")

    args = dict(
        port=service_port,
        servername=module.params["server_name"],
        servicegroupname=module.params["servicegroup_name"],
        weight=module.params["weight"]
    )
    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v)

    kwargs = dict()
    if port:
        kwargs["port"] = port

    session = ServiceGroup(host, username, password, use_ssl, validate_certs, **kwargs)
    session_login = session.login()
    if not session_login.ok:
        module.fail_json(msg="Unable to login")

    if partition:
        session_switch = session.switch_partition(partition)
        if not session_switch.ok:
            module.fail_json(msg=session_switch.content, reason="Unable to Switch Partitions")

    all_existing = session.get_server_bindings(proposed["servicegroupname"])

    if state == "present":
        results = change_config(session, module, proposed, all_existing)
    else:
        results = delete_server_binding(session, module, proposed, all_existing)

    return module.exit_json(**results)


def change_config(session, module, proposed, all_existing):
    """
    The purpose of this function is to determine if the binding needs to be pushed to the Netscaler. A new servicegroup
    to server binding will be configured if the binding does not currently exist.
    :param session: The ServiceGroup instance that has an established session with the Netscaler.
    :param module: The AnsibleModule instance.
    :param proposed: Type dict.
                     The proposed binding based on Ansible inputs.
    :param all_existing: Type list.
                         A list of dictionaries corresponding to the existing bindings for the object.
    :return: Returns a dictionary containing the module exit values.
    """
    changed = False
    config = []
    existing = {}
    # wildcard includes all ports meaning that no new ports need to be added; needed to keep idempotent
    proposed_wcard = dict(servicegroupname=proposed["servicegroupname"], servername=proposed["servername"], port=65535)
    proposed_minimum = dict(servicegroupname=proposed["servicegroupname"], servername=proposed["servername"],
                            port=proposed["port"])

    for binding in all_existing:
        if proposed_wcard == dict(servicegroupname=binding["servicegroupname"], servername=binding["servername"],
                                  port=binding["port"]):
            existing = proposed_wcard
            break
        elif proposed_minimum == dict(servicegroupname=binding["servicegroupname"], servername=binding["servername"],
                                      port=binding["port"]):
            existing = proposed
            break

    if not existing:
        changed = True
        config = session.add_server_binding(module, proposed)

    return {"all_existing": all_existing, "changed": changed, "config": config, "existing": existing}


def delete_server_binding(session, module, proposed, all_existing):
    """
    The purpose of this function is to delete a servicegroup to server binding from the Netscaler. Checks are currently
    only done to ensure the binding exists before submitting it for deletion.
    :param session: The Monitor instance that has an established session with the Netscaler.
    :param module: The AnsibleModule instance
    :param proposed: Type dict.
                     The proposed binding based on Ansible inputs.
    :param all_existing: Type list.
                         A list of dictionaries corresponding to the existing bindings for the object.
    :return: Returns a dictionary containing the module exit values.
    """
    changed = False
    config = []
    proposed_minimum = dict(servicegroupname=proposed["servicegroupname"], servername=proposed["servername"],
                            port=proposed["port"])

    for binding in all_existing:
        if proposed_minimum == dict(servicegroupname=binding["servicegroupname"], servername=binding["servername"],
                                    port=binding["port"]):
            changed = True
            config = session.remove_server_binding(module, proposed)
            existing = proposed

    if not config:
        existing = {}

    return {"all_existing": all_existing, "changed": changed, "config": config, "existing": existing}


if __name__ == "__main__":
    main()
