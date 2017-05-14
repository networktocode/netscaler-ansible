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
module: netscaler_lbvserver_servicegroup
version_added: "2.3"
short_description: Manages lbvserver to service group bindings.
description:
  - Manages Netscaler lbvserver to service group binding configurations using Nitro API.
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
  lbvserver_name:
    description:
      - The lbvserver name which is being bound to a service group.
    required: True
    type: str
  servicegroup_name:
    description:
      - The service group name which the lbvserver is being bound to.
    required: True
    type: str
'''

EXAMPLES = '''
- name: Bind VServer to Service Group
  netscaler_lbvserver:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    lbvserver_name: vserver_app01
    servicegroup_name: svcgrp_app01
- name: Bind VServer to Service Group in Lab Partition
  netscaler_lbvserver:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    lbvserver_name: vserver_app02
    servicegroup_name: svcgrp_app02
    partition: Lab
    port: 8080
    use_ssl: False
'''

RETURN = '''
all_existing:
    description: All existing service group bindings for the lbvserver.
    returned: always
    type: list
    sample: [{"name": "vserver_app01", "servicegroupname": "svcgrp_app01"}]
config:
    description: The configuration that was sent to the the Netscaler API. Existing bindings return an empty dict.
    returned: always
    type: dict
    sample: {}
existing:
    description: The existing binding for the lbvserver and service group pair. New bindings return an empty dict.
    returned: always
    type: dict
    sample: {"name": "vserver_app01", "servicegroupname": "svcgrp_app01"}
'''


import requests
from ansible.module_utils.basic import AnsibleModule, env_fallback

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


class LBVServer(Netscaler):
    """
    This is the class used for interacting with the "lbvserver" API endpoint. In addition to lbvserver specific methods,
    the api endpoint default value is set to "lbvserver."
    """

    def __init__(self, host, user, passw, secure=True, verify=False, api_endpoint="lbvserver", **kwargs):
        super(LBVServer, self).__init__(host, user, passw, secure, verify, api_endpoint, **kwargs)

    def add_certkey_binding(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and the
        proposed binding is new. The bind_certkey method is used to post the binding configuration to the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The binding configuration to send to the Nitro API.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.bind_certkey(new_config)
            if config_status.ok:
                config.append({"method": "post", "url": config_status.url, "body": new_config})
            else:
                module.fail_json(msg=config_status.content)
        else:
            config.append({"method": "post", "url": self.url + "sslvserver_sslcertkey_binding", "body": new_config})

        return config

    def add_servicegroup_binding(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and the
        proposed binding is new. The bind_servicegroup method is used to post the binding configuration to the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The binding configuration to send to the Nitro API.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.bind_servicegroup(new_config)
            if config_status.ok:
                config.append({"method": "post", "url": config_status.url, "body": new_config})
            else:
                module.fail_json(msg=config_status.content)
        else:
            config.append({"method": "post", "url": self.url + self.api_endpoint + "_servicegroup_binding",
                           "body": new_config})

        return config

    def bind_certkey(self, new_config):
        """
        This method is used to submit a binding request to the Netscaler using the Nitro API. It is expected that you
        compare the new_config with the results from get_certkey_bindings method before submitting the request.
        :param new_config: Type dict:
                           The new binding configuration to be sent to the Netscaler.
        :return: The response from the request to add the binding.
        """
        url = self.url + "sslvserver_sslcertkey_binding"
        body = {"sslvserver_sslcertkey_binding": new_config}
        response = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return response

    def bind_servicegroup(self, new_config):
        """
        This method is used to submit a binding request to the Netscaler using the Nitro API. It is expected that you
        compare the new_config with the results from get_servicegroup_bindings method before submitting the request.
        :param new_config: Type dict:
                           The new binding configuration to be sent to the Netscaler.
        :return: The response from the request to add the binding.
        """
        url = self.url + self.api_endpoint + "_servicegroup_binding"
        body = {self.api_endpoint + "_servicegroup_binding": new_config}
        response = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return response

    def check_duplicate_ip_port_service(self, proposed):
        """
        The purpose of this method is to identify if the proposed lbvserver has either an "ipv46" and "servicetype" or
        an "ipv46" and "port" value combination that already exists in the current partition and traffic domain. This
        should be used to prevent an invalid API request since each lbvserver "ipv46" must not reuse either
        "servicetype" or "port" values.
        :param proposed: Type dict.
                         The proposed lbvserver configuration.
        :return: A dictionary with the information about colliding lbvserver. An empty dictionary is returned if all
                 combinations are unique.
        """
        ip_address = proposed["ipv46"]
        traffic_domain = proposed["td"]
        service_type = proposed["servicetype"]
        port = proposed["port"]

        colliding_lbvserver_dict = {}
        colliding_lbvserver = self.get_lbvserver_by_ip_td_servicetype(ip_address, traffic_domain, service_type)

        if not colliding_lbvserver:
            colliding_lbvserver = self.get_lbvserver_by_ip_td_port(ip_address, traffic_domain, port)

        if colliding_lbvserver:
            colliding_lbvserver_dict["proposed_name"] = proposed["name"]
            colliding_lbvserver_dict["existing_name"] = colliding_lbvserver["name"]
            colliding_lbvserver_dict["ip_address"] = ip_address
            colliding_lbvserver_dict["traffic_domain"] = traffic_domain
            colliding_lbvserver_dict["existing_service"] = colliding_lbvserver["servicetype"]
            colliding_lbvserver_dict["existing_port"] = colliding_lbvserver["port"]

        return colliding_lbvserver_dict

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

    def get_certkey_bindings(self, proposed_config):
        """
        This method is used to get the lbvserver's current certkey bindings.
        :param proposed_config: Type dict.
                                The proposed lbvserver to sslcertkey binding.
        :return: A list of dictionaries of the current certificates bound to the lbvserver object. If no bindings
                 exist, then an empty dictionary is returned.
        """
        attrs_list = proposed_config.keys()
        attrs = "?attrs=" + ",".join(attrs_list)
        url = self.url + "sslvserver_sslcertkey_binding/" + proposed_config["vservername"] + attrs
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get("sslvserver_sslcertkey_binding", [])

    def get_lbvserver_by_ip_td_servicetype(self, ip_address, traffic_domain, service_type):
        """
        This method is used to collect the config of a server with an identical "ipv46," "td," and "port" as the
        proposed lbvserver.
        :param ip_address: Type str.
                           The proposed "ipaddress" value.
        :param traffic_domain: Type str.
                               The proposed "td" value.
        :param service_type: Type str.
                             The proposed "servicetype" value.
        :return: A dictionary of the server configuration. If the server is unique, then an empty dictionary is
                 returned.
        """
        url = self.url + self.api_endpoint + "?filter=ipv46:{},td:{},servicetype:{}".format(
            ip_address, traffic_domain, service_type
        )
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get("lbvserver", [{}])[0]

    def get_lbvserver_by_ip_td_port(self, ip_address, traffic_domain, port):
        """
        This method is used to collect the config of a server with an identical "ipv46," "td," and "port" as the
        proposed lbvserver.
        :param ip_address: Type str.
                           The proposed "ipaddress" value.
        :param traffic_domain: Type str.
                               The proposed "td" value.
        :param port: Type int.
                     The proposed "port" value.
        :return: A dictionary of the server configuration. If the server is unique, then an empty dictionary is
                 returned.
        """
        url = self.url + self.api_endpoint + "?filter=ipv46:{},td:{},port:{}".format(
            ip_address, traffic_domain, port
        )
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get("lbvserver", [{}])[0]

    def get_servicegroup_bindings(self, object_name):
        """
        This method is used to get the lbvserver's current servicegroup bindings.
        :param object_name: Type str.
                            The name of the lbvserver object.
        :return: A list of dictionaries of the current servicegroups bound to the lbvserver object. If no bindings
                 exist, then an empty dictionary is returned.
        """
        url = self.url + self.api_endpoint + "_servicegroup_binding/" + object_name + "?attrs=name,servicegroupname"
        response = self.session.get(url, headers=self.headers, verify=self.verify)

        return response.json().get("lbvserver_servicegroup_binding", [])

    def remove_certkey_binding(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "absent" and the
        proposed binding exists. The unbind_certkey method is used to delete the binding configuration from the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The binding configuration to build the Nitro API url.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.unbind_certkey(new_config)
            if config_status.ok:
                config.append({"method": "delete", "url": config_status.url, "body": {}})
            else:
                module.fail_json(msg=config_status.content)
        else:
            args_list = new_config.items()
            args = "?args="
            for k, v in args_list:
                if k != args_list[-1][0]:
                    args += k + ":" + str(v) + ","
                else:
                    args += k + ":" + str(v)

            config.append({"method": "delete", "url": self.url + "sslvserver_sslcertkey_binding" + args, "body": {}})

        return config

    def remove_servicegroup_binding(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "absent" and the
        proposed binding exists. The unbind_servicegroup method is used to delete the binding configuration from the
        Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param new_config: Type dict.
                           The binding configuration to build the Nitro API url.
        :return: The config dict corresponding to the config returned by the Ansible module.
        """
        config = []

        if not module.check_mode:
            config_status = self.unbind_servicegroup(new_config)
            if config_status.ok:
                config.append({"method": "delete", "url": config_status.url, "body": {}})
            else:
                module.fail_json(msg=config_status.content)
        else:
            url = self.url + self.api_endpoint + "_servicegroup_binding?args=name:{},servicegroupnaname:{}".format(
                new_config["name"], new_config["servicegroupname"])

            config.append({"method": "delete", "url": url, "body": {}})

        return config

    def unbind_certkey(self, binding_config):
        """
        This method is used to remove a certkey binding from a lbvserver object. It is expected that you check
        that the binding currently exists with the get_certkey_bindings method.
        :param binding_config: Type dict.
                               The current binding config that needs to be removed.
        :return: The response from the request to unbind the servicegroup from the lbvserver.
        """
        args_list = binding_config.items()
        args = "?args="
        for k, v in args_list:
            if k != args_list[-1][0]:
                args += k + ":" + str(v) + ","
            else:
                args += k + ":" + str(v)

        url = self.url + "sslvserver_sslcertkey_binding" + args
        response = self.session.delete(url, headers=self.headers, verify=self.verify)

        return response

    def unbind_servicegroup(self, binding_config):
        """
        This method is used to remove a servicegroup binding from a lbvserver object. It is expected that you check
        that the binding currently exists with the get_servicegroup_bindings method.
        :param binding_config: Type dict.
                               The current binding config that needs to be removed.
        :return: The response from the request to unbind the servicegroup from the lbvserver.
        """
        url = self.url + self.api_endpoint + "_servicegroup_binding?args=name:{},servicegroupname:{}".format(
            binding_config["name"], binding_config["servicegroupname"]
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
        lbvserver_name=dict(required=True, type="str"),
        servicegroup_name=dict(required=True, type="str")
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    provider = module.params['provider'] or {}
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

    proposed = dict(
        name=module.params["lbvserver_name"],
        servicegroupname=module.params["servicegroup_name"]
    )

    kwargs = dict()
    if port:
        kwargs["port"] = port

    session = LBVServer(host, username, password, use_ssl, validate_certs, **kwargs)
    session_login = session.login()
    if not session_login.ok:
        module.fail_json(msg="Unable to login")

    if partition:
        session_switch = session.switch_partition(partition)
        if not session_switch.ok:
            module.fail_json(msg=session_switch.content, reason="Unable to Switch Partitions")

    all_existing = session.get_servicegroup_bindings(proposed["name"])

    if state == "present":
        results = change_config(session, module, proposed, all_existing)
    else:
        results = delete_servicegroup_binding(session, module, proposed, all_existing)

    return module.exit_json(**results)


def change_config(session, module, proposed, all_existing):
    """
    The purpose of this function is to determine if the binding needs to be pushed to the Netscaler. A new lbvserver
    to servicegroup binding will be configured if the binding does not currently exist.
    :param session: The LBVServer instance that has an established session with the Netscaler.
    :param module: The AnsibleModule instance.
    :param proposed: Type dict.
                     The proposed binding based on Ansible inputs.
    :param all_existing: Type list.
                         A list of dictionaries corresponding to the existing bindings for the object.
    :return: Returns a dictionary containing the module exit values.
    """
    changed = False
    config = []

    if proposed not in all_existing:
        changed = True
        config = session.add_servicegroup_binding(module, proposed)
        existing = {}
    else:
        existing = proposed

    return {"all_existing": all_existing, "changed": changed, "config": config, "existing": existing}


def delete_servicegroup_binding(session, module, proposed, all_existing):
    """
    The purpose of this function is to delete a lbvserver to servicegroup binding from the Netscaler. Checks are
    currently only done to ensure binding exists before submitting it for deletion.
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

    if proposed in all_existing:
        changed = True
        config = session.remove_servicegroup_binding(module, proposed)
        existing = proposed
    else:
        existing = {}

    return {"all_existing": all_existing, "changed": changed, "config": config, "existing": existing}


if __name__ == "__main__":
    main()
