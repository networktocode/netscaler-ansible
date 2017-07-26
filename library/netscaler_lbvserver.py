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
module: netscaler_lbvserver
version_added: "2.3"
short_description: Manages LB VServer resources and attributes.
description:
  - Manages Netscaler LB VServer configurations using Nitro API.
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
  backup_lbvserver:
    description:
      - The name of the backup lbvserver
    required: false
    type: str
  client_timeout:
    description:
      - Seconds to wait before terminating a client session.
      - Valid inputs are from 0 to 31536000.
    required: false
    type: str
  comment:
    description:
      - A comment about the lbvserver
    required: false
    type: str
  config_override:
    description:
      - Setting to True enables changing IP Addresses and Names
      - If an LB VServer with a different name is configured with the same IP Address,
        Traffic Domain, and Port, then the existing VServer will be renamed.
      - If an LB VServer already exists with the same Name, but different IP Address,
        then the existing VServer will have its IP Address updated.
  conn_failover:
    description:
      - The lbvserver connection setting
    required: false
    type: str
    choices: ["DISABLED", "STATEFUL", "STATELESS"]
  cookie_name:
    description:
      - The name of the cookie to use.
      - Used with a COOKIE persistence type.
    required: false
    type: str
  ip_address:
     description:
       - The IP address of the Server Object.
     required: false
  lbmethod:
    description:
      - The method to load balance traffic.
    required: false
    choices: ["ROUNDROBIN", "LEASTCONNECTION", "LEASTRESPONSETIME", "URLHASH", "DOMAINHASH", "DESTINATIONIPHASH",
              "SOURCEIPHASH", "SRCIPDESTIPHASH", "LEASTBANDWIDTH", "LEASTPACKETS", "TOKEN", "SRCIPSRCPORTHASH",
              "LRTM", "CALLIDHASH", "CUSTOMLOAD", "LEASTREQUEST", "AUDITLOGHASH", "STATICPROXIMITY"]
    type: str
  lbvserver_name:
    description:
      - The name of the lbvserver object
    required: true
    type: str
  lbvserver_port:
    description:
      - The port the lbvserver will listen on.
      - Valid protocol port ranges and "*" are supported.
    required: false
    type: str
  lbvserver_state:
    description:
      - The resources desired activity.
      - Disabled marks it out of service.
      - Enabled marks it serviceable.
    required: false
    default: enabled
    type: str
    choices: ["disabled", "enabled"]
  persistence:
    description:
      - The persistence type used by the lbvserver.
    required: false
    type: str
    choices: ["SOURCEIP", "COOKIEINSERT", "SSLSESSION", "RULE", "URLPASSIVE", "CUSTOMSERVERID", "DESTIP",
              "SRCIPDESTIP", "CALLID", "RTSPSID", "DIAMETER", "FIXSESSION", "NONE"]
  service_type:
    description:
      - The type of service the lbvserver provides.
    required: false
    type: str
    choices: ["HTTP", "FTP", "TCP", "UDP", "SSL", "SSL_BRIDGE", "SSL_TCP", "DTLS", "NNTP", "DNS", "DHCPRA", "ANY",
              "SIP_UDP", "SIP_TCP", "SIP_SSL", "DNS_TCP", "RTSP", "PUSH", "SSL_PUSH", "RADIUS", "RDP", "MYSQL",
              "MSSQL", "DIAMETER", "SSL_DIAMETER", "TFTP", "ORACLE", "SMPP", "SYSLOGTCP", "SYSLOGUDP", "FIX"]
  traffic_domain:
    description:
      - The traffic domain associated with the servicegroup
    required: false
    type: str
    default: "0"
'''

EXAMPLES = '''
- name: Config Lbvserver Object
  netscaler_lbvserver:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    lbvserver_name: "lbvsvr_app01"
    ip_address: "10.10.10.21"
    service_type: "ANY"
    lbvserver_port: "*"
    lbmethod: "ROUNDROBIN"
- name: Config Backup Lbvserver Object
  netscaler_lbvserver:
    host: : "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    lbvserver_name: "lbvsvr_app02"
    ip_address: "0.0.0.0"
    service_type: "SSL"
    lbvserver_port: "0"
    persistence: "COOKIEINSERT"
    cookie_name: "choc_chip"
    partition: "Lab"
    port: 8080
    comment: app02 backup vserver
- name: Config Server Object in Lab Partition
  netscaler_lbvserver:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    lbvserver_name: "lbvsvr_app02"
    backup_lbvserver: "lbvsvr_app02_backup"
    ip_address: "10.10.10.22"
    lbvserver_port: "443"
    persistence: "COOKIEINSERT"
    cookie_name: "choc_chip"
    partition: "Lab"
    use_ssl: False
    port: 8080
    comment: app02 vserver
- name: Delete Lbvserver Object
  netscaler_lbvserver:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    state: "deleted"
    lbvserver_name: "lbvsvr_app01"
    validate_certs: True
'''

RETURN = '''
existing:
    description: The existing configuration for the lbvserver (uses lbvserver_name) before the task executed.
    returned: always
    type: dict
    sample: {"clttimeout": "120", "connfailover": "DISABLED", "ipv46": "100.0.0.0", "lbmethod": "ROUNDROBIN",
                 "name": "test", "persistencetype": "NONE", "port": 80, "servicetype": "ANY", "state": "ENABLED",
                 "td": "0"}
config:
    description: The configuration that was pushed to the Netscaler.
    returned: always
    type: list
    sample: [{"method": "post", "url": "https://netscaler/nitro/v1/config/lbvserver?action=disable",
              "body": {}},{"method": "put", "url": "https://10.1.100.121/nitro/v1/config/"
              "body": {"comment": "Temp Disable", "name": "test"}}]
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
        if "port" not in kwargs:
            self.port = ""
        else:
            self.port = ":{}".format(kwargs["port"])

        if use_ssl:
            self.url = "https://{lb}{port}/nitro/v1/config/".format(lb=self.host, port=self.port)
            self.stat_url = "https://{lb}{port}/nitro/v1/stat/".format(lb=self.host, port=self.port)
        else:
            self.url = "http://{lb}{port}/nitro/v1/config/".format(lb=self.host, port=self.port)
            self.stat_url = "http://{lb}{port}/nitro/v1/stat/".format(lb=self.host, port=self.port)

    def change_name(self, existing_name, proposed_name):
        """
        The purpose of this method is to change the name of a server object.
        :param existing_name: Type str.
                              The name of the server object to be renamed.
        :param proposed_name: Type str.
                              The new name of the server object.
        :return: The response from the request to delete the object.
        """
        url = self.url + self.api_endpoint + "?action=rename"
        body = {self.api_endpoint: {"name": existing_name, "newname":proposed_name}}
        response = self.session.post(url, json=body, headers=self.headers, verify=self.verify)

        return response

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

    def config_rename(self, module, existing_name, proposed_name):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and the
        proposed IP Address matches the IP Address of another Server in the same Traffic Domain. The change_name
        method is used to post the configuration to the Netscaler.
        :param module: The AnsibleModule instance started by the task.
        :param existing_name: Type str.
                              The current name of the Server object to be changed.
        :param proposed_name: Type str.
                              The name the Server object should be changed to.
        :return: A list with config dictionary corresponding to the config returned by the Ansible module.
        """
        config = []

        rename_config = {"name": existing_name, "newname": proposed_name}

        if not module.check_mode:
            config_status = self.change_name(existing_name, proposed_name)
            if config_status.ok:
                config.append({"method": "post", "url": config_status.url, "body": rename_config})
            else:
                module.fail_json(msg=config_status.content)
        else:
            config.append({"method": "post", "url": self.url + self.api_endpoint + "?action=rename", "body": rename_config})

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



VALID_SERVICETYPES = ["HTTP", "FTP", "TCP", "UDP", "SSL", "SSL_BRIDGE", "SSL_TCP", "DTLS", "NNTP", "DNS", "DHCPRA",
                      "ANY", "SIP_UDP", "SIP_TCP", "SIP_SSL", "DNS_TCP", "RTSP", "PUSH", "SSL_PUSH", "RADIUS", "RDP",
                      "MYSQL", "MSSQL", "DIAMETER", "SSL_DIAMETER", "TFTP", "ORACLE", "SMPP", "SYSLOGTCP", "SYSLOGUDP",
                      "FIX"]
VALID_LBMETHODS = ["ROUNDROBIN", "LEASTCONNECTION", "LEASTRESPONSETIME", "URLHASH", "DOMAINHASH", "DESTINATIONIPHASH",
                   "SOURCEIPHASH", "SRCIPDESTIPHASH", "LEASTBANDWIDTH", "LEASTPACKETS", "TOKEN", "SRCIPSRCPORTHASH",
                   "LRTM", "CALLIDHASH", "CUSTOMLOAD", "LEASTREQUEST", "AUDITLOGHASH", "STATICPROXIMITY"]
VALID_PERSISTENCE_TYPES = ["SOURCEIP", "COOKIEINSERT", "SSLSESSION", "RULE", "URLPASSIVE", "CUSTOMSERVERID", "DESTIP",
                           "SRCIPDESTIP", "CALLID", "RTSPSID", "DIAMETER", "FIXSESSION", "NONE"]


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
        backup_lbvserver=dict(required=False, type="str"),
        client_timeout=dict(required=False, type="str"),
        comment=dict(required=False, type="str"),
        config_override=dict(choices=[True, False], type="bool", default=False),
        conn_failover=dict(choices=["DISABLED", "STATEFUL", "STATELESS"], required=False, type="str"),
        cookie_name=dict(required=False, type="str"),
        ip_address=dict(required=False, type="str"),
        lbmethod=dict(choices=VALID_LBMETHODS, required=False, type="str"),
        lbvserver_name=dict(required=True, type="str"),
        lbvserver_port=dict(required=False, type="str"),
        lbvserver_state=dict(choices=["disabled", "enabled"], required=False, type="str", default="enabled"),
        persistence=dict(choices=VALID_PERSISTENCE_TYPES, required=False, type="str"),
        service_type=dict(choices=VALID_SERVICETYPES, required=False, type="str"),
        traffic_domain=dict(required=False, type="str", default="0"),
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

    args = dict(
        backupvserver=module.params["backup_lbvserver"],
        clttimeout=module.params["client_timeout"],
        comment=module.params["comment"],
        connfailover=module.params["conn_failover"],
        cookiename=module.params["cookie_name"],
        ipv46=module.params["ip_address"],
        lbmethod=module.params["lbmethod"],
        name=module.params["lbvserver_name"],
        port=module.params["lbvserver_port"],
        state=module.params["lbvserver_state"].upper(),
        persistencetype=module.params["persistence"],
        servicetype=module.params["service_type"],
        td=module.params["traffic_domain"]
    )

    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v)

    if "port" in proposed:
        if proposed["port"] == "*":
            if proposed["servicetype"] != "ANY":
                module.fail_json(msg="'*' can only be used with a service_type of 'ANY'")
            else:
                proposed["port"] = 65535
        else:
            try:
                proposed["port"] = int(proposed["port"])
            except ValueError:
                module.fail_json(msg="'lbvserver_port' Must be a Number from 0 to 65535, or '*'")

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

    existing_attrs = args.keys()
    existing = session.get_existing_attrs(proposed["name"], existing_attrs)

    if state == "present":
        results = change_config(session, module, proposed, existing)
    else:
        results = delete_lbvserver(session, module, proposed["name"], existing)

    return module.exit_json(**results)


def change_config(session, module, proposed, existing):
    """
    The purpose of this function is to determine the appropriate configuration to push to the Netscaler. A new lbvserver
    object has the full configuration submitted from the Ansible task pushed to the Netscaler. Configuration changes to
    an existing lbvserver will only push the modifications to the Netscaler. This will also handle changing the
    lbvserver's "state" from either enabled or disabled if the state is currently different than specified in the task.
    Checks are made to ensure that attempts to change either the servicetype or traffic domain values raise an error, as
    this is not allowed by Netscaler. Checks are also made to verify the IP address is not different than the current
    configuration.
    :param session: The Server instance that has an established session with the Netscaler.
    :param module: The AnsibleModule instance.
    :param proposed: Type dict.
                     The proposed configuration based on Ansible inputs.
    :param existing: Type dict.
                     A dictionary corresponding to the existing configuration for
                     the object.
    :return: Returns a dictionary containing the module exit values.
    """
    changed = False
    config = []
    rename = []

    config_method, config_diff = session.get_diff(proposed, existing)
    # check for duplicate lbvserver only if object is a primary vserver
    if "ipv46" in config_diff and config_diff["ipv46"] != "0.0.0.0" and "port" in config_diff:
        dup_lbvserver = session.get_lbvserver_by_ip_td_port(proposed["ipv46"], proposed["td"], proposed["port"])
        if dup_lbvserver and not module.params["config_override"]:
            dup_dict = dict(
                proposed_name=proposed["name"], existing_name=dup_lbvserver["name"], ip_address=dup_lbvserver["ipv46"],
                traffic_domain=dup_lbvserver["td"], service_type=dup_lbvserver["servicetype"], port=dup_lbvserver["port"]
            )
            module.fail_json(msg="Changing a LBVServer's Name requires setting the config_override param to True:.", conflict=dup_dict)
        elif dup_lbvserver:
           changed = True
           rename = session.config_rename(module, dup_lbvserver["name"], proposed["name"])
           new_existing = session.get_existing_attrs(proposed["name"], proposed.keys())
           config_method, config_diff = LBVServer.get_diff(proposed, new_existing)
    
    if config_method == "new":
        # raise error if new primary lbvserver does not include proper port and servicetype configurations
        if "ipv46" in config_diff and config_diff["ipv46"] != "0.0.0.0":
            if "port" not in config_diff or "servicetype" not in config_diff:
                module.fail_json(msg="The port and service type must be specified for a new primary lbvserver.")
            elif config_diff["port"] == 0:
                module.fail_json(msg="A port value of 0 is only supported with an ip_address of '0.0.0.0'")
        # raise error if new backup lbvserver has set the port to a value other than 0
        elif "ipv46" in config_diff and config_diff["port"] != 0:
            module.fail_json(msg="An ip_address value of '0.0.0.0' only supports a port of 0")

        changed = True
        config = session.config_new(module, config_diff)

    elif config_method == "update":
        # raise error if servicetype, traffic domain, port, or ipv46 are different than current config
        if "servicetype" in config_diff:
            module.fail_json(msg="Modifying the Service Type is not Supported")

        if "td" in config_diff:
            module.fail_json(msg="Updating a VServer's Traffic Domain is not Supported")

        if "port" in config_diff:
            module.fail_json(msg="Modifying the VServer's Port is not Supported")

        if "ipv46" in config_diff and not module.params["config_override"]:
            dup_dict = dict(name=proposed["name"], proposed_ip=proposed["ipv46"], existing_ip=existing["ipv46"], traffic_domain=proposed["td"])
            module.fail_json(msg="Updating a LBVServer's IP Addresses requires setting the config_override param to True.", conflict=dup_dict)

        changed = True
        config = session.config_update(module, config_diff)

    if rename:
        config.append(rename[0])

    return {"changed": changed, "config": config, "existing": existing}


def delete_lbvserver(session, module, proposed_name, existing):
    """
    The purpose of this function is to delete a lbvserver from the Netscaler. Checks are currently only done to ensure
    the object exists before submitting it for deletion. If the lbvserver has bindings, it will still be deleted.
    :param session: The Server instance that has an established session with the Netscaler.
    :param module: The AnsibleModule instance
    :param proposed_name: Type str.
                          The name of the proposed server to delete.
    :param existing: Type dict.
                     A dictionary corresponding to the existing configuration for
                     the object.
    :return: Returns a dictionary containing the module exit values.
    """
    changed = False
    config = []

    if existing:
        changed = True
        config = session.config_delete(module, proposed_name)

    return {"changed": changed, "config": config, "existing": existing}


if __name__ == "__main__":
    main()
    