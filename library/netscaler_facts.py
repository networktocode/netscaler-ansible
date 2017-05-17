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
module: netscaler_facts
version_added: "2.3"
short_description: Gathers Netscaler Facts
description:
  - Gathers System, Hardware, and Configuration Facts for Netscaler Nitro API
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
  provider:
    description:
      - Dictionary which acts as a collection of arguments used to define the characteristics
        of how to connect to the device.
      - Arguments hostname, username, and password must be specified in either provider or local param.
      - Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.
    required: false
    type: dict
  port:
    description:
      - The TCP port used to connect to the Netscaler if other than the default used by the transport
        method(http=80, https=443).
    required: false
    type: int
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
  gather_subset:
    description:
      - The list of facts to gather.
      - Gathered facts are limited using either an include list, or using an exclude list ("!...").
    required: false
    default: ["all"]
    choices: ["all", "hardware_data", "interface_data", "lbvserver_stats", "config", "server_config",
              "service_group_config", "lbvserver_config", "monitor_config", "!all", "!hardware_data", "!interface_data",
              "!lbvserver_stats", "!config", "!server_config", "!service_group_config", "!lbvserver_config",
              "!monitor_config"]
  config_scope:
    description:
      - The configuration scope to retrieve; used when gathering "config" fact.
      - setting to "true" will include default configuration values.
    required: false
    default: "false"
    choices: ["true", "false"]
'''

EXAMPLES = '''
- name: Gather All Facts
  netscaler_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
- name: Limit Facts with Includes
  netscaler_facts:
    host: : "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    gather_subset:
      - lbvserver_stats
      - lbvserver_config
- name: Limit Facts with Exclude
  netscaler_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    gather_subset:
      - "!config"
- name: Gather Full Config
  netscaler_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    config_state: "deleted"
    config_scope: true
    partition: Lab
- name: Gather System Data
  netscaler_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    uss_ssl: False
    port: 8080
'''

RETURN = '''
ntc_system_data:
    description: The Netscaler's system data.
    returned: always
    type: dict
    sample: {
        "current_time": "Tue May  9 02:38:34 2017",
        "hostname": "netscaler01",
        "last_config": "Mon May  8 14:59:07 2017",
        "last_save": "Mon May  8 14:57:44 2017",
        "mgmt_net": {
            "interfaces": [
                "0/1"
            ],
            "ip_address": "10.1.1.21",
            "netmask": "255.255.255.0",
            "primary_ip": "10.1.1.21",
            "vlan": "10",
            "vlan_tagged": "NO"
        },
        "model": "NetScaler Virtual Appliance",
        "serial_number": "HE1JV372E4",
        "system_mac": "001122aabbcc",
        "system_type": "Stand-alone",
        "timezone": "CoordinatedUniversalTime",
        "year": 2012
    }
hardware_data:
    description: The Netscaler's hardware data.
    returned: When hardware_data or all is included
    type: dict
    sample: {
        "auxtemp0": 0,
        "auxtemp1": 0,
        "auxtemp2": 0,
        "auxtemp3": 0,
        "auxvolt0": 0.0,
        "auxvolt1": 0.0,
        "auxvolt2": 0.0,
        "auxvolt3": 0.0,
        "auxvolt4": 0.0,
        "auxvolt5": 0.0,
        "auxvolt6": 0.0,
        "auxvolt7": 0.0,
        "cpu0temp": 0,
        "cpu1temp": 0,
        "cpufan0speed": 0,
        "cpufan1speed": 0,
        "cpuusage": "0",
        "cpuusagepcnt": 26.7,
        "disk0avail": 1298,
        "disk0perusage": 8,
        "disk0size": 1547,
        "disk0used": 125,
        "disk1avail": 12418,
        "disk1perusage": 4,
        "disk1size": 14208,
        "disk1used": 653,
        "fan0speed": 0,
        "fan2speed": 0,
        "fan3speed": 0,
        "fan4speed": 0,
        "fan5speed": 0,
        "fanspeed": 0,
        "internaltemp": 0,
        "mastercpuusage": "0",
        "memsizemb": "0",
        "memusagepcnt": 15.540566,
        "memuseinmb": "159",
        "mgmtcpuusagepcnt": 42.6,
        "numcpus": "1",
        "pktcpuusagepcnt": 26.7,
        "powersupply1status": "NOT SUPPORTED",
        "powersupply2status": "NOT SUPPORTED",
        "powersupply3status": "NOT SUPPORTED",
        "powersupply4status": "NOT SUPPORTED",
        "rescpuusage": "0",
        "rescpuusagepcnt": 0.0,
        "slavecpuusage": "0",
        "starttime": "Mon May  8 14:58:53 2017",
        "systemfanspeed": 0,
        "timesincestart": "00:00:00",
        "voltagev12n": 0.0,
        "voltagev12p": 0.0,
        "voltagev33main": 0.0,
        "voltagev33stby": 0.0,
        "voltagev5n": 0.0,
        "voltagev5p": 0.0,
        "voltagev5sb": 0.0,
        "voltagevbat": 0.0,
        "voltagevcc0": 0.0,
        "voltagevcc1": 0.0,
        "voltagevsen2": 0.0,
        "voltagevtt": 0.0
    }
interface_data:
    description: The Netscaler's interface configuration and stats
    returned: When interface_data or all is included
    type: list
    sample: [
        {
            "actduplex": "FULL",
            "actspeed": "1000",
            "actthroughput": "1000",
            "actualmtu": "1500",
            "autoneg": "ENABLED",
            "autonegresult": "0",
            "backplane": "DISABLED",
            "bandwidthhigh": "0",
            "bandwidthnormal": "0",
            "bdgmacmoved": "0",
            "bdgmuted": "0",
            "cleartime": "0",
            "description": "NetScaler Virtual Interface",
            "devicename": "0/1",
            "downtime": "11",
            "fctls": "0",
            "flags": "57440",
            "hamonitor": "ON",
            "hangdetect": "2",
            "hangreset": "0",
            "hangs": "0",
            "id": "0/1",
            "ifnum": [
                "0/1"
            ],
            "indisc": "0",
            "intfstate": "1",
            "intftype": "KVM Virtio",
            "lacpactoraggregation": "NS_EMPTY_STR",
            "lacpactorcollecting": "NS_EMPTY_STR",
            "lacpactordistributing": "NS_EMPTY_STR",
            "lacpactorinsync": "NS_EMPTY_STR",
            "lacpactorportno": "1",
            "lacpactorpriority": "32768",
            "lacppartneraggregation": "NS_EMPTY_STR",
            "lacppartnercollecting": "NS_EMPTY_STR",
            "lacppartnerdefaulted": "NS_EMPTY_STR",
            "lacppartnerdistributing": "NS_EMPTY_STR",
            "lacppartnerexpired": "NS_EMPTY_STR",
            "lacppartnerinsync": "NS_EMPTY_STR",
            "lacppartnerkey": "0",
            "lacppartnerportno": "0",
            "lacppartnerpriority": "0",
            "lacppartnersystemmac": "00:00:00:00:00:00",
            "lacppartnersystempriority": "0",
            "lacpportmuxstate": "DETACHED",
            "lacpportrxstat": "INIT",
            "lacpportselectstate": "UNSELECTED",
            "lacppriority": "32768",
            "lacptimeout": "LONG",
            "lagtype": "NODE",
            "linkredundancy": "OFF",
            "linkstate": "1",
            "lldpmode": "NONE",
            "lractiveintf": false,
            "lrsetpriority": "1024",
            "mac": "50:20:10:ea:ca:aa",
            "mtu": "1500",
            "outdisc": "0",
            "reqthroughput": "0",
            "rxbytes": "1758704",
            "rxdrops": "11377",
            "rxerrors": "0",
            "rxpackets": "18722",
            "rxstalls": "0",
            "slaveduplex": "3",
            "slaveflowctl": "0",
            "slavemedia": "0",
            "slavespeed": "4",
            "slavestate": "0",
            "slavetime": "25727",
            "state": "ENABLED",
            "stsstalls": "0",
            "tagall": "OFF",
            "tagged": "2",
            "taggedany": "1",
            "taggedautolearn": "1",
            "txbytes": "7501126",
            "txdrops": "0",
            "txerrors": "0",
            "txpackets": "9257",
            "txstalls": "0",
            "unit": "0",
            "uptime": "25727",
            "vlan": "10",
            "vmac": "00:00:00:00:00:00",
            "vmac6": "00:00:00:00:00:00"
        }
    ]
lbvserver_stats:
    description: The statistics for lbvservers
    returned: When lbvserver_stats or all is included
    type: list
    sample: [
        {
            "actsvcs": "0",
            "curclntconnections": "0",
            "cursrvrconnections": "0",
            "deferredreq": "0",
            "deferredreqrate": 0,
            "establishedconn": "0",
            "hitsrate": 0,
            "inactsvcs": "2",
            "invalidrequestresponse": "0",
            "invalidrequestresponsedropped": "0",
            "labelledconn": "0",
            "name": "vip-app01",
            "pktsrecvdrate": 0,
            "pktssentrate": 0,
            "primaryipaddress": "10.10.20.21",
            "primaryport": 80,
            "pushlabel": "0",
            "requestbytesrate": 0,
            "requestsrate": 0,
            "responsebytesrate": 0,
            "responsesrate": 0,
            "sortorder": "descending",
            "sothreshold": "0",
            "state": "DOWN",
            "surgecount": "0",
            "svcsurgecount": "0",
            "totalpktsrecvd": "0",
            "totalpktssent": "0",
            "totalrequestbytes": "0",
            "totalrequests": "0",
            "totalresponsebytes": "0",
            "totalresponses": "0",
            "tothits": "0",
            "totspillovers": "0",
            "totvserverdownbackuphits": "0",
            "type": "HTTP",
            "vslbhealth": "0",
            "vsvrsurgecount": "0"
        }
    ]
config:
    description: The Netscaler's configuration as it would be returned from the CLI
    returned: When config or all is included
    type: str
server_config:
    description: A list of server configurations; netscaler_server module params have their key names renamed to match
                 the module input, all others are kept as is and mapped to an "others" key.
    returned: When server_config or all is included
    type: list
    sample: [
        {
            "comment": "",
            "ip_address": "10.10.10.21",
            "others": {
                "appflowlog": "DISABLED",
                "boundtd": "0",
                "cacheable": "NO",
                "cip": "DISABLED",
                "cka": "NO",
                "clttimeout": 0,
                "cmp": "NO",
                "downstateflush": "DISABLED",
                "dup_port": 0,
                "dup_svctype": "HTTP",
                "ipv6address": "NO",
                "maxbandwidth": "0",
                "maxreq": "0",
                "port": 0,
                "sc": "OFF",
                "sp": "OFF",
                "statechangetimesec": "Thu Jan  1 00:00:00 1970",
                "svctype": "HTTP",
                "svrcfgflags": "0",
                "svrstate": "Unknown",
                "svrtimeout": 0,
                "tcpb": "NO",
                "tickssincelaststatechange": "0",
                "translationip": "0.0.0.0",
                "translationmask": "0.0.0.0",
                "usip": "NO"
            },
            "server_name": "server01",
            "server_state": "ENABLED",
            "traffic_domain": "0"
        }
    ]
service_group_config:
    description: A list of service group configurations; netscaler_service_group module params have their key names
                 renamed to match the module input, all others are kept as is and mapped to an "others" key.
    returned: When service_group_config or all is included
    type: list
    sample:[
        {
            "client_timeout": 180,
            "comment": "",
            "max_client": "0",
            "max_req": "0",
            "others": {
                "appflowlog": "ENABLED",
                "cacheable": "NO",
                "cachetype": "SERVER",
                "cip": "DISABLED",
                "cka": "NO",
                "clmonowner": "4294967295",
                "clmonview": "0",
                "cmp": "NO",
                "delay": 0,
                "downstateflush": "ENABLED",
                "graceful": "NO",
                "groupcount": "1",
                "hashid": "0",
                "healthmonitor": "YES",
                "ip": "0.0.0.0",
                "maxbandwidth": "0",
                "memberport": 0,
                "monitor_state": "Unknown",
                "monitorcurrentfailedprobes": "0",
                "monitortotalfailedprobes": "0",
                "monitortotalprobes": "0",
                "monstatcode": 0,
                "monstate": "ENABLED",
                "monstatparam1": 0,
                "monstatparam2": 0,
                "monstatparam3": 0,
                "monthreshold": "0",
                "monweight": "0",
                "numofconnections": 0,
                "passive": false,
                "pathmonitor": "NO",
                "pathmonitorindv": "NO",
                "port": 0,
                "riseapbrstatsmsgcode": 0,
                "riseapbrstatsmsgcode2": 1,
                "rtspsessionidremap": "OFF",
                "sc": "OFF",
                "serviceconftype": true,
                "servicegroupeffectivestate": "DOWN",
                "serviceipstr": "0.0.0.0",
                "sp": "OFF",
                "statechangetimemsec": "945",
                "statechangetimesec": "Mon May  8 19:29:48 2017",
                "stateupdatereason": "0",
                "svrstate": "DOWN",
                "tcpb": "NO",
                "tickssincelaststatechange": "2573178",
                "useproxyport": "YES",
                "usip": "NO"
            },
            "server_timeout": 360,
            "service_type": "HTTP",
            "servicegroup_name": "svcgrp-app01",
            "servicegroup_state": "ENABLED",
            "traffic_domain": "0"
        }
    ]
lbvserver_config:
    description: A list of lbvserver configurations; netscaler_lbvserver module params have their key names renamed to
                 match the module input, all others are kept as is and mapped to an "others" key.
    returned: When lbvsrver_config or all is included
    type: list
    sample: [
        {
            "backup_lbvserver": "",
            "client_timeout": "180",
            "comment": "",
            "conn_failover": "DISABLED",
            "cookie_name": "",
            "ip_address": "10.10.20.21",
            "lbmethod": "ROUNDROBIN",
            "lbvserver_name": "vip-app01",
            "lbvserver_port": 80,
            "lbvserver_state": "ENABLED",
            "others": {
                "activeservices": "0",
                "appflowlog": "ENABLED",
                "authentication": "OFF",
                "authn401": "OFF",
                "backuppersistencetimeout": 2,
                "bypassaaaa": "NO",
                "cacheable": "NO",
                "cachetype": "SERVER",
                "consolidatedlconn": "GLOBAL",
                "consolidatedlconngbl": "YES",
                "curstate": "DOWN",
                "datalength": "0",
                "dataoffset": "0",
                "disableprimaryondown": "DISABLED",
                "dns64": "DISABLED",
                "downstateflush": "ENABLED",
                "dynamicweight": "0",
                "effectivestate": "DOWN",
                "gt2gb": "DISABLED",
                "health": "0",
                "healththreshold": "0",
                "hits": "0",
                "icmpvsrresponse": "PASSIVE",
                "insertvserveripport": "OFF",
                "invoke": false,
                "ipmapping": "0.0.0.0",
                "ipmask": "*",
                "ippattern": "0.0.0.0",
                "isgslb": false,
                "l2conn": "OFF",
                "lbrrreason": 4,
                "listenpolicy": "NONE",
                "m": "IP",
                "macmoderetainvlan": "DISABLED",
                "map": "OFF",
                "maxautoscalemembers": "0",
                "minautoscalemembers": "0",
                "newservicerequestunit": "PER_SECOND",
                "persistencebackup": "NONE",
                "persistmask": "255.255.255.255",
                "pipolicyhits": "0",
                "policysubtype": "0",
                "pq": "OFF",
                "priority": "0",
                "processlocal": "DISABLED",
                "push": "DISABLED",
                "pushlabel": "none",
                "pushmulticlients": "NO",
                "range": "1",
                "redirectportrewrite": "DISABLED",
                "rhistate": "PASSIVE",
                "rtspnat": "OFF",
                "ruletype": "0",
                "sc": "OFF",
                "sessionless": "DISABLED",
                "skippersistency": "None",
                "somethod": "NONE",
                "sopersistence": "DISABLED",
                "sopersistencetimeout": "2",
                "statechangetimemsec": "209",
                "statechangetimesec": "Mon May  8 19:29:49 2017",
                "statechangetimeseconds": "1494271789",
                "status": 3,
                "thresholdvalue": 0,
                "tickssincelaststatechange": "2573188",
                "timeout": 2,
                "totalservices": "2",
                "type": "ADDRESS",
                "v6persistmasklen": "128",
                "version": 0,
                "vsvrbindsvcip": "10.10.20.21",
                "vsvrbindsvcport": 0,
                "vsvrdynconnsothreshold": "0"
            },
            "persistence": "SRCIPDESTIP",
            "service_type": "HTTP",
            "traffic_domain": "0"
        }
    ]
monitor_config:
    description: A list of monitor configurations; netscaler_monitor module params have their key names renamed to match
                 the module input, all others are kept as is and mapped to an "others" key.
    returned: When monitor_config or all is included
    type: list
    sample: [
        {
            "custom_headers": "",
            "http_request": "HEAD /healthcheck.html",
            "monitor_dest_ip": "",
            "monitor_dest_port": 0,
            "monitor_name": "mon-app01",
            "monitor_password": "",
            "monitor_secondary_password": "",
            "monitor_state": "ENABLED",
            "monitor_type": "HTTP",
            "monitor_use_ssl": "NO",
            "monitor_username": "",
            "others": {
                "action": "Not applicable",
                "alertretries": 0,
                "deviation": "0",
                "dispatcherip": "0.0.0.0",
                "dispatcherport": 0,
                "downtime": 30,
                "dup_state": "DISABLED",
                "dynamicinterval": 0,
                "dynamicresponsetimeout": 0,
                "failureretries": 0,
                "firmwarerevision": "0",
                "hostipaddress": "",
                "inbandsecurityid": "NO_INBAND_SECURITY",
                "interval": 5,
                "iptunnel": "NO",
                "lrtmconf": 1,
                "lrtmconfstr": "ENABLED",
                "maxforwards": "0",
                "multimetrictable": [
                    "local"
                ],
                "radaccounttype": "0",
                "radframedip": "0.0.0.0",
                "radnasip": "0.0.0.0",
                "resptimeout": 2,
                "resptimeoutthresh": "0",
                "retries": 3,
                "reverse": "NO",
                "rtsprequest": "HEAD /healthcheck.html",
                "sipmethod": "OPTIONS",
                "snmpversion": "V1",
                "storedb": "DISABLED",
                "storefrontacctservice": "NO",
                "storefrontcheckbackendservices": "NO",
                "successretries": 1,
                "tos": "NO",
                "transparent": "NO",
                "trofscode": "0",
                "units1": "SEC",
                "units2": "SEC",
                "units3": "SEC",
                "units4": "SEC",
                "vendorid": "0"
            },
            "response_code": [
                "200"
            ]
        }
    ]
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


SUBSET_INCLUDE = ["all", "hardware_data", "interface_data", "lbvserver_stats", "config", "server_config",
                  "service_group_config", "lbvserver_config", "monitor_config"]
SUBSET_EXCLUDE = ["!all", "!hardware_data", "!interface_data", "!lbvserver_stats", "!config", "!server_config",
                  "!service_group_config", "!lbvserver_config", "!monitor_config"]
SUBSET_OPTIONS = SUBSET_INCLUDE + SUBSET_EXCLUDE


def main():
    argument_spec = dict(
        host=dict(required=True, type="str"),
        port=dict(required=False, type="int"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        use_ssl=dict(default=True, type="bool"),
        validate_certs=dict(default=False, type="bool"),
        provider=dict(required=False, type="dict"),
        partition=dict(required=False, type="str"),
        gather_subset=dict(required=False, type="list", default=["all"]),
        config_scope=dict(choices=["true", "false"], required=False, type="str", default="false"),
    )

    module = AnsibleModule(argument_spec, supports_check_mode=False)
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
    use_ssl = module.params["use_ssl"]
    username = module.params["username"]
    validate_certs = module.params["validate_certs"]
    gather_subset = module.params["gather_subset"]
    config_scope = module.params["config_scope"]

    for subset in gather_subset:
        if subset not in SUBSET_OPTIONS:
            module.fail_json(msg="value of server_state must be one of:{}, got: {}".format(SUBSET_OPTIONS, subset))

    counter = 0
    for subset in gather_subset:
        if subset[0] == "!":
            counter += 1
    if counter == 0:
        include = True
    elif counter != len(gather_subset):
        module.fail_json(msg="Cannot use include and negate args at the same time.")
    else:
        include = False

    if "all" in gather_subset:
        subset_list = ["hardware_data", "interface_data", "lbvserver_stats", "config", "server_config",
                       "service_group_config", "lbvserver_config", "monitor_config"]
    elif "!all" in gather_subset:
        subset_list = []
    elif include:
        subset_list = gather_subset
    else:
        not_subset_list = []
        for not_subset in gather_subset:
            not_subset_list.append(not_subset.strip("!"))
        subset_list = set(not_subset_list).symmetric_difference(SUBSET_INCLUDE)
        subset_list.remove("all")

    kwargs = dict()
    if port:
        kwargs["port"] = port

    session = Netscaler(host, username, password, use_ssl, validate_certs, **kwargs)
    session_login = session.login()
    if not session_login.ok:
        module.fail_json(msg="Unable to login")

    if partition:
        session_switch = session.switch_partition(partition)
        if not session_switch.ok:
            module.fail_json(msg=session_switch.content, reason="Unable to Switch Partitions")

    ansible_facts = dict(ntc_system_data=get_system_data(session))

    if "hardware_data" in subset_list:
        ansible_facts["ntc_hardware_data"] = session.get_system()

    if "interface_data" in subset_list:
        ansible_facts["ntc_interface_data"] = session.get_interfaces()

    if "lbvserver_stats" in subset_list:
        ansible_facts["ntc_lbvserver_stats"] = session.get_lbvserver_stats()

    if "config" in subset_list:
        ansible_facts["ntc_config"] = session.get_config(config_scope)

    if "server_config" in subset_list:
        ansible_facts["ntc_server_config"] = get_server_config(session)

    if "service_group_config" in subset_list:
        ansible_facts["ntc_service_group_config"] = get_service_group_config(session)

    if "lbvserver_config" in subset_list:
        ansible_facts["ntc_lbvserver_config"] = get_lbvserver_config(session)

    if "monitor_config" in subset_list:
        ansible_facts["ntc_monitor_config"] = get_monitor_config(session)

    return module.exit_json(**ansible_facts)


def get_system_data(session):
    """
    This function is used to collect the system data using Netscaler's get_hostname, get_hardware, and get_nsconfig
    methods. The data is filtered and assembled together.
    :param session: The instance of the Netscaler class.
    :return: A dictionary of the Netscaler system data.
    """
    hostname = session.get_hostname()
    hardware = session.get_hardware()
    nsconfig = session.get_nsconfig()

    return dict(
        hostname=hostname.get("hostname"),
        model=hardware.get("hwdescription"),
        year=hardware.get("manufactureyear"),
        system_mac=hardware.get("host"),
        serial_number=hardware.get("serialno"),
        mgmt_net=dict(
            ip_address=nsconfig.get("ipaddress"),
            netmask=nsconfig.get("netmask"),
            vlan=nsconfig.get("nsvlan"),
            interfaces=nsconfig.get("ifnum"),
            vlan_tagged=nsconfig.get("tagged"),
            primary_ip=nsconfig.get("primaryip"),
        ),
        system_type=nsconfig.get("systemtype"),
        timezone=nsconfig.get("timezone"),
        last_config=nsconfig.get("lastconfigchangedtime"),
        last_save=nsconfig.get("lastconfigsavetime"),
        current_time=nsconfig.get("currentsytemtime")
    )


def get_server_config(session):
    """
    This function is used to collect all server configurations from the Netscaler using the get_all method.
    :param session: The instance of the Netscaler class.
    :return: A list of dictionaries corresponding to the Netscaler server configs.
    """
    server_list = session.get_all("server")

    server_config = []
    for server in server_list:
        server_dict = dict(
            comment=server.pop("comment", ""),
            ip_address=server.pop("ipaddress", ""),
            server_name=server.pop("name"),
            server_state=server.pop("state"),
            traffic_domain=server.pop("td"),
            others=server
        )
        server_config.append(server_dict)

    return server_config


def get_service_group_config(session):
    """
    This function is used to collect all service group configurations from the Netscaler using the get_all method.
    :param session: The instance of the Netscaler class.
    :return: A list of dictionaries corresponding to the Netscaler service group configs.
    """
    servicegroup_list = session.get_all("servicegroup")

    servicegroup_config = []
    for servicegroup in servicegroup_list:
        servicegroup_dict = dict(
            client_timeout=servicegroup.pop("clttimeout"),
            comment=servicegroup.pop("comment", ""),
            max_client=servicegroup.pop("maxclient"),
            max_req=servicegroup.pop("maxreq"),
            server_timeout=servicegroup.pop("svrtimeout"),
            service_type=servicegroup.pop("servicetype"),
            servicegroup_name=servicegroup.pop("servicegroupname"),
            servicegroup_state=servicegroup.pop("state"),
            traffic_domain=servicegroup.pop("td"),
            others=servicegroup
        )
        servicegroup_config.append(servicegroup_dict)

    return servicegroup_config


def get_lbvserver_config(session):
    """
    This function is used to collect all lbvserver configurations from the Netscaler using the get_all method.
    :param session: The instance of the Netscaler class.
    :return: A list of dictionaries corresponding to the Netscaler lbvserver configs.
    """
    attrs = (
    "name", "backupvserver", "insertvserveripport", "ipv46", "ippattern", "ipmask", "listenpolicy", "ipmapping", "port",
    "range", "servicetype", "type", "curstate", "effectivestate", "status", "lbrrreason", "cachetype", "authentication",
    "authn401", "dynamicweight", "priority", "clttimeout", "somethod", "sopersistence", "sopersistencetimeout",
    "healththreshold", "lbmethod", "dataoffset", "health", "datalength", "ruletype", "m", "persistencetype", "timeout",
    "persistmask", "v6persistmasklen", "persistencebackup", "backuppersistencetimeout", "cacheable", "pq", "sc",
    "rtspnat", "sessionless", "map", "connfailover", "redirectportrewrite", "downstateflush", "disableprimaryondown",
    "gt2gb", "consolidatedlconn", "consolidatedlconngbl", "thresholdvalue", "invoke", "version", "totalservices",
    "activeservices", "statechangetimesec", "statechangetimeseconds", "statechangetimemsec",
    "tickssincelaststatechange", "hits", "pipolicyhits", "push", "pushlabel", "pushmulticlients", "policysubtype",
    "l2conn", "appflowlog", "isgslb", "icmpvsrresponse", "rhistate", "newservicerequestunit", "vsvrbindsvcip",
    "vsvrbindsvcport", "skippersistency", "td", "minautoscalemembers", "maxautoscalemembers", "macmoderetainvlan",
    "dns64", "bypassaaaa", "processlocal", "vsvrdynconnsothreshold", "state"
    )

    lbvserver_list = session.get_all_attrs("lbvserver", attrs)

    lbvserver_config = []
    for lbvserver in lbvserver_list:
        lbvserver_dict = dict(
            backup_lbvserver=lbvserver.pop("backupvserver", ""),
            client_timeout=lbvserver.pop("clttimeout"),
            comment=lbvserver.pop("comment", ""),
            conn_failover=lbvserver.pop("connfailover"),
            cookie_name=lbvserver.pop("cookiename", ""),
            ip_address=lbvserver.pop("ipv46"),
            service_type=lbvserver.pop("servicetype"),
            lbvserver_name=lbvserver.pop("name"),
            lbvserver_state=lbvserver.pop("state"),
            lbmethod=lbvserver.pop("lbmethod"),
            lbvserver_port=lbvserver.pop("port"),
            persistence=lbvserver.pop("persistencetype"),
            traffic_domain=lbvserver.pop("td"),
            others=lbvserver
        )
        lbvserver_config.append(lbvserver_dict)

    return lbvserver_config


def get_monitor_config(session):
    """
    This function is used to collect all monitor configurations from the Netscaler using the get_all method.
    :param session: The instance of the Netscaler class.
    :return: A list of dictionaries corresponding to the Netscaler monitor configs.
    """
    monitor_list = session.get_all("lbmonitor")

    monitor_config = []
    for monitor in monitor_list:
        monitor_dict = dict(
            custom_headers=monitor.pop("customheaders", ""),
            http_request=monitor.pop("httprequest", ""),
            monitor_dest_ip=monitor.pop("destip", ""),
            monitor_dest_port=monitor.pop("destport", ""),
            monitor_name=monitor.pop("monitorname"),
            monitor_password=monitor.pop("password", ""),
            monitor_secondary_password=monitor.pop("secondarypassword", ""),
            monitor_state=monitor.pop("state"),
            monitor_type=monitor.pop("type"),
            monitor_use_ssl=monitor.pop("secure", ""),
            monitor_username=monitor.pop("username", ""),
            response_code=monitor.pop("respcode", ""),
            others=monitor
        )
        monitor_config.append(monitor_dict)

    return monitor_config


if __name__ == "__main__":
    main()
