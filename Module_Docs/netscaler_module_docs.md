# Citrix Netscaler Modules

---
### Requirements
* Python `requests`
* Everything tested was with Netscaler version 11.x

---
### Modules

  * [netscaler_lbvserver - manages lb vserver resources and attributes.](#netscaler_lbvserver)
  * [netscaler_monitor - manages monitor resources and attributes](#netscaler_monitor)
  * [netscaler_lbvserver_certkey - manages lbvserver to cert key bindings](#netscaler_lbvserver_certkey)
  * [netscaler_servicegroup_server - manages service group to server bindings.](#netscaler_servicegroup_server)
  * [netscaler_lbvserver_servicegroup - manages lbvserver to service group bindings.](#netscaler_lbvserver_servicegroup)
  * [netscaler_servicegroup_monitor - manages service group to monitor bindings.](#netscaler_servicegroup_monitor)
  * [netscaler_facts - gathers netscaler facts](#netscaler_facts)
  * [netscaler_server - manages server resources and attributes](#netscaler_server)
  * [netscaler_save_config - saves the running configuration to the netscaler.](#netscaler_save_config)
  * [netscaler_servicegroup - manages service group resources and attributes](#netscaler_servicegroup)

---

## netscaler_lbvserver
Manages LB VServer resources and attributes.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Netscaler LB VServer configurations using Nitro API.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| comment  |   no  |  | |  A comment about the lbvserver  |
| lbvserver_port  |   no  |  | |  The port the lbvserver will listen on.  Valid protocol port ranges and "*" are supported.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  Absent will delete resource.  Present will create resource.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| service_type  |   no  |  | <ul> <li>HTTP</li>  <li>FTP</li>  <li>TCP</li>  <li>UDP</li>  <li>SSL</li>  <li>SSL_BRIDGE</li>  <li>SSL_TCP</li>  <li>DTLS</li>  <li>NNTP</li>  <li>DNS</li>  <li>DHCPRA</li>  <li>ANY</li>  <li>SIP_UDP</li>  <li>SIP_TCP</li>  <li>SIP_SSL</li>  <li>DNS_TCP</li>  <li>RTSP</li>  <li>PUSH</li>  <li>SSL_PUSH</li>  <li>RADIUS</li>  <li>RDP</li>  <li>MYSQL</li>  <li>MSSQL</li>  <li>DIAMETER</li>  <li>SSL_DIAMETER</li>  <li>TFTP</li>  <li>ORACLE</li>  <li>SMPP</li>  <li>SYSLOGTCP</li>  <li>SYSLOGUDP</li>  <li>FIX</li> </ul> |  The type of service the lbvserver provides.  |
| conn_failover  |   no  |  | <ul> <li>DISABLED</li>  <li>STATEFUL</li>  <li>STATELESS</li> </ul> |  The lbvserver connection setting  |
| lbmethod  |   no  |  | <ul> <li>ROUNDROBIN</li>  <li>LEASTCONNECTION</li>  <li>LEASTRESPONSETIME</li>  <li>URLHASH</li>  <li>DOMAINHASH</li>  <li>DESTINATIONIPHASH</li>  <li>SOURCEIPHASH</li>  <li>SRCIPDESTIPHASH</li>  <li>LEASTBANDWIDTH</li>  <li>LEASTPACKETS</li>  <li>TOKEN</li>  <li>SRCIPSRCPORTHASH</li>  <li>LRTM</li>  <li>CALLIDHASH</li>  <li>CUSTOMLOAD</li>  <li>LEASTREQUEST</li>  <li>AUDITLOGHASH</li>  <li>STATICPROXIMITY</li> </ul> |  The method to load balance traffic.  |
| persistence  |   no  |  | <ul> <li>SOURCEIP</li>  <li>COOKIEINSERT</li>  <li>SSLSESSION</li>  <li>RULE</li>  <li>URLPASSIVE</li>  <li>CUSTOMSERVERID</li>  <li>DESTIP</li>  <li>SRCIPDESTIP</li>  <li>CALLID</li>  <li>RTSPSID</li>  <li>DIAMETER</li>  <li>FIXSESSION</li>  <li>NONE</li> </ul> |  The persistence type used by the lbvserver.  |
| client_timeout  |   no  |  | |  Seconds to wait before terminating a client session.  Valid inputs are from 0 to 31536000.  |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| cookie_name  |   no  |  | |  The name of the cookie to use.  Used with a COOKIE persistence type.  |
| lbvserver_state  |   no  |  enabled  | <ul> <li>disabled</li>  <li>enabled</li> </ul> |  The resources desired activity.  Disabled marks it out of service.  Enabled marks it serviceable.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| password  |   no  |  | |  The password associated with the username account.  |
| ip_address  |   no  |  | |  The IP address of the Server Object.  |
| backup_lbvserver  |   no  |  | |  The name of the backup lbvserver  |
| traffic_domain  |   no  |  0  | |  The traffic domain associated with the servicegroup  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| lbvserver_name  |   yes  |  | |  The name of the lbvserver object  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |


 


---


## netscaler_monitor
Manages Monitor resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Netscaler Monitor configurations using Nitro API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| monitor_secondary_password  |   no  |  | |  A secondary password to authenticate with the monitored service  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| monitor_name  |   yes  |  | |  The name of the monitor  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |
| response_code_action  |   no  |  add  | <ul> <li>add</li>  <li>remove</li> </ul> |  The action to take for response code items that differ from existing response codes.  add will add any missing values to the existing response codes.  remove will remove any matching values to the existing response codes.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  Absent will delete resource.  Present will create resource.  |
| monitor_use_ssl  |   no  |  | <ul> <li>YES</li>  <li>NO</li> </ul> |  Specifies to use SSL for the monitor  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| http_request  |   no  |  | |  The request to send to the server  |
| monitor_dest_ip  |   no  |  | |  The IP address to monitor.  |
| monitor_dest_port  |   no  |  | |  The port to monitor on the server  |
| monitor_state  |   no  |  enabled  | <ul> <li>disabled</li>  <li>enabled</li> </ul> |  The resources desired activity.  Disabled marks it out of service.  Enabled marks it serviceable.  |
| monitor_password  |   no  |  | |  The password used to authenticate with the monitored service.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| custom_headers  |   no  |  | |  Custom headers to add to the monitor request  |
| password  |   no  |  | |  The password associated with the username account.  |
| response_code  |   no  |  | |  The HTTP response code expected back from the monitored resource.  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| monitor_username  |   no  |  | |  The username used to authenticate with the monitored service.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| monitor_type  |   no  |  | <ul> <li>PING</li>  <li>TCP</li>  <li>HTTP</li>  <li>TCP-ECV</li>  <li>HTTP-ECV</li>  <li>UDP-ECV</li>  <li>DNS</li>  <li>FTP</li>  <li>LDNS-PING</li>  <li>LDNS-TCP</li>  <li>LDNS-DNS</li>  <li>RADIUS</li>  <li>USER</li>  <li>HTTP-INLINE</li>  <li>SIP-UDP</li>  <li>SIP-TCP</li>  <li>LOAD</li>  <li>FTP-EXTENDED</li>  <li>SMTP</li>  <li>SNMP</li>  <li>NNTP</li>  <li>MYSQL</li>  <li>MYSQL-ECV</li>  <li>MSSQL-ECV</li>  <li>ORACLE-ECV</li>  <li>LDAP</li>  <li>POP3</li>  <li>CITRIX-XML-SERVICE</li>  <li>CITRIX-WEB-INTERFACE</li>  <li>DNS-TCP</li>  <li>RTSP</li>  <li>ARP</li>  <li>CITRIX-AG</li>  <li>CITRIX-AAC-LOGINPAGE</li>  <li>CITRIX-AAC-LAS</li>  <li>CITRIX-XD-DDC</li>  <li>ND6</li>  <li>CITRIX-WI-EXTENDED</li>  <li>DIAMETER</li>  <li>RADIUS_ACCOUNTING</li>  <li>STOREFRONT</li>  <li>APPC</li>  <li>SMPP</li>  <li>CITRIX-XNC-ECV</li>  <li>CITRIX-XDM</li> </ul> |  The type of service to monitor  |


 


---


## netscaler_lbvserver_certkey
Manages lbvserver to cert key bindings

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Netscaler lbvserver to cert key binding configurations using Nitro API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| vserver_name  |   yes  |  | |  The name of the vserver to bind the cert key to.  |
| ocsp_check  |   no  |  | <ul> <li>Mandatory</li>  <li>Optional</li> </ul> |  The state of the OCSP check parameter.  |
| skip_ca_name  |   no  |  | <ul> <li>true</li>  <li>false</li> </ul> |  Used to indicate whether CA Name needs to be sent to the SSL client during the SSL handshake.  |
| ca_cert  |   no  |  | <ul> <li>true</li>  <li>false</li> </ul> |  Specifies if the certificate is a CA.  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  Absent will delete resource.  Present will create resource.  |
| crl_check  |   |  | <ul> <li>Mandatory</li>  <li>Optional</li> </ul> |  The state of the CRL check parameter.  |
| sni_cert  |   |  | <ul> <li>true</li>  <li>false</li> </ul> |  Specifies if SNI processing is in use.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| cert_key_name  |   yes  |  | |  The name of the cert key to bind to the lbvserver.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |


 


---


## netscaler_servicegroup_server
Manages service group to server bindings.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Netscaler service group to server binding configurations using Nitro API.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| servicegroup_name  |   yes  |  | |  The service group name which the server is being bound to.  |
| server_name  |   yes  |  | |  The server name which is being bound to a service group.  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| weight  |   no  |  | |  The weight to assing the servers in the Service Group.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  Absent will delete resource.  Present will create resource.  |
| server_port  |   yes  |  | |  The port the server is listening on to offer services.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |


 


---


## netscaler_lbvserver_servicegroup
Manages lbvserver to service group bindings.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Netscaler lbvserver to service group binding configurations using Nitro API.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| servicegroup_name  |   yes  |  | |  The service group name which the lbvserver is being bound to.  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| lbvserver_name  |   yes  |  | |  The lbvserver name which is being bound to a service group.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  Absent will delete resource.  Present will create resource.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |


 


---


## netscaler_servicegroup_monitor
Manages service group to monitor bindings.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Netscaler service group to monitor binding configurations using Nitro API.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| servicegroup_name  |   yes  |  | |  The service group name which the server is being bound to.  |
| weight  |   no  |  | |  The weight to assing the servers in the Service Group.  |
| monitor_name  |   yes  |  | |  The monitor name which is being bound to a service group.  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  Absent will delete resource.  Present will create resource.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |


 


---


## netscaler_facts
Gathers Netscaler Facts

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Gathers System, Hardware, and Configuration Facts for Netscaler Nitro API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| config_scope  |   no  |  false  | <ul> <li>true</li>  <li>false</li> </ul> |  The configuration scope to retrieve; used when gathering "config" fact.  setting to "true" will include default configuration values.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| gather_subset  |   no  |  [u'all']  | <ul> <li>all</li>  <li>hardware_data</li>  <li>interface_data</li>  <li>lbvserver_stats</li>  <li>config</li>  <li>server_config</li>  <li>service_group_config</li>  <li>lbvserver_config</li>  <li>monitor_config</li>  <li>!all</li>  <li>!hardware_data</li>  <li>!interface_data</li>  <li>!lbvserver_stats</li>  <li>!config</li>  <li>!server_config</li>  <li>!service_group_config</li>  <li>!lbvserver_config</li>  <li>!monitor_config</li> </ul> |  The list of facts to gather.  Gathered facts are limited using either an include list, or using an exclude list ("!...").  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |


 


---


## netscaler_server
Manages Server resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Netscaler Server configurations using Nitro API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| comment  |   no  |  | |  A comment to add to the object.  |
| server_name  |   no  |  | |  The name of the Server Object.  |
| server_state  |   no  |  enabled  | <ul> <li>disabled</li>  <li>enabled</li> </ul> |  The server's desired activity.  Disabled marks it out of service.  Enabled marks it serviceable.  |
| traffic_domain  |   no  |  0  | |  The traffic domain the server should belong to.  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  Absent will delete resource.  Present will create resource.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| ip_address  |   no  |  | |  The IP address of the Server Object.  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |


 


---


## netscaler_save_config
Saves the running configuration to the Netscaler.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Saves the running configuration to the Netscaler for the specified partition.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |


 


---


## netscaler_servicegroup
Manages Service Group resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages Netscaler Service Group configurations using Nitro API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   yes  |  | |  The username used to authenticate with the Netscaler.  |
| comment  |   no  |  | |  A comment about the servicegroup.  |
| servicegroup_state  |   no  |  enabled  | <ul> <li>disabled</li>  <li>enabled</li> </ul> |  The servicegroup's desired activity.  Disabled marks it out of service.  Enabled marks it serviceable.  |
| server_timeout  |   no  |  | |  Seconds to wait before terminating a server session.  Valid inputs are from 0 to 31536000  |
| servicegroup_name  |   yes  |  | |  The name of the servicegroup object  |
| max_client  |   no  |  | |  maximum number of simultaneous open connections  Valid inputs are from 0 to 65535  |
| traffic_domain  |   no  |  0  | |  The traffic domain associated with the servicegroup  |
| partition  |   no  |  | |  The Netscaler's partition if not the "default" partition.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  Absent will delete resource.  Present will create resource.  |
| host  |   yes  |  | |  The Netscaler's Address.  |
| max_req  |   no  |  | |  maximum number of simultaneous open connections  Valid inputs are from 0 to 65535  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specefied.  |
| service_type  |   no  |  | <ul> <li>HTTP</li>  <li>FTP</li>  <li>TCP</li>  <li>UDP</li>  <li>SSL</li>  <li>SSL_BRIDGE</li>  <li>SSL_TCP</li>  <li>DTLS</li>  <li>NNTP</li>  <li>RPCSVR</li>  <li>DNS</li>  <li>ADNS</li>  <li>SNMP</li>  <li>RTSP</li>  <li>DHCPRA</li>  <li>ANY</li>  <li>SIP_UDP</li>  <li>SIP_TCP</li>  <li>SIP_SSL</li>  <li>DNS_TCP</li>  <li>ADNS_TCP</li>  <li>MYSQL</li>  <li>MSSQL</li>  <li>ORACLE</li>  <li>RADIUS</li>  <li>RADIUSLISTENER</li>  <li>RDP</li>  <li>DIAMETER</li>  <li>SSL_DIAMETER</li>  <li>TFTP</li>  <li>SMPP</li>  <li>PPTP</li>  <li>GRE</li>  <li>SYSLOGTCP</li>  <li>SYSLOGUDP</li>  <li>FIX</li> </ul> |  The type of service associated with the bound vservers.  must be included for new servicegroup objects.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the Netscaler if other than the default used by the transport method(http=80, https=443).  |
| client_timeout  |   no  |  | |  Seconds to wait before terminating a client session.  Valid inputs are from 0 to 31536000.  |


 


---


---
Created by Network to Code, LLC
For:
2015
