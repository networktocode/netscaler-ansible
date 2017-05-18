# EXAMPLES

### Inventory File
```
[all:vars]
username=user
password=secret

[netscaler]
netscaler_lb01
```

### Playbook
```
---
- name: CONFIGURE LOAD BALANCE VIP
  hosts: all
  connection: local
  gather_facts: False

  tasks:
    - name: CONFIGURE SERVERS
      netscaler_server:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        server_name: "{{ item.name }}"
        ip_address: "{{ item.ip }}"
        comment: "{{ item.comment }}"
      with_items:
        - name: server01
          ip: 10.1.1.21
          comment: "First Server"
        - name: server02
          ip: 10.2.2.21
          comment: "Second Server"

    - name: CONFIGURE SERVICE GROUP
      netscaler_servicegroup:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        servicegroup_name: "sg_app01"
        service_type: "SSL"

    - name: CONFIGURE VSERVER
      netscaler_lbvserver:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        lbvserver_name: "vserver_app01"
        ip_address: "10.1.10.21"
        lbvserver_port: 443
        service_type: "SSL"
        lbmethod: "ROUNDROBIN"
        persistence: "SRCIPDESTIP"

    - name: CONFIGURE MONITOR
      netscaler_lbmonitor:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        monitor_name: "mon_app01"
        monitor_type: "HTTP"
        monitor_use_ssl: "YES"
        http_request: "HEAD /healthcheck.html"
        response_code:
          - "200-202"
          - "204"

    - name: BIND SERVICE GROUP TO SERVER
      netscaler_servicegroup_server:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        servicegroup_name: "sg_app01"
        server_name: "{{ item }}"
        server_port: 443
      with_items:
        - "server01"
        - "server02"

    - name: BIND SERVICE GROUP TO MONITOR
      netscaler_servicegroup_monitor:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        servicegroup_name: "sg_app01"
        monitor_name: "mon_app01"

    - name: BIND VSERVER TO SERVICE GROUP
      netscaler_lbvserver_servicegroup:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        lbvserver_name: "vserver_app01"
        servicegroup_name: "sg_app01"

    - name: BIND VSERVER TO CERT KEY
      netscaler_vserver_certkey:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        vserver_name: "vserver_app01"
        cert_key_name: "ck_app01"

    - name: SAVE CONFIG
      netscaler_save_config:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
```

## Netscaler Facts
```
---
- name: SHOW DIFFERENT WAYS TO USE THE FACTS MODULE
  hosts: all
  connection: local
  gather_facts: False

  tasks:
    - name: GET ALL FACTS
      netscaler_facts:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"

    - name: GET SOME FACTS USING INCLUDE METHOD
      netscaler_facts:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        gather_subset:
          - "hardware_data"
          - "interface_data"
          - "lbvserver_stats"

    - name: GET SOME FACTS USING EXCLUDE METHOD
      netscaler_facts:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        gather_subset:
          - "!config"
          - "!server_config"

    - name: GET ONLY SYSTEM FACTS
      netscaler_facts:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        gather_subset:
          - "!all"
```