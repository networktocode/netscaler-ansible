# Shell Output from Running Example Playbooks
This demonstrates how to execute the example playbooks using the example [vars](./vars/examples/) files for playbook variables. The example playbooks are related to each other and should be used in the order presented here.

### Deploy New Virtual Server
``` bash
$ ansible-playbook netscaler_deploy_full.yml --extra-vars "@./vars/example/deploy_full.yml"

PLAY [PLAY 1 - ENSURE ALL LOAD BALANCER OBJECTS EXIST] ******************************************************

TASK [TASK 1 - ENSURE SERVER OBJECTS ARE DEPLOYED] **********************************************************
changed: [netscaler1] => (item={u'comment': u'Intranet Server', u'ip_address': u'10.10.10.21', u'name': u'prod_rhel_01'})
changed: [netscaler1] => (item={u'comment': u'Intranet Server', u'ip_address': u'10.10.10.22', u'name': u'prod_rhel_02'})
changed: [netscaler1] => (item={u'comment': u'Backup Intranet Server', u'ip_address': u'10.10.20.21', u'name': u'dr_rhel_01'})
changed: [netscaler1] => (item={u'comment': u'Backup Intranet Server', u'ip_address': u'10.10.20.22', u'name': u'dr_rhel_02'})

TASK [TASK 2 - ENSURE SERVICE GROUPS ARE DEPLOYED] **********************************************************
changed: [netscaler1] => (item={u'service_type': u'SSL_BRIDGE', u'comment': u'Intranet HTTPS Service Group', u'name': u'svcgrp_intranet_https'})
changed: [netscaler1] => (item={u'service_type': u'SSL_BRIDGE', u'comment': u'Backup Intranet HTTPS Service Group', u'name': u'svcgrp_backup_intranet_https'})

TASK [TASK 3 - ENSURE BACKUP LB VSERVERS ARE DEPLOYED] ******************************************************
changed: [netscaler1] => (item={u'service_type': u'SSL_BRIDGE', u'comment': u'Backup Intranet HTTPS VIP', u'state': u'disabled', u'name': u'lbvs_backup_intranet_https', u'persistence': u'SRCIPDESTIP'})

TASK [TASK 4 - ENSURE LB VSERVERS ARE DEPLOYED] *************************************************************
changed: [netscaler1] => (item={u'comment': u'Intranet HTTPS VIP', u'lb_method': u'LEASTCONNECTION', u'name': u'lbvs_intranet_https', u'backup_vserver': u'lbvs_backup_intranet_https', u'service_type': u'SSL_BRIDGE', u'conn_failover': u'STATEFUL', u'ip_address': u'10.10.11.21', u'port': 443, u'persistence': u'SRCIPDESTIP'})

TASK [TASK 5 - ENSURE MONITORS ARE DEPLOYED] ****************************************************************
changed: [netscaler1] => (item={u'type': u'HTTP', u'response_code': u'200-202', u'request': u'HEAD /healthcheck.html', u'name': u'lbmon_intranet_https', u'secure': u'YES'})
changed: [netscaler1] => (item={u'type': u'HTTP', u'response_code': u'200-202', u'request': u'HEAD /healthcheck.html', u'name': u'lbmon_backup_intranet_https', u'secure': u'YES'})

PLAY [PLAY 2 - ENSURE ALL BINDINGS EXIST] *******************************************************************

TASK [TASK 1 - ENSURE VSEVERS ARE BOUND TO SERVICEGROUPS] ***************************************************
changed: [netscaler1] => (item={u'vserver_name': u'lbvs_intranet_https', u'servicegroup_name': u'svcgrp_intranet_https'})
changed: [netscaler1] => (item={u'vserver_name': u'lbvs_backup_intranet_https', u'servicegroup_name': u'svcgrp_backup_intranet_https'})

TASK [TASK 2 - ENSURE SERVICEGROUPS ARE BOUND TO SERVERS] ***************************************************
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_intranet_https', u'server_name': u'prod_rhel_01', u'port': 443})
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_intranet_https', u'server_name': u'prod_rhel_02', u'port': 443})
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_backup_intranet_https', u'server_name': u'dr_rhel_01', u'port': 443})
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_backup_intranet_https', u'server_name': u'dr_rhel_02', u'port': 443})

TASK [TASK 3 - ENSURE SERVICEGROUPS ARE BOUND TO MONITORS] **************************************************
changed: [netscaler1] => (item={u'monitor_name': u'lbmon_intranet_https', u'servicegroup_name': u'svcgrp_intranet_https'})
changed: [netscaler1] => (item={u'monitor_name': u'lbmon_backup_intranet_https', u'servicegroup_name': u'svcgrp_backup_intranet_https'})

PLAY RECAP **************************************************************************************************
netscaler1               : ok=8    changed=8    unreachable=0    failed=0 
$ 
```

### Add Service to Virtual Server
``` bash
$ ansible-playbook netscaler_deploy_vip.yml --extra-vars "@./vars/example/deploy_vip.yml"

PLAY [PLAY 1 - ENSURE ALL LOAD BALANCER OBJECTS EXIST] ******************************************************

TASK [TASK 1 - ENSURE SERVICE GROUPS ARE DEPLOYED] **********************************************************
changed: [netscaler1] => (item={u'service_type': u'HTTP', u'comment': u'Intranet HTTP Service Group', u'name': u'svcgrp_intranet_http'})

TASK [TASK 2 - ENSURE LB VSERVERS ARE DEPLOYED] *************************************************************
changed: [netscaler1] => (item={u'comment': u'Intranet HTTP VIP', u'lb_method': u'LEASTCONNECTION', u'name': u'lbvs_intranet_http', u'service_type': u'HTTP', u'ip_address': u'10.10.11.21', u'port': 80, u'persistence': u'SRCIPDESTIP'})

TASK [TASK 3 - ENSURE MONITORS ARE DEPLOYED] ****************************************************************
changed: [netscaler1] => (item={u'type': u'HTTP', u'response_code': u'200', u'request': u'HEAD /healthcheck.html', u'name': u'lbmon_intranet_http', u'secure': u'YES'})

PLAY [PLAY 2 - ENSURE ALL BINDINGS EXIST] *******************************************************************

TASK [TASK 1 - ENSURE VSEVERS ARE BOUND TO SERVICEGROUPS] ***************************************************
changed: [netscaler1] => (item={u'vserver_name': u'lbvs_intranet_http', u'servicegroup_name': u'svcgrp_intranet_http'})

TASK [TASK 2 - ENSURE SERVICEGROUPS ARE BOUND TO SERVERS] ***************************************************
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_intranet_http', u'server_name': u'prod_rhel_01', u'port': 80})
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_intranet_http', u'server_name': u'prod_rhel_02', u'port': 80})

TASK [TASK 3 - ENSURE SERVICEGROUPS ARE BOUND TO MONITORS] **************************************************
changed: [netscaler1] => (item={u'monitor_name': u'lbmon_intranet_http', u'servicegroup_name': u'svcgrp_intranet_http'})

PLAY RECAP **************************************************************************************************
netscaler1               : ok=6    changed=6    unreachable=0    failed=0 
```

### Disable Server
``` bash
$ ansible-playbook netscaler_change_server_state.yml --extra-vars "server_name=prod_rhel_01"

PLAY [PLAY 1 - MANAGE SERVER STATE] *************************************************************************

TASK [TASK 1 - ENSURE SERVER IS IN DESIRED STATE] ***********************************************************
changed: [netscaler1]

PLAY RECAP **************************************************************************************************
netscaler1               : ok=1    changed=1    unreachable=0    failed=0  
```

### Add Server to Virtual Servers
``` bash
$ ansible-playbook netscaler_add_server.yml --extra-vars "@./vars/example/add_server.yml"

PLAY [PLAY 1 - ENSURE ALL SERVER OBJECTS EXIST] *************************************************************

TASK [TASK 1 - ENSURE SERVER OBJECTS ARE DEPLOYED] **********************************************************
changed: [netscaler1] => (item={u'comment': u'Intranet Server', u'ip_address': u'10.10.10.23', u'name': u'prod_rhel_03'})
changed: [netscaler1] => (item={u'comment': u'Backup Intranet Server', u'ip_address': u'10.10.20.23', u'name': u'dr_rhel_03'})

PLAY [PLAY 2 - ENSURE ALL BINDINGS EXIST] *******************************************************************

TASK [TASK 1 - ENSURE SERVICEGROUPS ARE BOUND TO SERVERS] ***************************************************
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_intranet_https', u'server_name': u'prod_rhel_03', u'port': 443})
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_backup_intranet_https', u'server_name': u'dr_rhel_03', u'port': 443})
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_intranet_http', u'server_name': u'prod_rhel_03', u'port': 80})

PLAY RECAP **************************************************************************************************
netscaler1               : ok=2    changed=2    unreachable=0    failed=0  
```

### Enable Server
```bash
$ ansible-playbook netscaler_change_server_state.yml --extra-vars "server_name=prod_rhel_01 server_state=enabled"

PLAY [PLAY 1 - MANAGE SERVER STATE] *************************************************************************

TASK [TASK 1 - ENSURE SERVER IS IN DESIRED STATE] ***********************************************************
changed: [netscaler1]

PLAY RECAP **************************************************************************************************
netscaler1               : ok=1    changed=1    unreachable=0    failed=0 
```

### Deploy Virtual Server to Partition
``` bash
$ ansible-playbook netscaler_deploy_full.yml --extra-vars "@./vars/example/full_partition.yml"

PLAY [PLAY 1 - ENSURE ALL LOAD BALANCER OBJECTS EXIST] ******************************************************

TASK [TASK 1 - ENSURE SERVER OBJECTS ARE DEPLOYED] **********************************************************
changed: [netscaler1] => (item={u'comment': u'Dev Intranet Server', u'ip_address': u'10.10.12.21', u'name': u'prod_rhel_04'})
changed: [netscaler1] => (item={u'comment': u'Dev Backup Intranet Server', u'ip_address': u'10.10.22.21', u'name': u'dr_rhel_04'})

TASK [TASK 2 - ENSURE SERVICE GROUPS ARE DEPLOYED] **********************************************************
changed: [netscaler1] => (item={u'service_type': u'SSL_BRIDGE', u'comment': u'Dev Intranet Service Group', u'name': u'svcgrp_dev_intranet_https'})
changed: [netscaler1] => (item={u'service_type': u'SSL_BRIDGE', u'comment': u'Dev Backup Intranet HTTPS Service Group', u'name': u'svcgrp_dev_backup_intranet_https'})

TASK [TASK 3 - ENSURE BACKUP LB VSERVERS ARE DEPLOYED] ******************************************************
changed: [netscaler1] => (item={u'service_type': u'SSL_BRIDGE', u'comment': u'Dev Backup Intranet HTTPS VIP', u'state': u'disabled', u'name': u'lbvs_dev_backup_intranet_https', u'persistence': u'SRCIPDESTIP'})

TASK [TASK 4 - ENSURE LB VSERVERS ARE DEPLOYED] *************************************************************
changed: [netscaler1] => (item={u'comment': u'Dev Intranet HTTPS VIP', u'lb_method': u'LEASTCONNECTION', u'name': u'lbvs_dev_intranet_https', u'backup_vserver': u'lbvs_dev_backup_intranet_https', u'service_type': u'SSL_BRIDGE', u'ip_address': u'10.10.13.21', u'port': 443, u'persistence': u'SRCIPDESTIP'})

TASK [TASK 5 - ENSURE MONITORS ARE DEPLOYED] ****************************************************************
changed: [netscaler1] => (item={u'type': u'HTTP', u'response_code': u'200-202', u'request': u'HEAD /healthcheck.html', u'name': u'lbmon_dev_intranet_https', u'secure': u'YES'})
changed: [netscaler1] => (item={u'type': u'HTTP', u'response_code': u'200-202', u'request': u'HEAD /healthcheck.html', u'name': u'lbmon_dev_backup_intranet_https', u'secure': u'YES'})

PLAY [PLAY 2 - ENSURE ALL BINDINGS EXIST] *******************************************************************

TASK [TASK 1 - ENSURE VSEVERS ARE BOUND TO SERVICEGROUPS] ***************************************************
changed: [netscaler1] => (item={u'vserver_name': u'lbvs_dev_intranet_https', u'servicegroup_name': u'svcgrp_dev_intranet_https'})
changed: [netscaler1] => (item={u'vserver_name': u'lbvs_dev_backup_intranet_https', u'servicegroup_name': u'svcgrp_dev_backup_intranet_https'})

TASK [TASK 2 - ENSURE SERVICEGROUPS ARE BOUND TO SERVERS] ***************************************************
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_dev_intranet_https', u'server_name': u'prod_rhel_04', u'port': 443})
changed: [netscaler1] => (item={u'servicegroup_name': u'svcgrp_dev_backup_intranet_https', u'server_name': u'dr_rhel_04', u'port': 443})

TASK [TASK 3 - ENSURE SERVICEGROUPS ARE BOUND TO MONITORS] **************************************************
changed: [netscaler1] => (item={u'monitor_name': u'lbmon_dev_intranet_https', u'servicegroup_name': u'svcgrp_dev_intranet_https'})
changed: [netscaler1] => (item={u'monitor_name': u'lbmon_dev_backup_intranet_https', u'servicegroup_name': u'svcgrp_dev_backup_intranet_https'})

PLAY RECAP **************************************************************************************************
netscaler1               : ok=8    changed=8    unreachable=0    failed=0
```