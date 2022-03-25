import openstack
import json

# Initialize connection
conn = openstack.connect(cloud='openstack') 

if not conn.get_security_group('Anton'):
    conn.create_security_group(name='Anton', description='Milienkov Test')

with open('test.json', 'r', encoding='utf-8') as f: #открыли файл
    rules = json.load(f) #загнали все из файла в переменную
    
acceptable_protocols = [None, 'tcp', 'Tcp', 'TCP', 'udp', 'Udp', 'UDP', 'icmp', 'Icmp', 'ICMP']
acceptable_ethertypes = ['IPv4', 'IPv6']
acceptable_directions = ['ingress', 'egress']

rule_num = 0
for rule in rules:
    rule_num+=1  
    if ('protocol' not in rule or rule['protocol'] == None) and 'ports' in rule:
        print("Warning: rule ", rule_num, ": if parametr 'ports' is set then 'protocol' must also be set.", sep='')
        print('TCP is set')
        rule['protocol'] = "TCP"
        
    if (rule['protocol'] == "icmp" or rule['protocol'] == "Icmp" or rule['protocol'] == "ICMP") and 'ports' in rule:
        print("Error: rule ", rule_num, ": protocol ICMP can not have ports", sep='')
        continue
  
    protocol = None
    if 'protocol' in rule:
        if rule['protocol'] in acceptable_protocols:
            protocol = rule['protocol']
        else:
            print("Warning: rule ", rule_num, ": acceptable protocols: ", acceptable_protocols, sep='')
            print('TCP is set')
            rule['protocol'] = "TCP"
            protocol = "TCP"

    if ('remote_ip_prefix' in rule) + ('remote_group_id' in rule) > 1:
        print("Error: rule ", rule_num, ": Only one parametr can be set: remote_ip_prefix, remote_group_id", sep='')
        continue

    remote_ip_prefix = None
    if 'remote_ip_prefix' in rule:
        remote_ip_prefix = rule['remote_ip_prefix']

    remote_group_id = None
    if 'remote_group_id' in rule:
        remote_group_id = rule['remote_group_id']
        if not conn.get_security_group(remote_group_id):
            print("Error: rule ", rule_num, ": Security group ", remote_group_id, " does not exist" , sep='')
            continue

    direction = 'ingress'
    if 'direction' in rule:
        if rule['direction'] in acceptable_directions:
            direction = rule['direction']
        else:
            print("Warning: rule ", rule_num, ": acceptable directions: ", acceptable_directions, sep='')
            print('ingress is set')
            rule['direction'] = 'ingress'
            direction = 'ingress'

    ethertype = 'IPv4'
    if 'ethertype' in rule:
        if rule['ethertype'] in acceptable_ethertypes:
            ethertype = rule['ethertype']
        else:
            print("Warning: rule ", rule_num, ": acceptable ethertypes: ", acceptable_ethertypes, sep='')
            print('IPv4 is set')
            rule['ethertype'] = 'IPv4'
            ethertype = 'IPv4'

    project_id = None
    if 'project_id' in rule:
        project_id = rule['project_id']

    port_range_min = port_range_max = None
    if 'ports' in rule:
        arr_ports = rule['ports']
        for ports in arr_ports:
            if '-' in ports:
                port_range = ports.split("-")
                port_range_min = int(port_range[0])
                port_range_max = int(port_range[1])
            else:
                port_range_min = port_range_max = int(ports)

            try:
                conn.create_security_group_rule(secgroup_name_or_id='Anton', 
                                                port_range_min=port_range_min,
                                                port_range_max=port_range_max,
                                                protocol=protocol,
                                                remote_ip_prefix=remote_ip_prefix,
                                                remote_group_id=remote_group_id,
                                                direction=direction,
                                                ethertype=ethertype,
                                                project_id=project_id                                    
                                                )
            except Exception:
                print("Error: rule ", rule_num, ": Security group rule already exists", sep='')
                continue
    else:
        try:
            conn.create_security_group_rule(secgroup_name_or_id='Anton', 
                                            port_range_min=port_range_min,
                                            port_range_max=port_range_max,
                                            protocol=protocol,
                                            remote_ip_prefix=remote_ip_prefix,
                                            remote_group_id=remote_group_id,
                                            direction=direction,
                                            ethertype=ethertype,
                                            project_id=project_id                                    
                                            )
        except Exception:
            print("Error: rule ", rule_num, ": Security group rule already exists", sep='')
            continue

