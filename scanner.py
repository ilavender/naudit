#!/usr/bin/env python

import os, json
import nmap, socket, threading
import hashlib
import argparse
import boto3

MY_REGIONS = ['us-east-1', 'eu-west-1']

SCAN_TIMEOUT = 3
SCAN_CONCURRENCY = 10000

parser = argparse.ArgumentParser()
parser.add_argument('-n', '--network', action='append', dest='networks', required = True,
                    help='network or host to scan. i.e: 172.16.1.0/24')
parser.add_argument('-e','--exclude', action='append', dest='exclude', required = False,
                    help='host to exclude from scan. i.e: 172.16.1.10')
parser.add_argument('-t','--timeout', type=int, action='store', dest='timeout', required = False,
                    help='port scan timeout, default: %s.' % SCAN_TIMEOUT)
parser.add_argument('-c','--concurrency', type=int, action='store', dest='concurrency', required = False,
                    help='ports scan concurrency, default: %s.' % SCAN_CONCURRENCY)
parser.add_argument('-d', '--dead-ping', action='store_true', dest='dead_ping',
                    help='force scan of hosts which do not respond to ping.')
args = parser.parse_args()

output = {}



def running_instances(MY_REGIONS):
    
               
    MY_RUNNING = []                

    
    for I_REGION in MY_REGIONS:
    
        ec2 = boto3.resource('ec2', region_name=I_REGION)
        instances = ec2.instances.filter(
                                         Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    
        for instance in instances:                                       
                
            if instance.public_dns_name:
                I_ID = instance.id
                I_NAME = None
                for tag in instance.tags:
                    if tag['Key'] == 'Name':
                        I_NAME = tag['Value']           
                MY_RUNNING.append({'InstancesName':I_NAME, 
                                   'InstancesId':I_ID, 
                                   'InstanceType':instance.instance_type, 
                                   'AvailabilityZone':instance.placement['AvailabilityZone'], 
                                   'public_dns_name': instance.public_dns_name
                                   })
            
            
    return MY_RUNNING



def TCP_connect(ip, port_number, delay, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    if ip not in output:
        output[ip] = []
    try:
        TCPsock.connect((ip, port_number))
        output[ip].append(port_number)
        TCPsock.close()
    except:
        TCPsock.close()
        pass


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]
        

def get_cache_data(cachefile):
    data = []
    if os.path.isfile(cachefile): 
        with open(cachefile, 'r') as f:
            content = ''.join(f.readlines())
            data = json.loads(content)
        return data
            
    else:
        return False
    

def write_cache_data(cachefile, data):
    with open(cachefile, 'w') as outfile:
        json.dump(data, outfile)
        
    if os.path.isfile(cachefile):
        return True        
    else:
        return False


def scan_ports(host_ip, delay, chunk_size):

    for series in chunks(range(1, 65535), chunk_size):        

        threads_list = {}
    
        # Spawning threads
        for i in series:
            t = threading.Thread(target=TCP_connect, args=(host_ip, i, delay, output))
            threads_list[i] = t
    
        # Starting threads
        for i in threads_list:
            threads_list[i].start()
    
        # Locking script until all threads complete
        for i in threads_list:
            threads_list[i].join()  
            

def alert(IP, UDP_PORT, MESSAGE):    
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytes(json.dumps(MESSAGE), "utf-8"), (IP, UDP_PORT))
    



def main():        

    if 'AWS' in args.networks:
        args.networks.remove('AWS')
        for instance in running_instances(MY_REGIONS):
            args.networks.append(instance['public_dns_name'])


    networks = ' '.join(args.networks) 
    
    if args.exclude is not None:
            exclude_hosts = args.exclude
    else:
        exclude_hosts = []
        
    m = hashlib.sha256()
    m.update(b"%s" % networks.encode('utf-8'))
    m.update(b"%s" % ' '.join(exclude_hosts).encode('utf-8'))
    if args.dead_ping:
        m.update(b"%s" % '--dead-ping'.encode('utf-8'))
    id = m.hexdigest()
    
    map = '/tmp/naudit-%s.json' % id
    naudith_map = get_cache_data(map)
    
    if args.timeout:
        delay = args.timeout
    else:
        delay = SCAN_TIMEOUT   
    
    all_hosts = []        
    changes = []   
    
    scan = nmap.PortScanner()
    if args.dead_ping:
        scan.scan(hosts=networks, arguments='-n -sP -P0')
    else:
        scan.scan(hosts=networks, arguments='-n -sP')
        
    for host_ip in scan.all_hosts():
        if 'up' in scan[host_ip]['status']['state'] or args.dead_ping:
            all_hosts.append(host_ip)
    
    if args.concurrency and args.concurrency > 0:
        chunk_size = args.concurrency
    else:
        chunk_size = SCAN_CONCURRENCY
        
    
    for host_ip in all_hosts:
        if host_ip not in exclude_hosts:
            print('scanning host: ' + host_ip)
            scan_ports(host_ip, delay, chunk_size) 
                           
    for ip in output:
        for port in output[ip]:                
            if naudith_map == False or ip not in naudith_map or port not in naudith_map[ip]:
                print('new listener %s: %s' % (ip, port))
                MESSAGE = 'new listener %s: %s' % (ip, port )
                changes.append(MESSAGE)
                    
    write_cache_data(map, output)
    
    if len(changes) > 0:
        
        MESSAGE = { "name": "naudit_network_change",
                    "output": 'scanner detected % changes\n%s' % (len(changes), json.dumps(changes)),
                    "status": 2, 
                    "handler": "isubscribe",
                    "handle": True, 
                    "enable_deprecated_filtering": False, 
                    "occurrences": 1, 
                    "refresh": 0
                    }
        alert('127.0.0.1', 3030, MESSAGE)


if __name__ == "__main__":
    main()
