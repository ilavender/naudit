naudit
======

Scan for new listening ports and alert on Sensu client socket.

Designed to scan AWS public_dns_name, networks and hosts externally in order to check how the world see you and detect newly exposed ports.

# Requirements

pip install -r req.txt


# Configuration

- configure boto aws credentials:
    https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration
	http://boto3.readthedocs.io/en/latest/guide/configuration.html#shared-credentials-file
- when using -n AWS it default to scan instances in 'us-east-1', 'eu-west-1', you can set your regions by changing MY_REGIONS.
  

# Usage

  	scanner.py [-h] -n NETWORKS [-e EXCLUDE] [-t TIMEOUT] [-c CONCURRENCY]
                  [-d]

	optional arguments:
  		-h, --help            show this help message and exit
  		-n NETWORKS, --network NETWORKS
						network or host to scan. i.e: 172.16.1.0/24
  		-e EXCLUDE, --exclude EXCLUDE
                        host to exclude from scan. i.e: 172.16.1.10
  		-t TIMEOUT, --timeout TIMEOUT
                        port scan timeout, default: 3.
  		-c CONCURRENCY, --concurrency CONCURRENCY
                        ports scan concurrency, default: 10000.
  		-d, --dead-ping       force scan of hosts which do not respond to ping.


	example:
		python3.5 scanner.py -c 20000 -d -n AWS -n 172.30.1.0/24 -e 192.168.100.1 -e 192.168.100.254

