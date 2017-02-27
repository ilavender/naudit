Scan for new listening ports

  	```
  	usage: scanner.py [-h] -n NETWORKS [-e EXCLUDE] [-t TIMEOUT] [-c CONCURRENCY]
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
  	```

example:
	```
	python3.5 scanner.py -c 20000 -d -n 192.168.100.50 -n 172.30.1.0/24 -e 192.168.100.1 -e 192.168.100.254

	```
