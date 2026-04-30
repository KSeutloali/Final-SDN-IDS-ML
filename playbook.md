h1 nmap -sS -p 22,80,443 10.0.0.2
h1 nmap -sS 10.0.0.2
h1 nmap -sS -p 1-1000 10.0.0.2
h1 nmap -sS 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5
h1 nmap -sS -sV 10.0.0.2
h1 nmap -sU -p 53,67,123 10.0.0.2
h1 nmap -sS -T2 -f --randomize-host 10.0.0.2

h3 hping3 --icmp --flood 10.0.0.5
h1 hping3 -S -p 443 --flood 10.0.0.2
h1 hping3 --udp -p 53 --flood 10.0.0.2
h1 hping3 -A --flood -V 10.0.0.2
h1 hping3 -FXYAP --flood -V -p 80 10.0.02

h2 ping -f -c 800 10.0.0.5

sudo mn --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13 --topo=<topology>
mininet> h1 bash -lc 'nmap -sS -p 22,80,443 10.0.0.2 > /tmp/h1_nmap_ports.log 2>&1 & echo $! > /tmp/h1_nmap_ports.pid'

mininet> h1 bash -lc 'nmap -sS 10.0.0.2 > /tmp/h1_nmap_syn.log 2>&1 & echo $! > /tmp/h1_nmap_syn.pid'

mininet> h1 bash -lc 'nmap -sS -p 1-1000 10.0.0.2 > /tmp/h1_nmap_1_1000.log 2>&1 & echo $! > /tmp/h1_nmap_1_1000.pid'

mininet> h1 bash -lc 'nmap -sS 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 > /tmp/h1_nmap_multi_host.log 2>&1 & echo $! > /tmp/h1_nmap_multi_host.pid'

mininet> h1 bash -lc 'nmap -sS -sV 10.0.0.2 > /tmp/h1_nmap_service.log 2>&1 & echo $! > /tmp/h1_nmap_service.pid'

mininet> h1 bash -lc 'nmap -sU -p 53,67,123 10.0.0.2 > /tmp/h1_nmap_udp.log 2>&1 & echo $! > /tmp/h1_nmap_udp.pid'

mininet> h1 bash -lc 'nmap -sS -T2 -f --randomize-host 10.0.0.2 > /tmp/h1_nmap_stealth.log 2>&1 & echo $! > /tmp/h1_nmap_stealth.pid'
