h1 nmap -sS -p 22,80,443 10.0.0.2
h1 nmap -sS 10.0.0.2
h1 nmap -sS -p 1-1000 10.0.0.2
h1 nmap -sS 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5
h1 nmap -sS -sV 10.0.0.2
h1 nmap -sU -p 53,67,123 10.0.0.2

h3 hping3 --icmp --flood 10.0.0.5
h1 hping3 -S -p 443 --flood 10.0.0.2
**blocks but packets still transmitted** h1 hping3 --udp -p 53 --flood 10.0.0.2, h1 hping3 --icmp --flood 10.0.0.2
h1 nmap -sS -T2 -f --randomize-host 10.0.0.2
