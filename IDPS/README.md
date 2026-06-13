# Project
This project is to learn 2 common IDSs/IPSs called [Snort](https://www.snort.org/) and [Suricata](https://www.snort.org/)

## Environment:
- Ubuntu 22.04 LTS
    - Snort, Suricata: Installed in Host Machine and set up Inline mode to analyze network packets sent to Docker Containers.
    - Using Docker with 2 containers:
        - Victim 1: Using DVWA App
        - Victim 2: Using BWAPP
- Kali Linux: Attacker

## Problems:
- I tried to use `ipvlan`, the both `L2` and `L3` mode can't ping with host machine and the Internet. But I have not tried to create VLAN ID yet. (May try in the future :D)
- I tried with `macvlan`, but I don't know why the host machine can't ping with containers and vice versa, while my Kali Linux (Attacker's machine) can ping containers (of course the containers can ping to Internet as well :D). Must enable `promiscuous mode` in the Docker Host Machine's network interface.
- To enable `promiscuous mode` in Docker Container I must set `privileged: true` in `Docker Compose`
- And after wasting of my time to try run Snort3 Container, I realize that I should run Snort in the Host Machine instead of running it as Container LOL XD. Since I understood that it is necessary to use Network TAP or SPAN Port so that the Passive IDS can receive and analyze the copied packets.

## Draft Attack Scenario:

<img width="1491" height="792" alt="IDPS_Proj drawio" src="https://github.com/user-attachments/assets/69d20815-e268-4c4e-9d45-d6e344a7c5b2" />


## Updated Attack Scenario:

<img width="522" height="901" alt="IDPS_Proj_2 drawio" src="https://github.com/user-attachments/assets/608be343-9d21-447f-a3b6-7e151f1549a4" />


## Running Snort3 with this command:
### For saving logs into JSON files
```
    /home/snorty/snort3/bin/snort -c /home/snorty/snort3/etc/snort/oceantranlab.lua -i eth0 -A alert_json --lua "alert_json = {file = true}"
```

### For saving logger outputs event information
```
    /home/snorty/snort3/bin/snort -c /home/snorty/snort3/etc/snort/oceantranlab.lua -i eth0 -A alert_fast --lua "alert_fast = {packet = true, buffers = rule}"
```
