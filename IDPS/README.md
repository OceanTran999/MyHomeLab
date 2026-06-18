# Project
This project is to learn 2 common IDSs/IPSs called [Snort](https://www.snort.org/) and [Suricata](https://www.snort.org/)

## Environment (Updated):
- Ubuntu 22.04 LTS
    - Snort, Suricata: Installed in Host Machine and set up Inline mode to anal>
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

<img width="1491" height="792" alt="IDPS_Proj drawio" src="https://github.com/u>


## Updated Attack Scenario:

<img width="522" height="901" alt="IDPS_Proj_2 drawio" src="https://github.com/>


## Running Snort3 with this command:
### For saving logs into JSON files
- Snort3 Container
```
    /home/snorty/snort3/bin/snort -c /home/snorty/snort3/etc/snort/oceantranlab.lua -i eth0 -A alert_json --lua "alert_json = {file = true}"
```

- Snort Command:
```
    sudo snort -i ens33 -c snort/oceantranlab.lua -A alert_csv -l <place to save log files>
```

### For saving logger outputs event information
```
    /home/snorty/snort3/bin/snort -c /home/snorty/snort3/etc/snort/oceantranlab.lua -i eth0 -A alert_fast --lua "alert_fast = {packet = true, buffers = rule}"
```
