This project is to learn 2 common IDSs/IPSs called [Snort](https://www.snort.org/) and [Suricata](https://www.snort.org/)

Environment:
- Ubuntu 22.04 LTS
    - Using Docker with 4 containers: 
        - Snort, Suricata: Passive Intrusion Detection Systems (IDSs)
        - Victim 1: Using DVWA App
        - Victim 2: Using BWAPP
- Kali Linux: Attacker

Problems:
- I tried to use `ipvlan`, the both `L2` and `L3` mode can't ping with host machine and the Internet. But I have not tried to create VLAN ID yet. (May try in the future :D)
- I tried with `macvlan`, but I don't know why the host machine can't ping with containers and vice versa, while my Kali Linux (Attacker's machine) can ping containers (of course the containers can ping to Internet as well :D).

Attack Scenario:

<img width="1491" height="792" alt="IDPS_Proj drawio" src="https://github.com/user-attachments/assets/69d20815-e268-4c4e-9d45-d6e344a7c5b2" />
