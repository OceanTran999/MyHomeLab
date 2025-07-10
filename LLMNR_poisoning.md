# Introduction
This lab I want to research about a common powerful tool for network pentesting - `responder`. In this scenario, I will use this tool for sniffing and spoofing the LLMNR (Link-Local Multicast Name Resolution) protocol to give the fake the answers to the victim machine in order to get the NTLM Hash.

# Environment
- VMWare Virtual Environment.
- An attacker machine running Kali Linux.
- A Windows Server Domain Controller 2019.
- A Windows machine - victim.

<img width="415" height="311" alt="network_diagram" src="https://github.com/user-attachments/assets/fe838757-0cc0-4467-9dfc-261761d3c5b8" />


# What is LLMNR?
- LLMNR is a protocol that allows both IPv4 and IPv6 to perform name resolution without the requirement of a DNS server. It operates by sending out multicast packets over local networks asking if any specific computers with certain name exist and wait for the LLMNR reponse.

# Implementation
- First, running the `responder` tool in attacker machine. In victim machine, we will search an unexisted file called `hello`.

<img width="491" height="317" alt="responder_setting" src="https://github.com/user-attachments/assets/26891c27-7d09-45d4-93d6-f180b4a6569b" />


<img width="624" height="373" alt="UserConnect" src="https://github.com/user-attachments/assets/d88acd17-3c65-48ef-85fc-d25d3f877f40" />


- Then, the log-in form will be displayed, which means the attacker successfully sent a fake LLMNR response to the victim machine.

<img width="624" height="517" alt="Log_in" src="https://github.com/user-attachments/assets/1a67ba30-fb04-487d-b23f-b5a3dbdb1f19" />


<img width="624" height="400" alt="sniff_spoof_llmnr" src="https://github.com/user-attachments/assets/58387287-8ac1-4b9a-9ff7-10e3876732b2" />


Looking at packets in `Wireshark` tool, I see that the attacker machine sends a NBNS packet to the victim machine. After giving the credentials (username and password) with the login form, the victim machine sends `SMB_NETLOGON` to the attacker.

<img width="624" height="278" alt="wireshark1" src="https://github.com/user-attachments/assets/d06ca00a-bfcd-45ba-ac6e-3dcec9b1b9e0" />


Analyzing the `responder`'s code, I see that there is a function called `ThreadingUDPLLMNRServer()` with defined IPv4 and IPv6 same as packets in Wireshark. After sending the MDNS packets, I see that the victim sends LLMNR queries packets to the attacker server with IPv6, which is a fake LLMNR server in attacker machine.

<img width="624" height="110" alt="threadingUDPLLMNR" src="https://github.com/user-attachments/assets/e9919efc-5785-44f0-b000-1638ec8f65ff" />


<img width="624" height="224" alt="wireshark2" src="https://github.com/user-attachments/assets/a09a3e7f-8718-4b69-898f-9f73646d9617" />


Next, the attacker's fake server sends an `Negotiate Protocol Request` SMB2 packet to the victim machine.

<img width="624" height="368" alt="wireshark3" src="https://github.com/user-attachments/assets/807cf99c-1563-44a4-a7b9-17788afcb7f8" />


In these SMB2 packets, I see that there is a packet that has `NTLM Message Type: NTLMSSP_AUTH`, so I consider the structure of that packet.
<img width="624" height="362" alt="wireshark4" src="https://github.com/user-attachments/assets/b72a4787-cfb4-4202-8265-c03401afa374" />


In that packet, I see that there is 2 important factors, which are `NTLM Server challenge` and `NTLM Response`, which are NTLM Hash that we need to capture for obtaining password by bruteforce or using Pash The Hash technique.

<img width="624" height="84" alt="wireshark5" src="https://github.com/user-attachments/assets/219c878f-6226-4548-8646-fdc6559fec26" />


<img width="624" height="260" alt="wireshark6" src="https://github.com/user-attachments/assets/a286f8bc-7714-4a65-b2ed-2479283fffae" />


Checking in attacker machine, we finally get the targets we want :D

<img width="624" height="258" alt="pwned" src="https://github.com/user-attachments/assets/b5d06cce-61b7-4e09-87c7-cec8becf8594" />


# Conclusion
- This attack happens when the victim finds an unexisted name in the local network by mistyping, etc. When the victime machine doesn't get the response from the Domain Controller, it will sends other machines in the local network to find that names. If the attacker in the same LAN, he/she will capture and send fake responses to the victim to obtain the credentials (NTLM Hash).
- To avoid this attack, in Windows Server machine, the administrator must config the `Turn off multicast name resolution` and set to `Enabled`.
