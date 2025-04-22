---
title: "Digitech security assessment"
author: [HAN23080227]
date: "2025-05-"
subject: "Markdown"
keywords: [Markdown, Example]
lang: "en"
titlepage: true
titlepage-rule-height: 0
titlepage-background: "background1.pdf"
...
## I. Introduction

## II. Physical Security Assessment

## III. IT Security and Risk Assessment
#### 3.1. Assessment methodology
To further test your IT security, we have opted to conduct a gray box test on your internal systems. A gray box pentest is when a pentest is given limited intelligence or access in the target system (Shebli & Beheshti, 2018). This is to simulate an "assume breached" scenerio in the event that hackers managed to compromise a single endpoint system by the usage of C2s (Command and Control) or by the usage of RDP like the case of lapsus$, where they used compromised credentials from insiders or a social engineering job to wreck havoc on NVIDIA, Okta, etc (CISA, 2023). 

#### 3.2. Initial Access

With your permission, we were given an unmarked windows machine (WS01) to start with: 

![*Figure 3.2.1: WS01 initial access user*](images/ws01-inital.png)

The first thing we would do is to install a pivoting tool in order to access the internal network in the 192.168.56.0/24 subnet, we gonna use reverse-ssh by Fahrj (https://github.com/Fahrj/reverse-ssh) to act as a reverse ssh server within the network and as a pivoting proxy for proxychains. Proxychains is the tool we use to allow Linux tools to work with SOCKS proxy.


![*Figure 3.2.2: Reverse-SSH in action*](images/reverse-ssh.png)

After we got reverse-ssh running on the system, we can now ssh in ```ssh -D 9050 -p 31337 10.131.9.240```. The proxy is now running at 127.0.0.1:9050 on the attacker machine, which is proxychains's default option.

![*Figure 3.2.3: proxychains allowing the attacker to interact with the proxy*](images/nmap_reverseproxy.png)

#### 3.3. Internal network enumeration

After a while of running nmap with the `-st` and `-Pn` to disable host discovery, we discovered there server hosts: 

```
Nmap scan report for 192.168.56.10
Host is up (0.00018s latency).
Not shown: 985 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
5986/tcp open  wsmans

Nmap scan report for 192.168.56.11
Host is up (0.00026s latency).
Not shown: 986 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
5986/tcp open  wsmans

Nmap scan report for 192.168.56.22
Host is up (0.000095s latency).
Not shown: 992 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
5986/tcp open  wsmans

```

From the scan, we can determine that there is a CI/CD and file server, and 2 domain controllers. Additionally there were a camera system but it was beyond the scope of this test per your request.

After wards we ran them through netexec to determine the hostname, roles and domain of the machine:

![*Figure 3.3.1: Netexec identifying the hosts and their respective domains and hostnames*](images/netexec_host.png)

From here we can draw a relationship graph for all three of the top servers: 

![*Figure 3.3.2: Relationship graph*](images/Diagram_network.png)

Next, we looked around for any protential entry point and we found out that the dc02 domain controller allows for RPC anonymous bind. RPC is short for Remote Procedure Call, which is a protocol that would allow a client/server relationship between processes locally or over the network over "pipes" (Jonathan, 2021), one of them is MS-SAMR, which allows for remote account management. In this case, we can abuse the anonymous user (null login) with rpcclient to enumerate users and their descriptions: 

![*Figure 3.3.3: RPC anonymous bind user enumeration*](images/rpc.png)

After taking a closer look at the users, we spotted user ```samwell.tarly``` with their password in their description: 

![*Figure 3.3.4: User with password written in their Description field*](images/user_description.png)

#### 3.4. Domain lateral movement on dev.digitech.com

Running the account through netexec showed that `samwell` can Remote Desktop into SRV02. 

![*Figure 3.4.1: Initial access on SRV02*](images/srv02-rdp.png)

Next, we used SharpHound to collect all information of the dev.digitech.com Domain with the authenticated account:

![*Figure 3.4.2: Sharphound collecting Domain info with an authenticated account*](images/sharphound.png)

Then, we parsed the file through BloodHound to turn the data into graphs so that we can determine the "relationship" the objects (users, groups, etc) have with each other in the domain. 

![*Figure 3.4.3: Bloodhound showing the relationship between dev.digitech.com and digitech.com*](images/bloodhound.png)

When we inspected the current user, we found out that they have full control over the "DefaultWallpaper" a Group Policy Object. 

![*Figure 3.4.4: Bloodhound showing which object samwell.tarly can control on the domain*](images/bloodhound_gpo.png)

In Windows, a Group Policy Object is a set of rules for user, groups and computers. These rules can range from default wallpaper, startup programs, what rights an user have locally on that computer, can they be local admin on, etc (Microsoft Learn). 

![*Figure 3.4.5: Bloodhound showing which computer is affected by this Group Policy Object*](images/bloodhound_gpo2.png)

In this case, the ```DefaultWallpaper``` group policy object dictates the default wallpaper on DC02 and SRV02. With control of this group policy, we can hijack it to grant the current user local Administrator rights on DC02 and SRV02 with the usage of SharpGPOAbuse on SRV02 as samwell.tarly: 

![*Figure 3.4.6: Hijacking the DEFAULTWALLPAPER Group Policy Object*](images/sharpgpoabuse.png)

After the GPO was updated, we waited 90 minutes and we can now login as the local Administrator for SRV02 and DC02:

![*Figure 3.4.7: samwell.tarly as local Admin on SRV02*](images/srv02-admin.png)

![*Figure 3.4.8: samwell.tarly as local Admin on DC02*](images/dc02-admin.png)

With local admin right on DC02, we can now dump all of the known domain NTLM credentials using the secretsdump script from the impacket packages that will dump domain credentials from NTDS.dit on the domain controller: 

![*Figure 3.4.9: Dumping NTDS credentials from DC02 domain*](images/secretsdump.png)

While many of these NTLM hashes are uncrackable, they can be used for PtH (Pass the Hash) attacks on Windows.

#### 3.5. Cross-Forest Lateral movement to digitech.com

As shown in Figure 3.4.4, dev.digitech.com and digitech.com is part of the same "Forest". In Active Directory, a forest is a collection of AD domains that share the same basic schema or second level domain names (Microsoft). In order for users from either of these domains to use each other resources, both domain can trust other, unidirectionally or bidirectionally. 

![*Figure 3.4.1: Diagram of how one way of trust works (Microsoft)*](images/one-way trust.gif)

If domain A "trust" domain B, then domain B can access other's resources and vice versa.  

![*Figure 3.4.2: PowerView showing trust direction between two domains*](images/trust.png)

In this case, since digitech.com and dev.digitech.com trust are bidirectional, we can attempt to break into digitech.com. As shown on figure 3.4.9, one of the account we got from dc02.dev.digitech.com was named DIGITECH$, this is the "trust" account that is neeeded for cross-domain kerberos authentication, and with it, we can forge a fraudulent ticket-granting-ticket with a SIDHistory attribute containing the SID (Security Identifier) value of digitech's.com Domain Admin. SIDHistory is a feature that would retain an object's previous SID (security identifiers) when an object is migrated from another domain, attackers can abuse this attribute features to impersonate Domain Admin (Prasad, 2024)

 ![*Figure 3.4.3: Getting the SID of digitech.com*](images/sid.png)

With the antivirus disabled on DC02, we can use mimikatz the first generate our fraudulent TGT:

 ![*Figure 3.4.4: Crafting the fake TGT*](images/mimikatz.png)

With the TGT saved as trust.kirbi, we can next utilize Rubeus to request a TGS (Ticket Granting Service) with the service principal name of `cifs/dc02.digitech.com`: 

![*Figure 3.4.5: Requesting a Ticket Granting Service ticket from DC02*](images/rubeus.png)

With the CIFS (Common Internet File System) ticket in memory, we can try to access the C$ share on DC02: 

![*Figure 3.4.6: Listing file on the C$ share*](images/smb.png)

Next, to gain code execution on DC01.digitech.com, we can use PsExec, which uploads an reverse shell executable to the ADMIN$ share, then, it will start a service that will return a shell (Mitre). 

![*Figure 3.4.7: Psexec on DC01*](images/psexec.png)
 
![*Figure 3.4.8: Admin on DC01*](images/dom_admin.png)

With admin rights on DC01, we can now use `reg save` to dump the SAM and SYSTEM hive from the registry and then exfiltrate it to extract the credentials of the local Administrator account for a NTDS.dit credential dump:

![*Figure 3.4.9: SAM and SYSTEM dump from DC01*](images/sam_dump.png)

![*Figure 3.4.10: Extracting DC01 Admin hash*](images/admin_hash.png)

![*Figure 3.4.11: Dumping the credentials of the digitech.com domain*](images/dc01_dump.png)

And we had successfully compromised both digitech.com and dev.digitech.com domain.

## IV. Assets and Security Controls Assurance Review

## V. Mitigations and Security Recommandations

#### 5.1. Mitigations

In this section, we will talk about how to mitigates the critical security vulnerbilities we found during our penetration test.

- T1087: Account Discovery

In this case, attacker had managed to interact with the SAMR pipe in the RPC service with a "null", or an anonymous bind. To mitigate this, administrators should enfore the "Restrict anonymous access to Named Pipes and Shares" group policy domain wide to restrict unauthenticated access to Shares and Named Pipes. (MITRE)

- T1090: Proxying

In this case, the attacker had managed to use a reverse proxy in the form of the reverse-ssh tool to further gain access into the internal network. To mitigate and detect these kind of attacks, administrators should employ IDS (Intrusion Detection Systems) and IPS (Intrusion Prevention Systems) to detect proxying attempts. 

- T1552: Unsecured Credentials

In this case, the attacker managed to obtain a plaintext credential of a special account and used it to move laterally on the domain. To mitigate and prevent this, administrators should preemptively audit for any and all plaintext passwords in documents, text files on company SMB shares and educate users about the risk of storing plaintext passwords on their computers and servers (MITRE). 

- T1484.001: Group Policy Modification

In this case, the attacker abused an user account with complete control over a Group Policy Object that affects the SRV02 and DC02 servers, leading to the attacker granting themselves Admin rights and eventually compromise the entire Domain. To mitigate this, administrators needs to ensure that the only user accounts that can control GPOs are Domain Admins. (MITRE)

- T1558.001 and T1134: Cross-domain golden ticket

As the Administrator on DC02, the attacker managed to obtain the trust credentials of the digitech.com Domain, allowing the attacker to forge a cross domain trust ticket with an SID-History attribute of Digitech's Domain Admin, effectively granting them control over the digitech.com domain. To mitigate this, Administrators on the digitech.com should enable SID Filtering for cross-trust authentication to automatically filter out SIDHistory (MITRE). 


#### 5.2. Security policies recommandations



## VI. References

Shebli, H.M. and Beheshti, B.D. (2018) ‘A study on penetration testing process and Tools’, 2018 IEEE Long Island Systems, Applications and Technology Conference (LISAT), pp. 1–7. doi:10.1109/lisat.2018.8378035. 

Review of the attacks associated with lapsus$ and related threat groups executive summary: CISA (2023) Cybersecurity and Infrastructure Security Agency CISA. Available at: https://www.cisa.gov/resources-tools/resources/review-attacks-associated-lapsus-and-related-threat-groups-executive-summary. 

Jonathan, J. (2021) RPC for Detection Engineers. Available at: https://specterops.io/wp-content/uploads/sites/3/2022/06/RPC_for_Detection_Engineers.pdf (Accessed: 12 April 2025). 

Group policy API (no date) Microsoft Learn. Available at: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-start-page (Accessed: 13 April 2025). 

Trust technologies: Domain and forest trusts (no date) Domain and Forest Trusts | Microsoft Learn. Available at: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)?redirectedfrom=MSDN (Accessed: 14 April 2025). 

Prasad, S.K. (2024) Domain trusts- A comprehensive exploitation guide. Available at: https://redfoxsec.com/blog/domain-trusts-a-comprehensive-exploitation-guide/ (Accessed: 15 April 2025). 

MITRE (no date) PSEXEC, PsExec, Software S0029 | MITRE ATT&CK®. Available at: https://attack.mitre.org/software/S0029/ (Accessed: 15 April 2025). 

MITRE (no date) Account discovery, Account Discovery, Technique T1087 - Enterprise | MITRE ATT&CK®. Available at: https://attack.mitre.org/techniques/T1087/ (Accessed: 22 April 2025).

Vinay , P. (no date) Network Access Restrict anonymous access to named pipes and shares - windows 10, Network access Restrict anonymous access to Named Pipes and Shares - Windows 10 | Microsoft Learn. Available at: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares (Accessed: 22 April 2025).

MITRE (no date) Proxy, Proxy, Technique T1090 - Enterprise | MITRE ATT&CK®. Available at: https://attack.mitre.org/techniques/T1090/ (Accessed: 22 April 2025).

MITRE (no date b) Unsecured credentials, Unsecured Credentials, Technique T1552 - Enterprise | MITRE ATT&CK®. Available at: https://attack.mitre.org/techniques/T1552/ (Accessed: 22 April 2025).

MITRE (no date a) Domain or tenant policy modification: Group policy modification, Domain or Tenant Policy Modification: Group Policy Modification, Sub-technique T1484.001 - Enterprise | MITRE ATT&CK®. Available at: https://attack.mitre.org/techniques/T1484/001/ (Accessed: 22 April 2025). 

MITRE (no date a) Access token manipulation: Sid-history injection, Access Token Manipulation: SID-History Injection, Sub-technique T1134.005 - Enterprise | MITRE ATT&CK®. Available at: https://attack.mitre.org/techniques/T1134/005/ (Accessed: 22 April 2025). 

MITRE (no date d) Steal or Forge Kerberos tickets: Golden Ticket, Steal or Forge Kerberos Tickets: Golden Ticket, Sub-technique T1558.001 - Enterprise | MITRE ATT&CK®. Available at: https://attack.mitre.org/techniques/T1558/001/ (Accessed: 22 April 2025). 