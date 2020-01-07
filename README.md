[![Say Thanks](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg?style=flat)](https://saythanks.io/to/deadbits)

# yara-rules
Collection of YARA signatures from recent malware research

## Ruleset

**Dacls Trojan**
- Rule: [Dacls_Linux.yara](https://github.com/deadbits/yara-rules/blob/master/rules/Dacls_Linux.yara)
- Rule: [Dacls_Windows.yara](https://github.com/deadbits/yara-rules/blob/master/rules/Dacls_Windows.yara)
- Reference: https://blog.netlab.360.com/dacls-the-dual-platform-rat/

**APT32 KerrDown**
- Rule: [APT32_KerrDown.yara](https://github.com/deadbits/yara-rules/blob/master/rules/APT32_KerrDown.yara)
- Reference: https://unit42.paloaltonetworks.com/tracking-oceanlotus-new-downloader-kerrdown/

****
**ACBackdoor - Linux build**
- Rule: [ACBackdoor_Linux.rule](https://raw.githubusercontent.com/deadbits/yara-rules/master/rules/ACBackdoor_Linux.yara)
- Reference: [Intezer](https://www.intezer.com/blog-acbackdoor-analysis-of-a-new-multiplatform-backdoor/)

****
**Unnamed Linux Golang Ransomware**
- Rule: [Linux_Golang_Ransomware.rule](https://github.com/deadbits/yara-rules/master/rules/Linux_Golang_Ransomware.rule)
- Reference: Fortinet Blog

****
**KPOT v2**
- Rule: [KPOT_v2.yara](https://github.com/deadbits/yara-rules/blob/master/rules/KPOT_v2.yara)
- Reference: (ProofPoint Threat Insight)[https://www.proofpoint.com/us/threat-insight/post/new-kpot-v20-stealer-brings-zero-persistence-and-memory-features-silently-steal]

****

**WatchBog Linux botnet**
- Rule: [WatchBog_Linux.yara](https://github.com/deadbits/yara-rules/blob/master/rules/WatchBog_Linux.yara)
- References:
  - https://twitter.com/polarply/status/1153232987762376704
  - https://www.alibabacloud.com/blog/return-of-watchbog-exploiting-jenkins-cve-2018-1000861_594798

****
**EvilGnome Linux malware**
- Rule: [EvilGnome_Linux.yara](https://github.com/deadbits/yara-rules/blob/master/rules/EvilGnome_Linux.yara)
- Reference: [Intezer](https://www.intezer.com/blog-evilgnome-rare-malware-spying-on-linux-desktop-users/)

****
**APT34 PICKPOCKET**
- Rule: [APT34_PICKPOCKET.yara](https://github.com/deadbits/yara-rules/blob/master/rules/APT34_PICKPOCKET.yara)
- Reference: [FireEye Threat Reseearch](https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html)

****
**APT34 LONGWATCH**
- Rule: [APT34_LONGWATCH.yara](https://github.com/deadbits/yara-rules/blob/master/rules/APT34_LONGWATCH.yara)
- Reference: [FireEye Threat Reseearch](https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html)

****
**APT34 VALUEVAULT**
- Rule: [APT34_VALUEVAULT.yara](https://github.com/deadbits/yara-rules/blob/master/rules/APT34_VALUEVAULT.yara)
- Reference: [FireEye Threat Reseearch](https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html)

****
**RedGhost Linux tool**
- Rule: [RedGhost_Linux](https://github.com/deadbits/yara-rules/blob/master/rules/RedGhost_Linux.yara)
- Reference: [RedGhost Gitub repo](https://github.com/d4rk007/RedGhost/blob/master/redghost.sh)

****
**SilentTrinity**
- Rule: [SilentTrinity_Payload.rule](https://raw.githubusercontent.com/deadbits/yara-rules/master/rules/SilentTrinity_Payload.yara)
- Rule: [SilentTrinity_Delivery.rule](https://raw.githubusercontent.com/deadbits/yara-rules/master/rules/SilentTrinity_Delivery.yara)
- Reference: [Countercept](https://countercept.com/blog/hunting-for-silenttrinity/)

****
**DNSpionage**
- Rule: [DNSpionage.yara](https://github.com/deadbits/yara-rules/blob/master/rules/DNSpionage.yara)
- References: [Talos Intelligence](https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html), [Talos Intelligence #2](https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html)

****

**TA505 FlowerPippi**
- Rule: [TA505_FlowerPippi.yara](https://github.com/deadbits/yara-rules/blob/master/rules/TA505_FlowerPippi.yara)
- Reference: https://blog.trendmicro.com/trendlabs-security-intelligence/latest-spam-campaigns-from-ta505-now-using-new-malware-tools-gelup-and-flowerpippi/

****
**REMCOS RAT**
- Rule: [REMCOS_RAT_2019.yara](https://github.com/deadbits/yara-rules/blob/master/rules/REMCOS_RAT_2019.yara)
- Reference: https://exchange.xforce.ibmcloud.com/collection/Remcos-Rat-Delivered-via-Email-Campaign-056f98e4fc97bd142337d6b2271aeaa7

****
**GodLua Linux Backdoor**
- Rule: [godlua_linux.yara](https://github.com/deadbits/yara-rules/blob/master/rules/godlua_linux.yara)
- Reference: https://blog.netlab.360.com/an-analysis-of-godlua-backdoor-en/

****
**APT32 Ratsnif**
- Rule: [apt32-ratsnif.yara](https://github.com/deadbits/yara-rules/blob/master/rules/apt32-ratsnif.yara)
- Reference: https://threatvector.cylance.com/en_us/home/threat-spotlight-ratsnif-new-network-vermin-from-oceanlotus.html

****
**OSX/CrescentCore**
- Rule: [crescentcore_dmg.yara](https://github.com/deadbits/yara-rules/blob/master/rules/crescentcore_dmg.yara)
- Reference: https://www.intego.com/mac-security-blog/osx-crescentcore-mac-malware-designed-to-evade-antivirus/

side note: _when will we all decide to change mac sig names to macOS/<malware>? its way past time, imho_

****
**WarZone RAT aka Ave Maria Stealer**
- Rule: [avemaria_warzone.yara](https://github.com/deadbits/yara-rules/blob/master/rules/avemaria_warzone.yara)
- Reference: http://blog.morphisec.com/threat-alert-ave-maria-infostealer-on-the-rise-with-new-stealthier-delivery

****
**Winnti Linux**
- Rule: [winnti_linux.yara](https://github.com/deadbits/yara-rules/blob/master/rules/winnti_linux.yara)
- Reference: https://medium.com/chronicle-blog/winnti-more-than-just-windows-and-gates-e4f03436031a
