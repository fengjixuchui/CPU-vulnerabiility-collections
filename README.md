# CPU-vulnerabiility-collections

# 1.papers

description                              |paper|
-----------------------------------------|--------|
Meltdown|Meltdown: Reading Kernel Memory from User Space(https://meltdownattack.com/meltdown.pdf)
Spectre v1,Bounds Check Bypass&Spectre v2,Branch Target Injection|Spectre Attacks: Exploiting Speculative Execution(https://spectreattack.com/spectre.pdf)
Spectre v1.1,Bounds Check Bypass on Stores&Spectre v1.2,Read-only Protection Bypass|Speculative Buffer Overflows: Attacks and Defenses(https://arxiv.org/pdf/1807.03757.pdf)
Spectre v3a,Rogue System Register Read|https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3640
Spectre v4,Speculative Store Bypass|Issue 1528: speculative execution, variant 4: speculative store bypass(https://bugs.chromium.org/p/project-zero/issues/detail?id=1528)
portsmash|Port Contention for Fun and Profit(https://eprint.iacr.org/2018/1060.pdf)
NetSpectre|NetSpectre: Read Arbitrary Memory over Network(https://arxiv.org/pdf/1807.10535.pdf)
ret2spec|ret2spec: Speculative Execution Using Return Stack Buffers(https://arxiv.org/pdf/1807.10364.pdf)
spectreRSB|Spectre Returns! Speculation Attacks using the Return Stack Buffer(https://arxiv.org/pdf/1807.07940.pdf)
LazyFP|LazyFP: Leaking FPU Register State using Microarchitectural Side-Channels(https://arxiv.org/pdf/1806.07480.pdf)
BranchScope|BranchScope: A New Side-Channel Attack on Directional Branch Predictor(http://www.cs.ucr.edu/~nael/pubs/asplos18.pdf)
SgxPectre|SgxPectre Attacks: Stealing Intel Secrets from SGX Enclaves via Speculative Execution(https://arxiv.org/pdf/1802.09085.pdf)
ExSpectre|ExSpectre: Hiding Malware in Speculative Execution(https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_02B-5_Wampler_paper.pdf)
TLBleed|Translation Leak-aside Buffer: Defeating Cache Side-channel Protections with TLB Attacks(https://www.vusec.net/wp-content/uploads/2018/07/tlbleed-author-preprint.pdf)
analysis of side-channels and speculative execution|Spectre is here to stay: An analysis of side-channels and speculative execution(https://arxiv.org/pdf/1902.05178.pdf)
MeltdownPrime and SpectrePrime|MeltdownPrime and SpectrePrime: Automatically-Synthesized Attacks Exploiting Invalidation-Based Coherence Protocols(https://arxiv.org/pdf/1802.03802.pdf)
Spectre-PHT-CA-OP&Spectre-PHT-CA-IP&Spectre-PHT-SA-OP&Spectre-BTB-SA-IP&Spectre-BTB-SA-OP&Meltdown-PK&Meltdown-BND|A Systematic Evaluation of Transient Execution Attacks and Defenses(https://arxiv.org/pdf/1811.05441.pdf)
System Management Mode Speculative Execution Attacks|System Management Mode Speculative Execution Attacks(https://blog.eclypsium.com/2018/05/17/system-management-mode-speculative-execution-attacks/)
L1 Terminal Fault for SGX,aka Foreshadow|FORESHADOW: Extracting the Keys to the Intel SGX Kingdom with Transient Out-of-Order Execution(https://foreshadowattack.eu/foreshadow.pdf)
L1 Terminal Fault for for operating systems and SMM/virtualization,aka Foreshadow-NG|Foreshadow-NG: Breaking the Virtual Memory Abstraction with Transient Out-of-Order Execution(https://foreshadowattack.eu/foreshadow-NG.pdf)
SPOILER|SPOILER: Speculative Load Hazards Boost Rowhammer and Cache Attacks(https://arxiv.org/pdf/1903.00446.pdf)
SMoTherSpectre|SMoTherSpectre: exploiting speculative execution through port contention(https://arxiv.org/pdf/1903.01843.pdf)

# 2.POC

https://github.com/Eugnis/spectre-attack

https://github.com/bbbrumley/portsmash

https://github.com/lsds/spectre-attack-sgx

https://github.com/paboldin/meltdown-exploit

# 3.check tool

windows:https://github.com/ionescu007/SpecuCheck

linux&BSD:https://github.com/speed47/spectre-meltdown-checker

# 4.vuln analysis

性能VS安全？CPU芯片漏洞攻击实战(1) - 破解macOS KASLR篇(https://paper.seebug.org/497/)

性能VS安全？CPU芯片漏洞攻击实战(2) - Meltdown获取Linux内核数据(https://paper.seebug.org/499/)

Into the Implementation of Spectre(https://www.fortinet.com/blog/threat-research/into-the-implementation-of-spectre.html)

Reading privileged memory with a side-channel(https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)

Foreshadow: Breaking the Virtual Memory Abstraction with Speculative Execution(https://www.youtube.com/watch?v=LVeWUq_mciM)

Intel LazyFP vulnerability: Exploiting lazy FPU state switching(https://blog.cyberus-technology.de/posts/2018-06-06-intel-lazyfp-vulnerability.html)

Analysis and mitigation of L1 Terminal Fault (L1TF)(https://blogs.technet.microsoft.com/srd/2018/08/14/analysis-and-mitigation-of-l1-terminal-fault-l1tf/) 

Analysis and mitigation of speculative store bypass (CVE-2018-3639)(https://blogs.technet.microsoft.com/srd/2018/05/21/analysis-and-mitigation-of-speculative-store-bypass-cve-2018-3639/)

# 5.patch analysis

## 5.1.KPTI(Kernel Page Table Isolation)

KPTI补丁分析(https://mp.weixin.qq.com/s/kQaZnqjbdxz6HS8ljLp3zw)

## 5.2.KVAS(Kernel Virtual Address Shadow)

简单看了一下微软新出的内核页表隔离补丁(https://bbs.pediy.com/thread-223805.htm)

KVA Shadow: Mitigating Meltdown on Windows(https://blogs.technet.microsoft.com/srd/2018/03/23/kva-shadow-mitigating-meltdown-on-windows/)

A Deep Dive Analysis of Microsoft’s Kernel Virtual Address Shadow Feature(https://www.fortinet.com/blog/threat-research/a-deep-dive-analysis-of-microsoft-s-kernel-virtual-address-shadow-feature.html)

## 5.3.Retpoline(return trampoline)

Retpoline: The Anti sectre type 2 mitigation in windows(https://www.youtube.com/watch?v=ZfxXjDQRpsU)

**pdf:https://www.slideshare.net/MSbluehat/bluehat-v18-retpoline-the-antispectre-type-2-mitigation-in-windows**

Retpoline: a software construct for preventing branch-target-injection(https://support.google.com/faqs/answer/7625886)

Mitigating Spectre variant 2 with Retpoline on Windows(https://techcommunity.microsoft.com/t5/Windows-Kernel-Internals/Mitigating-Spectre-variant-2-with-Retpoline-on-Windows/ba-p/295618)

## 5.4.others

Spectre mitigations in MSVC(https://blogs.msdn.microsoft.com/vcblog/2018/01/15/spectre-mitigations-in-msvc/)

Mitigating speculative execution side channel hardware vulnerabilities(https://blogs.technet.microsoft.com/srd/2018/03/15/mitigating-speculative-execution-side-channel-hardware-vulnerabilities/)

# 6.videos

Intel官方解释CPU漏洞原理和补丁的视频(https://www.bilibili.com/video/av21021306/)

Beyond Belief: Spectre and Meltdown(https://www.youtube.com/watch?v=_4O0zMW-Zu4)

**pdf:https://gruss.cc/files/beyond_belief.pdf**

Speculative Store Bypass in 3 minutes from Red Hat(https://www.youtube.com/watch?v=Uv6lDgcUAC0)

Exploiting modern microarchitectures: Meltdown, Spectre, and other attacks(https://www.youtube.com/watch?v=2kCDPCgjlJ4)

**pdf:https://people.redhat.com/jcm/talks/FOSDEM_2018.pdf**

# 7.others

https://software.intel.com/security-software-guidance

Exploiting CVE-2018-1038 - Total Meltdown(https://blog.xpnsec.com/total-meltdown-cve-2018-1038/)

Issue 1711: Linux: eBPF Spectre v1 mitigation is insufficient(https://bugs.chromium.org/p/project-zero/issues/detail?id=1711)

Detecting Attacks that Exploit Meltdown and Spectre with Performance Counters(https://blog.trendmicro.com/trendlabs-security-intelligence/detecting-attacks-that-exploit-meltdown-and-spectre-with-performance-counters/)
