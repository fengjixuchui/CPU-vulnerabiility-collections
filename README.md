# CPU-vulnerabiility-collections

# 1.papers

<table>
<thead>
<tr>
	<th>description</th>
	<th>paper</th>
	<th>blog</th>
	<th>POC</th>
</tr>
</thead>
<tbody>
<tr>
	<td>Meltdown</td>
	<td>Meltdown: Reading Kernel Memory from User Space(https://meltdownattack.com/meltdown.pdf)</td>
	<td></td>
	<td>https://github.com/IAIK/meltdown</td>
</tr>
<tr>
	<td>Spectre v1,Bounds Check Bypass&amp;Spectre v2,Branch Target Injection</td>
	<td>Spectre Attacks: Exploiting Speculative Execution(https://spectreattack.com/spectre.pdf)</td>
	<td></td>
	<td>provided in the paper</td>
</tr>
<tr>
	<td>Spectre v1.1,Bounds Check Bypass on Stores&amp;Spectre v1.2,Read-only Protection Bypass</td>
	<td>Speculative Buffer Overflows: Attacks and Defenses(https://arxiv.org/pdf/1807.03757.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>Spectre v3a,Rogue System Register Read</td>
	<td>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3640</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>Spectre v4,Speculative Store Bypass</td>
	<td>Issue 1528: speculative execution, variant 4: speculative store bypass(https://bugs.chromium.org/p/project-zero/issues/detail?id=1528)</td>
	<td></td>
	<td>provided in the paper</td>
</tr>
<tr>
	<td>portsmash</td>
	<td>Port Contention for Fun and Profit(https://eprint.iacr.org/2018/1060.pdf)</td>
	<td></td>
	<td>https://github.com/bbbrumley/portsmash</td>
</tr>
<tr>
	<td>NetSpectre</td>
	<td>NetSpectre: Read Arbitrary Memory over Network(https://arxiv.org/pdf/1807.10535.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>ret2spec</td>
	<td>ret2spec: Speculative Execution Using Return Stack Buffers(https://arxiv.org/pdf/1807.10364.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>spectreRSB</td>
	<td>Spectre Returns! Speculation Attacks using the Return Stack Buffer(https://arxiv.org/pdf/1807.07940.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>LazyFP</td>
	<td>LazyFP: Leaking FPU Register State using Microarchitectural Side-Channels(https://arxiv.org/pdf/1806.07480.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>BranchScope</td>
	<td>BranchScope: A New Side-Channel Attack on Directional Branch Predictor(http://www.cs.ucr.edu/~nael/pubs/asplos18.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>SgxPectre</td>
	<td>SgxPectre Attacks: Stealing Intel Secrets from SGX Enclaves via Speculative Execution(https://arxiv.org/pdf/1802.09085.pdf)</td>
	<td></td>
	<td>https://github.com/osusecLab/SgxPectre</td>
</tr>
<tr>
	<td>ExSpectre</td>
	<td>ExSpectre: Hiding Malware in Speculative Execution(https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_02B-5_Wampler_paper.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>TLBleed</td>
	<td>Translation Leak-aside Buffer: Defeating Cache Side-channel Protections with TLB Attacks(https://www.vusec.net/wp-content/uploads/2018/07/tlbleed-author-preprint.pdf)</td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>analysis of side-channels and speculative execution</td>
	<td>Spectre is here to stay: An analysis of side-channels and speculative execution(https://arxiv.org/pdf/1902.05178.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>MeltdownPrime and SpectrePrime</td>
	<td>MeltdownPrime and SpectrePrime: Automatically-Synthesized Attacks Exploiting Invalidation-Based Coherence Protocols(https://arxiv.org/pdf/1802.03802.pdf)</td>
	<td></td>
	<td>provided in the paper</td>
</tr>
<tr>
	<td>Spectre-PHT-CA-OP&amp;Spectre-PHT-CA-IP&amp;Spectre-PHT-SA-OP&amp;Spectre-BTB-SA-IP&amp;Spectre-BTB-SA-OP&amp;Meltdown-PK&amp;Meltdown-BND</td>
	<td>A Systematic Evaluation of Transient Execution Attacks and Defenses(https://arxiv.org/pdf/1811.05441.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>System Management Mode Speculative Execution Attacks</td>
	<td>System Management Mode Speculative Execution Attacks(https://blog.eclypsium.com/2018/05/17/system-management-mode-speculative-execution-attacks/)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>Foreshadow&amp;Foreshadow-NG</td>
	<td>FORESHADOW: Extracting the Keys to the Intel SGX Kingdom with Transient Out-of-Order Execution(https://foreshadowattack.eu/foreshadow.pdf) Foreshadow-NG: Breaking the Virtual Memory Abstraction with Transient Out-of-Order Execution(https://foreshadowattack.eu/foreshadow-NG.pdf)</td>
	<td></td>
	<td>https://github.com/gregvish/l1tf-poc</td>
</tr>
<tr>
	<td>SPOILER</td>
	<td>SPOILER: Speculative Load Hazards Boost Rowhammer and Cache Attacks(https://arxiv.org/pdf/1903.00446.pdf)</td>
	<td></td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td>SMoTherSpectre</td>
	<td>SMoTherSpectre: exploiting speculative execution through port contention(https://arxiv.org/pdf/1903.01843.pdf)</td>
	<td></td>
	<td>https://github.com/HexHive/SMoTherSpectre</td>
</tr>
</tbody>
</table>

# 2.check tool

windows:https://github.com/ionescu007/SpecuCheck

linux&BSD:https://github.com/speed47/spectre-meltdown-checker

# 3.vuln analysis

性能VS安全？CPU芯片漏洞攻击实战(1) - 破解macOS KASLR篇(https://paper.seebug.org/497/)

性能VS安全？CPU芯片漏洞攻击实战(2) - Meltdown获取Linux内核数据(https://paper.seebug.org/499/)

Into the Implementation of Spectre(https://www.fortinet.com/blog/threat-research/into-the-implementation-of-spectre.html)

Foreshadow: Breaking the Virtual Memory Abstraction with Speculative Execution(https://www.youtube.com/watch?v=LVeWUq_mciM)

SMoTherSpectre: transient execution attacks through port contention(http://nebelwelt.net/blog/20190306-SMoTherSpectre.html)

Reading privileged memory with a side-channel(https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)

Intel LazyFP vulnerability: Exploiting lazy FPU state switching(https://blog.cyberus-technology.de/posts/2018-06-06-intel-lazyfp-vulnerability.html)

Analysis and mitigation of L1 Terminal Fault (L1TF)(https://blogs.technet.microsoft.com/srd/2018/08/14/analysis-and-mitigation-of-l1-terminal-fault-l1tf/) 

Analysis and mitigation of speculative store bypass (CVE-2018-3639)(https://blogs.technet.microsoft.com/srd/2018/05/21/analysis-and-mitigation-of-speculative-store-bypass-cve-2018-3639/)

# 4.patch analysis

## 4.1.KPTI(Kernel Page Table Isolation)

KPTI补丁分析(https://mp.weixin.qq.com/s/kQaZnqjbdxz6HS8ljLp3zw)

## 4.2.KVAS(Kernel Virtual Address Shadow)

简单看了一下微软新出的内核页表隔离补丁(https://bbs.pediy.com/thread-223805.htm)

KVA Shadow: Mitigating Meltdown on Windows(https://blogs.technet.microsoft.com/srd/2018/03/23/kva-shadow-mitigating-meltdown-on-windows/)

A Deep Dive Analysis of Microsoft’s Kernel Virtual Address Shadow Feature(https://www.fortinet.com/blog/threat-research/a-deep-dive-analysis-of-microsoft-s-kernel-virtual-address-shadow-feature.html)

## 4.3.Retpoline(return trampoline)

Retpoline: The Anti sectre type 2 mitigation in windows(https://www.youtube.com/watch?v=ZfxXjDQRpsU)

**pdf:https://www.slideshare.net/MSbluehat/bluehat-v18-retpoline-the-antispectre-type-2-mitigation-in-windows**

Retpoline: a software construct for preventing branch-target-injection(https://support.google.com/faqs/answer/7625886)

Mitigating Spectre variant 2 with Retpoline on Windows(https://techcommunity.microsoft.com/t5/Windows-Kernel-Internals/Mitigating-Spectre-variant-2-with-Retpoline-on-Windows/ba-p/295618)

## 4.4.others

Spectre mitigations in MSVC(https://blogs.msdn.microsoft.com/vcblog/2018/01/15/spectre-mitigations-in-msvc/)

Mitigating speculative execution side channel hardware vulnerabilities(https://blogs.technet.microsoft.com/srd/2018/03/15/mitigating-speculative-execution-side-channel-hardware-vulnerabilities/)

# 5.videos

Intel官方解释CPU漏洞原理和补丁的视频(https://www.bilibili.com/video/av21021306/)

Beyond Belief: Spectre and Meltdown(https://www.youtube.com/watch?v=_4O0zMW-Zu4)

**pdf:https://gruss.cc/files/beyond_belief.pdf**

Speculative Store Bypass in 3 minutes from Red Hat(https://www.youtube.com/watch?v=Uv6lDgcUAC0)

Exploiting modern microarchitectures: Meltdown, Spectre, and other attacks(https://www.youtube.com/watch?v=2kCDPCgjlJ4)

**pdf:https://people.redhat.com/jcm/talks/FOSDEM_2018.pdf**

# 6.others

https://software.intel.com/security-software-guidance

Exploiting CVE-2018-1038 - Total Meltdown(https://blog.xpnsec.com/total-meltdown-cve-2018-1038/)

Issue 1711: Linux: eBPF Spectre v1 mitigation is insufficient(https://bugs.chromium.org/p/project-zero/issues/detail?id=1711)

Detecting Attacks that Exploit Meltdown and Spectre with Performance Counters(https://blog.trendmicro.com/trendlabs-security-intelligence/detecting-attacks-that-exploit-meltdown-and-spectre-with-performance-counters/)
