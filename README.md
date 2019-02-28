# CPU-vulnerabiility-collections

CVE               |description                             |paper
------------------|-----------------------------------------|--------
CVE-2017-5754|Meltdown|Meltdown: Reading Kernel Memory from User Space(https://meltdownattack.com/meltdown.pdf)
CVE-2017-5753&CVE-2017-5715|Spectre v1,Bounds Check Bypass&Spectre v2,Branch Target Injection|Spectre Attacks: Exploiting Speculative Execution(https://spectreattack.com/spectre.pdf)
CVE-2018-3615|L1 Terminal Fault for SGX,aka Foreshadow|FORESHADOW: Extracting the Keys to the Intel SGX Kingdom withTransient Out-of-Order Execution(https://foreshadowattack.eu/foreshadow.pdf)
CVE-2018-3620&CVE-2018-3646|L1 Terminal Fault for for operating systems and SMM,aka Foreshadow-NG&L1 Terminal Fault for virtualization aka Foreshadow-NG|Foreshadow-NG: Breaking the Virtual Memory Abstraction with TransientOut-of-Order Execution(https://foreshadowattack.eu/foreshadow-NG.pdf)
CVE-2018-3639|Spectre v4,Speculative Store Bypass|Analysis and mitigation of speculative store bypass (CVE-2018-3639)(https://blogs.technet.microsoft.com/srd/2018/05/21/analysis-and-mitigation-of-speculative-store-bypass-cve-2018-3639/)
CVE-2018-3640|Spectre v3a,Rogue System Register Read|https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3640
CVE-2018-3665|LazyFP|LazyFP: Leaking FPU Register State using Microarchitectural Side-Channels(https://arxiv.org/pdf/1806.07480.pdf)
CVE-2018-3693&CVE unknown|Spectre v1.1,Bounds Check Bypass on Stores&Spectre v1.2,Read-only Protection Bypass|Speculative Buffer Overflows: Attacks and Defenses(https://people.csail.mit.edu/vlk/spectre11.pdf)
CVE-2018-9056|BranchScope|BranchScope: A New Side-Channel Attack onDirectional Branch Predictor (http://www.cs.ucr.edu/~nael/pubs/asplos18.pdf)
CVE-2018-15572|spectreRSB|Spectre Returns! Speculation Attacks using the Return Stack Buffer(https://arxiv.org/pdf/1807.07940.pdf)
CVE unknown|Spectre-PHT-CA-OP&Spectre-PHT-CA-IP&Spectre-PHT-SA-OP&Spectre-BTB-SA-IP&Spectre-BTB-SA-OP&Meltdown-PK&Meltdown-BND|A Systematic Evaluation of Transient Execution Attacks and Defenses(https://arxiv.org/pdf/1811.05441.pdf)
CVE unknown|ret2spec|ret2spec: Speculative Execution Using Return Stack Buffers(https://arxiv.org/pdf/1807.10364.pdf)


Notes:

1.Spectre V1 can be exploited over network connections rather than through local code execution of remotely delivered code such as JavaScript. This remote attack is known as NetSpectre.

NetSpectre: Read Arbitrary Memory over Network(https://misc0110.net/web/files/netspectre.pdf)

2.Spectre V1 has been demonstrated to bypass protections provided by Intel SGX. Intel has updated the SGX SDK to mitigate these vulnerabilities when SGX enclaves are rebuilt. 

SgxPectre Attacks: Stealing Intel Secrets from SGX Enclaves via Speculative Execution(https://arxiv.org/pdf/1802.09085.pdf)

Intel® Software Guard Extensions(SGX) SW Development Guidance for Potential Bounds Check Bypass Side Channel Exploits(https://software.intel.com/sites/default/files/managed/e1/ec/SGX_SDK_Developer_Guidance-CVE-2017-5753.pdf)

3.Spectre V1 has been demonstrated to bypass protections provided by the System Management Range Register (SMRR) to access protected System Management Mode (SMM) memory.

System Management Mode Speculative Execution Attacks(https://blog.eclypsium.com/2018/05/17/system-management-mode-speculative-execution-attacks/)

4.Linux: eBPF Spectre v1 mitigation is insufficient,causing CVE-2019-7308.(https://bugs.chromium.org/p/project-zero/issues/detail?id=1711)

5.The researchers developed a tool to explore how else cyber criminals could take advantage of the CPU flaws and found new techniques that could be used to extract sensitive info like passwords from devices.These techniques, which they've dubbed MeltdownPrime and SpectrePrime, pit two CPU cores against each other to dupe multi-core systems and get access to their cached data.

MeltdownPrime and SpectrePrime: Automatically-Synthesized Attacks Exploiting Invalidation-Based Coherence Protocols(https://arxiv.org/pdf/1802.03802.pdf)

6.Side-channel attacks such as the Spectre family of vulnerabilities are more widespread threat than previously thought - affecting all microprocessors that employ the performance-enhancing feature of speculative execution, and defeating all software-based attempts at fixing the vulnerabilities, according to Google researchers.

Spectre is here to stay: An analysis of side-channels and speculative execution(https://arxiv.org/pdf/1902.05178.pdf)

7.ExSpectre: Hiding Malware in Speculative Execution(https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_02B-5_Wampler_paper.pdf)
