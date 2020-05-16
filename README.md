# aids-dpi

**AngelIDS DPI - Deep Packet Inspection Kernel Module **

Simple linux kernel module with powerful Deep Packet Inspection by using Netfilter API.

It allows you:

1. Match TCP & UDP & HTTP packet
2. Match data packet by IP, Subnet, PortRange, PayloadData, PayloadDataLength, etc.
3. Match HTTP data by URL, Header(s), File Extension, Domain, Body, etc.
4. For each match rule, there are 5 different match mode: EXACT_MATCH, REGEX_MATCH, NO_FIXED_DATA_MATCH, PART_EXACT_MATCH, BM_MATCH
5. Display connection status by tracking TCP connection lifecycle automatically
6. Effectively and really low resource cost

Licensed Under **GPL2.0** with **ABSOLUTELY NO WARRANTY**.

# aids-dpi

**AngelIDS DPI - 深度数据包检测内核模块 **

这是一个使用Netfilter API实现的简单但强大的深度数据包检测内核模块.

它可以让你:

1. 匹配TCP、UDP、HTTP共三种协议类型的数据包
2. 使用IP地址、网段、端口范围、数据包内容、数据包长度等多种方式对数据包进行匹配检测
3. 根据URL、HTTP Header、请求的URL后缀名、域名、正文部分等多种方式对HTTP数据包进行匹配检测
4. 每个匹配规则可以使用5种不同的匹配模式: 完整匹配、正则匹配、无固定内容匹配、部分匹配、BM算法文本搜索
5. 显示TCP连接状态，全自动追踪TCP连接的完整生命周期
6. 高效且极低的资源占用

本代码使用 **GPL2.0** 授权, **无任何担保**.