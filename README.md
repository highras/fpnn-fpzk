## FPZK Server v3

### Features

1. 同步间隔

	同步分为实时同步和定时同步。

	+ 实时同步

		* 如果配置项 `FPZK.server.event_notify.realtime` 为 `true`，则实时同步开启。一旦有任何变动，将立刻通知**订阅者**，和 FPZK Server **其余节点**。
		* 配置项 `FPZK.server.event_notify.realtime`默认值为 `true`。

	+ 定时同步

		* FPZK Server 会以 200ms 一个周期，将集群变动通知**订阅者**，和 FPZK Server **其余节点**。
		* 定时同步为强制同步，不能关闭。

	所有同步，均仅同步**更新**的数据。

1. 配置文件加载

	FPZK Server 30秒检查一次配置文件修改。如有改动，则自动加载更新。

	更新仅限于以下配置项：

	* FPZK.server.projects
	* FPZK.server.server_list
	* FPZK.server.region_list
	* FPZK.server.region.*.server_list

1. FPZK Server 周期性任务总计

	* 200ms FPZK Server 个节点之间同步一次
	* 200ms 订阅通知一次
	* 30秒检查一次配置文件修改

### Interfaces

1. 接口参数单位
	
	| 参数 | 单位 |
	|------|-----|
	| startTime (App Service) | 毫秒 |
	| startTime (FPZK) | 秒 |
	| clusterAlteredTime | 毫秒 |
	| activedTime | 秒 |
	| registeredTime | 秒 |


### Config

#### Single Region

单区域使用，兼容 FPZK Server v2 的配置文件。

对于 FPZK Server v3 的配置文件，存在以下两种等价的配置方式

1. 传统配置 （推荐）

	仅配置 `FPZK.server.server_list` 项。

	注释掉配置项 `FPZK.server.self_region`，或者不配置，留为空。
	注释掉配置项 `FPZK.server.region_list`，或者不配置，留为空。
	注释掉所有 `FPZK.server.region.*.server_list` 配置项，或者不配置，留为空。

1. 多区域兼容配置

	1. `FPZK.server.region_list` 配置为本区域名称
	2. `FPZK.server.self_region` 配置为本区域名称
	3. `FPZK.server.region.*.server_list` 修改 '*' 号为本区域名称，例如：`FPZK.server.region.beijing.server_list`，然后配置该条目。

以上两种配置可混合使用。

**所有 FPZK Server 可使用相同的配置文件**。


#### Multi-regions

1. 注释掉配置项 `FPZK.server.server_list`，或者不配置，留为空。
1. 配置 `FPZK.server.region_list`
1. 配置 `FPZK.server.self_region`
1. 根据区域，逐条配置 `FPZK.server.region.*.server_list`

	比如：`FPZK.server.region.beijing.server_list`，`FPZK.server.region.tokyo.server_list`，……


* **同一区域内，所有 FPZK Server 可使用相同的配置文件**
* **不同区域的配置文件，`FPZK.server.self_region` 项不相同**
* **如果配置项 `FPZK.server.region.*.server_list` 内含有本机 endpoint，则配置项 `FPZK.server.self_region` 可不配置**

#### 区域间数据同步

前提条件：

1. FPZK Server 配置为 Multi-regions
1. 客户端为 FPZK Client v3，且配置项 `FPZK.client.sync.syncPublicInfo` 为 true


#### 配置项 FPZK.server.sync.external.batch_size

区域间同步数据时，单条数据包含：

		"endpoint", "srvVersion", "registerTime", "startTime", "online",
		"ipv4", "ipv6", "domain",
		"port", "port6", "sslport", "sslport6", "uport", "uport6"

按文本字符计算，所占字节估算为

		21 6 10 10 4
		15 39 20
		5 5 5 5 5 5

总计 155 字节。

以太网的 MTU 是 1500 Bytes，Internet上 的标准 MTU 值为 576 Bytes。

常规只会有 ipv4 的普通端口，且无服务版本和 ipv6 地址和域名。这样大约可节省 90 Bytes。这样一条数据大概 65 Bytes。

20条大概 1300 Bytes。再加上FPNN包头（16Byte），数据链路层（以太网帧 18Bytes），TCP帧头部（20Bytes），IP帧头部（20Bytes），大约能控制在 1374 Bytes，再加上msagepack编码的其他字段，适合以太网内网传输。

7条大概控制在 455 Bytes，FPNN包头（16Byte），TCP帧头部（20Bytes），IP帧头部（20Bytes），大约在 511 Bytes 左右。再加上msagepack编码的其他字段，适合公网传输。