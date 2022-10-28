#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "msec.h"
#include "FPJson.h"
#include "HostLookup.h"
#include "ServerInfo.h"
#include "StringUtil.h"
#include "NetworkUtility.h"
#include "FPZKQuestProcessor.h"

std::vector<std::string> FPZKQuestProcessor::ServiceInfoResult::fields{
	"endpoint", "region", "srvVersion", "registerTime", "lastMTime", "online",
	"tcpNum", "udpNum", "loadAvg", "cpuUsage",
	"ipv4", "ipv6", "domain", 
	"port", "port6", "sslport", "sslport6", "uport", "uport6",
	"gpu", "extra"
};

static std::vector<std::string> InternalSyncFields{
	"endpoint", "srvVersion", "registerTime", "startTime", "online",
	"tcpNum", "udpNum", "loadAvg", "cpuUsage",
	"ipv4", "ipv6", "domain",
	"port", "port6", "sslport", "sslport6", "uport", "uport6",
	"gpu", "extra"
};

static std::vector<std::string> ExternalSyncFields{
	"endpoint", "srvVersion", "registerTime", "startTime", "online",
	"ipv4", "ipv6", "domain",
	"port", "port6", "sslport", "sslport6", "uport", "uport6"
};

void FPZKQuestProcessor::ServiceInfos::updateServiceNode(const std::string& endpoint, ServiceNode& node)
{
	auto iter = nodeMap.find(endpoint);
	bool exist = (iter != nodeMap.end());
	if (exist && node.startTime == iter->second.startTime)
		node.registeredTime = iter->second.registeredTime;
	else
		node.registeredTime = node.activedTime;

	if (!exist || iter->second.online != node.online)
	{
		revision += 1;
		clusterAlteredTime = slack_real_msec();
	}

	nodeMap[endpoint] = node;
}

void FPZKQuestProcessor::ServiceInfos::updateServiceNodes(std::map<std::string, ServiceNode>& nodes)
{
	bool changed = false;
	for (auto& nodespr: nodes)
	{
		auto iter = nodeMap.find(nodespr.first);
		bool exist = (iter != nodeMap.end());
		if (!exist || iter->second.online != nodespr.second.online)
			changed = true;

		nodeMap[nodespr.first] = nodespr.second;
	}

	if (changed)
	{
		revision += 1;
		clusterAlteredTime = slack_real_msec();
	}
}

void FPZKQuestProcessor::initSelfIPs()
{
	_myIP4Address.insert("127.0.0.1");
	_myIP4Address.insert(ServerInfo::getServerLocalIP4());
	_myIP4Address.insert(ServerInfo::getServerPublicIP4());

	_myIP6Address.insert("::1");
	_myIP6Address.insert(ServerInfo::getServerLocalIP6());
	_myIP6Address.insert(ServerInfo::getServerPublicIP6());

	std::map<enum IPTypes, std::set<std::string>> ipDict;
	if (getIPs(ipDict))
	{
		for (auto& setPair: ipDict)
		{
			if (setPair.first == IPv4_Public)
				_myIP4Address.insert(setPair.second.begin(), setPair.second.end());
			else if (setPair.first == IPv4_Local)
				_myIP4Address.insert(setPair.second.begin(), setPair.second.end());
			else if (setPair.first == IPv6_Global)
				_myIP6Address.insert(setPair.second.begin(), setPair.second.end());
			else if (setPair.first == IPv6_LinkLocal)
				_myIP6Address.insert(setPair.second.begin(), setPair.second.end());
			else if (setPair.first == IPv6_SiteLocal)
				_myIP6Address.insert(setPair.second.begin(), setPair.second.end());
			else if (setPair.first == IPv6_Multicast)
				_myIP6Address.insert(setPair.second.begin(), setPair.second.end());
		}
	}
}

bool FPZKQuestProcessor::updateProjects(const std::string& projects)
{
	std::vector<std::string> projVec;
	StringUtil::split(projects, "\t ,", projVec);

	std::map<std::string, std::string> newTokenMap;
	for (auto& str: projVec)
	{
		std::string projToken = StringUtil::trim(str);
		std::vector<std::string> vec;
		StringUtil::split(projToken, ":", vec);
		if(vec.size() != 2)
		{
			LOG_FATAL("project format error, should be <project>:<token>");
			return false;
		}
		newTokenMap[vec[0]] = vec[1];
	}

	{
		std::lock_guard<std::mutex> lck(_mutex);
		_tokenMap.swap(newTokenMap);
	}

	LOG_INFO("Projects change to: %s", projects.c_str());
	return true;
}

bool FPZKQuestProcessor::checkEndpoint(const std::string& endpoint, int port4, int port6, const std::string& hintInfo, std::string& realEndpoint, bool& self)
{
	EndPointType eType;
	std::string host;
	int port;
	if (parseAddress(endpoint, host, port, eType) == false)
	{
		LOG_FATAL("parseAddress %s error. hintInfo: %s", endpoint.c_str(), hintInfo.c_str());
		return false;
	}
	if (eType == ENDPOINT_TYPE_DOMAIN)
	{
		host = HostLookup::get(host);
		if (host.empty())
		{
			LOG_FATAL("parsHostLookup for address %s error. hintInfo: %s", endpoint.c_str(), hintInfo.c_str());
			return false;
		}
		eType = ENDPOINT_TYPE_IP4;
	}

	if (port == port4 || port == port6)
	{
		if (eType == ENDPOINT_TYPE_IP4)
		{
			if (_myIP4Address.find(host) != _myIP4Address.end())
			{
				self = true;
				return true;
			}
		}
		else
		{
			if (_myIP6Address.find(host) != _myIP6Address.end())
			{
				self = true;
				return true;
			}
		}
	}
	self = false;
	realEndpoint = std::string(host).append(":").append(std::to_string(port));
	return true;
}

bool FPZKQuestProcessor::updateServerList(const std::string& serverList, const std::set<std::string>& selfRegionServers)
{
	int port4 = Setting::getInt(std::vector<std::string>{
		"FPNN.server.tcp.ipv4.listening.port",
		"FPNN.server.ipv4.listening.port",
		"FPNN.server.listening.port"}, 0);
	int port6 = Setting::getInt(std::vector<std::string>{
		"FPNN.server.tcp.ipv6.listening.port",
		"FPNN.server.ipv6.listening.port",
		}, 0);

	std::set<std::string> servers;
	std::vector<std::string> newSrvVec;
	StringUtil::split(serverList, "\t ,", servers);

	servers.insert(selfRegionServers.begin(), selfRegionServers.end());

	for (auto& endpoint: servers)
	{
		bool self = false;
		std::string realEndpoint;
		if (checkEndpoint(endpoint, port4, port6, "[updateServerList]", realEndpoint, self) == false)
			return false;

		if (self)
			continue;

		newSrvVec.push_back(realEndpoint);
	}

	{
		std::lock_guard<std::mutex> lck(_mutex);
		_peerServers.updateEndpoints(newSrvVec);
	}

	LOG_INFO("Internal server list change to: %s", StringUtil::join(newSrvVec, ",").c_str());
	return true;
}

std::map<std::string, std::set<std::string>> FPZKQuestProcessor::buildRegionServersMap(const Setting::MapType& map)
{
	std::map<std::string, std::set<std::string>> regionMap;
	std::string regionList = Setting::getString("FPZK.server.region_list", "", map);

	std::set<std::string> regions;
	StringUtil::split(regionList, "\t ,", regions);
	for (auto& region: regions)
	{
		std::string key("FPZK.server.region.");
		key.append(region).append(".server_list");

		std::string serverList = Setting::getString(key, "", map);

		std::set<std::string> servers;
		StringUtil::split(serverList, "\t ,", servers);

		regionMap[region].swap(servers);
	}
	
	return regionMap;
}

bool FPZKQuestProcessor::checkRegionMap(const std::string& localServerList, std::map<std::string, std::set<std::string>>& regionMap)
{
	int port4 = Setting::getInt(std::vector<std::string>{
		"FPNN.server.tcp.ipv4.listening.port",
		"FPNN.server.ipv4.listening.port",
		"FPNN.server.listening.port"}, 0);
	int port6 = Setting::getInt(std::vector<std::string>{
		"FPNN.server.tcp.ipv6.listening.port",
		"FPNN.server.ipv6.listening.port",
		}, 0);

	std::set<std::string> selfRegions;
	for (auto& pp: regionMap)
	{
		std::string hintInfo = "region: ";
		hintInfo.append(pp.first);

		std::set<std::string> servers;
		for (auto& endpoint: pp.second)
		{
			bool self = false;
			std::string realEndpoint;
			if (checkEndpoint(endpoint, port4, port6, hintInfo, realEndpoint, self) == false)
				return false;

			if (self)
			{
				selfRegions.insert(pp.first);
				continue;
			}
			
			servers.insert(realEndpoint);
		}
		pp.second.swap(servers);
	}
	
	if (selfRegions.size() > 1)
	{
		LOG_FATAL("Self endpoint appeared in region: %s", StringUtil::join(selfRegions, ", ").c_str());
		return false;
	}
	else if (_selfRegion.empty())
	{
		if (selfRegions.size() == 1)
		{
			_selfRegion = *(selfRegions.begin());
			return true;
		}

		std::set<std::string> servers;
		StringUtil::split(localServerList, "\t ,", servers);
		if (servers.size())
			return true;

		LOG_FATAL("Cannot detect self region. "
			"Please reconfig regions' endpoints to include self endpoint, or config item 'FPZK.server.self_region'.");
		return false;
	}
	else
	{
		if (selfRegions.empty() || _selfRegion == *(selfRegions.begin()))
			return true;

		LOG_FATAL("Detected self region is %s, but config item 'FPZK.server.self_region' is point to %s.",
			selfRegions.begin()->c_str(), _selfRegion.c_str());
		return false;
	}
}

bool FPZKQuestProcessor::updateExternalServers(const std::map<std::string, std::set<std::string>>& regionMap)
{
	std::map<std::shared_ptr<std::string>, TCPRandomProxyPtr> externalServers;

	for (auto& pp: regionMap)
	{
		if (pp.second.size())
		{
			std::vector<std::string> srvVec;
			for (auto& endpoint: pp.second)
				srvVec.push_back(endpoint);

			TCPRandomProxyPtr proxy(new TCPRandomProxy());
			proxy->updateEndpoints(srvVec);

			std::shared_ptr<std::string> region(new std::string(pp.first));
			externalServers[region] = proxy;

			LOG_INFO("External servers proxies will change to [%s]%s.", pp.first.c_str(), StringUtil::join(srvVec, ",").c_str());
		}
	}

	{
		std::lock_guard<std::mutex> lck(_mutex);
		_externalServers.swap(externalServers);
	}

	LOG_INFO("External servers proxies changed.");
	return true;
}

bool FPZKQuestProcessor::checkReloadConfig(time_t& lastModifyTime)
{
	struct stat st;
	if(stat(_configFile.c_str(), &st) < 0)
	{
		LOG_FATAL("stat() failed when checking config %s, error: %s", _configFile.c_str(), strerror(errno));
		return false;
	}
	if (st.st_mtime != lastModifyTime)
	{
		Setting::MapType map = Setting::loadMap(_configFile.c_str());
		std::string projects = Setting::getString("FPZK.server.projects", "", map);
		std::string serverList = Setting::getString("FPZK.server.server_list", "", map);

		std::map<std::string, std::set<std::string>> regionMap = buildRegionServersMap(map);
		if (!checkRegionMap(serverList, regionMap))
			return false;
		
		std::set<std::string> selfRegionServers;
		selfRegionServers.swap(regionMap[_selfRegion]);
		regionMap.erase(_selfRegion);

		if(!updateProjects(projects) || !updateServerList(serverList, selfRegionServers) || !updateExternalServers(regionMap))
			return false;

		lastModifyTime = st.st_mtime;
		LOG_INFO("Reload config(%s), mtime:%ld", _configFile.c_str(), st.st_mtime);
	}
	return true;
}

void FPZKQuestProcessor::cleanExpiredNodes()
{
	int64_t threshold = slack_real_sec() - _nodeExpireSecs;

	std::lock_guard<std::mutex> lck(_mutex);
	for (auto pit = _servicesMap.begin(); pit != _servicesMap.end(); )
	{
		for (auto sit = pit->second.begin(); sit != pit->second.end(); )
		{
			bool changed = false;
			for (auto nit = sit->second.nodeMap.begin(); nit != sit->second.nodeMap.end(); )
			{
				if (nit->second.activedTime < threshold)
				{
					nit = sit->second.nodeMap.erase(nit);
					changed = true;
				}
				else
					nit++;
			}
			if (sit->second.nodeMap.empty())
				sit = pit->second.erase(sit);
			else
			{
				if (changed)
				{
					sit->second.revision += 1;
					sit->second.clusterAlteredTime = slack_real_msec();
				}
				sit++;
			}
		}

		if (pit->second.empty())
			pit = _servicesMap.erase(pit);
		else
			pit++;
	}

	for (auto pit = _machineStatus.begin(); pit != _machineStatus.end(); )
	{
		for (auto mit = pit->second.begin(); mit != pit->second.end(); )
		{
			if (mit->second.activedTime < threshold)
				mit = pit->second.erase(mit);
			else
				mit++;
		}

		if (pit->second.empty())
			pit = _machineStatus.erase(pit);
		else
			pit++;
	}
}

void FPZKQuestProcessor::buildInternalSyncUpdateNodes(const std::map<std::string, std::map<std::string, ServiceInfos>>& updatedServicesMap,
	const std::map<std::string, std::map<std::string, MachineNode>>& updatedMachineStatus,
	std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>>& updateNodes,
	std::map<std::string, std::map<std::string, std::list<std::list<unsigned long long>>>>& GPUInfos)
{

	for (auto& ppr: updatedServicesMap)
	{
		std::map<std::string, std::vector<std::vector<std::string>>>& updateServices = updateNodes[ppr.first];

		auto machineIt = updatedMachineStatus.find(ppr.first);

		for (auto& spr: ppr.second)
		{
			std::vector<std::vector<std::string>>& serviceInfos = updateServices[spr.first];
			serviceInfos.reserve(spr.second.nodeMap.size());

			for (auto& npr: spr.second.nodeMap)
			{
				serviceInfos.push_back(std::vector<std::string>());
				std::vector<std::string>& serviceInfo = serviceInfos.back();
				serviceInfo.reserve(InternalSyncFields.size());

				// static std::vector<std::string> InternalSyncFields{
				// 	"endpoint", "srvVersion", "registerTime", "startTime", "online",
				// 	"tcpNum", "udpNum", "loadAvg", "cpuUsage",
				// 	"ipv4", "ipv6", "domain",
				// 	"port", "port6", "sslport", "sslport6", "uport", "uport6",
				//	"gpu", "extra"
				// };

				serviceInfo.push_back(npr.first);

				serviceInfo.push_back(npr.second.version);
				serviceInfo.push_back(std::to_string(npr.second.registeredTime));
				serviceInfo.push_back(std::to_string(npr.second.startTime));
				serviceInfo.push_back(npr.second.online ? "true" : "false");

				std::string host;
				GPUInfoPtr gpuInfo;
				bool usingMachineInfo = false;

				if (npr.second.usingMachineInfo)
				{
					int port;
					if (parseAddress(npr.first, host, port))
					{
						if (machineIt != updatedMachineStatus.end())
						{
							auto hostIt = machineIt->second.find(host);
							if (hostIt != machineIt->second.end())
							{
								serviceInfo.push_back(std::to_string(hostIt->second.tcpCount));
								serviceInfo.push_back(std::to_string(hostIt->second.udpCount));
								serviceInfo.push_back(std::to_string(hostIt->second.loadAvg));
								serviceInfo.push_back(std::to_string(hostIt->second.CPUUsage));
								gpuInfo = hostIt->second.gpuInfo;
								usingMachineInfo = true;
							}
							else
							{
								LOG_ERROR("Cannot find machine status record for endpoint %s for service %s in project %s when calling buildInternalSyncUpdateNodes function. Machine IP level is not found.",
									npr.first.c_str(), spr.first.c_str(), ppr.first.c_str());
							}
						}
						else
						{
							LOG_ERROR("Cannot find machine status record for endpoint %s for service %s in project %s when calling buildInternalSyncUpdateNodes function. Project level is not found.",
								npr.first.c_str(), spr.first.c_str(), ppr.first.c_str());
						}
					}
					else
					{
						LOG_ERROR("Cannot parse endpoint %s for service %s in project %s when calling buildInternalSyncUpdateNodes function.",
							npr.first.c_str(), spr.first.c_str(), ppr.first.c_str());
					}
				}
				if (usingMachineInfo == false)
				{
					//-- 当所有 FPZKServer 升级到 3.1.0 及以上后，这里压入空字符串。
					serviceInfo.push_back("-1");
					serviceInfo.push_back("-1");
					serviceInfo.push_back("-1.0");
					serviceInfo.push_back("-1.0");
				}

				serviceInfo.push_back(npr.second.ipv4);
				serviceInfo.push_back(npr.second.ipv6);
				serviceInfo.push_back(npr.second.domain);
				
				serviceInfo.push_back(std::to_string(npr.second.port));
				serviceInfo.push_back(std::to_string(npr.second.port6));

				serviceInfo.push_back(std::to_string(npr.second.sslport));
				serviceInfo.push_back(std::to_string(npr.second.sslport6));

				serviceInfo.push_back(std::to_string(npr.second.uport));
				serviceInfo.push_back(std::to_string(npr.second.uport6));

				if (npr.second.usingGPUInfo)
				{
					if (gpuInfo)
					{
						std::list<std::list<unsigned long long>>& gpuInfoData = GPUInfos[ppr.first][host];
						if (gpuInfoData.empty())
						{
							for (auto& info: *gpuInfo)
							{
								std::list<unsigned long long> cardInfo;
								cardInfo.push_back(info.index);
								cardInfo.push_back(info.usage);
								cardInfo.push_back(info.memory.usage);
								cardInfo.push_back(info.memory.used);
								cardInfo.push_back(info.memory.total);

								gpuInfoData.push_back(cardInfo);
							}
						}
					}
					else
					{
						LOG_ERROR("Cannot find GPU info for endpoint %s for service %s in project %s when calling buildInternalSyncUpdateNodes function.",
							npr.first.c_str(), spr.first.c_str(), ppr.first.c_str());
					}
					serviceInfo.push_back("1");
				}
				else
					serviceInfo.push_back("");

				if (npr.second.extra)
				{
					serviceInfo.push_back(*(npr.second.extra));
				}
			}
		}
	}
}

void FPZKQuestProcessor::syncToInternalPeers(const std::map<std::string, std::map<std::string, ServiceInfos>>& updatedServicesMap,
	const std::map<std::string, std::map<std::string, MachineNode>>& updatedMachineStatus,
	const std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices)
{
	if(_peerServers.empty() || !_running)
		return;

	std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>> updateNodes;
	std::map<std::string, std::map<std::string, std::list<std::list<unsigned long long>>>> GPUInfos;
	buildInternalSyncUpdateNodes(updatedServicesMap, updatedMachineStatus, updateNodes, GPUInfos);

	if (updateNodes.empty() && unregisteredServices.empty())
		return;

	FPQWriter qw(GPUInfos.empty() ? 3 : 4, "internalSyncServiceInfos");
	qw.param("fields", InternalSyncFields);
	qw.param("updateNodes", updateNodes);
	qw.param("unregistered", unregisteredServices);

	if (!GPUInfos.empty())
		qw.param("GPUInfo", GPUInfos);

	FPQuestPtr quest = qw.take();
	bool status = _peerServers.sendQuest(quest, [](FPAnswerPtr answer, int errorCode){
		if (errorCode != FPNN_EC_OK)
			LOG_ERROR("exception occurred when sending internal broadcast message. No all peer received. ErrorCode: %d", errorCode);
	});
	if (!status)
		LOG_ERROR("Failed to sync status to internal peer.");
}

void FPZKQuestProcessor::buildExternalSyncUpdateNodes(const std::map<std::string, std::map<std::string, ServiceInfos>>& updatedServicesMap,
	std::list<FPQuestPtr>& questList)
{
	int count = 0;
	size_t remain = 0;
	std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>> updateNodes;

	for (auto& ppr: updatedServicesMap)
	{
		std::map<std::string, std::vector<std::vector<std::string>>> *updateServices = &(updateNodes[ppr.first]);

		for (auto& spr: ppr.second)
		{
			std::vector<std::vector<std::string>> *serviceInfos = &((*updateServices)[spr.first]);
			serviceInfos->reserve(spr.second.nodeMap.size());
			remain = spr.second.nodeMap.size();

			for (auto& npr: spr.second.nodeMap)
			{
				if (!npr.second.externalVisible)
					continue;

				serviceInfos->push_back(std::vector<std::string>());
				std::vector<std::string>& serviceInfo = serviceInfos->back();
				serviceInfo.reserve(ExternalSyncFields.size());

				// static std::vector<std::string> ExternalSyncFields{
				//	"endpoint", "srvVersion", "registerTime", "startTime", "online",
				//	"ipv4", "ipv6", "domain",
				//	"port", "port6", "sslport", "sslport6", "uport", "uport6"
				// };

				if (npr.second.publishEndpoint)
					serviceInfo.push_back(npr.first);
				else
					serviceInfo.push_back("");

				serviceInfo.push_back(npr.second.version);
				serviceInfo.push_back(std::to_string(npr.second.registeredTime));
				serviceInfo.push_back(std::to_string(npr.second.startTime));
				serviceInfo.push_back(npr.second.online ? "true" : "false");

				// serviceInfo.push_back(std::to_string(npr.second.tcpCount));
				// serviceInfo.push_back(std::to_string(npr.second.udpCount));
				// serviceInfo.push_back(std::to_string(npr.second.loadAvg));
				// serviceInfo.push_back(std::to_string(npr.second.CPUUsage));

				serviceInfo.push_back(npr.second.ipv4);
				serviceInfo.push_back(npr.second.ipv6);
				serviceInfo.push_back(npr.second.domain);
				
				serviceInfo.push_back(std::to_string(npr.second.port));
				serviceInfo.push_back(std::to_string(npr.second.port6));

				serviceInfo.push_back(std::to_string(npr.second.sslport));
				serviceInfo.push_back(std::to_string(npr.second.sslport6));

				serviceInfo.push_back(std::to_string(npr.second.uport));
				serviceInfo.push_back(std::to_string(npr.second.uport6));

				{
					count += 1;
					remain -= 1;
					if (count >= _externalSyncBatchSize)
					{
						FPQWriter qw(4, "externalSyncServiceInfos");
						qw.param("region", _selfRegion);
						qw.param("fields", ExternalSyncFields);
						qw.param("updateNodes", updateNodes);
						qw.paramMap("unregistered", 0);

						FPQuestPtr quest = qw.take();
						questList.push_back(quest);

						count = 0;
						updateNodes.clear();
						updateServices = &(updateNodes[ppr.first]);
						if (remain)
						{
							serviceInfos = &((*updateServices)[spr.first]);
							serviceInfos->reserve(remain);
						}
					}
				}
			}
		}
	}

	if (count)
	{
		FPQWriter qw(4, "externalSyncServiceInfos");
		qw.param("region", _selfRegion);
		qw.param("fields", ExternalSyncFields);
		qw.param("updateNodes", updateNodes);
		qw.paramMap("unregistered", 0);

		FPQuestPtr quest = qw.take();
		questList.push_back(quest);
	}
}

void FPZKQuestProcessor::syncToExternalPeers(const std::map<std::string, std::map<std::string, ServiceInfos>>& updatedServicesMap,
	const std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices)
{
	if(_externalServers.empty() || !_running)
		return;

	std::list<FPQuestPtr> questList;
	buildExternalSyncUpdateNodes(updatedServicesMap, questList);

	if (unregisteredServices.size())
	{
		FPQWriter qw(4, "externalSyncServiceInfos");
		qw.param("region", _selfRegion);
		qw.paramArray("fields", 0);
		qw.paramMap("updateNodes", 0);
		qw.param("unregistered", unregisteredServices);

		FPQuestPtr quest = qw.take();
		questList.push_back(quest);
	}

	for (auto quest: questList)
		sendToExternalPeers(quest);
}

void FPZKQuestProcessor::syncToPeers()
{
	std::map<std::string, std::map<std::string, MachineNode>> updatedMachineStatus;
	std::map<std::string, std::map<std::string, ServiceInfos>> updatedServicesMap;
	std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>> unregisteredServices;

	{
		std::lock_guard<std::mutex> lck(_mutex);
		_updatedServicesMap.swap(updatedServicesMap);
		_updatedMachineStatus.swap(updatedMachineStatus);
		_unregisteredServices.swap(unregisteredServices);
	}

	syncToInternalPeers(updatedServicesMap, updatedMachineStatus, unregisteredServices);
	syncToExternalPeers(updatedServicesMap, unregisteredServices);
}

void FPZKQuestProcessor::instantSyncToExternalPeers(const std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices)
{
	if(_externalServers.empty() || !_running)
		return;

	FPQWriter qw(4, "externalSyncServiceInfos");
	qw.param("region", _selfRegion);
	qw.paramArray("fields", 0);
	qw.paramMap("updateNodes", 0);
	qw.param("unregistered", unregisteredServices);

	FPQuestPtr quest = qw.take();
	sendToExternalPeers(quest);
}

void FPZKQuestProcessor::instantSyncToPeers(const std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices)
{
	if(_peerServers.empty() || !_running)
		return;

	FPQWriter qw(3, "internalSyncServiceInfos");
	qw.paramArray("fields", 0);
	qw.paramMap("updateNodes", 0);
	qw.param("unregistered", unregisteredServices);

	FPQuestPtr quest = qw.take();
	bool status = _peerServers.sendQuest(quest, [](FPAnswerPtr answer, int errorCode){
		if (errorCode != FPNN_EC_OK)
			LOG_ERROR("exception occurred when sending internal instant broadcast message. No all peer received. ErrorCode: %d", errorCode);
	});
	if (!status)
		LOG_ERROR("Failed to sync internal instant status to peer.");
}

void FPZKQuestProcessor::instantSyncToExternalPeers(const std::string& project, const std::vector<std::string>& serviceNames,
	const std::string& endpoint, ServiceNode& node)
{
	if(_externalServers.empty() || !_running)
		return;

	std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>> updateNodes;
	std::map<std::string, std::vector<std::vector<std::string>>>& updateServices = updateNodes[project];

	for (auto& serviceName: serviceNames)
	{
		std::vector<std::vector<std::string>>& serviceInfos = updateServices[serviceName];
		serviceInfos.push_back(std::vector<std::string>());

		std::vector<std::string>& serviceInfo = serviceInfos.back();
		serviceInfo.reserve(ExternalSyncFields.size());

		{
			// static std::vector<std::string> ExternalSyncFields{
			// 	"endpoint", "srvVersion", "registerTime", "startTime", "online",
			// 	"ipv4", "ipv6", "domain",
			// 	"port", "port6", "sslport", "sslport6", "uport", "uport6"
			// };

			// serviceInfo.push_back(endpoint);

			if (node.publishEndpoint)
					serviceInfo.push_back(endpoint);
				else
					serviceInfo.push_back("");

			serviceInfo.push_back(node.version);
			serviceInfo.push_back(std::to_string(node.registeredTime));
			serviceInfo.push_back(std::to_string(node.startTime));
			serviceInfo.push_back(node.online ? "true" : "false");

			// serviceInfo.push_back(std::to_string(node.tcpCount));
			// serviceInfo.push_back(std::to_string(node.udpCount));
			// serviceInfo.push_back(std::to_string(node.loadAvg));
			// serviceInfo.push_back(std::to_string(node.CPUUsage));

			serviceInfo.push_back(node.ipv4);
			serviceInfo.push_back(node.ipv6);
			serviceInfo.push_back(node.domain);
			
			serviceInfo.push_back(std::to_string(node.port));
			serviceInfo.push_back(std::to_string(node.port6));

			serviceInfo.push_back(std::to_string(node.sslport));
			serviceInfo.push_back(std::to_string(node.sslport6));

			serviceInfo.push_back(std::to_string(node.uport));
			serviceInfo.push_back(std::to_string(node.uport6));
		}
	}

	FPQWriter qw(4, "externalSyncServiceInfos");
	qw.param("region", _selfRegion);
	qw.param("fields", ExternalSyncFields);
	qw.param("updateNodes", updateNodes);
	qw.paramMap("unregistered", 0);

	FPQuestPtr quest = qw.take();
	sendToExternalPeers(quest);
}

void FPZKQuestProcessor::instantSyncToPeers(const std::string& project, const std::vector<std::string>& serviceNames,
	const std::string& endpoint, ServiceNode& node, MachineNode& machineNode)
{
	if(_peerServers.empty() || !_running)
		return;

	std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>> updateNodes;
	std::map<std::string, std::vector<std::vector<std::string>>>& updateServices = updateNodes[project];

	for (auto& serviceName: serviceNames)
	{
		std::vector<std::vector<std::string>>& serviceInfos = updateServices[serviceName];
		serviceInfos.push_back(std::vector<std::string>());

		std::vector<std::string>& serviceInfo = serviceInfos.back();
		serviceInfo.reserve(InternalSyncFields.size());

		{
			// static std::vector<std::string> InternalSyncFields{
			// 	"endpoint", "srvVersion", "registerTime", "startTime", "online",
			// 	"tcpNum", "udpNum", "loadAvg", "cpuUsage",
			// 	"ipv4", "ipv6", "domain",
			// 	"port", "port6", "sslport", "sslport6", "uport", "uport6",
			//	"gpu", "extra"
			// };

			serviceInfo.push_back(endpoint);

			serviceInfo.push_back(node.version);
			serviceInfo.push_back(std::to_string(node.registeredTime));
			serviceInfo.push_back(std::to_string(node.startTime));
			serviceInfo.push_back(node.online ? "true" : "false");

			if (machineNode.activedTime)
			{
				serviceInfo.push_back(std::to_string(machineNode.tcpCount));
				serviceInfo.push_back(std::to_string(machineNode.udpCount));
				serviceInfo.push_back(std::to_string(machineNode.loadAvg));
				serviceInfo.push_back(std::to_string(machineNode.CPUUsage));
			}
			else
			{
				serviceInfo.push_back("");
				serviceInfo.push_back("");
				serviceInfo.push_back("");
				serviceInfo.push_back("");
			}

			serviceInfo.push_back(node.ipv4);
			serviceInfo.push_back(node.ipv6);
			serviceInfo.push_back(node.domain);
			
			serviceInfo.push_back(std::to_string(node.port));
			serviceInfo.push_back(std::to_string(node.port6));

			serviceInfo.push_back(std::to_string(node.sslport));
			serviceInfo.push_back(std::to_string(node.sslport6));

			serviceInfo.push_back(std::to_string(node.uport));
			serviceInfo.push_back(std::to_string(node.uport6));

			if (node.usingGPUInfo)
				serviceInfo.push_back("1");
			else
				serviceInfo.push_back("");

			if (node.extra)
				serviceInfo.push_back(*(node.extra));
		}
	}

	bool includeGPUInfo = node.usingGPUInfo && machineNode.gpuInfo;

	FPQWriter qw(includeGPUInfo ? 4 : 3, "internalSyncServiceInfos");
	qw.param("fields", InternalSyncFields);
	qw.param("updateNodes", updateNodes);
	qw.paramMap("unregistered", 0);

	if (includeGPUInfo)
	{
		std::string host;
		int port;

		if (parseAddress(endpoint, host, port))
		{
			std::map<std::string, std::map<std::string, std::list<std::list<unsigned long long>>>> GPUInfos;
			std::list<std::list<unsigned long long>>& gpuInfo = GPUInfos[project][host];

			for (auto& info: *(machineNode.gpuInfo))
			{
				std::list<unsigned long long> cardInfo;
				cardInfo.push_back(info.index);
				cardInfo.push_back(info.usage);
				cardInfo.push_back(info.memory.usage);
				cardInfo.push_back(info.memory.used);
				cardInfo.push_back(info.memory.total);

				gpuInfo.push_back(cardInfo);
			}

			qw.param("GPUInfo", GPUInfos);
		}
		else
		{
			LOG_ERROR("Cannot parse endpoint %s for service %s in project %s when calling instantSyncToPeers function.",
				endpoint.c_str(), serviceNames[0].c_str(), project.c_str());

			qw.param("GPUInfo", std::map<int, int>());
		}
	}

	FPQuestPtr quest = qw.take();
	bool status = _peerServers.sendQuest(quest, [](FPAnswerPtr answer, int errorCode){
		if (errorCode != FPNN_EC_OK)
			LOG_ERROR("exception occurred when sending internal instant broadcast message. No all peer received. ErrorCode: %d", errorCode);
	});
	if (!status)
		LOG_ERROR("Failed to sync internal instant status to peer.");
}

void FPZKQuestProcessor::sendExternalSyncQuest(std::shared_ptr<std::string> region, TCPRandomProxyPtr proxy, FPQuestPtr quest, int timeout, int retryCount)
{
	bool status = proxy->sendQuest(quest, [region, proxy, quest, timeout, retryCount](FPAnswerPtr answer, int errorCode) {
		if (errorCode != FPNN_EC_OK)
		{
			if (retryCount <= 1)
			{
				LOG_ERROR("exception occurred when sending external instant broadcast message to %s region. ErrorCode: %d",
					region->c_str(), errorCode);
			}
			else
				sendExternalSyncQuest(region, proxy, quest, timeout, retryCount - 1);
		}
	}, timeout);

	if (!status)
	{
		if (retryCount <= 1)
		{
			LOG_ERROR("Failed to sync external instant broadcast message to %s region.", region->c_str());
		}
		else
			sendExternalSyncQuest(region, proxy, quest, timeout, retryCount - 1);
	}
}

void FPZKQuestProcessor::sendToExternalPeers(FPQuestPtr quest)
{
	for (auto& pp: _externalServers)
		sendExternalSyncQuest(pp.first, pp.second, quest);
}

void FPZKQuestProcessor::notifySubscriber()
{
	if (!_running)
		return;

	std::map<std::string, std::map<QuestSenderPtr, std::set<std::string>>> senderMap;
	{
		std::lock_guard<std::mutex> lck(_mutex);
		for (auto& cpr: _changedServices)
		{
			auto pit = _clientNotifiers.find(cpr.first);
			if (pit == _clientNotifiers.end())
				continue;

			for (auto& service: cpr.second)
			{
				auto sit = _clientNotifiers[cpr.first].find(service);
				if (sit == _clientNotifiers[cpr.first].end())
					continue;

				for (auto& pr: _clientNotifiers[cpr.first][service])
					senderMap[cpr.first][pr.second].insert(service);
			}
		}

		_changedServices.clear();
	}

	for (auto& ppr: senderMap)
	{
		for (auto& spr: ppr.second)
		{
			struct ServiceInfoResult result;
			fetchServiceInfos(ppr.first, spr.second, result);

			FPQWriter qw(7, "servicesChange");
			qw.param("services", result.services);
			qw.param("revisions", result.revisions);
			qw.param("clusterAlteredTimes", result.clusterAlteredTimes);
			qw.param("nodeInfoFields", ServiceInfoResult::fields);
			qw.param("srvNodes", result.nodes);
			qw.param("invalidServices", result.invalidServices);
			qw.param("GPUInfo", result.gpuInfos);

			FPQuestPtr quest = qw.take();
			bool status = spr.first->sendQuest(quest, [](FPAnswerPtr answer, int errorCode){
				if (errorCode != FPNN_EC_OK)
					LOG_ERROR("Send notify to subscriber failed. ErrorCode: %d", errorCode);
			});
			if (!status)
				LOG_ERROR("Failed to send notify to subscriber.");
		}
	}
}

void FPZKQuestProcessor::instantNotifySubscriber(const std::string& project, const std::vector<std::string>& serviceNames)
{
	if (!_running)
		return;
	
	std::map<QuestSenderPtr, std::set<std::string>> senderMap;
	{
		std::lock_guard<std::mutex> lck(_mutex);

		auto pit = _clientNotifiers.find(project);
		if (pit == _clientNotifiers.end())
			return;

		for (auto& service: serviceNames)
		{
			auto sit = pit->second.find(service);
			if (sit == pit->second.end())
				continue;

			for (auto& pr: sit->second)
				senderMap[pr.second].insert(service);
		}
	}

	if (senderMap.empty())
		return;

	for (auto& spr: senderMap)
	{
		struct ServiceInfoResult result;
		fetchServiceInfos(project, spr.second, result);

		FPQWriter qw(7, "servicesChange");
		qw.param("services", result.services);
		qw.param("revisions", result.revisions);
		qw.param("clusterAlteredTimes", result.clusterAlteredTimes);
		qw.param("nodeInfoFields", ServiceInfoResult::fields);
		qw.param("srvNodes", result.nodes);
		qw.param("invalidServices", result.invalidServices);
		qw.param("GPUInfo", result.gpuInfos);

		FPQuestPtr quest = qw.take();
		bool status = spr.first->sendQuest(quest, [](FPAnswerPtr answer, int errorCode){
			if (errorCode != FPNN_EC_OK)
				LOG_ERROR("Send notify to subscriber failed. ErrorCode: %d", errorCode);
		});
		if (!status)
			LOG_ERROR("Failed to send notify to subscriber.");
	}
}

void FPZKQuestProcessor::daemonFunc()
{
	const int checkConfigPeriod = 30 * 5;
	const int cleanExpiredPeriod = 5;

	int checkConfigTicket = checkConfigPeriod;
	int cleanExpiredTicket = 0;

	time_t configFileLastModifyTime = 0;
	bool canBeNotify = false;	//-- short circuit flag

	while (_running)
	{
		if (checkConfigTicket >= checkConfigPeriod)
			if (checkReloadConfig(configFileLastModifyTime))
				checkConfigTicket = 0;

		usleep(200000);			//-- 200ms
		checkConfigTicket++;
		cleanExpiredTicket++;

		syncToPeers();

		if (canBeNotify || _peerServers.empty() || (slack_real_sec() - _startTime > _warmUpSecs))		//-- _peerServers empty(): meaning this is the only usable FPZK server.
		{
			canBeNotify = true;
			notifySubscriber();
		}

		if (cleanExpiredTicket >= cleanExpiredPeriod)
		{
			cleanExpiredNodes();
			cleanExpiredTicket = 0;
		}
	}
}

FPAnswerPtr FPZKQuestProcessor::checkProjectToken(const std::string& project, const FPReaderPtr args, const FPQuestPtr quest)
{
	std::string token = args->wantString("projectToken");

	std::lock_guard<std::mutex> lck(_mutex);
	if (_tokenMap.find(project) == _tokenMap.end())
		return FPAWriter::errorAnswer(quest, FPZKError::ProjectNotFound, "Project not found.", "FPZKServer");
	if (_tokenMap[project] != token)
		return FPAWriter::errorAnswer(quest, FPZKError::ProjectTokenNotMatched, "Project token not matched.", "FPZKServer");

	return nullptr;
}

void FPZKQuestProcessor::makeMachineInfoNode(const FPReaderPtr args, ServiceNode& sn, MachineNode& mn)
{
	mn.tcpCount = args->getInt("tcpNum", -1);
	mn.udpCount = args->getInt("udpNum", -1);
	mn.loadAvg = args->getDouble("perCPULoad", -1.0);
	mn.CPUUsage = args->getDouble("perCPUUsage", -1.0);

	if (mn.tcpCount >= 0 || mn.udpCount >= 0 || mn.loadAvg >= 0. || mn.CPUUsage >= 0.)
		sn.usingMachineInfo = true;

	std::list<std::vector<unsigned long long>> gpuInfo;
	gpuInfo = args->get("GPUInfo", gpuInfo);

	if (gpuInfo.size() > 0)
	{
		mn.gpuInfo.reset(new std::list<MachineStatus::GPUCardInfo>());
		for (auto& cardData: gpuInfo)
		{
			if (cardData.empty())
				continue;

			MachineStatus::GPUCardInfo cardInfo;

			if (cardData.size() > 0)
				cardInfo.index = (unsigned int)cardData[0];

			if (cardData.size() > 1)
				cardInfo.usage = (unsigned int)cardData[1];
			
			if (cardData.size() > 2)
				cardInfo.memory.usage = (unsigned int)cardData[2];

			if (cardData.size() > 3)
				cardInfo.memory.used = cardData[3];

			if (cardData.size() > 4)
				cardInfo.memory.total = cardData[4];

			mn.gpuInfo->push_back(cardInfo);
		}

		if (mn.gpuInfo->empty())
			mn.gpuInfo.reset();
		else
			sn.usingGPUInfo = true;
	}

	if (sn.usingMachineInfo || sn.usingGPUInfo)
		mn.activedTime = slack_real_sec();
}

FPAnswerPtr FPZKQuestProcessor::syncServerInfo(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
{
	std::string project = args->wantString("project");
	bool externalVisible = args->getBool("externalVisible", true);
	FPAnswerPtr answer = checkProjectToken(project, args, quest);
	if (answer) return answer;

	ServiceNode sn;
	MachineNode mn;

	std::string serviceName = args->getString("serviceName");
	std::string endpoint = args->getString("endpoint");
	std::string cluster;
	if (serviceName.length() && endpoint.length())
	{
		sn.online = args->getBool("online", true);
		sn.externalVisible = externalVisible;
		sn.version = args->getString("srvVersion");

		sn.clientId = clientId(ci);
		sn.startTime = args->getInt("startTime");

		sn.port = args->getInt("port");
		sn.port6 = args->getInt("port6");

		sn.sslport = args->getInt("sslport");
		sn.sslport6 = args->getInt("sslport6");

		sn.uport = args->getInt("uport");
		sn.uport6 = args->getInt("uport6");

		sn.domain = args->getString("domain");
		sn.ipv4 = args->getString("ipv4");
		sn.ipv6 = args->getString("ipv6");

		sn.publishEndpoint = args->getBool("publishEndpoint", true);

		cluster = args->getString("cluster");

		if (args->existKey("extra"))
		{
			sn.extra.reset(new std::string());
			*(sn.extra) = args->getString("extra");
		}

		makeMachineInfoNode(args, sn, mn);
	}

	std::vector<std::string> answeredServices;
	std::vector<int64_t> answeredRevisions;
	std::vector<int64_t> answeredClusterAlteredTimes;
	std::vector<std::string> interests = args->get("interests", std::vector<std::string>());
	
	bool clusterAltered = false;
	std::vector<std::string> registerNames;
	{
		std::lock_guard<std::mutex> lck(_mutex);
		if (serviceName.length())
		{
			registerNames.push_back(serviceName);
			if (cluster.length())
				registerNames.push_back(clusteredServiceName(serviceName, cluster));

			sn.activedTime = slack_real_sec();

			for (auto& regName: registerNames)
			{
				//-- update _servicesMap
				ServiceInfos &si = _servicesMap[project][regName];
				int64_t oldRev = si.revision;
				si.updateServiceNode(endpoint, sn);

				if (oldRev != si.revision)
				{
					clusterAltered = true;

					//-- update _changedServices
					_changedServices[project].insert(regName);
				}
				
				//-- update _updatedServicesMap
				_updatedServicesMap[project][regName].nodeMap[endpoint] = sn;

				//-- update _updatedMachineStatus
				if (mn.activedTime > 0)
				{
					std::string host;
					int port;
					if (parseAddress(endpoint, host, port))
					{
						_machineStatus[project][host] = mn;
						_updatedMachineStatus[project][host] = mn;
					}
					else
					{
						LOG_ERROR("Cannot parse endpoint %s for service %s in project %s when calling syncServerInfo interface.",
							endpoint.c_str(), regName.c_str(), project.c_str());
					}	
				}

				//-- remove from _unregisteredServices
				auto upit = _unregisteredServices.find(project);
				if (upit != _unregisteredServices.end())
				{
					auto usit = upit->second.find(regName);
					if (usit != upit->second.end())
						usit->second.erase(endpoint);
				}
			}

			//-- udapte _connectionMap
			_connectionMap[sn.clientId] = std::vector<std::string>{project, serviceName, endpoint, cluster};
		}

		//-- for insterested services
		if (interests.size() && (_servicesMap.find(project) != _servicesMap.end()))
		{
			std::map<std::string, ServiceInfos> &srvMap = _servicesMap[project];
			for (auto& service: interests)
			{
				auto it = srvMap.find(service);
				if (it != srvMap.end())
				{
					answeredServices.push_back(service);
					answeredRevisions.push_back(it->second.revision);
					answeredClusterAlteredTimes.push_back(it->second.clusterAlteredTime);
				}
			}
		}
	}

	if (_realtimeNotify && clusterAltered && !registerNames.empty())
	{
		instantSyncToPeers(project, registerNames, endpoint, sn, mn);
		instantNotifySubscriber(project, registerNames);

		if (externalVisible)
			instantSyncToExternalPeers(project, registerNames, endpoint, sn);
		
	}

	FPAWriter aw(3, quest);
	aw.param("services", answeredServices);
	aw.param("revisions", answeredRevisions);
	aw.param("clusterAlteredTimes", answeredClusterAlteredTimes);
	return aw.take();
}

void FPZKQuestProcessor::fetchServiceInfos(const std::string& project, const std::set<std::string>& serviceNames, struct ServiceInfoResult& result)
{
	if (serviceNames.empty())
		return;

	result.reserve(serviceNames.size());

	std::lock_guard<std::mutex> lck(_mutex);
	if (_servicesMap.find(project) == _servicesMap.end())
		return;

	std::map<std::string, ServiceInfos> &srvMap = _servicesMap[project];
	auto machineIt = _machineStatus.find(project);

	for (auto& serviceName: serviceNames)
	{
		auto it = srvMap.find(serviceName);
		if (it == srvMap.end())
		{
			result.invalidServices.insert(serviceName);
			continue;
		}

		result.services.push_back(serviceName);
		result.revisions.push_back(it->second.revision);
		result.clusterAlteredTimes.push_back(it->second.clusterAlteredTime);

		std::vector<std::vector<std::string>> serviceNodeInfos;
		serviceNodeInfos.reserve(it->second.nodeMap.size());

		for (auto& srvPair: it->second.nodeMap)
		{
			std::vector<std::string> nodeInfos;
			nodeInfos.reserve(ServiceInfoResult::fields.size());
/*
	"endpoint", "region", "srvVersion", "registerTime", "lastMTime", "online",
	"tcpNum", "udpNum", "loadAvg", "cpuUsage",
	"ipv4", "ipv6", "domain", 
	"port", "port6", "sslport", "sslport6", "uport", "uport6",
	"gpu", "extra"
*/
			nodeInfos.push_back(srvPair.first);
			nodeInfos.push_back(srvPair.second.region);
			nodeInfos.push_back(srvPair.second.version);
			
			nodeInfos.push_back(std::to_string(srvPair.second.registeredTime));
			nodeInfos.push_back(std::to_string(srvPair.second.activedTime));
			nodeInfos.push_back(srvPair.second.online ? "true" : "false");

			std::string host;
			GPUInfoPtr gpuInfo;
			bool usingMachineInfo = false;

			if (srvPair.second.usingMachineInfo)
			{
				if (machineIt != _machineStatus.end())
				{
					int port;
					if (parseAddress(srvPair.first, host, port))
					{
						auto hostIt = machineIt->second.find(host);
						if (hostIt != machineIt->second.end())
						{
							nodeInfos.push_back(std::to_string(hostIt->second.tcpCount));
							nodeInfos.push_back(std::to_string(hostIt->second.udpCount));
							nodeInfos.push_back(std::to_string(hostIt->second.loadAvg));
							nodeInfos.push_back(std::to_string(hostIt->second.CPUUsage));
							gpuInfo = hostIt->second.gpuInfo;
							usingMachineInfo = true;
						}
						else
						{
							LOG_ERROR("Cannot find machine status record for endpoint %s for service %s in project %s when calling fetchServiceInfos function. Machine IP level is not found.",
								srvPair.first.c_str(), serviceName.c_str(), project.c_str());
						}
					}
					else
					{
						LOG_ERROR("Cannot parse endpoint %s for service %s in project %s when calling fetchServiceInfos function.",
							srvPair.first.c_str(), serviceName.c_str(), project.c_str());
					}
				}
				else
				{
					LOG_ERROR("Cannot find machine status record for endpoint %s for service %s in project %s when calling fetchServiceInfos function. Project level is not found.",
						srvPair.first.c_str(), serviceName.c_str(), project.c_str());
				}
			}
			
			if (usingMachineInfo == false)
			{
				//-- 当所有 FPZKServer 升级到 3.1.0 及以上后，这里压入空字符串。
				nodeInfos.push_back("-1");
				nodeInfos.push_back("-1");
				nodeInfos.push_back("-1.0");
				nodeInfos.push_back("-1.0");
			}

			nodeInfos.push_back(srvPair.second.ipv4);
			nodeInfos.push_back(srvPair.second.ipv6);
			nodeInfos.push_back(srvPair.second.domain);

			nodeInfos.push_back(std::to_string(srvPair.second.port));
			nodeInfos.push_back(std::to_string(srvPair.second.port6));

			nodeInfos.push_back(std::to_string(srvPair.second.sslport));
			nodeInfos.push_back(std::to_string(srvPair.second.sslport6));

			nodeInfos.push_back(std::to_string(srvPair.second.uport));
			nodeInfos.push_back(std::to_string(srvPair.second.uport6));

			if (srvPair.second.usingGPUInfo)
			{
				if (gpuInfo)
				{
					std::vector<std::vector<unsigned long long>>& gpuInfoData = result.gpuInfos[project][host];
					if (gpuInfoData.empty())
					{
						for (auto& info: *gpuInfo)
						{
							std::vector<unsigned long long> cardInfo;
							cardInfo.push_back(info.index);
							cardInfo.push_back(info.usage);
							cardInfo.push_back(info.memory.usage);
							cardInfo.push_back(info.memory.used);
							cardInfo.push_back(info.memory.total);

							gpuInfoData.push_back(cardInfo);
						}
					}
				}
				else
				{
					LOG_ERROR("Cannot find GPU info for endpoint %s for service %s in project %s when calling fetchServiceInfos function.",
						srvPair.first.c_str(), serviceName.c_str(), project.c_str());
				}
				nodeInfos.push_back("1");
			}
			else
				nodeInfos.push_back("");

			if (srvPair.second.extra)
			{
				nodeInfos.push_back(*(srvPair.second.extra));
			}

			// serviceNodeInfos.push_back(nodeInfos);
			serviceNodeInfos.push_back(std::vector<std::string>());
			serviceNodeInfos.back().swap(nodeInfos);
		}
		//result.nodes.push_back(serviceNodeInfos);
		result.nodes.push_back(std::vector<std::vector<std::string>>());
		result.nodes.back().swap(serviceNodeInfos);
	}
}

FPAnswerPtr FPZKQuestProcessor::getServiceInfo(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
{
	if(_peerServers.empty() == false && slack_real_sec() - _startTime < _warmUpSecs)
		return FPAWriter::errorAnswer(quest, FPZKError::ServerWarmUp, "FPZK Server is waring up.", "FPZKServer");

	std::string project = args->wantString("project");
	FPAnswerPtr answer = checkProjectToken(project, args, quest);
	if (answer) return answer;

	struct ServiceInfoResult result;
	std::set<std::string> services = args->get("services", std::set<std::string>());

	fetchServiceInfos(project, services, result);
	FPAWriter aw(7, quest);
	aw.param("services", result.services);
	aw.param("revisions", result.revisions);
	aw.param("clusterAlteredTimes", result.clusterAlteredTimes);
	aw.param("nodeInfoFields", ServiceInfoResult::fields);
	aw.param("srvNodes", result.nodes);
	aw.param("invalidServices", result.invalidServices);
	aw.param("GPUInfo", result.gpuInfos);

	return aw.take();
}

FPAnswerPtr FPZKQuestProcessor::getServiceNames(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
{
	if(_peerServers.empty() == false && slack_real_sec() - _startTime < _warmUpSecs)
		return FPAWriter::errorAnswer(quest, FPZKError::ServerWarmUp, "FPZK Server is waring up.", "FPZKServer");

	std::string project = args->wantString("project");
	FPAnswerPtr answer = checkProjectToken(project, args, quest);
	if (answer) return answer;

	std::set<std::string> services;

	{
		std::lock_guard<std::mutex> lck(_mutex);
		auto it = _servicesMap.find(project);
		if (it != _servicesMap.end()){
			std::map<std::string, ServiceInfos> &srvMap = it->second;
			for (auto itt = srvMap.begin(); itt != srvMap.end(); ++itt){
				services.insert(itt->first);
			}
		}
	}

	FPAWriter aw(1, quest);
	aw.param("services", services);
	return aw.take();
}

FPAnswerPtr FPZKQuestProcessor::subscribeServicesChange(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
{
	if(_peerServers.empty() == false && slack_real_sec() - _startTime < _warmUpSecs)
		return FPAWriter::errorAnswer(quest, FPZKError::ServerWarmUp, "FPZK Server is waring up.", "FPZKServer");

	std::string project = args->wantString("project");
	FPAnswerPtr answer = checkProjectToken(project, args, quest);
	if (answer) return answer;

	struct ServiceInfoResult result;
	std::set<std::string> services = args->get("services", std::set<std::string>());

	uint64_t id = clientId(ci);
	QuestSenderPtr sender = genQuestSender(ci);
	{
		std::lock_guard<std::mutex> lck(_mutex);
		for (auto& service: services)
			_clientNotifiers[project][service][id] = sender;
	}

	fetchServiceInfos(project, services, result);
	FPAWriter aw(7, quest);
	aw.param("services", result.services);
	aw.param("revisions", result.revisions);
	aw.param("clusterAlteredTimes", result.clusterAlteredTimes);
	aw.param("nodeInfoFields", ServiceInfoResult::fields);
	aw.param("srvNodes", result.nodes);
	aw.param("invalidServices", result.invalidServices);
	aw.param("GPUInfo", result.gpuInfos);

	return aw.take();
}

int64_t FPZKQuestProcessor::dropServiceNode(const std::string& project, const std::string& service, const std::string& endpoint)
{
	int64_t startTimeAsInstanceId = _servicesMap[project][service].nodeMap[endpoint].startTime;

	_servicesMap[project][service].nodeMap.erase(endpoint);
	if (_servicesMap[project][service].nodeMap.empty())
	{
		_servicesMap[project].erase(service);
		if (_servicesMap[project].empty())
			_servicesMap.erase(project);
	}
	else
	{
		_servicesMap[project][service].revision += 1;
		_servicesMap[project][service].clusterAlteredTime = slack_real_msec();
	}

	
	_updatedServicesMap[project][service].nodeMap.erase(endpoint);
	if (_updatedServicesMap[project][service].nodeMap.empty())
	{
		_updatedServicesMap[project].erase(service);
		if (_updatedServicesMap[project].empty())
			_updatedServicesMap.erase(project);
	}

	_unregisteredServices[project][service][endpoint] = startTimeAsInstanceId;
	_changedServices[project].insert(service);

	return startTimeAsInstanceId;
}

FPAnswerPtr FPZKQuestProcessor::unregisterService(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
{
	std::string project = args->wantString("project");
	FPAnswerPtr answer = checkProjectToken(project, args, quest);
	if (answer) return answer;

	std::string serviceName = args->wantString("serviceName");
	std::string endpoint = args->wantString("endpoint");
	std::string cluster = args->getString("cluster");

	std::vector<std::string> serviceNames;
	std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>> unregisteredServices;
	{
		std::lock_guard<std::mutex> lck(_mutex);

		int64_t startTime = dropServiceNode(project, serviceName, endpoint);
		unregisteredServices[project][serviceName][endpoint] = startTime;
		serviceNames.push_back(serviceName);

		if (cluster.length())
		{
			std::string clusterlizeName = clusteredServiceName(serviceName, cluster);
			startTime = dropServiceNode(project, clusterlizeName, endpoint);
			unregisteredServices[project][clusterlizeName][endpoint] = startTime;
			serviceNames.push_back(clusterlizeName);
		}
	}

	if (_realtimeNotify)
	{
		instantSyncToPeers(unregisteredServices);
		instantSyncToExternalPeers(unregisteredServices);
		instantNotifySubscriber(project, serviceNames);
	}
	
	return FPAWriter::emptyAnswer(quest);
}

void FPZKQuestProcessor::buildInternalSyncedServiceInfos(const FPReaderPtr args,
	std::map<std::string, std::map<std::string, ServiceInfos>>& synced,
	std::map<std::string, std::map<std::string, MachineNode>>& machineInfos)
{
	std::vector<std::string> fields;
	std::map<std::string, std::map<std::string, std::vector<std::vector<unsigned long long>>>> GPUInfos;
	std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>> updateNodes;

	fields = args->want("fields", fields);
	updateNodes = args->want("updateNodes", updateNodes);
	GPUInfos = args->get("GPUInfo", GPUInfos);

	for (auto& projectPP: updateNodes)
	{
		if (projectPP.first.empty())
		{
			LOG_ERROR("[internalSyncServiceInfos] Got invalid info: empty project!");
			continue;
		}

		for (auto& servicePP: projectPP.second)
		{
			if (servicePP.first.empty())
			{
				LOG_ERROR("[internalSyncServiceInfos] Got invalid info: empty serivce! Project: %s", projectPP.first.c_str());
				continue;
			}

			for (auto& row: servicePP.second)
			{
				ServiceNode sn;
				MachineNode mn;
				std::string endpoint;

				for (size_t i = 0; i < row.size(); i++)
				{
					if(fields[i] =="endpoint")
						endpoint = row[i];
					else if(fields[i] =="srvVersion")
						sn.version = row[i];

					else if(fields[i] =="startTime")
						sn.startTime = std::stoll(row[i]);
					else if(fields[i] =="registerTime")
						sn.registeredTime = std::stoll(row[i]);
					else if(fields[i] =="online")
						sn.online = (row[i] == "true"? true : false);

					else if(fields[i] =="tcpNum")
					{
						if (row[i].size() && row[i][0] != '-')
						{
							mn.tcpCount = std::stoi(row[i]);
							sn.usingMachineInfo = true;
						}
					}
					else if(fields[i] =="udpNum")
					{
						if (row[i].size() && row[i][0] != '-')
						{
							mn.udpCount = std::stoi(row[i]);
							sn.usingMachineInfo = true;
						}
					}
					else if(fields[i] =="loadAvg")
					{
						if (row[i].size() && row[i][0] != '-')
						{
							mn.loadAvg = std::stof(row[i]);
							sn.usingMachineInfo = true;
						}
					}
					else if(fields[i] =="cpuUsage")
					{
						if (row[i].size() && row[i][0] != '-')
						{
							mn.CPUUsage = std::stof(row[i]);
							sn.usingMachineInfo = true;
						}
					}
			
					else if(fields[i] =="domain")
						sn.domain = row[i];
					else if(fields[i] =="ipv4")
						sn.ipv4 = row[i];
					else if(fields[i] =="ipv6")
						sn.ipv6 = row[i];

					else if(fields[i] =="port")
						sn.port = std::stoi(row[i]);
					else if(fields[i] =="port6")
						sn.port6 = std::stoi(row[i]);

					else if(fields[i] =="sslport")
						sn.sslport = std::stoi(row[i]);
					else if(fields[i] =="sslport6")
						sn.sslport6 = std::stoi(row[i]);

					else if(fields[i] =="uport")
						sn.uport = std::stoi(row[i]);
					else if(fields[i] =="uport6")
						sn.uport6 = std::stoi(row[i]);

					else if(fields[i] =="gpu")
					{
						if (row[i].size())
						{
							sn.usingGPUInfo = true;
							sn.usingMachineInfo = true;
						}
					}
					else if(fields[i] =="extra")
					{
						sn.extra.reset(new std::string());
						sn.extra->swap(row[i]);
					}
				}
				sn.activedTime = slack_real_sec();

				if (endpoint.empty())
				{
					LOG_ERROR("[internalSyncServiceInfos] Got invalid info: empty endpoint! Project: %s, service: %s",
						projectPP.first.c_str(), servicePP.first.c_str());
					continue;
				}

				synced[projectPP.first][servicePP.first].nodeMap[endpoint] = sn;

				//-- Process Machine & GPU info
				if (sn.usingMachineInfo)
				{
					int port;
					std::string host;
					if (parseAddress(endpoint, host, port) == false)
					{
						// sn.ipv4 is public IP.
						LOG_ERROR("[internalSyncServiceInfos] Parse host from endpoint for machine data failed! Project: %s, service: %s, endpoint: %s",
							projectPP.first.c_str(), servicePP.first.c_str(), endpoint.c_str());

						continue;
					}
					
					mn.activedTime = sn.activedTime;

					if (sn.usingGPUInfo)
					{
						std::vector<std::vector<unsigned long long>>& GPUCardInfos = GPUInfos[projectPP.first][host];
						GPUInfoPtr info(new std::list<MachineStatus::GPUCardInfo>());

						for (auto& cardData: GPUCardInfos)
						{
							MachineStatus::GPUCardInfo cardInfo;

							if (cardData.size() > 0)
								cardInfo.index = (unsigned int)cardData[0];

							if (cardData.size() > 1)
								cardInfo.usage = (unsigned int)cardData[1];
							
							if (cardData.size() > 2)
								cardInfo.memory.usage = (unsigned int)cardData[2];

							if (cardData.size() > 3)
								cardInfo.memory.used = cardData[3];

							if (cardData.size() > 4)
								cardInfo.memory.total = cardData[4];

							info->push_back(cardInfo);
						}

						if (info->size() > 0)
							mn.gpuInfo = info;
					}

					machineInfos[projectPP.first][host] = mn;
				}
			}
		}
	}
}

FPAnswerPtr FPZKQuestProcessor::internalSyncServiceInfos(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
{
	std::map<std::string, std::map<std::string, ServiceInfos>> synced;
	std::map<std::string, std::map<std::string, MachineNode>> machineInfos;
	buildInternalSyncedServiceInfos(args, synced, machineInfos);

	std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>> unregistered;
	unregistered = args->want("unregistered", unregistered);

	std::map<std::string, std::vector<std::string>> alteredServices;

	//-- update _servicesMap, _changedServices, _machineStatus, _updatedServicesMap, _updatedMachineStatus, _unregisteredServices
	{
		std::lock_guard<std::mutex> lck(_mutex);

		//-- update _servicesMap, _changedServices
		for (auto& ppr: synced)
		{
			if (_tokenMap.find(ppr.first) != _tokenMap.end())
			{
				for (auto& spr: ppr.second)
				{
					ServiceInfos &si = _servicesMap[ppr.first][spr.first];
					
					int64_t oldRev = si.revision;
					si.updateServiceNodes(synced[ppr.first][spr.first].nodeMap);
					if (oldRev != si.revision)
					{
						_changedServices[ppr.first].insert(spr.first);
						alteredServices[ppr.first].push_back(spr.first);
					}
				}
			}
			else
			{
				LOG_ERROR("[internalSyncServiceInfos][Project invalid] Got invalid project: %s for service infos", ppr.first.c_str());
			}
		}

		//-- update _machineStatus, _updatedMachineStatus
		for (auto& ppr: machineInfos)
		{
			if (_tokenMap.find(ppr.first) != _tokenMap.end())
			{
				for (auto& mpr: ppr.second)
				{
					_machineStatus[ppr.first][mpr.first] = mpr.second;
					_updatedMachineStatus[ppr.first][mpr.first] = mpr.second;
				}
			}
			else
			{
				LOG_ERROR("[internalSyncServiceInfos][Project invalid] Got invalid project: %s for machine infos", ppr.first.c_str());
			}
		}

		//-- unregistered
		for (auto& ppr: unregistered)
		{
			const std::string& project = ppr.first;
			auto projIt = _servicesMap.find(project);
			if (projIt == _servicesMap.end())
				continue;

			for (auto& spr: ppr.second)
			{
				const std::string& serviceName = spr.first;
				auto srvIt = projIt->second.find(serviceName);
				if (srvIt == projIt->second.end())
					continue;

				for (auto& epr: spr.second)
				{	
					if (srvIt->second.nodeMap.find(epr.first) == srvIt->second.nodeMap.end())
						continue;

					if (srvIt->second.nodeMap[epr.first].startTime <= epr.second)
					{
						srvIt->second.nodeMap.erase(epr.first);
						_updatedServicesMap[project][serviceName].nodeMap.erase(epr.first);
					}
				}

				//-- clean & update _servicesMap
				if (srvIt->second.nodeMap.empty())
				{
					projIt->second.erase(serviceName);
					if (projIt->second.empty())
						_servicesMap.erase(projIt);
				}
				else
				{
					srvIt->second.revision += 1;
					srvIt->second.clusterAlteredTime = slack_real_msec();
				}

				//-- clean _updatedServicesMap
				if (_updatedServicesMap[project][serviceName].nodeMap.empty())
				{
					_updatedServicesMap[project].erase(serviceName);
					if (_updatedServicesMap[project].empty())
						_updatedServicesMap.erase(project);
				}

				_changedServices[project].insert(serviceName);
				alteredServices[project].push_back(serviceName);
			}
		}
	}

	if (_realtimeNotify && !alteredServices.empty())
	{
		for (auto& alterPair: alteredServices)
			instantNotifySubscriber(alterPair.first, alterPair.second);
	}

	return FPAWriter::emptyAnswer(quest);
}

std::string FPZKQuestProcessor::buildExternalServiceEndpoint(const ServiceNode& sn)
{
	int port = sn.port ? sn.port : sn.sslport;
	int port6 = sn.port6 ? sn.port6 : sn.sslport6;

	std::string endpoint;

	if (port && sn.ipv4.size())
	{
		endpoint = sn.ipv4;
		endpoint.append(":").append(std::to_string(port));
	}
	else if (port6 && sn.ipv6.size())
	{
		endpoint = "[";
		endpoint.append(sn.ipv6);
		endpoint.append("]:").append(std::to_string(port6));
	}
	else if (sn.domain.size())
	{
		if (port)
		{
			endpoint = sn.domain;
			endpoint.append(":").append(std::to_string(port));
		}
		else if (port6)
		{
			endpoint = sn.domain;
			endpoint.append(":").append(std::to_string(port));
		}
	}
	
	return endpoint;
}

void FPZKQuestProcessor::buildExternalSyncedServiceInfos(const FPReaderPtr args, std::map<std::string, std::map<std::string, ServiceInfos>>& synced)
{
	std::vector<std::string> fields;
	std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>> updateNodes;

	std::string region = args->wantString("region");
	fields = args->want("fields", fields);
	updateNodes = args->want("updateNodes", updateNodes);

	for (auto& projectPP: updateNodes)
	{
		if (projectPP.first.empty())
		{
			LOG_ERROR("[externalSyncServiceInfos] Got invalid info: empty project!");
			continue;
		}

		for (auto& servicePP: projectPP.second)
		{
			if (servicePP.first.empty())
			{
				LOG_ERROR("[externalSyncServiceInfos] Got invalid info: empty serivce! Project: %s", projectPP.first.c_str());
				continue;
			}

			for (auto& row: servicePP.second)
			{
				ServiceNode sn;
				std::string endpoint;

				for (size_t i = 0; i < row.size(); i++)
				{
					if(fields[i] =="endpoint")
						endpoint = row[i];
					else if(fields[i] =="srvVersion")
						sn.version = row[i];

					else if(fields[i] =="startTime")
						sn.startTime = std::stoll(row[i]);
					else if(fields[i] =="registerTime")
						sn.registeredTime = std::stoll(row[i]);
					else if(fields[i] =="online")
						sn.online = (row[i] == "true"? true : false);
			
					else if(fields[i] =="domain")
						sn.domain = row[i];
					else if(fields[i] =="ipv4")
						sn.ipv4 = row[i];
					else if(fields[i] =="ipv6")
						sn.ipv6 = row[i];

					else if(fields[i] =="port")
						sn.port = std::stoi(row[i]);
					else if(fields[i] =="port6")
						sn.port6 = std::stoi(row[i]);

					else if(fields[i] =="sslport")
						sn.sslport = std::stoi(row[i]);
					else if(fields[i] =="sslport6")
						sn.sslport6 = std::stoi(row[i]);

					else if(fields[i] =="uport")
						sn.uport = std::stoi(row[i]);
					else if(fields[i] =="uport6")
						sn.uport6 = std::stoi(row[i]);
				}
				sn.activedTime = slack_real_sec();

				if (endpoint.empty())
				{
					endpoint = buildExternalServiceEndpoint(sn);
					
					if (endpoint.empty())
					{
						LOG_ERROR("[externalSyncServiceInfos] Got invalid info: project: %s, service: %s, "
							"ipv4:%s, ipv6 %s, domain:%s, "
							"port:%d, port6:%d, ssl port:%d, ssl port6:%d",
							projectPP.first.c_str(), servicePP.first.c_str(),
							sn.ipv4.c_str(), sn.ipv6.c_str(), sn.domain.c_str(),
							sn.port, sn.port6, sn.sslport, sn.sslport6
							);
						continue;
					}
				}

				sn.region = region;
				synced[projectPP.first][servicePP.first].nodeMap[endpoint] = sn;
			}
		}
	}
}

void FPZKQuestProcessor::bypassExternalSyncInfos(const FPReaderPtr args)
{
	if (_peerServers.empty())
		return;

	FPQWriter qw(5, "externalSyncServiceInfos");
	qw.param("region", args->wantString("region"));
	qw.param("fields", args->want("fields", std::vector<std::string>()));
	qw.param("internal", true);

	{
		std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>> updateNodes;
		updateNodes = args->want("updateNodes", updateNodes);
		qw.param("updateNodes", updateNodes);
	}

	{
		std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>> unregistered;
		unregistered = args->want("unregistered", unregistered);
		qw.param("unregistered", unregistered);
	}

	FPQuestPtr quest = qw.take();
	bool status = _peerServers.sendQuest(quest, [](FPAnswerPtr answer, int errorCode){
		if (errorCode != FPNN_EC_OK)
			LOG_ERROR("exception occurred when sync external instant status to internal peers. No all peer received. ErrorCode: %d", errorCode);
	});
	if (!status)
		LOG_ERROR("Failed to sync external instant status to internal peers.");
}

FPAnswerPtr FPZKQuestProcessor::externalSyncServiceInfos(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
{
	if (args->getBool("internal", false) == false)
		bypassExternalSyncInfos(args);

	std::map<std::string, std::map<std::string, ServiceInfos>> synced;
	buildExternalSyncedServiceInfos(args, synced);

	std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>> unregistered;
	unregistered = args->want("unregistered", unregistered);
	std::string region = args->wantString("region");

	std::map<std::string, std::vector<std::string>> alteredServices;

	//-- update _servicesMap, _changedServices
	{
		std::lock_guard<std::mutex> lck(_mutex);

		//-- update _servicesMap, _changedServices
		for (auto& ppr: synced)
		{
			if (_tokenMap.find(ppr.first) != _tokenMap.end())
			{
				for (auto& spr: ppr.second)
				{
					ServiceInfos &si = _servicesMap[ppr.first][spr.first];
					
					int64_t oldRev = si.revision;
					si.updateServiceNodes(synced[ppr.first][spr.first].nodeMap);
					if (oldRev != si.revision)
					{
						_changedServices[ppr.first].insert(spr.first);
						alteredServices[ppr.first].push_back(spr.first);
					}
				}
			}
			else
			{
				LOG_ERROR("[externalSyncServiceInfos][Project invalid] Got invalid project: %s", ppr.first.c_str());
			}
		}

		//-- unregistered
		for (auto& ppr: unregistered)
		{
			const std::string& project = ppr.first;
			auto projIt = _servicesMap.find(project);
			if (projIt == _servicesMap.end())
				continue;

			for (auto& spr: ppr.second)
			{
				const std::string& serviceName = spr.first;
				auto srvIt = projIt->second.find(serviceName);
				if (srvIt == projIt->second.end())
					continue;

				for (auto& epr: spr.second)
				{	
					if (srvIt->second.nodeMap.find(epr.first) == srvIt->second.nodeMap.end())
						continue;

					if (srvIt->second.nodeMap[epr.first].startTime <= epr.second)
						srvIt->second.nodeMap.erase(epr.first);
				}

				//-- clean & update _servicesMap
				if (srvIt->second.nodeMap.empty())
				{
					projIt->second.erase(serviceName);
					if (projIt->second.empty())
						_servicesMap.erase(projIt);
				}
				else
				{
					srvIt->second.revision += 1;
					srvIt->second.clusterAlteredTime = slack_real_msec();
				}

				_changedServices[project].insert(serviceName);
				alteredServices[project].push_back(serviceName);
			}
		}
	}

	if (_realtimeNotify && !alteredServices.empty())
	{
		for (auto& alterPair: alteredServices)
			instantNotifySubscriber(alterPair.first, alterPair.second);
	}

	return FPAWriter::emptyAnswer(quest);
}

void FPZKQuestProcessor::cleanQuestSender(uint64_t clientId)
{
	std::list<std::string> emptyProjects;
	for (auto& projpair: _clientNotifiers)
	{
		std::list<std::string> emptyServices;

		for (auto& notifierPair: projpair.second)
		{
			notifierPair.second.erase(clientId);
			if (notifierPair.second.empty())
				emptyServices.push_back(notifierPair.first);
		}

		for (auto& service: emptyServices)
			projpair.second.erase(service);

		if (projpair.second.empty())
			emptyProjects.push_back(projpair.first);
	}

	for (auto& project: emptyProjects)
		_clientNotifiers.erase(project);
}

void FPZKQuestProcessor::cleanConnection(uint64_t clientId, std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices)
{
	auto it = _connectionMap.find(clientId);
	if (it == _connectionMap.end())
		return;

	std::vector<std::string> info;
	info.swap(it->second);

	_connectionMap.erase(clientId);

	std::vector<std::string> names{info[1]};
	if (info[3].length())
		names.push_back(clusteredServiceName(info[1], info[3]));

	//-- check _servicesMap, _changedServices, _updatedServicesMap, _unregisteredServices
	auto pit = _servicesMap.find(info[0]);
	if (pit == _servicesMap.end()) return;

	for (auto& name: names)
	{
		auto sit = pit->second.find(name);
		if (sit == pit->second.end()) continue;

		auto nit = sit->second.nodeMap.find(info[2]);
		if (nit == sit->second.nodeMap.end()) continue;

		if (nit->second.clientId == clientId)
		{
			int64_t startTime = dropServiceNode(info[0], name, info[2]);
			unregisteredServices[info[0]][name][info[2]] = startTime;
		}
	}
}

void FPZKQuestProcessor::cleanConnectionAndNotifier(const ConnectionInfo& ci)
{
	uint64_t id = clientId(ci);

	std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>> unregisteredServices;
	{
		std::lock_guard<std::mutex> lck(_mutex);
		cleanQuestSender(id);
		cleanConnection(id, unregisteredServices);
	}

	if (_realtimeNotify && !unregisteredServices.empty() && _running)
	{
		instantSyncToPeers(unregisteredServices);
		instantSyncToExternalPeers(unregisteredServices);

		for (auto& projPair: unregisteredServices)
		{
			std::vector<std::string> serviceNames;
			for (auto& srvPair: projPair.second)
				serviceNames.push_back(srvPair.first);

			instantNotifySubscriber(projPair.first, serviceNames);
		}
	}
}

std::string FPZKQuestProcessor::infos()
{
	Json json;
	json["version"] = "3.1.0";
	Json& projectNode = json["projects"];
	Json& statusNode = json["status"];
	projectNode.setArray();
	statusNode.setDict();

	{
		std::lock_guard<std::mutex> lck(_mutex);
		for (auto& ppr: _tokenMap)
			projectNode.push(ppr.first);

		for (auto& ppr: _servicesMap)
		{
			JsonPtr prjNode = statusNode.addDict(ppr.first, "/");  //-- avoid '.' in project name.
			for(auto& spr: ppr.second)
			{
				JsonPtr srvNode = prjNode->addDict(spr.first, "/");  //-- avoid '.' in service name.
				srvNode->add("revision", spr.second.revision);
				srvNode->add("alteredTime", spr.second.clusterAlteredTime);
				JsonPtr cluster = srvNode->addDict("cluster");

				for (auto& epr: spr.second.nodeMap)
				{
					JsonPtr node = cluster->addDict(epr.first, "/");	//-- '.' will appear in ip address.
					node->add("online", epr.second.online);
					node->add("version", epr.second.version);
					node->add("region", epr.second.region);

					node->add("registeredTime", epr.second.registeredTime);
					node->add("startTime", epr.second.startTime);

					if (epr.second.usingMachineInfo)
					{
						auto projectIt = _machineStatus.find(ppr.first);
						if (projectIt != _machineStatus.end())
						{
							std::string host;
							int port;
							if (parseAddress(epr.first, host, port))
							{
								auto machintIt = projectIt->second.find(host);
								if (machintIt != projectIt->second.end())
								{
									node->add("tcpCount", machintIt->second.tcpCount);
									node->add("udpCount", machintIt->second.udpCount);
									node->add("load", machintIt->second.loadAvg);

									if (epr.second.usingGPUInfo && machintIt->second.gpuInfo)
									{
										JsonPtr gpuNode = node->addArray("GPU");
										for (auto& cardInfo: *(machintIt->second.gpuInfo))
										{
											JsonPtr cardNode = gpuNode->pushDict();
											cardNode->add("index", cardInfo.index);
											cardNode->add("gpu(%)", cardInfo.usage);
											cardNode->add("memory(%)", cardInfo.memory.usage);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return json.str();
}
