#ifndef FPZK_Processor_h
#define FPZK_Processor_h

#include "Setting.h"
#include "MachineStatus.h"
#include "IQuestProcessor.h"
#include "TCPRandomProxy.hpp"
#include "TCPConsistencyProxy.hpp"

using namespace fpnn;

namespace FPZKError
{
	const int NoError = 0;
	const int ErrorBase = 30000;
	const int ProjectNotFound = ErrorBase + 301;
	const int ProjectTokenNotMatched = ErrorBase + 302;
	const int ServerWarmUp = ErrorBase + 400;
}

typedef std::shared_ptr<std::list<MachineStatus::GPUCardInfo>> GPUInfoPtr;
typedef std::shared_ptr<std::string> ExtraPtr;

class FPZKQuestProcessor: public IQuestProcessor
{
	struct MachineNode
	{
		int tcpCount;
		int udpCount;
		float loadAvg;
		float CPUUsage;
		int64_t activedTime;

		GPUInfoPtr gpuInfo;

		MachineNode(): tcpCount(-1), udpCount(-1), loadAvg(-1.), CPUUsage(-1.), activedTime(0) {}
	};

	struct ServiceNode
	{
		bool online;
		bool externalVisible;
		bool publishEndpoint;
		bool usingMachineInfo;
		bool usingGPUInfo;

		int64_t activedTime;
		int64_t registeredTime;
		std::string version;
		std::string region;

		int64_t startTime;
		uint64_t clientId;
		int port;
		int port6;
		int sslport;
		int sslport6;
		int uport;
		int uport6;
		std::string domain;
		std::string ipv4;
		std::string ipv6;
		ExtraPtr extra;

		ServiceNode(): online(true), externalVisible(false), publishEndpoint(false),
			usingMachineInfo(false), usingGPUInfo(false),
			activedTime(0), registeredTime(0), startTime(0), clientId(0),
			port(0), port6(0), sslport(0), sslport6(0), uport(0), uport6(0) {}
	};

	struct ServiceInfos
	{
		int64_t revision;
		int64_t clusterAlteredTime;		//-- in milliseconds
		std::map<std::string, ServiceNode> nodeMap;

		ServiceInfos(): revision(0), clusterAlteredTime(0) {}
		void updateServiceNode(const std::string& endpoint, ServiceNode& node);
		void updateServiceNodes(std::map<std::string, ServiceNode>& nodes);
	};

	struct ServiceInfoResult
	{
		static std::vector<std::string> fields;

		std::set<std::string> invalidServices;
		std::vector<std::string> services;
		std::vector<int64_t> revisions;
		std::vector<int64_t> clusterAlteredTimes;
		std::vector<std::vector<std::vector<std::string>>> nodes;
		std::map<std::string, std::map<std::string, std::vector<std::vector<unsigned long long>>>> gpuInfos;

		void reserve(size_t size)
		{
			services.reserve(size);
			revisions.reserve(size);
			clusterAlteredTimes.reserve(size);
			nodes.reserve(size);
		}
	};

	QuestProcessorClassPrivateFields(FPZKQuestProcessor)

	int _warmUpSecs;
	std::mutex _mutex;
	int64_t _startTime;
	int _nodeExpireSecs;
	bool _realtimeNotify;
	std::string _configFile;
	std::string _selfRegion;
	std::atomic<bool> _running;
	int _externalSyncBatchSize;
	TCPConsistencyProxy _peerServers;
	std::map<std::shared_ptr<std::string>, TCPRandomProxyPtr> _externalServers;
	std::set<std::string> _myIP4Address;
	std::set<std::string> _myIP6Address;
	std::map<std::string, std::string> _tokenMap;
	std::map<std::string, std::set<std::string>> _changedServices;				//-- for client notify. map<project, set<services>>
	std::map<std::string, std::map<std::string, ServiceInfos>> _servicesMap;	//-- map<project-name, map<service, ServiceInfos>>
	std::map<std::string, std::map<std::string, ServiceInfos>> _updatedServicesMap;		//-- map<project, map<services, ServiceInfos>>
	std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>> _unregisteredServices;		//-- map<project, map<services, map<endpoint, startTime>>>
	std::map<std::string, std::map<std::string, std::map<uint64_t, QuestSenderPtr>>> _clientNotifiers;		//-- map<project, map<serviceName, map<clientId, sender>>>
	std::thread _deamonThread;

	std::map<std::string, std::map<std::string, MachineNode>> _machineStatus;		//-- map<project, map<ip, MachineNode>>
	std::map<std::string, std::map<std::string, MachineNode>> _updatedMachineStatus;	//-- map<project, map<ip, MachineNode>>
	std::map<uint64_t, std::vector<std::string>> _connectionMap; //-- map<clientId, vector<project, service, endpoint, cluster>>

	uint64_t clientId(const ConnectionInfo& ci) { return ((uint64_t)ci.socket << 32) | ci.port; }
	std::string clusteredServiceName(const std::string& serviceName, const std::string& clusterName)
	{
		return std::string(serviceName).append("@").append(clusterName);
	}

	void initSelfIPs();
	bool updateProjects(const std::string& projects);
	bool checkEndpoint(const std::string& endpoint, int port4, int port6, const std::string& hintInfo, std::string& realEndpoint, bool& self);
	bool updateServerList(const std::string& serverList, const std::set<std::string>& selfRegionServers);
	std::map<std::string, std::set<std::string>> buildRegionServersMap(const Setting::MapType& map);
	bool checkRegionMap(const std::string& localServerList, std::map<std::string, std::set<std::string>>& regionMap);
	bool updateExternalServers(const std::map<std::string, std::set<std::string>>& regionMap);
	bool checkReloadConfig(time_t& lastModifyTime);
	void cleanExpiredNodes();
	void buildInternalSyncUpdateNodes(const std::map<std::string, std::map<std::string, ServiceInfos>>& updatedServicesMap,
		const std::map<std::string, std::map<std::string, MachineNode>>& updatedMachineStatus,
		std::map<std::string, std::map<std::string, std::vector<std::vector<std::string>>>>& updateNodes,
		std::map<std::string, std::map<std::string, std::list<std::list<unsigned long long>>>>& GPUInfos);
	void buildExternalSyncUpdateNodes(const std::map<std::string, std::map<std::string, ServiceInfos>>& updatedServicesMap,
		std::list<FPQuestPtr>& questList);
	void syncToInternalPeers(const std::map<std::string, std::map<std::string, ServiceInfos>>& updatedServicesMap,
		const std::map<std::string, std::map<std::string, MachineNode>>& updatedMachineStatus,
		const std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices);
	void syncToExternalPeers(const std::map<std::string, std::map<std::string, ServiceInfos>>& updatedServicesMap,
		const std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices);
	void syncToPeers();
	void instantSyncToPeers(const std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices);
	void instantSyncToPeers(const std::string& project, const std::vector<std::string>& serviceNames,
		const std::string& endpoint, ServiceNode& node, MachineNode& mn);
	void instantSyncToExternalPeers(const std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices);
	void instantSyncToExternalPeers(const std::string& project, const std::vector<std::string>& serviceNames,
		const std::string& endpoint, ServiceNode& node);
	void notifySubscriber();
	void instantNotifySubscriber(const std::string& project, const std::vector<std::string>& serviceNames);
	static void sendExternalSyncQuest(std::shared_ptr<std::string> region, TCPRandomProxyPtr proxy, FPQuestPtr quest, int timeout = 0, int retryCount = 3);
	void sendToExternalPeers(FPQuestPtr quest);
	void daemonFunc();
	void makeMachineInfoNode(const FPReaderPtr args, ServiceNode& node, MachineNode& mn);
	FPAnswerPtr checkProjectToken(const std::string& project, const FPReaderPtr args, const FPQuestPtr quest);
	void fetchServiceInfos(const std::string& project, const std::set<std::string>& serviceNames, struct ServiceInfoResult& result);
	int64_t dropServiceNode(const std::string& project, const std::string& service, const std::string& endpoint);
	void buildInternalSyncedServiceInfos(const FPReaderPtr args, std::map<std::string, std::map<std::string, ServiceInfos>>& synced,
		std::map<std::string, std::map<std::string, MachineNode>>& machineInfos);
	void buildExternalSyncedServiceInfos(const FPReaderPtr args, std::map<std::string, std::map<std::string, ServiceInfos>>& synced);
	void bypassExternalSyncInfos(const FPReaderPtr args);
	void cleanQuestSender(uint64_t clientId);
	void cleanConnection(uint64_t clientId, std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>& unregisteredServices);
	void cleanConnectionAndNotifier(const ConnectionInfo&);
	std::string buildExternalServiceEndpoint(const ServiceNode& sn);

public:
	FPAnswerPtr syncServerInfo(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci);
	FPAnswerPtr getServiceInfo(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci);
	FPAnswerPtr getServiceNames(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci);
	FPAnswerPtr subscribeServicesChange(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci);
	FPAnswerPtr unregisterService(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci);
	FPAnswerPtr internalSyncServiceInfos(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci);
	FPAnswerPtr externalSyncServiceInfos(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci);

	virtual std::string infos();
	virtual void connectionWillClose(const ConnectionInfo& ci, bool closeByError) { cleanConnectionAndNotifier(ci); }
	virtual void serverWillStop() { _running = false; }

	FPZKQuestProcessor(const char *configfile): _configFile(configfile), _peerServers(ConsistencySuccessCondition::AllQuestsSuccess)
	{
		initSelfIPs();

		_warmUpSecs = Setting::getInt("FPZK.server.warmup_second", 10);
		_nodeExpireSecs = Setting::getInt("FPZK.server.node_expire_second", 10);
		_realtimeNotify = Setting::getBool("FPZK.server.event_notify.realtime", true);
		_selfRegion = Setting::getString("FPZK.server.self_region", "");
		_externalSyncBatchSize = Setting::getInt("FPZK.server.sync.external.batch_size", 20);

		registerMethod("syncServerInfo", &FPZKQuestProcessor::syncServerInfo);
		registerMethod("getServiceInfo", &FPZKQuestProcessor::getServiceInfo);
		registerMethod("getServiceNames", &FPZKQuestProcessor::getServiceNames);
		registerMethod("subscribeServicesChange", &FPZKQuestProcessor::subscribeServicesChange);
		registerMethod("unregisterService", &FPZKQuestProcessor::unregisterService);
		registerMethod("internalSyncServiceInfos", &FPZKQuestProcessor::internalSyncServiceInfos);
		registerMethod("externalSyncServiceInfos", &FPZKQuestProcessor::externalSyncServiceInfos);

		_running = true;
		_startTime = slack_real_sec();
		_deamonThread = std::thread(&FPZKQuestProcessor::daemonFunc, this);
	}
	~FPZKQuestProcessor()
	{
		_running = false;
		_deamonThread.join();
	}

	QuestProcessorClassBasicPublicFuncs
};

#endif
