#include <iostream>
#include "TCPEpollServer.h"
#include "FPZKQuestProcessor.h"
#include "Setting.h"

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cout<<"Usage: "<<argv[0]<<" config"<<std::endl;
		return 0;
	}
	if(!Setting::load(argv[1])){
		std::cout<<"Config file error:"<< argv[1]<<std::endl;
		return 1;
	}

	ServerPtr server = TCPEpollServer::create();
	server->setQuestProcessor(std::make_shared<FPZKQuestProcessor>(argv[1]));
	if (server->startup())
		server->run();

	return 0;
}
