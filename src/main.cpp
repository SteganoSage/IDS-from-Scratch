#include <iostream>
#include<pcap.h>



int main(int argc, char* argv[]){

	char errbuff[PCAP_ERRBUF_SIZE];
	const char* device = nullptr;

	if(argc > 1) device = argv[1];
	else device = pcap_lookupdev(errbuff);

	if(!device){
		std::cerr << "pcap_lookupdev failed :" << errbuff << std :: endl;
		return 1;
	}

	std::cout << "[+] Using Device : "<< device << std::endl;

	pcap_t* handle = pcap_open_live(device,65535,1,1000,errbuff);

	if(!handle){
		std::cerr << "pcap_open_live failed"<< errbuff << std::endl;
		return 1;
	}

	std::cout << "[+] Opened handle \n";
	pcap_close(handle);
	return 0;

}
