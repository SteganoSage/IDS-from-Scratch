#include <iostream>
#include<pcap.h>

extern "C" void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes){
	(void)user;

	std::cout << "Packet_len : "<< header->len << std :: endl << "Caplen : "<< header->caplen << std::endl<< "ts : " << header->ts.tv_sec << "." << header->ts.tv_usec << "\n";
}

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

	std::cout << "Capturing 5 packets\n";
	pcap_loop(handle,5,packet_handler,nullptr);
	
	pcap_close(handle);
	std::cout<<"Done\n";
	return 0;

}
