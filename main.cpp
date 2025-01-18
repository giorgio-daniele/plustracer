#include <iostream>
#include <fstream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <netdb.h>
#include <chrono>
#include <iomanip>
#include <sstream>

// Declare file stream globally
std::ofstream traceFile;

// Function to resolve IP to hostname
std::string resolveIPToHost(const struct in_addr &ipAddr) {
    struct hostent *host = gethostbyaddr(&ipAddr, sizeof(ipAddr), AF_INET);
    if (host != nullptr) {
        return host->h_name;  // Return the resolved hostname
    }
    return inet_ntoa(ipAddr);  // Return the IP if resolution fails
}

// Utility function to display TCP flags
std::string getTcpFlags(const struct tcphdr *tcpHeader) {
    std::string flags;
    if (tcpHeader->th_flags & TH_FIN)  flags += "FIN ";
    if (tcpHeader->th_flags & TH_SYN)  flags += "SYN ";
    if (tcpHeader->th_flags & TH_RST)  flags += "RST ";
    if (tcpHeader->th_flags & TH_PUSH) flags += "PSH ";
    if (tcpHeader->th_flags & TH_ACK)  flags += "ACK ";
    if (tcpHeader->th_flags & TH_URG)  flags += "URG ";
    return flags.empty() ? "NONE" : flags;
}

// Utility function to parse and print TCP packet details
void handleTCP(const unsigned char *packet, const struct ip *ipHeader) {
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + (ipHeader->ip_hl << 2));
    unsigned short srcPort   = ntohs(tcpHeader->th_sport);
    unsigned short destPort  = ntohs(tcpHeader->th_dport);
    unsigned int seqNum      = ntohl(tcpHeader->th_seq);
    unsigned int ackNum      = ntohl(tcpHeader->th_ack);

    std::string flags = getTcpFlags(tcpHeader);

    std::string srcIP = resolveIPToHost(ipHeader->ip_src);
    std::string dstIP = resolveIPToHost(ipHeader->ip_dst);

    traceFile << "tcp - srcip: " << inet_ntoa(ipHeader->ip_src) << " [" << srcIP << "]"
              << ", sport: "  << srcPort
              << ", dstip: "  << inet_ntoa(ipHeader->ip_dst) << " [" << dstIP << "]"
              << ", dport: "  << destPort
              << ", seq: "    << seqNum
              << ", ack: "    << ackNum
              << ", flags: "  << flags << std::endl;
}

// Utility function to parse and print UDP packet details
void handleUDP(const unsigned char *packet, const struct ip *ipHeader) {
    struct udphdr *udpHeader = (struct udphdr *)(packet + 14 + (ipHeader->ip_hl << 2));
    unsigned short srcPort  = ntohs(udpHeader->uh_sport);
    unsigned short destPort = ntohs(udpHeader->uh_dport);

    std::string srcIP = resolveIPToHost(ipHeader->ip_src);
    std::string dstIP = resolveIPToHost(ipHeader->ip_dst);

    traceFile << "udp - srcip: " << inet_ntoa(ipHeader->ip_src) << " [" << srcIP << "]"
              << ", sport: "  << srcPort
              << ", dstip: "  << inet_ntoa(ipHeader->ip_dst) << " [" << dstIP << "]"
              << ", dport: "  << destPort << std::endl;
}

// Utility function to parse and print ICMP packet details
void handleICMP(const unsigned char *packet, const struct ip *ipHeader) {
    struct icmphdr *icmpHeader = (struct icmphdr *)(packet + 14 + (ipHeader->ip_hl << 2));
    unsigned char type = icmpHeader->type;
    unsigned char code = icmpHeader->code;

    std::string srcIP = resolveIPToHost(ipHeader->ip_src);
    std::string dstIP = resolveIPToHost(ipHeader->ip_dst);

    traceFile << "icmp - srcip: " << inet_ntoa(ipHeader->ip_src) << " [" << srcIP << "]"
              << ", dstip: " << inet_ntoa(ipHeader->ip_dst) << " [" << dstIP << "]"
              << ", type: "  << (int)type
              << ", code: "  << (int)code << std::endl;
}

// Callback function for packet processing
void packetHandler(unsigned char *userData, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Check for minimum packet size (Ethernet + IP header)
    if (pkthdr->len < 34) {
        return;
    }

    struct ip *ipHeader = (struct ip *)(packet + 14);  // Ethernet header is 14 bytes
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP:
            handleTCP(packet, ipHeader);
            break;
        case IPPROTO_UDP:
            handleUDP(packet, ipHeader);
            break;
        case IPPROTO_ICMP:
            handleICMP(packet, ipHeader);
            break;
        default:
            break;
    }
}

// Function to show usage information
void showUsage(const char* programName) {
    std::cerr << "\nError: Invalid usage\n";
    std::cerr << "------------------------------------------\n";
    std::cerr << "Usage: " << programName << " <interface> <buffer_size>\n";
    std::cerr << "------------------------------------------\n";
    std::cerr << "Example: " << programName << " eth0 1024\n";
    std::cerr << "\nPlease provide a valid network interface and buffer size.\n";
}

// Function to get the current date and time as a string
std::string getCurrentDatetime() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S");
    return oss.str();
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        showUsage(argv[0]);
        return -1;
    }

    const char *interface = argv[1];
    int bufferSize = atoi(argv[2]);

    if (bufferSize <= 0) {
        std::cerr << "\nError: Invalid buffer size\n";
        std::cerr << "------------------------------------------\n";
        std::cerr << "Buffer size must be a positive integer.\n";
        std::cerr << "Example: " << argv[0] << " eth0 1024\n";
        return -1;
    }

    // Generate the filename with the current datetime
    std::string filename = "trace_" + getCurrentDatetime() + ".trace";

    // Open the trace file for writing
    traceFile.open(filename, std::ios::out);
    if (!traceFile.is_open()) {
        std::cerr << "Error: Could not open trace file for writing." << std::endl;
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, bufferSize, 1, 2000, errbuf);

    if (!handle) {
        std::cerr << "\nError: Failed to open device: " << errbuf << "\n";
        std::cerr << "Please ensure the interface name is correct and try again.\n";
        traceFile.close();
        return -1;
    }

    std::cout << "Successfully capturing packets on interface: " << interface
              << " with buffer size: " << bufferSize << " bytes.\n";

    // Start capturing packets and call packetHandler for each captured packet
    if (pcap_loop(handle, 0, packetHandler, NULL) < 0) {
        std::cerr << "\nError during capture: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        traceFile.close();
        return -1;
    }

    // Close the trace file after packet capture is finished
    pcap_close(handle);
    traceFile.close();

    return 0;
}
