#include <pcap.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <winsock2.h>
#include <thread>
#include <chrono>
#include <exception> // For handling exceptions

// Global batch buffer
std::vector<std::string> batchBuffer;
const int BATCH_SIZE = 10; // Adjust batch size as needed

// Global variable to track the timestamp of the last packet
struct timeval lastTimestamp = {0, 0};

// Define a custom structure for the IP header
struct IPV4_HDR {
    unsigned char  ip_header_len : 4;
    unsigned char  ip_version : 4;
    unsigned char  ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char  ip_ttl;
    unsigned char  ip_protocol;
    unsigned short ip_checksum;
    unsigned int   ip_src_addr;
    unsigned int   ip_dest_addr;
};

// Function to send data to Python server
void sendBatchToPython() {
    if (batchBuffer.empty()) return;

    WSADATA wsaData;
    SOCKET clientSocket;
    sockaddr_in serverAddr;

    try {
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Python server IP
        serverAddr.sin_port = htons(8080); // Python server port

        if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
            // Serialize the batch as a single string
            std::ostringstream oss;
            for (const auto& packetData : batchBuffer) {
                oss << packetData << "\n"; // Separate packets by newline
            }

            // Send the batch
            std::string serializedBatch = oss.str();
            send(clientSocket, serializedBatch.c_str(), serializedBatch.length(), 0);
        }

        closesocket(clientSocket);
        WSACleanup();

        // Clear the batch buffer after sending
        batchBuffer.clear();
    } catch (const std::exception& e) {
        std::cerr << "Error sending data to Python server: " << e.what() << std::endl;
    }
}

// Function to calculate time interval between packets
double calculateTimeInterval(const struct timeval& current) {
    double interval = (current.tv_sec - lastTimestamp.tv_sec) +
                      (current.tv_usec - lastTimestamp.tv_usec) / 1e6;
    lastTimestamp = current; // Update the last timestamp
    return interval;
}

// Function to extract features from a packet
std::string extractFeatures(const struct pcap_pkthdr* header, const u_char* packet) {
    try {
        const struct IPV4_HDR* ipHeader = (struct IPV4_HDR*)(packet + 14); // Skip Ethernet header

        // Convert source and destination IP addresses to strings
        char srcIP[INET_ADDRSTRLEN];
        char dstIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src_addr), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dest_addr), dstIP, INET_ADDRSTRLEN);

        // Packet size
        size_t packetSize = header->len;

        // Protocol
        int protocol = ipHeader->ip_protocol;

        // Calculate time interval
        double timeInterval = calculateTimeInterval(header->ts);

        // Serialize features as CSV
        std::ostringstream oss;
        oss << packetSize << "," << protocol << "," << srcIP << "," << dstIP << "," << timeInterval;
        return oss.str();
    } catch (const std::exception& e) {
        std::cerr << "Error extracting features: " << e.what() << std::endl;
        return ""; // Return an empty string if an error occurs
    }
}

// Callback function for pcap loop
void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet) {
    try {
        // Extract features from the packet
        std::string features = extractFeatures(header, packet);

        if (!features.empty()) {
            // Add to batch buffer
            batchBuffer.push_back(features);

            // If batch size is reached, send it to the Python server
            if (batchBuffer.size() >= BATCH_SIZE) {
                sendBatchToPython();
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in packet handler: " << e.what() << std::endl;
    }
}

// Timer function to flush batch periodically
void flushBatchPeriodically(int intervalMs) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        sendBatchToPython(); // Flush the batch every interval
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    try {
        // Open the first network interface for packet capture
        handle = pcap_open_live("\\Device\\NPF_{EF0FEC95-CC2E-45C4-BBDD-213D4DABC9DF}", BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "Error opening device: " << errbuf << std::endl;
            return 1;
        }

        std::cout << "Capturing packets in batches..." << std::endl;

        // Start a background thread to flush the batch periodically
        std::thread batchFlusher(flushBatchPeriodically, 1000); // Flush every 1 second
        batchFlusher.detach();

        // Start the packet capture loop
        pcap_loop(handle, 0, packetHandler, NULL);

        pcap_close(handle);
    } catch (const std::exception& e) {
        std::cerr << "Error in main: " << e.what() << std::endl;
    }

    return 0;
}
