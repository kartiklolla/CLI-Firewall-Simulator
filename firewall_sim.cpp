// cli_firewall_sim.cpp
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <regex>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
using namespace std;

struct Rule {
    bool allow;               // true will allow, false will deny the ip packet
    std::string ipPattern;    // IP or CIDR (e.g., 192.168.1.0/24 or IPv6)
    std::string port;         // port number or "any"
};

std::vector<Rule> rules;

void add_rule(const std::string& action, const std::string& ip, const std::string& port) {
    rules.push_back({action == "allow", ip, port});
    cout << "Rule added.\n";
}

void delete_rule(size_t index) {
    if (index < rules.size()) {
        rules.erase(rules.begin() + index);
        cout << "Rule deleted.\n";
    } else {
        cout << "Invalid index.\n";
    }
}

void list_rules() {
    for (size_t i = 0; i < rules.size(); ++i) {
        cout << "[" << i << "] " << (rules[i].allow ? "allow" : "deny")
             << " " << rules[i].ipPattern << " " << rules[i].port << "\n";
    }
}

bool ip_in_cidr(const std::string& ip, const std::string& cidr) {
    size_t slash = cidr.find('/');
    std::string base = cidr;
    int prefix_len = -1;

    if (slash != std::string::npos) {
        base = cidr.substr(0, slash);
        prefix_len = std::stoi(cidr.substr(slash + 1));
    }

    struct in6_addr addr_ip, addr_base;
    if (inet_pton(AF_INET6, ip.c_str(), &addr_ip) == 1 && inet_pton(AF_INET6, base.c_str(), &addr_base) == 1) {
        if (prefix_len < 0) return memcmp(&addr_ip, &addr_base, sizeof(in6_addr)) == 0;

        for (int i = 0; i < 16; ++i) {
            int bits = (prefix_len > 8) ? 8 : prefix_len;
            if (bits == 0) break;

            uint8_t mask = (uint8_t)(0xFF << (8 - bits));
            if ((addr_ip.s6_addr[i] & mask) != (addr_base.s6_addr[i] & mask)) {
                return false;
            }
            prefix_len -= bits;
        }
        return true;
    }

    struct in_addr ipv4_ip, ipv4_base;
    if (inet_pton(AF_INET, ip.c_str(), &ipv4_ip) == 1 && inet_pton(AF_INET, base.c_str(), &ipv4_base) == 1) {
        if (prefix_len < 0) return ipv4_ip.s_addr == ipv4_base.s_addr;
        uint32_t mask = htonl(0xFFFFFFFF << (32 - prefix_len));
        return (ipv4_ip.s_addr & mask) == (ipv4_base.s_addr & mask);
    }

    return false;
}

bool match(const Rule& rule, const std::string& ip, const std::string& port) {
    bool ip_match = ip_in_cidr(ip, rule.ipPattern);
    bool port_match = (rule.port == "any" || rule.port == port);
    return ip_match && port_match;
}

void simulate_packet(const std::string& ip, const std::string& port) {
    for (size_t i = 0; i < rules.size(); ++i) {
        if (match(rules[i], ip, port)) {
            cout << (rules[i].allow ? "Allowed" : "Blocked")
                      << " (matched rule " << i << ")\n";
            return;
        }
    }
    cout << "Default action: Blocked (no match)\n";
}

void save_rules(const std::string& filename = "firewall.rules") {
    std::ofstream file(filename);
    for (const auto& rule : rules) {
        file << (rule.allow ? "allow" : "deny") << " "
             << rule.ipPattern << " "
             << rule.port << "\n";
    }
}

void load_rules(const std::string& filename = "firewall.rules") {
    std::ifstream file(filename);
    std::string action, ip, port;
    while (file >> action >> ip >> port) {
        rules.push_back({action == "allow", ip, port});
    }
}

int main() {
    load_rules(); // Load existing rules from file
    std::string cmd;
    std::cout << "CLI Firewall Rule Simulator\n";
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, cmd);
        std::istringstream iss(cmd);
        std::string action, arg1, arg2, arg3;
        iss >> action >> arg1 >> arg2 >> arg3;

        if (action == "add") {
            add_rule(arg1, arg2, arg3);
            save_rules();
        } else if (action == "delete") {
            delete_rule(stoi(arg1));
            save_rules();
        } else if (action == "list") {
            list_rules();
        } else if (action == "simulate") {
            simulate_packet(arg1, arg2);
        } else if (action == "exit") {
            break;
        } else {
            cout << "Unknown command.\n";
        }
    }
    return 0;
}
