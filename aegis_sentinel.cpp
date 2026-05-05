#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <future>
#include <mutex>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

/**
 * AEGIS-SOC: ENTERPRISE SECURITY ORCHESTRATION ENGINE
 * This is the MASTER OOP FILE for the GitHub repository.
 * * Features:
 * 1. Abstraction: Virtual interfaces for security modules.
 * 2. Polymorphism: Dynamic loading of diagnostic probes.
 * 3. Templates: Static dispatch for AI risk calculations.
 * 4. Multi-threading: Parallel port discovery via std::async.
 */

mutex logMutex;

/**
 * Interface for all security audit modules.
 */
class ISecurityModule {
public:
    virtual float runAudit(const string& ip) = 0;
    virtual string getModuleName() const = 0;
    virtual ~ISecurityModule() {}
};

/**
 * Asynchronous Port Discovery Module.
 * Probes common service ports to identify the attack surface.
 */
class MultiPortScanner : public ISecurityModule {
public:
    float runAudit(const string& ip) override {
        int openPorts = 0;
        vector<int> targetPorts = {80, 443, 22, 8080, 3306};
        vector<future<bool>> probes;

        for (int port : targetPorts) {
            probes.push_back(async(launch::async, [this, ip, port]() {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) return false;

                // Set non-blocking for high-speed probing
                fcntl(sock, F_SETFL, O_NONBLOCK);

                struct sockaddr_in serv;
                serv.sin_family = AF_INET;
                serv.sin_port = htons(port);
                inet_pton(AF_INET, ip.c_str(), &serv.sin_addr);

                // Short-lived connection attempt
                connect(sock, (struct sockaddr*)&serv, sizeof(serv));
                
                fd_set set;
                struct timeval tv;
                FD_ZERO(&set);
                FD_SET(sock, &set);
                tv.tv_sec = 0;
                tv.tv_usec = 500000; // 0.5s timeout for OCI performance

                int res = select(sock + 1, NULL, &set, NULL, &tv);
                close(sock);
                return res > 0;
            }));
        }

        for (auto& p : probes) {
            if (p.get()) openPorts++;
        }

        return (float)openPorts;
    }

    string getModuleName() const override { return "Async-Port-Scanner-v2"; }
};

/**
 * Template-based Heuristic AI Engine.
 * Calculates risk levels based on discovered system metrics.
 */
template <typename T>
class AIAnalyticEngine {
public:
    static float calculateRisk(T metric, bool encryptionSecure) {
        float baseRisk = (metric * 1.5f);
        if (!encryptionSecure) baseRisk += 4.0f;
        
        // Normalize score to 0.0 - 10.0
        return (baseRisk > 10.0f) ? 10.0f : baseRisk;
    }
};

/**
 * The Central Orchestrator managing the lifecycle of the audit.
 */
class SecurityOrchestrator {
private:
    vector<shared_ptr<ISecurityModule>> activeModules;
    string targetIP;

public:
    SecurityOrchestrator(string ip) : targetIP(ip) {}

    void registerModule(shared_ptr<ISecurityModule> m) {
        activeModules.push_back(m);
    }

    void executeFullAudit() {
        float aggregatedMetric = 0.0f;
        
        for (auto& module : activeModules) {
            aggregatedMetric += module->runAudit(targetIP);
        }

        // Final Heuristic pass via Template AI
        float finalScore = AIAnalyticEngine<float>::calculateRisk(aggregatedMetric, true);
        
        // Output formatted specifically for the Python Flask bridge
        cout << finalScore << endl;
    }
};

int main(int argc, char* argv[]) {
    // Check for target IP passed from app.py
    if (argc < 2) {
        cerr << "Aegis-SOC: Error - Target IP Required." << endl;
        return 1;
    }

    string ip = argv[1];
    
    SecurityOrchestrator engine(ip);
    engine.registerModule(make_shared<MultiPortScanner>());
    
    // Start OOP-based lifecycle
    engine.executeFullAudit();

    return 0;
}
