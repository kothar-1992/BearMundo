#ifndef BEARMUNDO_SECURITY_STATE_ANALYZER_H
#define BEARMUNDO_SECURITY_STATE_ANALYZER_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <json/json.h>

class SecurityStateAnalyzer {
private:
    static SecurityStateAnalyzer* instance;
    static std::mutex instanceMutex;
    bool isAnalyzing;
    std::thread analyzerThread;
    std::mutex stateMutex;
    std::map<std::string, bool> securityState;
    std::vector<std::string> suspiciousPatterns;
    std::vector<std::string> protectedRegions;
    int seccompFilter;

    SecurityStateAnalyzer();
    void initializePatterns();
    void setupSeccompFilter();
    void analyzeMemoryRegions();
    void checkForHooks();
    void checkForDebuggers();
    void checkForEmulators();
    void checkForRoot();
    void analyzeSecurityState();

public:
    static SecurityStateAnalyzer* getInstance();
    void startAnalysis();
    void stopAnalysis();
    Json::Value getSecurityState();
    ~SecurityStateAnalyzer();
};

#endif // BEARMUNDO_SECURITY_STATE_ANALYZER_H 