#include "crow_all.h"
#include <string>

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/add")([](const crow::request& req) {
        int value = 10;
        if (auto num = req.url_params.get("num")) {
            // Potential vulnerability: directly converting user input
            value += std::stoi(num);  
        }
        return crow::response(std::to_string(value));
    });

    app.port(8080).multithreaded().run();
}
Give shell script to recognize the c++ equivalent vulnerability in python like this 
"











# RULE 86: Use of insecure file permissions (e.g., 0777)
        echo "$line" | grep -q -E '\bchmod\s*\(\s*.*0777\s*\)'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E '\bchmod\s*\(\s*.*0o777\s*\)'
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi
        # RULE 87: Use of insecure file permissions (e.g., 0755)
        echo "$line" | grep -q -E '\bchmod\s*\(\s*.*0755\s*\)'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E '\bchmod\s*\(\s*.*0o755\s*\)'
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi



            -inj_count=0;  # Injection
            -crypto_count=0; # Cryptografic Failures
            -sec_mis_count=0; # Security Misconfiguration
            -bac_count=0;  # Broken Access Control
            -id_auth_count=0; # Identification and Authentication Failures
            -sec_log_count=0; # Secuirty Logging and Monitoring Failures 
            -ins_des_count=0; # Insecure Design
            -ssrf_count=0; # SSRF
            -soft_data_count=0; # Software and Data Integrity Failures