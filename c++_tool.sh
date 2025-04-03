start=$(date +%s.%N)

input=$1

#tool for DETECTION of OWASP top 10 categories

#DET file intro
echo -e "==================>      SNIPPETS DETECTED      <========================" > $2  
echo -e "|                                                                       |" >> $2
echo -e "|           (!) VULN CODE : Vulnerable code snippets detected           |" >> $2
echo -e "|           ==> SAFE CODE : Safe code snippet                           |" >> $2
echo -e "|                                                                       |" >> $2
echo -e "|                 [XXX s] : Execution Time per snippet                  |" >> $2
echo -e "|                                                                       |" >> $2
echo -e "=========================================================================\n" >> $2



countvuln=0; 
dimtestset=0;
contNoMod=0;
contMod=0;

name_os=$(uname) #OS-system

# VARIABLES FOR OWASP MAPPING - GLOBAL COUNTERS
inj_count=0;  # Injection
crypto_count=0; # Cryptografic Failures
sec_mis_count=0; # Security Misconfiguration
bac_count=0;  # Broken Access Control
id_auth_count=0; # Identification and Authentication Failures
sec_log_count=0; # Secuirty Logging and Monitoring Failures 
ins_des_count=0; # Insecure Design
ssrf_count=0; # SSRF
soft_data_count=0; # Software and Data Integrity Failures

while IFS= read -r line; do

    #initial timestamp all rules for snippet
    start_snippet=$(date +%s.%N)

    if [ ! -z "$line" ]; then
        num_occ=0;
        pass=0;
        var=
        vuln=

        # VARIABLES FOR OWASP MAPPING  
        inj=0;  # Injection
        crypto=0; # Cryptografic Failures
        sec_mis=0; # Security Misconfiguration
        bac=0;  # Broken Access Control
        id_auth=0; # Identification and Authentication Failures
        sec_log=0; # Secuirty Logging and Monitoring Failures 
        ins_des=0; # Insecure Design
        ssrf=0; # SSRF
        soft_data=0; # Software and Data Integrity Failures
        cpp_found=0; # Initialize a flag to ensure we tag the vulnerability only once.

        #RULE 1: if exists a the following pattern: = (..+request.args.get())
        echo $line | grep -E -q "\+request.args.get\(|\+ request.args.get\("
        if [ $? -eq 0 ]; then 
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi"import yaml\n\n\ndef yaml_load(filename):\n    '''\n    Use the filename variable to open a file, \n    load its contents into a variable with yaml, and return it.\n    '''\n    with open(filename, 'r') as f:\n        data = yaml.load(f, Loader=yaml.BaseLoader)\n        return data"
        fi

        #RULE 1: Check if the line contains req.url_params.get(" which retrieves the query parameter
        echo "$line" | grep -E -q 'req\.url_params\.get\("'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -q "\+?(std::stoi|stoi)("
                if [ $? -eq 0 ]; then
                    if [ $inj -eq 0 ]; then
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                fi
        fi

        #RULE 2: if exists a the following pattern: = (..+request.args[])
        echo "$line" | grep -q "(.*+request.args\["
        if [ $? -eq 0 ]; then
            # Exclude lines that contain safe patterns (for example, conditional checks)
            echo "$line" | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
            if [ $? -eq 0 ]; then
                # Mark as a vulnerability if not already flagged
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        #RULE 2: std::stoi( ... query_map.get(
        echo "$line" | grep -E -q 'std::stoi\(.*query_map\.get\('
        if [ $? -eq 0 ]; then
            # Exclude lines that match specific unwanted patterns
            echo "$line" | grep -E -v -q 'if\s*\(.*std::regex_match\(|if\s+obj_match\(|if\s+std::filesystem::exists\(|args\.send_static_file\('
            if [ $? -eq 0 ]; then
                if [ $cpp_found -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1 
                fi
            fi
        fi

        #RULE 3: if exists a the following pattern: = (request.POST.get())
        echo "$line" | grep -q "(request.POST.get(.*%"
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        #RULE 3: Check for unsafe use of user input in format strings (C++)
        echo "$line" | grep -q -E '\b(sprintf|printf|fprintf|snprintf|syslog)\s*\(.*((".*%[^"]*".*,(.*(getenv|cgiParam|POST_DATA))|(getenv|cgiParam|POST_DATA).*\)))'
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi


        # RULE 4: Detect unsafe C++ network/command operations
        # Check for libcurl, system(), and SQL patterns
        echo "$line" | grep -q -E '\b(curl_easy_setopt|system|sqlite3_exec|fprintf|snprintf)\b'
        if [ $? -eq 0 ]; then
            #Extract variables from vulnerable functions
            var=$(echo "$line" | awk -F 'CURLOPT_URL,' '{print $2}' | awk -F '[ ,);]' '{print $1}')
            if [ -z "$var" ]; then
                var=$(echo "$line" | awk -F 'system(' '{print $2}' | awk -F '[);]' '{print $1}' | tr -d '"')
            fi
            if [ -z "$var" ]; then
                var=$(echo "$line" | awk -F 'sqlite3_exec.*' '{print $2}' | awk -F '[ ,]' '{print $1}')
            fi

            if [ -n "$var" ]; then
                # Check for unsafe variable usage patterns
                echo "$line" | grep -q -E "\b$var\b.*(\+|%|\"|')"
                concat_unsafe=$?
                echo "$line" | grep -q -E "(sanitize|validate|escape|whitelist).*\b$var\b"
                sanitized=$?

                # Check for mitigations
                if [ $concat_unsafe -eq 0 ] && [ $sanitized -ne 0 ]; then
                    # SSRF/Command Injection check
                    echo "$line" | grep -q -E '(CURLOPT_URL|system|sqlite3_exec)'
                    if [ $? -eq 0 ]; then
                        if [ $ssrf -eq 0 ]; then
                            vuln="$vuln, SSRF/Command Injection"
                            let ssrf=ssrf+1
                        fi
                    fi

                # Authentication failure check
                    echo "$line" | grep -q -E '(Authorization|Bearer|Token).*\b$var\b'
                    if [ $? -eq 0 ]; then
                        if [ $auth_fail -eq 0 ]; then
                            vuln="$vuln, Authentication Failures"
                            let auth_fail=auth_fail+1
                        fi
                    fi
                fi
            fi
        fi

        # RULE 5: Detect unsafe returns of network operations/user input (C++)
        #RULE 5: if exists a the following pattern: return requests.get(...)
        echo "$line" | grep -q -E '\breturn\b.*\b(curl_easy_perform|system|sqlite3_exec|fprintf|std::cout)\b'
        if [ $? -eq 0 ]; then
            # Extract the returned variable/expression
            var=$(echo "$line" | awk -F 'return ' '{print $2}' | awk -F '[ ;()+]' '{print $1}')
            
            # Check for mitigations
            echo "$line" | grep -E -q -i "sanitize\($var|validate\($var|escape\($var"
            sanitized=$?
            
            # Check context of variable usage
            echo "$line" | grep -q -E "(CURLOPT_URL|Authorization|SELECT|system).*\b$var\b"
            unsafe_usage=$?
            
            if [ $sanitized -ne 0 ] && [ $unsafe_usage -eq 0 ]; then
                # SSRF check
                echo "$line" | grep -q "CURLOPT_URL"
                if [ $? -eq 0 ] && [ $ssrf -eq 0 ]; then
                    vuln="$vuln, SSRF"
                    let ssrf=ssrf+1
                fi
                
                # Authentication failure check
                echo "$line" | grep -q -E "(Authorization|Token|Bearer).*\b$var\b"
                if [ $? -eq 0 ] && [ $auth_fail -eq 0 ]; then
                    vuln="$vuln, Identification and Authentication Failures"
                    let auth_fail=auth_fail+1
                fi
            fi
        fi

    fi
done < "$input"
