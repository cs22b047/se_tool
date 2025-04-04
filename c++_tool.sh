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

    # RULE 6_CPP: Detect unsafe handling of user input in C++ (cin, argv, getline) leading to Injection or Logging failures
        # Check for common C++ input methods: cin, getline, argv
        echo $line | grep -q -E "std::cin >>|getline\(|argv\[|scanf\("
        if [ $? -eq 0 ]; then
            # Extract the variable name (handles cin >> var, getline(cin, var), etc.)
            var=$(echo $line | sed -n -E 's/.*(std::cin >>|getline\(.*, *)([a-zA-Z_][a-zA-Z0-9_]*).*/\2/p')
            if [ -z "$var" ]; then
                # Fallback for argv cases
                var=$(echo $line | sed -n -E 's/.*argv\[[0-9]+\][^=]*=[^=]*([a-zA-Z_][a-zA-Z0-9_]*).*/\1/p')
            fi

            if [ -n "$var" ]; then
                # Check if the variable is used unsafely (similar to Python rule but C++-style)
                # FIRST CHECK: String concatenation or assignment (+=, =, etc.)
                echo $line | grep -q -E "\\+\\s*$var|=\\s*$var|\\+=\\s*$var|<<\\s*$var"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "std::regex_match|boost::regex_match|input_validation\("
                    if [ $? -eq 0 ]; then
                        echo $line | grep -E -v -q "escape\\(\\s*$var|sanitize\\(\\s*$var|htmlspecialchars\\(\\s*$var"
                        if [ $? -eq 0 ]; then
                            if [ $inj -eq 0 ]; then
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                            if [ $sec_log -eq 0 ]; then
                                vuln="$vuln, Security Logging and Monitoring Failures"
                                let sec_log=sec_log+1
                            fi
                        fi
                    fi
                else
                    # SECOND CHECK: Used in a function call (SQL, system(), etc.)
                    echo $line | grep -q -E "\\(.*$var.*\\)"
                    if [ $? -eq 0 ]; then
                        echo $line | grep -E -v -q "std::regex_match|boost::regex_match|input_validation\("
                        if [ $? -eq 0 ]; then
                            echo $line | grep -E -v -q "escape\\(\\s*$var|sanitize\\(\\s*$var|htmlspecialchars\\(\\s*$var"
                            if [ $? -eq 0 ]; then
                                if [ $inj -eq 0 ]; then
                                    vuln="$vuln, Injection"
                                    let inj=inj+1
                                fi
                                if [ $sec_log -eq 0 ]; then
                                    vuln="$vuln, Security Logging and Monitoring Failures"
                                    let sec_log=sec_log+1
                                fi
                            fi
                        fi
                    fi
                fi
            fi
        fi

        # RULE 7: Detect unsafe handling of user input in C++ (cin, getline, argv) leading to Injection or Logging failures
        # Check for common C++ input methods: std::cin, getline, argv, scanf
        echo $line | grep -q -E "std::cin >>|getline\(.*,|argv\[[0-9]+\]|scanf\("
        if [ $? -eq 0 ]; then
            # Extract the variable name (handles cin >> var, getline(cin, var), etc.)
            var=$(echo $line | sed -n -E 's/.*(std::cin >>|getline\(.*, *|argv\[[0-9]+\][^=]*= *)([a-zA-Z_][a-zA-Z0-9_]*).*/\2/p')
            
            # Fallback for scanf cases
            if [ -z "$var" ]; then
                var=$(echo $line | sed -n -E 's/.*scanf\(.*%[^,]*,[^&]*&([a-zA-Z_][a-zA-Z0-9_]*).*/\1/p')
            fi

            if [ -n "$var" ]; then
                # Remove any trailing semicolons or commas (C++ specific)
                var=$(echo "$var" | sed 's/[;,]*$//')

                # Check if the variable is used unsafely (similar to Python rule but C++-style)
                # FIRST CHECK: String concatenation or assignment (+, =, +=, etc.)
                echo $line | grep -q -E "\\b$var\\b\\s*\\+|=\\s*\\b$var\\b|\\+=\\s*\\b$var\\b|<<\\s*\\b$var\\b"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "std::regex_match|boost::regex_match|input_validation\\(|input_sanitize\\("
                    if [ $? -eq 0 ]; then
                        echo $line | grep -E -v -q "escape\\(\\s*$var|sanitize\\(\\s*$var|htmlspecialchars\\(\\s*$var|SQLite3::escape\\("
                        if [ $? -eq 0 ]; then
                            if [ $inj -eq 0 ]; then
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                            if [ $sec_log -eq 0 ]; then
                                vuln="$vuln, Security Logging and Monitoring Failures"
                                let

        # RULE 8: Detect unsafe LDAP server configurations in C++
        # Check for common C++ LDAP initialization patterns
        echo $line | grep -q -E "ldap_init|ldap_sslinit|ldap_initialize|ldap_open"
        if [ $? -eq 0 ]; then
            # Extract the LDAP server variable name
            var=$(echo $line | sed -n -E 's/.*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(ldap_init|ldap_sslinit|ldap_initialize|ldap_open)\(.*/\1/p')
            
            if [ -n "$var" ]; then
                # Check if the LDAP server variable is used unsafely
                # FIRST CHECK: Used in LDAP bind/search without proper escaping
                echo $line | grep -q -E "ldap_simple_bind|ldap_bind|ldap_search_ext|ldap_search_s.*$var"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "ldap_escape|ber_escape"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $ldap -eq 0 ]; then
                            vuln="$vuln, LDAP Injection"
                            let ldap=ldap+1
                        fi
                    fi
                fi

                # SECOND CHECK: Used in string concatenation for DN construction
                echo $line | grep -q -E "\\+\\s*$var|=\\s*$var|\\+=\\s*$var"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "ldap_escape|ber_escape"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $ldap -eq 0 ]; then
                            vuln="$vuln, LDAP Injection"
                            let ldap=ldap+1
                        fi
                    fi
                fi

                # THIRD CHECK: Used in filter construction without escaping
                echo $line | grep -q -E "ldap_search.*$var"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "ldap_escape_filter|ber_escape"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $ldap -eq 0 ]; then
                            vuln="$vuln, LDAP Injection"
                            let ldap=ldap+1
                        fi
                    fi
                fi
            fi
        fi

        # RULE 9: Detect unsafe LDAP search operations in C++
        # Check for common C++ LDAP search patterns
        echo $line | grep -q -E "ldap_search(_ext|_st|_s|_ext_s)?\\("
        if [ $? -eq 0 ]; then
            # Extract the search filter variable name
            var=$(echo $line | sed -n -E 's/.*ldap_search[^,]*,[^,]*,[^,]*,[^,]*,\s*([a-zA-Z_][a-zA-Z0-9_]*)[^,)]*.*/\1/p')
            
            # Fallback for different search function variants
            if [ -z "$var" ]; then
                var=$(echo $line | sed -n -E 's/.*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*ldap_search[^,]*,[^,]*,[^,]*,[^,]*,[^,)]*.*/\1/p')
            fi

            if [ -n "$var" ]; then
                # Remove any trailing characters that might be part of the syntax
                var=$(echo "$var" | sed 's/[^a-zA-Z0-9_].*//')

                # Check if the search filter is used unsafely
                # FIRST CHECK: Direct usage in ldap_search without validation
                echo $line | grep -q -E "ldap_search[^(]*\\([^,]*,[^,]*,[^,]*,[^,]*,\\s*$var"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "ldap_escape_filter|ber_escape"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $ldap -eq 0 ]; then
                            vuln="$vuln, LDAP Injection"
                            let ldap=ldap+1
                        fi
                    fi
                fi

                # SECOND CHECK: String concatenation in filter construction
                echo $line | grep -q -E "\\b$var\\b\\s*\\+|=\\s*\\b$var\\b|\\+=\\s*\\b$var\\b"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "ldap_escape_filter|ber_escape"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $ldap -eq 0 ]; then
                            vuln="$vuln, LDAP Injection"
                            let ldap=ldap+1
                        fi
                    fi
                fi

                # THIRD CHECK: Used in return value or subsequent operations
                echo $line | grep -q -E "return\\s*\\b$var\\b|\\b$var\\b\\s*=\\s*ldap_first_entry"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "ldap_escape_filter|ber_escape"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                    fi
                fi
            fi
        fi

        # RULE 10: Detect unsafe comparison of request parameters in C++ web frameworks
        # Check for common C++ web framework parameter patterns
        echo $line | grep -q -E "req\\.getParam|req\\.getQuery|request\\["
        if [ $? -eq 0 ]; then
            # Check for direct comparison (==) with the parameter
            echo $line | grep -q -E "==\\s*[a-zA-Z_][a-zA-Z0-9_]*|\\bstrcmp\\("
            if [ $? -eq 0 ]; then
                # Extract the variable being compared
                var=$(echo $line | sed -n -E 's/.*==\s*([a-zA-Z_][a-zA-Z0-9_]*).*/\1/p')
                if [ -z "$var" ]; then
                    var=$(echo $line | sed -n -E 's/.*strcmp\([^,]*,\s*([a-zA-Z_][a-zA-Z0-9_]*).*/\1/p')
                fi

                if [ -n "$var" ]; then
                    # Check for missing validation/sanitization
                    echo $line | grep -E -v -q "regex_match|input_validation|sanitize\\("
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $bac -eq 0 ]; then
                            vuln="$vuln, Broken Access Control"
                            let bac=bac+1
                        fi
                    fi
                fi
            fi
        fi

        # RULE 11: Detect unsafe URL parsing in C++
        # Check for common C++ URL parsing functions
        echo $line | grep -q -E "Poco::URI|boost::urls::parse_uri|QUrl::fromUserInput|uri::parse|URLParser::parse"
        if [ $? -eq 0 ]; then
            # Extract the variable name
            var=$(echo $line | sed -n -E 's/.*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(Poco::URI|boost::urls::parse_uri|QUrl::fromUserInput|uri::parse|URLParser::parse)\(.*/\1/p')
            
            if [ -n "$var" ]; then
                # Check for unsafe usage patterns
                # FIRST CHECK: Direct component access without validation
                echo $line | grep -q -E "$var\\.get(Host|Path|Query|Port)"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "isValid\\(|isSecure\\(|validateUrl\\(|allowedDomains\\.count"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                        if [ $ssrf -eq 0 ]; then
                            vuln="$vuln, SSRF"
                            let ssrf=ssrf+1
                        fi
                    fi
                fi

                # SECOND CHECK: String concatenation with URL components
                echo $line | grep -q -E "\\+\\s*$var\\.|\\+=\\s*$var\\."
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "escapeUrl\\(|sanitize\\(|validateComponent"
                    if [ $? -eq 0 ]; then
                        if [ $inj -eq 0 ]; then
                            vuln="$vuln, Injection"
                            let inj=inj+1
                        fi
                    fi
                fi

                # THIRD CHECK: Used in network operations
                echo $line | grep -q -E "curl_easy_setopt.*$var|HttpRequest::setUrl.*$var"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "isWhitelisted\\(|validateExternalUrl"
                    if [ $? -eq 0 ]; then
                        if [ $ssrf -eq 0 ]; then
                            vuln="$vuln, SSRF"
                            let ssrf=ssrf+1
                        fi
                    fi
                fi

                # FOURTH CHECK: Used in file operations
                echo $line | grep -q -E "std::ifstream.*$var|std::ofstream.*$var"
                if [ $? -eq 0 ]; then
                    echo $line | grep -E -v -q "isLocalPath\\(|validateFilePath"
                    if [ $? -eq 0 ]; then
                        if [ $pt -eq 0 ]; then
                            vuln="$vuln, Path Traversal"
                            let pt=pt+1
                        fi
                    fi
                fi
            fi
        fi

        # RULE 12: Detect unsafe method chaining after URL parsing in C++
        # Check for method calls on URL parsing objects
        echo $line | grep -P -q "(Poco::URI|QUrl|boost::urls::url_view|uri::parse)\(.*?\)\.[a-zA-Z_]*"
        if [ $? -eq 0 ]; then
            # Check for unsafe direct usage without validation
            echo $line | grep -E -v -q "isValid\\(|isSecure\\(|validateUrl\\(|allowedDomains\\.count"
            if [ $? -eq 0 ]; then
                # Check for common vulnerable method calls
                echo $line | grep -P -q "getHost\\(|getPath\\(|getQuery\\(|toString\\(|authority\\("
                if [ $? -eq 0 ]; then
                    if [ $inj -eq 0 ]; then
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                    if [ $ssrf -eq 0 ]; then
                        vuln="$vuln, SSRF"
                        let ssrf=ssrf+1
                    fi
                fi
            fi
        fi

        # Additional check for pointer-based URL objects
        echo $line | grep -P -q "(Poco::URI|QUrl|boost::urls::url_view|uri::parse)\(.*?\)->[a-zA-Z_]*"
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "isValid\\(|isSecure\\(|validateUrl\\(|allowedDomains\\.count"
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi
done < "$input"
