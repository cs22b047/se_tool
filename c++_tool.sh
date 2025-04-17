start=$(date +%s.%N)

input=$1
output_file=$2

if [ -z "$input_file" ] || [ -z "$output_file" ]; then
    echo "Usage: $0 <input_java_file> <output_report>"
    exit 1
fi

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

        # RULE 13: Detect unsafe return of URL parsing results
        echo $line | grep -q -E "return (Poco::URI|QUrl|boost::urls::parse_uri|uri::parse)\("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "isValid\\(|isSecure\\(|validateUrl\\("
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi

        # RULE 14: Detect unsafe session variable access
        echo $line | grep -q -E "session\\[.*\\]"
        if [ $? -eq 0 ]; then
            # Check for common framework session patterns
            echo $line | grep -E -v -q "isAuthenticated\\(|hasPermission\\(|validateSession\\("
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        # RULE 15: Detect unsafe request parameter access
        # Check for common C++ web framework parameter patterns
        echo $line | grep -q -E "req\\.get(Param|Query|Header|Cookie)|request\\["
        if [ $? -eq 0 ]; then
            # Check for direct usage without validation
            echo $line | grep -E -v -q "regex_match|input_validation|sanitize\\("
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi

        # RULE 16: Detect unsafe JSON request handling
        echo $line | grep -q -E "req\\.getJSON|request\\.json|json::parse"
        if [ $? -eq 0 ]; then
            # Check for direct field access without validation
            echo $line | grep -E -v -q "validateJson|sanitizeJson|hasField\\("
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

       # RULE 17: Detect unsafe return of request parameters
        echo $line | grep -q -E "return req\\.(getParam|getQuery|getHeader|getCookie)\("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "regex_match|input_validation|sanitize\\("
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 18: Detect unsafe array-style request parameter access
        echo $line | grep -q -E "return req\\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "regex_match|input_validation|sanitize\\("
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 19: Detect unsafe file upload handling
        echo $line | grep -q -E "req\\.getFile|req\\.files\\["
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "checkFileExtension|validateFileType|sanitizeFilename"
            if [ $? -eq 0 ]; then
                if [ $ins_des -eq 0 ]; then
                    vuln="$vuln, Insecure Design"
                    let ins_des=ins_des+1
                fi
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi

        # RULE 20: Detect unsafe raw request data access
        echo $line | grep -q -E "return req\\.(getData|readBody|rawContent)\("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "validateContent|sanitizeInput|checkContentType"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 21: Detect unsafe request data assignment
        echo $line | grep -q -E "=\\s*req\\.(getData|readBody|rawContent)\\("
        if [ $? -eq 0 ]; then
            echo $line | grep -E -v -q "validateContent|sanitizeInput|checkContentType"
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        # RULE 22: Detect unsafe environment variable or JSON parsing
        # RULE 22: Detect unsafe use of env vars/JSON data (C++)
# Check for getenv() and JSON parsing patterns
        echo "$line" | grep -q -E '\b(getenv|std::getenv|json::parse|nlohmann::json::parse)\b'
        if [ $? -eq 0 ]; then
            # Extract variable from env/JSON parsing
            var=$(echo "$line" | awk -F '=' '{print $1}' | tr -d ' ' | tr -d ';')
            
            # Check for JSON parsing
            if echo "$line" | grep -q -E 'json::parse|nlohmann::json::parse'; then
                json_var=$var
            fi

            # Check for unsafe usage patterns
            if [ -n "$var" ]; then
                # Check for command injection patterns
                echo "$line" | grep -q -E '\bsystem\s*\(.*\b'"$var"'\b'
                cmd_injection=$?
                
                # Check for SQL concatenation
                echo "$line" | grep -q -E '\bsqlite3_exec\b.*\b'"$var"'\b'
                sql_risk=$?
                
                # Check for path traversal
                echo "$line" | grep -q -E 'open\s*\(.*\b'"$var"'\b'
                file_risk=$?
                
                # Check for auth token usage
                echo "$line" | grep -q -E '(Authorization|Token|Session).*\b'"$var"'\b'
                auth_risk=$?
                
                # Check for JSON validation
                echo "$line" | grep -q -E '(validate|sanitize|escape).*\b'"$var"'\b'
                sanitized=$?
                
                # Flag vulnerabilities
                if [ $sanitized -ne 0 ]; then
                    if { [ $cmd_injection -eq 0 ] || [ $sql_risk -eq 0 ] || [ $file_risk -eq 0 ]; } && [ $bac -eq 0 ]; then
                        vuln="$vuln, Broken Access Control"
                        let bac=bac+1
                    fi
                    
                    if [ $auth_risk -eq 0 ] && [ $auth_fail -eq 0 ]; then
                        vuln="$vuln, Authentication Failures"
                        let auth_fail=auth_fail+1
                    fi
                fi
                
                # Additional JSON validation check
                if [ -n "$json_var" ]; then
                    echo "$line" | grep -q -E "$json_var\s*\[.*\]\s*="
                    if [ $? -eq 0 ] && [ $bac -eq 0 ]; then
                        vuln="$vuln, Insecure Deserialization"
                        let bac=bac+1
                    fi
                fi
            fi
        fi


        #RULE C++23: if exists a the following pattern: = getenv() or = json::parse()
        source_function="getenv\\\(|json::parse\\\("
        num_occ=$(echo "$line" | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;

        while [ $i -le $num_occ ]; do
            var=$(echo "$line" | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $NF}')
            
            if [ -z "$var" ]; then
                pass=1;
            else
                last_char=$(echo "${var: -1}")
                if [ $name_os = "Darwin" ]; then
                    var=${var:0:$((${#var} - 1))}
                elif [ $name_os = "Linux" ]; then
                    var=${var::-1}
                fi

                # Strip variable usages to avoid false positives
                new_line=$(echo "$line" \
                    | sed "s/$var(/func(/g" \
                    | sed "s/$var =/ =/g" \
                    | sed "s/$var=/ =/g" \
                    | sed "s/\"$var/ /g" \
                    | sed "s/$var\"/ /g" \
                    | sed "s/'$var'/ /g")

                # FIRST CHECK: Variable used in expressions or command
                echo "$new_line" | grep -E -q "\+\b$var\b|\+ \b$var\b|=\b$var\b|= \b$var\b"
                if [ $? -eq 0 ]; then
                    echo "$new_line" | grep -E -v -q "std::filesystem::exists|std::optional"
                    if [ $? -eq 0 ]; then
                        echo "$new_line" | grep -v -P -i -q "system\(.*(\b$var\b).*?\)|exec\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo "$new_line" | grep -E -v -q "escape\( *$var *\)"
                            if [ $? -eq 0 ]; then
                                if [ $bac -eq 0 ]; then
                                    vuln="$vuln, Broken Access Control"
                                    let bac=bac+1
                                fi
                            fi
                        fi
                    fi
                else
                    # SECOND CHECK: Direct key:value usage (e.g., json["$var"])
                    echo "$new_line" | grep -E -q "\b$var\b:|\b$var\b :"
                    if [ $? -eq 0 ]; then
                        echo "$new_line" | grep -E -v -q "std::filesystem::exists|std::optional"
                        if [ $? -eq 0 ]; then
                            echo "$new_line" | grep -v -P -i -q "system\(.*(\b$var\b).*?\)"
                            if [ $? -eq 0 ]; then
                                echo "$new_line" | grep -E -v -q "escape\( *$var *\)"
                                if [ $? -eq 0 ]; then
                                    if [ $bac -eq 0 ]; then
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    else
                        # THIRD CHECK: Function use like func($var)
                        echo "$new_line" | grep -P -q "\(.*(\b$var\b).*?\)"
                        if [ $? -eq 0 ]; then
                            echo "$new_line" | grep -E -v -q "std::filesystem::exists|escape\( *$var *\)"
                            if [ $? -eq 0 ]; then
                                if [ $bac -eq 0 ]; then
                                    vuln="$vuln, Broken Access Control"
                                    let bac=bac+1
                                fi
                            fi
                        else
                            # FOURTH CHECK: Return $var or method use like $var.method()
                            echo "$new_line" | grep -E -q "return \b$var\b| \b$var\b\.[a-zA-Z]*\("
                            if [ $? -eq 0 ]; then
                                echo "$new_line" | grep -E -v -q "escape\( *$var *\)"
                                if [ $? -eq 0 ]; then
                                    if [ $bac -eq 0 ]; then
                                        vuln="$vuln, Broken Access Control"
                                        let bac=bac+1
                                    fi
                                fi
                            fi
                        fi
                    fi
                fi
            fi
            let i=i+1;
            let check=num_occ+1;
        done

        # RULE 23: Detect insecure JSON parsing/environment variable usage (C++)
        # Check for nlohmann::json::parse() and getenv() patterns
        echo "$line" | grep -q -E '\b(nlohmann::json::parse|json::parse|getenv|std::getenv)\b'
        if [ $? -eq 0 ]; then
            # Extract parsed variable/expression
            if echo "$line" | grep -q -E 'json::parse|nlohmann::json::parse'; then
                var=$(echo "$line" | awk -F '=' '{print $1}' | tr -d ' ' | tr -d ';')
                json_source=1
            else
                var=$(echo "$line" | awk -F 'getenv' '{print $2}' | awk -F '[)" ]' '{print $2}')
            fi

            if [ -n "$var" ]; then
                # Normalize line for analysis
                new_line=$(echo "$line" | sed "s/${var}/_VAR_/g" | sed 's/"/ /g' | sed "s/'/ /g")

                # Check for security anti-patterns
                echo "$new_line" | grep -q -E '\b(system|popen|sqlite3_exec|fopen|ofstream)\b.*_VAR_'
                unsafe_usage=$?
                
                # Check for validation/sanitization
                echo "$line" | grep -q -E "(validate|sanitize|escape|check).*\b${var}\b"
                sanitized=$?

                # JSON-specific checks
                if [ -n "$json_source" ]; then
                    echo "$new_line" | grep -q -E '_VAR_\[.*\]'
                    json_access_risk=$?
                    echo "$new_line" | grep -q -E '(\.dump|\.get\<|\.at\()'
                    serialization_risk=$?
                fi

                # Vulnerability determination
                if [ $unsafe_usage -eq 0 ] && [ $sanitized -ne 0 ]; then
                    if [ $bac -eq 0 ]; then
                        vuln="$vuln, Broken Access Control"
                        let bac=bac+1
                    fi
                    
                    if [ -n "$json_source" ] && [ $json_access_risk -eq 0 ] && [ $serialization_risk -eq 0 ]; then
                        if [ $insecure_deser -eq 0 ]; then
                            vuln="$vuln, Insecure Deserialization"
                            let insecure_deser=insecure_deser+1
                        fi
                    fi
                fi
            fi
        fi

        #RULE C++24: if exists a the following pattern: returnType functionName(var1,var2,...,varn)
        source_function="[a-zA-Z_:][a-zA-Z0-9_:<>]*[ ]+[a-zA-Z_][a-zA-Z0-9_]*[ ]*\\(" # matches "int func(", "std::string foo(", etc.
        num_occ=$(echo "$line" | awk -F "$source_function" '{print NF-1}')
        i=1;
        split=0;
        check=0;
        num_commas=0;
        num_vars=0;

        while [ $i -le $num_occ ]; do
            let split=i;
            var=$(echo "$line" | awk -F "$source_function" -v i="$i" '{print $(i+1)}' | cut -d')' -f1)
            if [ -z "$var" ]; then
                pass=1
            else
                if [[ "$var" == *","* ]]; then
                    num_commas=$(echo "$var" | tr -cd ',' | wc -c)
                fi
                let num_vars=num_commas+1
                j=1
                while [ $j -le $num_vars ]; do
                    var_part=$(echo "$var" | awk -v j="$j" -F, '{print $j}' | awk '{print $NF}' | sed 's/[^a-zA-Z0-9_]//g')
                    
                    # clean the current line of this var_part to avoid false positives
                    new_line=$(echo "$line" | sed "s/$var_part(/func(/g" | sed "s/$var_part =/ =/g" | sed "s/$var_part=/ =/g" | sed "s/'$var_part'/ /g" | sed "s/\"$var_part\"/ /g" | sed "s/$var_part\"/ /g" | sed "s/\"$var_part/ /g" | sed "s/ $var_part / /g")

                    if [ $num_occ -eq 1 ]; then
                        new_line=$(echo "$new_line" | awk -F "$source_function" '{print $2}' | cut -d')' -f2-)
                    else
                        new_line=$(echo "$new_line" | awk -F "$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }' | cut -d')' -f$split-)
                    fi

                    # Check for vulnerable function usage with parameter
                    rule1="system\(.*(\b$var_part\b).*?\)|execl\(.*(\b$var_part\b).*?\)|execv\(.*(\b$var_part\b).*?\)|popen\(.*(\b$var_part\b).*?\)"
                    rule2=".*query\(.*(\b$var_part\b).*?\)|.*execute\(.*(\b$var_part\b).*?\)"
                    rule3="fprintf\(.*(\b$var_part\b).*?\)|fwrite\(.*(\b$var_part\b).*?\)|ofstream.*<<.*(\b$var_part\b)"

                    echo "$new_line" | grep -P -q "($rule1|$rule2|$rule3)"
                    if [ $? -eq 0 ]; then
                        echo "$new_line" | grep -P -v -q "std::filesystem::exists|std::optional|escape\( *$var_part *\)"
                        if [ $? -eq 0 ]; then
                            if [ $inj -eq 0 ]; then
                                vuln="$vuln, Injection"
                                let inj=inj+1
                            fi
                        fi
                    fi
                    let j=j+1
                done
            fi
            let i=i+1;
            let check=num_occ+1;
        done
        #RULE C++25: if exists the following pattern: (... + user_input)
        source_function="\+ *(argv\[.*\]|std::cin|std::getline|std::getenv|std::ifstream|std::stringstream|std::istringstream|scanf|gets|fgets)"
        substitution=$(echo "$line" | grep -o -E "$source_function")

        if [ -n "$substitution" ]; then
            echo "$line" | grep -E -v -q "if.*\.match\(|std::regex_match|std::filesystem::exists"
            if [ $? -eq 0 ]; then
                echo "$line" | grep -E -v -q "escape\(.*\)|sanitize\(.*\)"
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1
                    fi
                fi
            fi
        fi


        # RULE 26: Detect unsafe string concatenation with user input (C++)
        # Check for CGI/env var concatenation in strings
        echo "$line" | grep -q -E '\b(std::string::operator\+|\bstrcat|\bsprintf|\bstrn?cpy)\b.*\b(getenv|std::getenv|cgiParam|cin|std::cin)\b'
        if [ $? -eq 0 ]; then
            # Extract the user input source
            input_source=$(echo "$line" | grep -o -E '\b(getenv|std::getenv|cgiParam|cin|std::cin)\b')
            
            # Extract the concatenation operation
            concat_op=$(echo "$line" | grep -o -E '\b(std::string::operator\+|\bstrcat|\bsprintf|\bstrn?cpy)\b')
            
            # Check for mitigation patterns
            echo "$line" | grep -q -E '\b(sanitize|validate|escape|check|verify)\b'
            mitigated=$?
            
            if [ $mitigated -ne 0 ]; then
                # Security Misconfiguration check
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
                
                # Additional checks for specific vulnerabilities
                echo "$line" | grep -q -E '\b(system|popen|exec[lv]?|sqlite3_exec)\b'
                if [ $? -eq 0 ] && [ $command_inj -eq 0 ]; then
                    vuln="$vuln, Command Injection"
                    let command_inj=command_inj+1
                fi
                
                echo "$line" | grep -q -E '\b(fopen|ofstream|ifstream)\b'
                if [ $? -eq 0 ] && [ $file_inj -eq 0 ]; then
                    vuln="$vuln, File Injection"
                    let file_inj=file_inj+1
                fi
            fi
        fi

        # RULE 27 (C++ equivalent): Look for usage like std::string result = "..." + request["..."];
        source_function="\\+ *request\\[\"(args|form|headers|params|cookies|data|json|files)\"\\]"
        num_occ=$(echo $line | grep -o -P "$source_function" | wc -l)

        i=1
        while [ $i -le $num_occ ]; do
            substitution=$(echo $line | grep -o -P "$source_function")
            if [ -n "$substitution" ]; then
                var="request" # placeholder, since it's embedded

                # Clean the line from variable usages
                new_line=$(echo $line | sed -E "s/request\\[\"[a-zA-Z_]+\"\\]/REPLACED/g")

                # Check for risky patterns
                echo $new_line | grep -qE "\+\s*REPLACED|\=\s*REPLACED"
                if [ $? -eq 0 ]; then
                    echo $new_line | grep -qvE "escape\\(|sanitize\\(|valid\\(|check\\("
                    if [ $? -eq 0 ]; then
                        if [ $bac -eq 0 ]; then
                            vuln="$vuln, Broken Access Control"
                            let bac=bac+1
                        fi
                    fi
                fi
            fi
            let i=i+1
        done

        # RULE 28 (C++ Equivalent): Detect ( request.get("...") ) or ( req.url_params.get("...") )
        source_function="\\( *(request|req)(\\.|->)(get|url_params\\.get)\\(\"[a-zA-Z0-9_]+\"\\)"
        substitution=$(echo "$line" | grep -o -P "$source_function")

        if [ -n "$substitution" ]; then
            echo "$line" | grep -E -v -q "if.*\\.match\\(|if obj_match\\("
            if [ $? -eq 0 ]; then
                echo "$line" | grep -E -v -q "escape\\(|sanitize\\(|validate\\("
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1
                    fi
                fi
            fi
        fi

        # RULE 29 (C++ Equivalent): Detect potential format string or concatenation vulnerabilities with request input
        # Pattern: ... % request.get(...) or req.url_params.get(...) (e.g., vulnerable string formatting or injection)
        source_function="\\% *(request|req)(\\.|->)(get|url_params\\.get)\\(\"[a-zA-Z0-9_]+\"\\)"
        substitution=$(echo "$line" | grep -o -P "$source_function")

        if [ -n "$substitution" ]; then
            echo "$line" | grep -E -v -q "if.*\\.match\\(|if obj_match\\("
            if [ $? -eq 0 ]; then
                echo "$line" | grep -E -v -q "escape\\(|sanitize\\(|validate\\("
                if [ $? -eq 0 ]; then
                    if [ $sec_mis -eq 0 ]; then
                        vuln="$vuln, Security Misconfiguration"
                        let sec_mis=sec_mis+1
                    fi
                fi
            fi
        fi

        # RULE 13F (C++ Equivalent): Detect usage of insecure template rendering with entire variable contexts
        source_function="(context|env|map|locals|globals|session|params)"
        num_occ=$(echo "$line" | awk -F "$source_function" '{print NF-1}')
        i=1
        split=0
        check=0

        while [ $i -le $num_occ ]; do
            var=$(echo "$line" | awk -F "$source_function" -v i="$i" '{print $i}' | awk '{print $NF}')

            if [ -z "$var" ]; then
                pass=1
            else
                if [ "$var" == "=" ]; then
                    var=$(echo "$line" | awk -F "$source_function" -v i="$i" '{print $(NF-1)}')
                else
                    last_char=$(echo "${var: -1}")
                    if [ "$name_os" = "Darwin" ]; then
                        var=${var:0:$((${#var} - 1))}
                    elif [ "$name_os" = "Linux" ]; then
                        var=${var::-1}
                    fi
                fi

                # Replace suspicious usage for checking
                new_line=$(echo "$line" | sed "s/$var(/func(/g" | sed "s/$var =/ =/g" | sed "s/$var=/ =/g")

                let split=i
                let split=split+1
                if [ $num_occ -eq 1 ]; then
                    new_line=$(echo "$new_line" | awk -F "$source_function" '{print $2}' | cut -d\) -f$split-)
                else
                    new_line=$(echo "$new_line" | awk -F "$source_function" -v i="$i" '!found && NF > i { found = 1; $1=""; print $0 }' | cut -d\) -f$split-)
                fi

                # Match suspicious render/engine usage
                regex="(engine|renderer|template)\.(render|generate|compile)\(.*\b$var\b.*\)"
                if echo "$new_line" | grep -q -E "$regex"; then
                    if [ $inj -eq 0 ]; then
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                fi
            fi

            let i=i+1
            let check=num_occ+1
        done

        # Direct check for context-based rendering
        rule1="(engine|renderer|template)\.(render|generate|compile)\(.*(context|env|globals|params|map).*\)"
        if echo "$line" | grep -q -E "$rule1"; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        # RULE 30 (C++ Equivalent): Detect unsafe HTML escaping/encoding — suggest use of safe_escape()
        echo "$line" | grep -E -q "(html_decode\(|html_unescape\(|HtmlRenderer::render\(|HtmlSafe\(|Html::parse\(|sanitizeHtml\()" 
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then # Count this category once per snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        # RULE 30: Detect unsafe HTML/XML output in C++
        # Check for unescaped output streams and string conversions
        echo "$line" | grep -q -E '\b(std::cout|printf|fprintf|sprintf|operator<<)\b.*\<[^\>]*\>'
        if [ $? -eq 0 ]; then
            # Check if the output contains HTML/XML tags without escaping
            contains_tags=$(echo "$line" | grep -o -E '\<(a|div|span|script|img)[^>]*\>')
            
            if [ -n "$contains_tags" ]; then
                # Look for escaping functions
                echo "$line" | grep -q -E '\b(escapeHtml|sanitize|htmlspecialchars|XMLString::transcode)\b'
                escaped=$?
                
                if [ $escaped -ne 0 ]; then
                    if [ $xss -eq 0 ]; then
                        vuln="$vuln, Cross-Site Scripting (XSS)"
                        let xss=xss+1
                    fi
                    
                    # Additional context checks
                    echo "$line" | grep -q -E '\b(innerHTML|document\.write|ReactDOM\.render)\b'
                    if [ $? -eq 0 ] && [ $dom_xss -eq 0 ]; then
                        vuln="$vuln, DOM-based XSS"
                        let dom_xss=dom_xss+1
                    fi
                fi
            fi
        fi

        # RULE 31: Detect unsafe direct user input in function parameters (C++)
        # Check for cin/getline/getenv patterns in function arguments
        echo "$line" | grep -q -E '\b(cin\s*>>|std::cin\s*>>|getline\s*\(|std::getline\s*\(|getenv\s*\(|std::getenv\s*\()'
        if [ $? -eq 0 ]; then
            # Extract the function call pattern
            func_call=$(echo "$line" | grep -o -E '\b\w+\s*\(.*(cin|getline|getenv).*\)')
            
            if [ -n "$func_call" ]; then
                # Check for mitigation patterns
                echo "$line" | grep -q -E '\b(sanitize|validate|escape|check|verify)\b'
                mitigated=$?
                
                # Check if input is used in dangerous contexts
                echo "$line" | grep -q -E '\b(system|popen|exec[lv]?|sqlite3_exec|fopen|ofstream)\b'
                dangerous_usage=$?
                
                if [ $mitigated -ne 0 ]; then
                    if [ $inj -eq 0 ]; then
                        vuln="$vuln, Injection"
                        let inj=inj+1
                    fi
                    
                    # Additional specific vulnerability checks
                    if [ $dangerous_usage -eq 0 ]; then
                        if [[ $func_call == *"system"* ]] && [ $cmd_inj -eq 0 ]; then
                            vuln="$vuln, Command Injection"
                            let cmd_inj=cmd_inj+1
                        fi
                        
                        if [[ $func_call == *"sqlite3_exec"* ]] && [ $sqli -eq 0 ]; then
                            vuln="$vuln, SQL Injection"
                            let sqli=sqli+1
                        fi
                        
                        if [[ $func_call == *"fopen"* ]] && [ $file_inj -eq 0 ]; then
                            vuln="$vuln, File Injection"
                            let file_inj=file_inj+1
                        fi
                    fi
                fi
            fi
        fi

        # RULE 32 (C++ Equivalent): Detect unsafe CSV writing or output using ofstream or fprintf
        regex="(#include *<fstream>|std::ofstream|ofstream|fprintf *\(|fopen *\()"
        echo "$line" | grep -E -q -i "$regex"
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then # Count this vulnerability once per snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        # RULE 32: Detect unsafe CSV/file operations in C++
        # Check for ofstream/fprintf without proper validation
        echo "$line" | grep -q -E '\b(std::ofstream|fprintf|fopen|fputs)\b.*\.csv'
        if [ $? -eq 0 ]; then
            # Check for user-controlled inputs in file operations
            user_input_pattern='\b(cin|std::cin|getline|std::getline|getenv|std::getenv|cgiParam)\b'
            echo "$line" | grep -q -E "$user_input_pattern"
            
            if [ $? -eq 0 ]; then
                # Look for CSV-specific injection patterns
                echo "$line" | grep -q -E '<<\s*[^"]*\,|fprintf\([^"]*\,'
                csv_injection=$?
                
                # Check for mitigations
                echo "$line" | grep -q -E '\b(escapeCsv|sanitize|validate)\b'
                mitigated=$?
                
                if [ $csv_injection -eq 0 ] && [ $mitigated -ne 0 ]; then
                    if [ $inj -eq 0 ]; then
                        vuln="$vuln, CSV Injection"
                        let inj=inj+1
                    fi
                    
                    # Additional context checks
                    echo "$line" | grep -q -E '\b(system|popen|exec[lv]?)\b'
                    if [ $? -eq 0 ] && [ $cmd_inj -eq 0 ]; then
                        vuln="$vuln, Command Injection"
                        let cmd_inj=cmd_inj+1
                    fi
                fi
            fi
        fi

        # RULE 33 (C++ Equivalent): Detect unsafe subprocess calls like system(), popen(), exec*
        regex="(system *\(|popen *\(|exec[lvp]{1,2} *\()"
        echo "$line" | grep -E -q -i "$regex"
        if [ $? -eq 0 ]; then 
            if [ $inj -eq 0 ]; then # Count this vulnerability once per snippet
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        # RULE 33: Detect unsafe command execution in C++
        # Check for system()/popen() without proper validation
        echo "$line" | grep -q -E '\b(system|popen|_popen|exec[lv]?|_wsystem)\b'
        if [ $? -eq 0 ]; then
            # Check for user-controlled command input
            user_input_pattern='\b(cin|std::cin|getline|std::getline|getenv|std::getenv|cgiParam|argv)\b'
            echo "$line" | grep -q -E "$user_input_pattern"
            
            if [ $? -eq 0 ]; then
                # Look for command concatenation
                echo "$line" | grep -q -E '\+.*(cin|getenv|argv)'
                concat_unsafe=$?
                
                # Check for mitigations
                echo "$line" | grep -q -E '\b(validate|sanitize|escapeShellCmd|check)\b'
                mitigated=$?
                
                if [ $concat_unsafe -eq 0 ] && [ $mitigated -ne 0 ]; then
                    if [ $cmd_inj -eq 0 ]; then
                        vuln="$vuln, Command Injection"
                        let cmd_inj=cmd_inj+1
                    fi
                    
                    # Additional severity checks
                    echo "$line" | grep -q -E '\b(root|sudo|chmod|rm)\b'
                    if [ $? -eq 0 ] && [ $priv_esc -eq 0 ]; then
                        vuln="$vuln, Privilege Escalation Risk"
                        let priv_esc=priv_esc+1
                    fi
                fi
            fi
        fi

        # RULE 34 (C++ Equivalent): Detect unsafe deserialization usage
        regex="(boost::archive::|cereal::|std::ifstream|std::istringstream).*>>"
        echo "$line" | grep -E -q -i "$regex"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -v -q "(archive_flags_safe|verify_signature|secure_deserialize)" # Skip known secure wrappers
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
                if [ $soft_data -eq 0 ]; then
                    vuln="$vuln, Injection, Software and Data Integrity Failures"
                    let soft_data=soft_data+1
                fi
            fi
        fi

        # RULE 34: Detect unsafe YAML/JSON parsing in C++
        # Check for yaml-cpp or similar libraries without safe loading
        echo "$line" | grep -q -E '\b(YAML::LoadFile|YAML::Load|yaml_parser_initialize|yyjson_read)\b'
        if [ $? -eq 0 ]; then
            # Check for safe loading patterns
            echo "$line" | grep -q -E '\b(YAML::LoadFile|YAML::Load)\b.*\bSafeLoader\b'
            safe_loading=$?
            
            # Check for untrusted input sources
            echo "$line" | grep -q -E '\b(std::cin|getenv|std::getenv|fopen|ifstream)\b'
            untrusted_source=$?
            
            if [ $safe_loading -ne 0 ] && [ $untrusted_source -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Insecure Deserialization"
                    let inj=inj+1
                fi
                if [ $soft_data -eq 0 ]; then
                    vuln="$vuln, Software and Data Integrity Failures"
                    let soft_data=soft_data+1
                fi
                
                # Additional severity checks
                echo "$line" | grep -q -E '\b(system|exec[lv]?|popen)\b'
                if [ $? -eq 0 ] && [ $cmd_inj -eq 0 ]; then
                    vuln="$vuln, Command Injection"
                    let cmd_inj=cmd_inj+1
                fi
            fi
        fi

        # RULE 35 (C++ Equivalent): Detect unsafe code execution via system-like functions
        regex="(system|popen|execl|execv|execlp|execvp|execve|WinExec|CreateProcess)\("
        echo "$line" | grep -E -q -i "$regex"
        if [ $? -eq 0 ]; then
            # Exclude known-safe wrappers (if any)
            echo "$line" | grep -E -v -q "(safe_exec|sanitize_command)"
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi

        # RULE 35: Detect unsafe code execution patterns in C++
        # Check for system(), popen(), and interpreter embedding
        echo "$line" | grep -q -E '\b(system\s*\(|popen\s*\(|exec[lv]?p?\s*\(|Lua_LoadString\s*\(|v8::Script::Compile\s*\()'
        if [ $? -eq 0 ]; then
            # Check for user-controlled input in execution context
            user_input_pattern='\b(cin|std::cin|getenv|std::getenv|argv|fgets|scanf)\b'
            echo "$line" | grep -q -E "$user_input_pattern"
            
            if [ $? -eq 0 ]; then
                # Check for command/string concatenation
                echo "$line" | grep -q -E '\+.*(std::cin|argv|getenv)'
                concat_unsafe=$?
                
                # Check for mitigations
                echo "$line" | grep -q -E '\b(validate|sanitize|escapeShellCmd|check)\b'
                mitigated=$?
                
                if [ $concat_unsafe -eq 0 ] && [ $mitigated -ne 0 ]; then
                    if [ $inj -eq 0 ]; then
                        vuln="$vuln, Code Injection"
                        let inj=inj+1
                    fi
                    
                    # Additional severity checks
                    echo "$line" | grep -q -E '\b(boost::python|python::exec|PyRun_SimpleString)\b'
                    if [ $? -eq 0 ] && [ $py_eval -eq 0 ]; then
                        vuln="$vuln, Python Evaluation in C++"
                        let py_eval=py_eval+1
                    fi
                fi
            fi
        fi

        # RULE 36 (C++ Equivalent): Detect use of dangerous exec-like functions
        regex="(execv|execl|execvp|execve|execlp|system|WinExec|CreateProcess)\("
        echo "$line" | grep -E -q -i "$regex"
        if [ $? -eq 0 ]; then
            # Optional: exclude any known-safe wrappers if needed
            echo "$line" | grep -E -v -q "(safe_exec|sanitize_command)"
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi

        # RULE 36: Detect insecure exec family usage in C++
        # Check for exec*() functions with potential injection risks
        echo "$line" | grep -q -E '\bexec[lv]?p?e?\b\s*\(.*\b(cin|argv|getenv|std::getenv|cgiParam)\b'
        if [ $? -eq 0 ]; then
            # Check for command concatenation patterns
            echo "$line" | grep -q -E '\+.*(std::cin|argv|getenv)'
            concat_unsafe=$?
            
            # Check for mitigations
            echo "$line" | grep -q -E '\b(validate|sanitize|escape|check|secure_exec)\b'
            mitigated=$?
            
            if [ $concat_unsafe -eq 0 ] && [ $mitigated -ne 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Process Injection"
                    let inj=inj+1
                fi
                
                # Additional severity checks
                echo "$line" | grep -q -E '\b(bash|sh|python|perl)\b'
                if [ $? -eq 0 ] && [ $shell_inj -eq 0 ]; then
                    vuln="$vuln, Shell Injection"
                    let shell_inj=shell_inj+1
                fi
            fi
        fi

        # RULE 37 (C++ Equivalent): Detect use of system/popen or shell command execution
        regex="(system|popen|std::system)\(.*(\"|').*(;|&&|\\||\$|\`|\$\().*"
        echo "$line" | grep -E -q -i "$regex"
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        # RULE 37: Detect unsafe shell execution in C++
        # Check for system()/popen() with shell invocation patterns
        echo "$line" | grep -q -E '\b(system|popen|_popen|_wsystem)\b\s*\(.*(sh -c|bash -c|cmd /c)'
        if [ $? -eq 0 ]; then
            # Check for user-controlled command input
            user_input_pattern='\b(cin|std::cin|getenv|std::getenv|argv|fgets|scanf)\b'
            echo "$line" | grep -q -E "$user_input_pattern"
            
            if [ $? -eq 0 ]; then
                # Check for command concatenation
                echo "$line" | grep -q -E '\+.*(std::cin|argv|getenv)'
                concat_unsafe=$?
                
                # Check for mitigations
                echo "$line" | grep -q -E '\b(validate|sanitize|escapeShellCmd|check)\b'
                mitigated=$?
                
                if [ $concat_unsafe -eq 0 ] && [ $mitigated -ne 0 ]; then
                    if [ $shell_inj -eq 0 ]; then
                        vuln="$vuln, Shell Injection"
                        let shell_inj=shell_inj+1
                    fi
                    
                    # Additional severity checks
                    echo "$line" | grep -q -E '\b(&&|\|\||;|`|\$\(|\\)\b'
                    if [ $? -eq 0 ] && [ $cmd_inj -eq 0 ]; then
                        vuln="$vuln, Command Injection"
                        let cmd_inj=cmd_inj+1
                    fi
                fi
            fi
        fi

        ###############################
        # RULE 38: Inline Exception Handling Vulnerability
        # Detection of "std::exception().what()" used directly without saving output in a variable.
        var=$(echo "$line" | awk -F "std::exception().what(" '{print $1}' | awk '{print $NF}')
        if [ -z "$var" ]; then
            pass=1
        else
            if [ "$var" == "=" ]; then
                var=$(echo "$line" | awk -F "std::exception().what(" '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ "$last_char" == "=" ]; then
                    if [ "$name_os" = "Darwin" ]; then  # MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ "$name_os" = "Linux" ]; then  # LINUX system
                        var=${var::-1}
                    fi
                fi
            fi
            # Check if the formatted exception output is immediately used in a return or print call
            echo "$line" | grep -E -q -i "return std::exception().what\\(\\)|std::(cerr|cout) *<< *$var"
            if [ $? -eq 0 ]; then
                if [ $ins_des -eq 0 ]; then  # Count the single category occurrence per snippet
                    vuln="$vuln, Insecure Design"
                    let ins_des=ins_des+1
                fi
            fi
        fi

        # RULE 39: Detection of run(debugMode=true) Function
        # For example, a C++ web framework might have a run() method with a debug mode enabled.
        echo "$line" | grep -E -q -i "run\\( *debugMode *= *true *\\)"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]run\\("
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then  # Toggle the category variable for the specific snippet
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 40: Detection of FTP() Function
        # Looks for use of an FTP function/class, e.g., "ftplib::FTP(" or bare "FTP(".
        echo "$line" | grep -E -q -i "ftplib::FTP\\(|FTP\\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]FTP\\("
            if [ $? -eq 0 ]; then
                echo "$line" | grep -v -i -q " FTP()"
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then  # Toggle the category variable for the specific snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi

        # RULE 38: Detect insecure error handling patterns
        echo "$line" | grep -q -E '\b(std::cerr|std::cout|logError|LOG_ERR)\b.*\b(what\(|exception\.what\(|e\.what\(|catch\(.*exception)'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E '\b(sanitize|redact|secure_log)\b'
            if [ $? -eq 0 ]; then
                if [ $ins_des -eq 0 ]; then
                    vuln="$vuln, Insecure Error Handling"
                    let ins_des=ins_des+1
                fi
            fi
        fi

        # RULE 39: Detect debug mode configurations
        echo "$line" | grep -q -E '\b(_DEBUG|NDEBUG|DEBUG_MODE)\b.*=.*(true|1)|DEBUG.*defined'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E '//.*DEBUG|/\*.*DEBUG.*\*/'
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Debug Mode Enabled"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 40: Detect insecure FTP usage
        echo "$line" | grep -q -E '\b(curl_easy_setopt|ftp_connect)\b.*ftp://'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E 'ftps://|sftp://'
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Insecure FTP Protocol"
                    let crypto=crypto+1
                fi
            fi
        fi
        ###############################


        ###################################
        # RULE 41: Detection of SMTP() Function (C++ Variant)
        # For example, detecting calls to an SMTP client library, such as SMTPClient::send(...) or bare SMTP(...)
        echo "$line" | grep -E -q -i "SMTPClient::[A-Za-z0-9_]+\(|SMTP\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]SMTPClient::"
            if [ $? -eq 0 ]; then
                echo "$line" | grep -v -i -q " SMTPClient::"
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then   # Count only one occurrence per snippet
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi

        # RULE 42: Detection of SHA256() Function (C++ Variant)
        # For example, insecure direct use of SHA256(...) without proper precautions
        echo "$line" | grep -E -q -i "SHA256\(|sha256\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]SHA256\("
            if [ $? -eq 0 ]; then
                echo "$line" | grep -v -i -q " SHA256\("
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi
        # RULE 43: Detection of DSA_generate_parameters_ex() with a Bit Length <= 1024
        # An insecure key length for DSA key generation (should be >1024 bits)
        echo "$line" | grep -E -i -q "DSA_generate_parameters_ex\("
        if [ $? -eq 0 ]; then
            value=$(echo "$line" | awk -F "DSA_generate_parameters_ex\\(" '{print $2}' | awk -F ',' '{print $1}')
            # Assuming 'value' is numeric; flag if less than or equal to 1024
            if [ "$value" -le 1024 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 44: Detection of DES_set_key() Function (C++ Variant)
        # The use of DES is considered insecure.
        echo "$line" | grep -q -i "DES_set_key("
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi

        # RULE 45: Detection of SSL_wrap_socket() Function (C++ Variant)
        # Detect a wrapper function for SSL sockets that might be insecure.
        echo "$line" | grep -q -i "SSL_wrap_socket("
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi

        # RULE 41: Detect insecure SMTP usage
        echo "$line" | grep -q -E '\b(curl_easy_setopt|smtp_connect)\b.*smtp://'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E 'smtps://'
            if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
                vuln="$vuln, Insecure SMTP Protocol"
                let crypto=crypto+1
            fi
        fi

        # RULE 42: Detect insecure SHA-256 usage
        echo "$line" | grep -q -E '\b(SHA256_Init|EVP_sha256)\b.*\b(password|secret)\b'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E '\b(HMAC|PKCS5_PBKDF2_HMAC|EVP_BytesToKey)\b'
            if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
                vuln="$vuln, Insecure Hashing"
                let crypto=crypto+1
            fi
        fi

        # RULE 43: Detect weak DSA key generation
        echo "$line" | grep -q -E '\bDSA_generate_parameters\b.*\b(512|768|1024)\b'
        if [ $? -eq 0 ]; then
            key_size=$(echo "$line" | awk -F 'DSA_generate_parameters' '{print $2}' | tr -d '()' | awk -F ',' '{print $2}')
            if [ $key_size -le 1024 ] && [ $crypto -eq 0 ]; then
                vuln="$vuln, Weak DSA Key"
                let crypto=crypto+1
            fi
        fi

        # RULE 44: Detect DES usage
        echo "$line" | grep -q -E '\b(DES_encrypt|DES_cblock|EVP_des_)\b'
        if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
            vuln="$vuln, Insecure DES Algorithm"
            let crypto=crypto+1
        fi

        # RULE 45: Detect weak SSL/TLS configurations
        echo "$line" | grep -q -E '\b(SSLv23_method|SSL_CTX_new)\b.*SSLv3'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E 'TLS_method|SSL_CTX_set_min_proto_version'
            if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
                vuln="$vuln, Weak TLS Configuration"
                let crypto=crypto+1
            fi
        fi
        ###################################

        ###################################
        # RULE 46: detection of MD5 usage
        # Detects functions like MD5_Init, EVP_md5, or direct calls to MD5()
        echo "$line" | grep -E -q -i "MD5_Init|EVP_md5|MD5\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]MD5("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 47: detection of SHA1 usage
        # Detects SHA1_Init, EVP_sha1, or SHA1()
        echo "$line" | grep -E -q -i "SHA1_Init|EVP_sha1|SHA1\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]SHA1("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 48: detection of AES usage via OpenSSL or custom AES class
        # Detects `AES_set_encrypt_key`, `AES_encrypt`, or general `AES(...)`
        echo "$line" | grep -E -q -i "AES_set_encrypt_key|AES_encrypt|AES\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]AES("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 49: detection of CBC mode usage (e.g., EVP_CIPHER_CTX with CBC)
        # Examples: EVP_aes_128_cbc(), EVP_aes_256_cbc(), or MODE_CBC usage
        echo "$line" | grep -E -q -i "EVP_aes_.*_cbc|MODE_CBC|CBC\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "def CBC("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 50: detection of insecure PRNG - rand()/srand()
        # These are not suitable for crypto purposes
        echo "$line" | grep -E -q -i "rand\(|srand\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]rand("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi
        ###################################


        # RULE 46: Detect MD5 usage
        echo "$line" | grep -q -E '\b(MD5_Init|EVP_md5)\b'
        if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
            vuln="$vuln, Insecure MD5 Hashing"
            let crypto=crypto+1
        fi

        # RULE 47: Detect SHA1 usage
        echo "$line" | grep -q -E '\b(SHA1_Init|EVP_sha1)\b'
        if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
            vuln="$vuln, Insecure SHA1 Hashing"
            let crypto=crypto+1
        fi

        # RULE 48: Detect AES in insecure contexts
        echo "$line" | grep -q -E '\bEVP_aes_[0-9]+_ecb\b'
        if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
            vuln="$vuln, Insecure AES Mode (ECB)"
            let crypto=crypto+1
        fi

        # RULE 49: Detect CBC mode without authentication
        echo "$line" | grep -q -E '\bEVP_aes_[0-9]+_cbc\b'
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E '\b(EVP_CIPHER_CTX_ctrl|EVP_CTRL_AEAD)\b'
            if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
                vuln="$vuln, Unauthenticated CBC Mode"
                let crypto=crypto+1
            fi
        fi

        # RULE 50: Detect insecure random numbers
        echo "$line" | grep -q -E '\brand\s*\('
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q -E '\b(arc4random|RAND_bytes|std::random_device)\b'
            if [ $? -eq 0 ] && [ $crypto -eq 0 ]; then
                vuln="$vuln, Insecure Random Number Generation"
                let crypto=crypto+1
            fi
        fi
        ########################################


        ###################################
        # RULE 51: detection of std::rand() based selection (e.g., insecure random.choice equivalent)
        # This simulates Python's random.choice using rand() and index-based access
        echo "$line" | grep -E -q -i "rand\(\)|srand\(\)"
        if [ $? -eq 0 ]; then
            # Exclude secure alternatives like <random> with std::mt19937 or std::random_device
            echo "$line" | grep -v -q "random_device\|mt19937"
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 52: detection of bit-based RNG using rand() for bit manipulation (e.g., getrandbits)
        echo "$line" | grep -E -q -i "rand\(\)\s*%|\<\<\s*rand\(\)"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "random_device\|mt19937"
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 53: detection of custom or unsafe JWT parsing
        # Looks for functions like parse_jwt, decode_jwt, or similar without verification
        echo "$line" | grep -E -q -i "parse_jwt|decode_jwt|jwt_decode"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "verify_jwt\|jwt_verify"
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 54: detection of tmpnam(), tempnam() or mktemp() - unsafe temp file generation
        echo "$line" | grep -E -q -i "tmpnam\(|tempnam\(|mktemp\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "def mktemp\|define mktemp"
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        # RULE 55: detection of deprecated/unsafe time functions (e.g., time.clock)
        # Detect use of `clock()` that may be platform-specific or unsafe
        echo "$line" | grep -E -q -i "clock\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "def clock\|define clock"
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi
        ###################################

        ###################################
        # RULE 56: detection of boost::serialization or custom deserialization (pickle equivalent)
        # These may introduce unsafe object loading
        echo "$line" | grep -E -q -i "boost::archive::text_iarchive|boost::archive::binary_iarchive|load_from_file|deserialize|deserializeFrom"
        if [ $? -eq 0 ]; then
            if [ $soft_data -eq 0 ]; then
                vuln="$vuln, Software and Data Integrity Failures"
                let soft_data=soft_data+1
            fi
        fi

        # RULE 57: detection of insecure XML parsing (like xml.sax.make_parser without safe features)
        echo "$line" | grep -E -q -i "XMLParser|xmlParse|xmlCreatePushParserCtxt|SAXParser"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -v -q -i "noent|NONET|XML_PARSE_NOENT|XML_PARSE_NONET"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 58: detection of assert statements in production (security misconfig)
        echo "$line" | grep -E -q -i "\bassert\b"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "catch\s*\(.*AssertionError.*\)"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 59: detection of use of OpenSSL EVP_get_digestbyname (equiv to hashlib.new)
        echo "$line" | grep -E -q -i "EVP_get_digestbyname"
        if [ $? -eq 0 ]; then
            proto=$(echo "$line" | awk -F 'EVP_get_digestbyname\\(' '{print $2}' | awk -F '\\)' '{print $1}')
            echo "$proto" | grep -E -q -i "sha512|sha3_224|sha3_256|sha3_384|sha3_512"
            if [ $? -eq 1 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        # RULE 60: detection of PBKDF2 usage with weak hash (equivalent to weak pbkdf2_hmac use)
        echo "$line" | grep -E -q -i "PKCS5_PBKDF2_HMAC"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -v -q -i "SHA512|SHA3_224|SHA3_256|SHA3_384|SHA3_512"
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi
        ###################################


        ###################################
        # RULE 61: detection of parseUDPpacket() or similar insecure parsing
        echo "$line" | grep -E -q -i "parseUDPpacket\s*\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]parseUDPpacket\s*\("
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        # RULE 62: detection of system call with .bin file
        echo "$line" | grep -E -q -i "system\s*\(.*\.bin"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]system\s*\(.*\.bin"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 63: detection of exec/system-style injection (e.g., using system("..."))
        echo "$line" | grep -E -q -i "exec\s*\(|system\s*\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -q -i "import|std::system|execv|execl"
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Injection"
                    let inj=inj+1
                fi
            fi
        fi

        # RULE 64: detection of XML parsing via etree (equivalent: TinyXML, pugixml, etc.)
        echo "$line" | grep -E -q -i "tinyxml2::|pugi::xml_document|pugixml|xmlDoc"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -v -q -i "load_options::parse_default|XML_PARSE_NOENT|NONET"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 65: detection of privilege escalation pattern (e.g., setuid, seteuid)
        echo "$line" | grep -E -q -i "setuid\s*\(|seteuid\s*\(|seteuid\(0\).*setuid\(non"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -q -i "setuid\(0\).*setuid\([0-9]+\)"
            if [ $? -eq 0 ]; then
                if [ $ins_des -eq 0 ]; then
                    vuln="$vuln, Insecure Design"
                    let ins_des=ins_des+1
                fi
            fi
        fi


        ###################################


        ###################################
        # RULE 66: detection of insecure HTTPS (e.g., curl with -k or verify false)
        echo "$line" | grep -E -q -i "curl.* -k|CURLOPT_SSL_VERIFYPEER\s*=\s*0"
        if [ $? -eq 0 ]; then
            if [ $id_auth -eq 0 ]; then
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi

        # RULE 67: detection of chmod with insecure permissions
        echo "$line" | grep -E -q -i "chmod\s*\(.*,(.*777|.*755|.*0o777|.*0o755)"
        if [ $? -eq 0 ]; then
            if [ $sec_mis -eq 0 ]; then
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi

        # RULE 68: detection of setting cookies manually (esp. password/session ID in plain text)
        echo "$line" | grep -E -q -i "Set-Cookie:.*(password|session|token|auth)"
        if [ $? -eq 0 ]; then
            if [ $sec_mis -eq 0 ]; then
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi

        # RULE 69: detection of disabling cert verification in SSL context
        echo "$line" | grep -E -q -i "verify_mode\s*=\s*SSL_VERIFY_NONE"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -q -i "check_hostname\s*=\s*false"
            if [ $? -eq 0 ]; then
                if [ $id_auth -eq 0 ]; then
                    vuln="$vuln, Identification and Authentication Failures"
                    let id_auth=id_auth+1
                fi
            fi
        fi

        # RULE 70: detection of use of unverified SSL context (OpenSSL variants)
        echo "$line" | grep -E -q -i "SSL_CTX_set_verify\s*\(.*SSL_VERIFY_NONE"
        if [ $? -eq 0 ]; then
            if [ $id_auth -eq 0 ]; then
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi
        ###################################


        ###################################
        # RULE 71: detection of custom insecure SSL context creation
        echo "$line" | grep -E -q -i "SSL_CTX_new\(|SSL_new\("
        if [ $? -eq 0 ]; then
            if [ $id_auth -eq 0 ]; then
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi

        # RULE 72: detection of 'check_hostname = false' in SSL config
        echo "$line" | grep -E -q -i "check_hostname\s*=\s*false"
        if [ $? -eq 0 ]; then
            if [ $id_auth -eq 0 ]; then
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi

        # RULE 73: usage of insecure or specific SSL methods (e.g., TLSv1_2_METHOD)
        echo "$line" | grep -E -q -i "TLSv1_2_METHOD|TLSv1_method|SSLv3_method|SSLv2_method"
        if [ $? -eq 0 ]; then
            if [ $id_auth -eq 0 ]; then
                vuln="$vuln, Identification and Authentication Failures"
                let id_auth=id_auth+1
            fi
        fi

        # RULE 74: usage of insufficient entropy (e.g., small urandom buffers)
        echo "$line" | grep -E -q -i "rand_bytes\s*\(\s*(0|1|2|4|8|16|32)\s*\)|RAND_bytes\s*\(\s*[a-zA-Z0-9_]*,\s*(0|1|2|4|8|16|32)\s*\)"
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi

        # RULE 75: RSA key size less than 2048 bits
        echo "$line" | grep -E -q -i "RSA_generate_key\([^,]+,\s*(512|1024|1536|204[0-7])\s*,"
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi


        ###################################

        ###################################
        # RULE 76: Insecure JWT decode with verify false (simulated in C++)
        echo "$line" | grep -E -q -i "jwt::decode\(.*verify\s*=\s*false|jwt::decode\(.*verify=false"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]decode("
            if [ $? -eq 0 ]; then
                echo "$line" | grep -v -q "([a-zA-Z0-9]verify\s*=\s*false"
                if [ $? -eq 0 ]; then
                    if [ $crypto -eq 0 ]; then
                        vuln="$vuln, Cryptographic Failures"
                        let crypto=crypto+1
                    fi
                fi
            fi
        fi

        ###################################
        # RULE 77: decode JWT without verifying key
        echo "$line" | grep -E -q -i "jwt::decode\([a-zA-Z0-9_]*\)"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]decode("
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi

        ###################################
        # RULE 78: decode JWT with disabled signature verification via options
        echo "$line" | grep -q -i "jwt::decode\(.*,.*options\s*=\s*{[^}]*verify_signature[^}]*false"
        if [ $? -eq 0 ]; then
            if [ $crypto -eq 0 ]; then
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi

        ###################################
        # RULE 79: socket bound to 0.0.0.0 (insecure network exposure)
        echo "$line" | grep -P -q -i "\.bind\s*\(\s*.*\"0\.0\.0\.0\".*\)"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]bind\s*\(\s*\"0\.0\.0\.0\""
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        ###################################
        # RULE 80: XMLParser with entity resolution enabled or without options
        echo "$line" | grep -E -q -i "XMLParser\s*\(\s*resolve_entities\s*=\s*true\s*\)|XMLParser\s*\(\s*\)"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "[a-zA-Z0-9]XMLParser("
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi


        ##########    START SECURITY MISCONFIGURATION     ##########

        # RULE 80: Use of XML parsers vulnerable to XXE (e.g., TinyXML, pugixml)
        echo "$line" | grep -E -q -i "XMLDocument|load_file|parse"
        if [ $? -eq 0 ]; then
            echo "$line" | grep -v -q "XXE_DISABLED\|NOENT"
            if [ $? -eq 0 ]; then
                if [ $sec_mis -eq 0 ]; then
                    vuln="$vuln, Security Misconfiguration"
                    let sec_mis=sec_mis+1
                fi
            fi
        fi

        # RULE 81: Use of unsafe XSLT-style file loading
        echo "$line" | grep -E -q -i "read_network\s*=\s*true|write_network\s*=\s*true"
        if [ $? -eq 0 ]; then
            if [ $sec_mis -eq 0 ]; then
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi

        # RULE 82: chmod file.bin in C++ (e.g., using chmod() on sensitive binaries)
        echo "$line" | grep -E -q -i "chmod\s*\(\s*\"?[^\"]*\.bin\"?"
        if [ $? -eq 0 ]; then
            if [ $sec_mis -eq 0 ]; then
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi

        ##########    START SECURITY LOGGING AND MONITORING FAILURES    ##########

        # RULE 83: Loop without increment - risky while loops
        echo "$line" | grep -q -i "while\s*[^;]*<"
        if [ $? -eq 0 ]; then
            var=$(echo "$line" | awk -F "<" '{print $1}' | awk '{print $NF}')
            echo "$line" | grep -E -v -q "$var\s*\+\+|$var\s*+=\s*1|$var\s*=\s*$var\s*\+"
            if [ $? -eq 0 ]; then
                if [ $sec_log -eq 0 ]; then
                    vuln="$vuln, Security Logging and Monitoring Failures"
                    let sec_log=sec_log+1
                fi
            fi
        fi

        # RULE 84: Lock acquire without checking if locked (e.g., std::mutex usage)
        echo "$line" | grep -E -q -i "std::mutex\s+[a-zA-Z_0-9]+;.*\.lock\(\)"
        if [ $? -eq 0 ]; then
            var=$(echo "$line" | awk -F "std::mutex" '{print $2}' | awk '{print $1}')
            echo "$line" | grep -v -q "if\s*$var\.try_lock\(\)"
            if [ $? -eq 0 ]; then
                if [ $sec_log -eq 0 ]; then
                    vuln="$vuln, Security Logging and Monitoring Failures"
                    let sec_log=sec_log+1
                fi
            fi
        fi

        ##########    START BROKEN ACCESS CONTROL     ##########

        # RULE 85: File read without checking if file exists
        echo "$line" | grep -q -i "std::ifstream\s+[a-zA-Z0-9_]*\(.*\)\s*;.*\.read("
        if [ $? -eq 0 ]; then
            var=$(echo "$line" | awk -F "std::ifstream" '{print $2}' | awk '{print $1}')
            echo "$line" | grep -v -q "std::filesystem::exists\($var\)|access\($var"
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        ##################################
        
        ##################################################################################3
        
        # RULE 8F-CLUSTER-6 C++: Detect unsanitized user input in SQL queries (e.g., strcat, string +, sprintf with query)
        rule_cpp1='(SELECT|INSERT|UPDATE|DELETE)[^;]*["\"][^"\"]*(std::cin|gets|scanf|argv\[).*["\"]'
        rule_cpp2='(SELECT|INSERT|UPDATE|DELETE)[^;]*\+[^;]*(std::cin|gets|scanf|argv\[)'
        rule_cpp3='sprintf\s*\(.*(SELECT|INSERT|UPDATE|DELETE).*%s.*(std::cin|gets|scanf|argv\[)'
        rule_cpp4='(std::string|char\s+\*?)\s+\w+\s*=\s*.*(SELECT|INSERT|UPDATE|DELETE).*(std::cin|gets|scanf|argv\[)'

        regex_cpp="($rule_cpp1|$rule_cpp2|$rule_cpp3|$rule_cpp4)"

        if echo "$line" | grep -E -iq "$regex_cpp"; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        # RULE 18F CLUSTER-12 C++: Detect improper template escaping
        # Equivalent: rendering HTML without proper escaping
        if echo "$line" | grep -E -iq "render\(.+,(.+escape\s*=\s*false|escape\s*=\s*0)" ; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi



    fi
done < "$input"

# ===================== Final Prompt Output =========================

end=$(date +%s.%N)
runtime=$(awk -v start="$start" -v end="$end" 'BEGIN { print end - start }')

dimtestset=$(wc -l < "$input_file")
countvuln=$(grep -c "\[!\] VULNERABLE" "$output_file")

echo -e "\n"
echo -e "=================>          DATASET SIZE         <=================\n"
{ echo "#DimTestSet:"; echo $dimtestset; } | tr "\n" " ";
echo -e "\n\n"

echo -e "=================>    FINAL RESULTS DETECTION    <=================\n"
{ echo "#TotalVulnerabilities:"; echo $countvuln; } | tr "\n" " ";
echo -e "\n"
{ echo "#SafeCode:";  awk -v var1=$dimtestset -v var2=$countvuln 'BEGIN { if(var1!=0) { print  ( var1 - var2 )  } else {print 0} }'; } | tr "\n" " ";
echo -e "\n"
{ echo "Vulnerability Rate:"; awk -v var1=$countvuln -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) * 100 } else {print 0} }'; echo "%"; } | tr "\n" " ";
echo -e "\n\n"

echo -e "=================>        OWASP CATEGORIES       <=================\n"
{ echo "#Injection:"; echo $inj_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Cryptographic Failures:"; echo $crypto_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Security Misconfiguration:"; echo $sec_mis_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Broken Authentication:"; echo $bac_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Identification and Authentication Failures:"; echo $id_auth_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Insecure Design:"; echo $ins_des_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Vulnerable Components:"; echo $vuln_comp_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Security Logging and Monitoring Failures:"; echo $sec_log_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Software and Data Integrity Failures:"; echo $soft_data_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#SSRF:"; echo $ssrf_count; } | tr "\n" " ";
echo -e "\n\n"

echo -e "=================>        EXECUTION TIME        <=================\n"
{ echo "Runtime:"; echo $runtime; echo "s"; } | tr "\n" " ";
echo -e "\n"
{ echo "Average runtime per snippet:"; awk -v var1=$runtime -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) } else {print 0} }'; echo "s"; } | tr "\n" " ";
echo -e "\n"

