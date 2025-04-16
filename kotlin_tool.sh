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

        # RULE 1: Detects user input concatenated unsafely (SQL/command/log injection)
        echo $line | grep -E -q "\+.*request\.getParameter\(|\+.*@RequestParam\("
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then
              vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi


        # RULE 2: Detects unsafe access to files/DBs without validation
        echo $line | grep -E -q "File\(.*\+.*@RequestParam|@GetMapping\(\".*\{.*\}" | grep -E -v "@PreAuthorize|@Secured"
        if [ $? -eq 0 ]; then
            if [ $bac -eq 0 ]; then
               vuln="$vuln, Broken Access Control"
                   let bac=bac+1
            fi
        fi

        # RULE 3: Detects unsanitized POST data usage (e.g., format strings)
echo $line | grep -E -q "@PostMapping.*@RequestBody.*String.format|\"\\$\{.*@RequestBody\"" 
if [ $? -eq 0 ]; then
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

      # RULE 4: Detects unsafe HTTP calls (SSRF) or auth-sensitive data exposure
echo $line | grep -E -q "RestTemplate\(\)\.getForObject\(|WebClient\.create\(\).get\(\).uri\(|java\.net\.URL\(|httpClient\.execute\(|@Value\(\"\${http:\/\/.*}\"\)" | grep -E -v "@PreAuthorize|@Secured|\"https://trusted\.com\""
if [ $? -eq 0 ]; then
    if [ $ssrf -eq 0 ]; then
        vuln="$vuln, SSRF"
        let ssrf=ssrf+1
    fi
    if [ $auth -eq 0 ]; then
        vuln="$vuln, Authentication Failures"
        let auth=auth+1
    fi
fi

     # RULE 5: Detects direct return of unsafe HTTP calls (SSRF/Auth exposure)
     echo $line | grep -E -q "return RestTemplate\(\)\.|return WebClient\.|return java\.net\.URL\(|return httpClient\.execute\(|@GetMapping.*return.*@RequestParam.*http" | grep -E -v "@PreAuthorize|@Secured|\"https://trusted\.com\""
if [ $? -eq 0 ]; then
    if [ $ssrf -eq 0 ]; then
        vuln="$vuln, SSRF"
        let ssrf=ssrf+1
    fi
    if [ $auth -eq 0 ]; then
        vuln="$vuln, Authentication Failures"
        let auth=auth+1
    fi
fi


# RULE 6: Detects unsafe handling of user input (readLine(), Scanner, args)
echo $line | grep -E -q "readLine\(\)|Scanner\(System\.in\)|args\[[0-9]+\]" | grep -E -v "\.toIntOrNull\(\)|\.filter\(|Regex\(\"\\\\d+\"\)|@Valid|@Size\(|@Pattern\("
if [ $? -eq 0 ]; then
    # Check for unsafe usage patterns
    echo $line | grep -E -q "\+.*readLine\(\)|\+.*args\[|\+.*Scanner\(|String\.format\(.*readLine\(\)|String\.format\(.*args\["
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

# RULE 7: Detects unsafe handling of user input in Kotlin
echo $line | grep -E -q "readLine\(\)(\s*!!)?|args\[[0-9]+\]|Scanner\(System\.in\)\.next\w+\(\)" | grep -E -v "\.toIntOrNull\(\)|\.filter\(|@Valid|@Size\(|@Pattern\("
if [ $? -eq 0 ]; then
    # Check for dangerous usage patterns
    echo $line | grep -E -q "\+.*(readLine\(\)|args\[|\b${var}\b)|String\.format\(.*(readLine\(\)|args\[)"
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

# RULE 8: Detects unsafe LDAP server configurations
echo $line | grep -E -q "LdapContext\(|InitialLdapContext\(|DirContext\(|javax\.naming\.directory\.InitialDirContext\(" | grep -E -v "SSL|TLS|startTls\(\)|com\.sun\.jndi\.ldap\.LdapCtxFactory"
if [ $? -eq 0 ]; then
    # Check for unencrypted LDAP connections
    echo $line | grep -q "ldap://" 
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, LDAP Injection"
            let inj=inj+1
        fi
        if [ $encrypt -eq 0 ]; then
            vuln="$vuln, Missing Encryption"
            let encrypt=encrypt+1
        fi
    fi
fi


# RULE 9: Detects unsafe LDAP search operations
echo $line | grep -E -q "\.search\(|\.searchControls\(|new SearchControls\(|DirContext\.search\(" | grep -E -v "searchScope|RETURN_OBJECT|OBJECT_SCOPE"
if [ $? -eq 0 ]; then
    # Check for common LDAP injection patterns
    echo $line | grep -E -q "\+.*@RequestParam|\+.*getParameter|\"\\$\{.*@RequestParam\""
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, LDAP Injection"
            let inj=inj+1
        fi
    fi
    
    # Check for excessive result return limits
    echo $line | grep -q "SearchControls\(.*, 0,"
    if [ $? -eq 0 ]; then
        if [ $config -eq 0 ]; then
            vuln="$vuln, Excessive Data Exposure"
            let config=config+1
        fi
    fi
fi

# RULE 10: Detects unsafe request parameter comparisons
echo $line | grep -E -q "@RequestParam.*==|@PathVariable.*==|request\.getParameter.*==" | grep -E -v "@PreAuthorize|@Secured|matches\\(|Regex\\("
if [ $? -eq 0 ]; then
    # Check for direct comparison without validation
    echo $line | grep -E -q "==\\s*[a-zA-Z0-9_]+\\s*$|==\\s*[a-zA-Z0-9_]+\\s*[;)]"
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

# RULE 11: Detects unsafe URL parsing and handling
echo $line | grep -E -q "java\.net\.URL\(|URI\.create\(|URLEncoder\.encode\(|URLDecoder\.decode\(" | grep -E -v "https?://trusted\.com|URI\.create\(\".*\"\)\.normalize\(\)"
if [ $? -eq 0 ]; then
    # Check for user input in URL construction
    echo $line | grep -E -q "\+.*@RequestParam|\+.*getParameter|\"\\$\{.*@RequestParam\""
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, URL Injection"
            let inj=inj+1
        fi
        if [ $ssrf -eq 0 ]; then
            vuln="$vuln, SSRF"
            let ssrf=ssrf+1
        fi
    fi
    
    # Check for improper encoding
    echo $line | grep -q "URLDecoder\.decode\(.*getParameter"
    if [ $? -eq 0 ]; then
        if [ $xss -eq 0 ]; then
            vuln="$vuln, XSS"
            let xss=xss+1
        fi
    fi
fi

# RULE 12: Detects unsafe URL method chaining
echo $line | grep -P -q "(java\.net\.URL|URI)\(.*?\)\.[a-zA-Z]*" | grep -E -v "toString\(\)|normalize\(\)|toASCIIString\(\)"
if [ $? -eq 0 ]; then
    # Check for dangerous method calls
    echo $line | grep -P -q "\.(getPath\(\)|getQuery\(\)|getHost\(\)|openConnection\(\)|getContent\(\))"
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, URL Injection"
            let inj=inj+1
        fi
        if [ $ssrf -eq 0 ]; then
            vuln="$vuln, SSRF"
            let ssrf=ssrf+1
        fi
    fi
fi

# RULE 13: Detects unsafe URL returns
echo $line | grep -q "return URL\(|return URI\(|return java\.net\.URL\(|return java\.net\.URI\("
if [ $? -eq 0 ]; then
    # Check if URL contains user input
    echo $line | grep -E -q "\+.*(request\.|@RequestParam|getParameter)"
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, URL Injection"
            let inj=inj+1
        fi
        if [ $ssrf -eq 0 ]; then
            vuln="$vuln, SSRF"
            let ssrf=ssrf+1
        fi
    fi
fi

# RULE 14: Detects unsafe session handling patterns
echo $line | grep -E -q "session\[|session\.getAttribute\(|request\.session|\@SessionAttribute" | grep -E -v "\.setAttribute\(|\@PreAuthorize|\@Secured|SecurityContextHolder"
if [ $? -eq 0 ]; then
    # Check for session fixation/ID exposure
    echo $line | grep -E -q "session\[.*user.*\]|session\[.*id.*\]|session\[.*token.*\]"
    if [ $? -eq 0 ]; then
        if [ $auth -eq 0 ]; then
            vuln="$vuln, Authentication Failure"
            let auth=auth+1
        fi
    fi
    
    # Check for sensitive data in session
    echo $line | grep -E -qi "session\[.*(pass|credit|secret|auth)"
    if [ $? -eq 0 ]; then
        if [ $data -eq 0 ]; then
            vuln="$vuln, Sensitive Data Exposure"
            let data=data+1
        fi
    fi
    
    # Check for session ID in URLs/logs
    echo $line | grep -E -q "session\[.*\] \+|\+ session\[.*\]|println\(session\[|logger\.info\(session\["
    if [ $? -eq 0 ]; then
        if [ $log -eq 0 ]; then
            vuln="$vuln, Security Logging Failure"
            let log=log+1
        fi
    fi
fi

# RULE 15: Detects unsafe request parameter handling in Spring/Kotlin
echo $line | grep -E -q "@RequestParam|@PathVariable|request\.getParameter" | grep -E -v "@Valid|@Size|@Pattern|@PreAuthorize"
if [ $? -eq 0 ]; then
    # Check for dangerous parameter usage patterns
    echo $line | grep -E -q "\+\s*@RequestParam|\+\s*@PathVariable|\+\s*request\.getParameter|\"\s*\\$\{\s*@RequestParam"
    if [ $? -eq 0 ]; then
        # Exclude safe validation patterns
        echo $line | grep -E -v -q "matches\\(|Regex\\("
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
    
    # Check for direct sensitive operations
    echo $line | grep -E -q "@RequestParam.*\.execute\\(|@RequestParam.*File\\(|@RequestParam.*Runtime\.getRuntime\\(|@RequestParam.*ProcessBuilder"
    if [ $? -eq 0 ]; then
        if [ $cmd -eq 0 ]; then
            vuln="$vuln, Command Injection"
            let cmd=cmd+1
        fi
    fi
fi

# RULE 16: Detects unsafe JSON request handling in Spring/Kotlin
echo $line | grep -E -q "@RequestBody|request\.body|ObjectMapper\.readValue" | grep -E -v "@Valid|@Schema|@JsonFormat|JsonParser\."
if [ $? -eq 0 ]; then
    # Check for dangerous JSON parsing patterns
    echo $line | grep -E -q "\+.*@RequestBody|\+.*request\.body|\"\\$\{.*@RequestBody\""
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection"
            let inj=inj+1
        fi
    fi
    
    # Check for direct deserialization
    echo $line | grep -E -q "ObjectMapper\.readValue\(.*@RequestBody|ObjectMapper\.readValue\(.*request\.body"
    if [ $? -eq 0 ]; then
        if [ $des -eq 0 ]; then
            vuln="$vuln, Unsafe Deserialization"
            let des=des+1
        fi
    fi
    
    # Check for sensitive field exposure
    echo $line | grep -E -qi "@RequestBody.*(password|token|secret)"
    if [ $? -eq 0 ]; then
        if [ $data -eq 0 ]; then
            vuln="$vuln, Sensitive Data Exposure"
            let data=data+1
        fi
    fi
fi

# RULE 17: Detects unsafe return of request parameters
echo $line | grep -E -q "return @RequestParam|return request\.getParameter|return params\[" | grep -E -v "@ResponseBody|@RestController|@Valid"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
    if [ $data -eq 0 ]; then
        vuln="$vuln, Sensitive Data Exposure"
        let data=data+1
    fi
fi

# RULE 18: Detects unsafe return of request arrays/maps
echo $line | grep -E -q "return request\.parameterMap|return request\.getParameterValues|return request\.getQueryString" | grep -E -v "@ResponseBody|@RestController"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
    if [ $data -eq 0 ]; then
        vuln="$vuln, Sensitive Data Exposure"
        let data=data+1
    fi
fi


        
