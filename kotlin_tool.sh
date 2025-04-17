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

        # RULE 19: Detects unsafe file upload handling
echo $line | grep -E -q "@RequestPart|MultipartFile|request\.parts|request\.getParts" | grep -E -v "@Valid|@Size|@Pattern|@PreAuthorize"
if [ $? -eq 0 ]; then
    # Check for dangerous file operations
    echo $line | grep -E -q "\.transferTo\(|\.bytes|\.inputStream|Files\.copy\(.*MultipartFile"
    if [ $? -eq 0 ]; then
        # Exclude safe validation patterns
        echo $line | grep -E -v -q "FilenameUtils\.getExtension|FileTypeValidator|\.contentType\.matches\("
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
    
    # Check for path traversal patterns
    echo $line | grep -E -q "File\(.*\+.*@RequestPart|Path\.of\(.*\+.*MultipartFile"
    if [ $? -eq 0 ]; then
        if [ $traversal -eq 0 ]; then
            vuln="$vuln, Path Traversal"
            let traversal=traversal+1
        fi
    fi
fi

# RULE 20: Detects unsafe return of request data
echo $line | grep -E -q "return request\.body|return request\.content|return request\.inputStream|return request\.reader" | grep -E -v "@ResponseBody|@RestController|@Valid"
if [ $? -eq 0 ]; then
    # Check for sensitive data exposure
    echo $line | grep -E -qi "return.*(password|token|secret|credit_card)"
    if [ $? -eq 0 ]; then
        if [ $data -eq 0 ]; then
            vuln="$vuln, Sensitive Data Exposure"
            let data=data+1
        fi
    fi
    
    # Check for raw data return
    echo $line | grep -E -q "return String\(request\.body\)|return request\.inputStream\.readAllBytes\(\)"
    if [ $? -eq 0 ]; then
        if [ $sec_mis -eq 0 ]; then
            vuln="$vuln, Security Misconfiguration"
            let sec_mis=sec_mis+1
        fi
    fi
fi

# RULE 21: Detects unsafe request data handling in Spring/Kotlin
echo $line | grep -E -q "request\.body|request\.content|request\.inputStream|request\.reader|HttpEntity|RequestBody" | grep -E -v "@Valid|@ResponseBody|@RestController"
if [ $? -eq 0 ]; then
    # Check for dangerous data handling patterns
    echo $line | grep -E -q "\+.*request\.body|\+.*request\.content|\"\\$\{.*request\.body\""
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection"
            let inj=inj+1
        fi
    fi
    
    # Check for direct deserialization
    echo $line | grep -E -q "ObjectMapper\.readValue\(.*request\.body|JsonParser\.parse\(.*request\.content"
    if [ $? -eq 0 ]; then
        if [ $des -eq 0 ]; then
            vuln="$vuln, Unsafe Deserialization"
            let des=des+1
        fi
    fi
    
    # Check for sensitive data exposure
    echo $line | grep -E -qi "request\.body.*(password|token|secret)"
    if [ $? -eq 0 ]; then
        if [ $data -eq 0 ]; then
            vuln="$vuln, Sensitive Data Exposure"
            let data=data+1
        fi
    fi
fi

# RULE 22: Detects unsafe environment variable and JSON handling
echo $line | grep -E -q "System\.getenv\(|environment\.getProperty\(|ObjectMapper\(\)\.readValue\(|JsonParser\(\)\.parse\(" | grep -E -v "@Value\(\"\${[A-Z_]+\}\"\)|@ConfigurationProperties|JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES"
if [ $? -eq 0 ]; then
    # Check for sensitive environment variables
    echo $line | grep -E -qi "(System\.getenv|environment\.getProperty)\(\"(API_KEY|SECRET|PASSWORD|TOKEN)\""
    if [ $? -eq 0 ]; then
        if [ $sec_mis -eq 0 ]; then
            vuln="$vuln, Security Misconfiguration"
            let sec_mis=sec_mis+1
        fi
    fi
    
    # Check for unsafe JSON parsing
    echo $line | grep -E -q "ObjectMapper\(\)\.readValue\(.*, String::class\.java\)|JsonParser\(\)\.parse\(.*\)\.asText\(\)"
    if [ $? -eq 0 ]; then
        if [ $des -eq 0 ]; then
            vuln="$vuln, Unsafe Deserialization"
            let des=des+1
        fi
    fi
    
    # Check for raw environment variable concatenation
    echo $line | grep -E -q "\+.*System\.getenv\(|\+.*environment\.getProperty\("
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection"
            let inj=inj+1
        fi
    fi
fi

# RULE 23: Detects unsafe JSON parsing in Kotlin
echo $line | grep -E -q "ObjectMapper\(\)\.readValue\(|JsonParser\(\)\.parse\(|Gson\(\)\.fromJson\(" | grep -E -v "@Valid|@JsonFormat|JsonParser.Feature|TypeReference"
if [ $? -eq 0 ]; then
    # Check for direct parsing of untrusted input
    echo $line | grep -E -q "ObjectMapper\(\)\.readValue\(.*(request\.body|@RequestParam|@RequestBody|getParameter)"
    if [ $? -eq 0 ]; then
        if [ $des -eq 0 ]; then
            vuln="$vuln, Unsafe Deserialization"
            let des=des+1
        fi
    fi
    
    # Check for polymorphic type handling (Jackson Databind vulnerability)
    echo $line | grep -E -q "@JsonTypeInfo|enableDefaultTyping\(|activateDefaultTyping\("
    if [ $? -eq 0 ]; then
        if [ $sec_mis -eq 0 ]; then
            vuln="$vuln, Security Misconfiguration"
            let sec_mis=sec_mis+1
        fi
    fi
    
    # Check for direct string parsing without validation
    echo $line | grep -E -q "JsonParser\(\)\.parse\(.*\)\.asText\(\)|Gson\(\)\.fromJson\(.*, String::class\.java\)"
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection"
            let inj=inj+1
        fi
    fi
fi

# RULE 24: Detects unsafe function parameter handling in Kotlin
echo $line | grep -E -q "fun [[:alnum:]_]+\\\(" | while read -r line; do
    # Extract function parameters
    params=$(echo "$line" | sed -n 's/.*fun[[:space:]]\+[[:alnum:]_]\+\(([^)]*)\).*/\1/p' | tr -d '()' | tr ',' '\n')
    
    # Check each parameter
    echo "$params" | while read -r param; do
        # Clean parameter (remove types, modifiers, etc.)
        clean_param=$(echo "$param" | awk -F: '{print $1}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Skip empty or constructor parameters
        [ -z "$clean_param" ] && continue
        [[ "$clean_param" == *"constructor"* ]] && continue
        
        # Check for dangerous usage patterns
        echo "$line" | grep -E -q "($clean_param\\.)?(execute|run|eval|system|exec)\\("
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi
        
        # Check for direct SQL usage
        echo "$line" | grep -E -q "($clean_param\\.)?(createStatement|executeQuery|prepareStatement)\\("
        if [ $? -eq 0 ]; then
            if [ $sql -eq 0 ]; then
                vuln="$vuln, SQL Injection"
                let sql=sql+1
            fi
        fi
        
        # Check for sensitive data handling
        echo "$clean_param" | grep -E -qi "password|secret|token|key"
        if [ $? -eq 0 ]; then
            if [ $data -eq 0 ]; then
                vuln="$vuln, Sensitive Data Exposure"
                let data=data+1
            fi
        fi
    done
done

# RULE 25: Detects unsafe request parameter array concatenation
echo $line | grep -E -q "\\+.*request\\.(parameterMap|getParameterValues|getParameterNames|getQueryString)\\[" | grep -E -v "@Valid|@Size|@Pattern"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

# RULE 26: Detects unsafe request parameter getter concatenation
echo $line | grep -E -q "\\+.*request\\.(getParameter|getHeader|getAttribute|getCookies)\\(" | grep -E -v "@Valid|@Size|@Pattern"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

# RULE 27: Detects unsafe string formatting with request data
echo $line | grep -E -q "\"\\$\{.*(request\.|@RequestParam|@PathVariable|@RequestHeader|@RequestBody)" | grep -E -v "@Valid|@Size|@Pattern"
if [ $? -eq 0 ]; then
    # Check for dangerous formatting patterns
    echo $line | grep -E -q "\"\\$\{.*(getParameter|parameterMap|getHeader|getAttribute)"
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection"
            let inj=inj+1
        fi
        if [ $sec_mis -eq 0 ]; then
            vuln="$vuln, Security Misconfiguration"
            let sec_mis=sec_mis+1
        fi
    fi
    
    # Check for sensitive data exposure
    echo $line | grep -E -qi "\"\\$\{.*(password|secret|token|key)"
    if [ $? -eq 0 ]; then
        if [ $data -eq 0 ]; then
            vuln="$vuln, Sensitive Data Exposure"
            let data=data+1
        fi
    fi
fi

# RULE 28: Detects unsafe request parameter usage in parentheses
echo $line | grep -E -q "\\( *request\\.(getParameter|getParameterValues|getHeader|getAttribute)\\(" | grep -E -v "@Valid|@Size|@Pattern"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

# RULE 29: Detects unsafe request parameter usage in format strings
echo $line | grep -E -q "% *request\\.(getParameter|getHeader|getAttribute)\\(" | grep -E -v "@Valid|@Size|@Pattern"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

# RULE 13F: Detects unsafe context variable usage in Spring/Kotlin
echo $line | grep -E -q "model\.addAttribute\\(.*(request\.|session\.|servletContext\.)" | grep -E -v "@ModelAttribute|@Valid"
if [ $? -eq 0 ]; then
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
fi

# Check for direct request/session access in views
echo $line | grep -E -q "Thymeleaf.*\\.(request|session|servletContext)\\." | grep -E -v "th:if|th:unless"
if [ $? -eq 0 ]; then
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

# RULE 30: Detects unsafe HTML handling
echo $line | grep -E -q "StringEscapeUtils\.unescapeHtml|HtmlUtils\.htmlUnescape" | grep -E -v "StringEscapeUtils\.escapeHtml|HtmlUtils\.htmlEscape"
if [ $? -eq 0 ]; then
    if [ $xss -eq 0 ]; then
        vuln="$vuln, Cross-Site Scripting (XSS)"
        let xss=xss+1
    fi
fi

# RULE 31: Detects direct input usage in functions
echo $line | grep -E -q "fun [a-zA-Z0-9_]+\(.*readLine\\(\\).*\)"
if [ $? -eq 0 ]; then
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

# RULE 32: Detects unsafe CSV handling
echo $line | grep -E -q "CSVReader|CSVWriter" | grep -E -v "CSVFormat\.RFC4180|CSVPrinter"
if [ $? -eq 0 ]; then
    if [ $csv -eq 0 ]; then
        vuln="$vuln, CSV Injection"
        let csv=csv+1
    fi
fi

# RULE 33: Detects unsafe process execution
echo $line | grep -E -q "Runtime\.getRuntime\\(\\)\\.exec\\(|ProcessBuilder\\(" | grep -E -v "waitFor\\(|inputStream"
if [ $? -eq 0 ]; then
    if [ $cmd -eq 0 ]; then
        vuln="$vuln, Command Injection"
        let cmd=cmd+1
    fi
fi

# RULE 34: Detects unsafe YAML deserialization
echo $line | grep -E -q "Yaml\\(\\)\\.load\\(|ObjectMapper\\(\\)\\.readValue\\(.*YAML" | grep -E -v "SafeConstructor|TypeSafeConstructor"
if [ $? -eq 0 ]; then
    if [ $des -eq 0 ]; then
        vuln="$vuln, Unsafe Deserialization"
        let des=des+1
    fi
    if [ $data -eq 0 ]; then
        vuln="$vuln, Software and Data Integrity Failures"
        let data=data+1
    fi
fi

# RULE 35: Detects dynamic code evaluation
echo $line | grep -E -q "ScriptEngine\\.eval\\(|GroovyShell\\(\\)\\.evaluate\\("
if [ $? -eq 0 ]; then
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

# RULE 36: Detects unsafe process execution
echo $line | grep -E -q "Runtime\\.getRuntime\\(\\)\\.exec\\(|ProcessBuilder\\(" | grep -E -v "waitFor\\(|inputStream"
if [ $? -eq 0 ]; then
    if [ $cmd -eq 0 ]; then
        vuln="$vuln, Command Injection"
        let cmd=cmd+1
    fi
fi

# RULE 37: Detects shell command execution
echo $line | grep -E -q "arrayOf\\(\"/bin/sh\", \"-c\"" | grep -E -v "Pattern\\.compile"
if [ $? -eq 0 ]; then
    if [ $cmd -eq 0 ]; then
        vuln="$vuln, Command Injection"
        let cmd=cmd+1
    fi
fi

#RULE 38: detection of printStackTrace() without proper logging control
        var=$(echo $line | awk -F "printStackTrace\\\(" '{print $1}' |  awk '{print $NF}')
        if [ -z "$var" ]; then
                pass=1;
        else
            if [ $var == "=" ]; then
                var=$(echo $line | awk -F "printStackTrace\\\(" '{print $1}' | awk '{print $(NF-1)}')
            else
                last_char=$(echo "${var: -1}")
                if [ $last_char == "=" ]; then
                    if [ $name_os = "Darwin" ]; then  #MAC-OS system
                        var=${var:0:$((${#var} - 1))}
                    elif [ $name_os = "Linux" ]; then #LINUX system
                        var=${var::-1}
                    fi
                fi            
            fi   
            ### CHECK  
            echo $line | grep -E -q -i "return $var\.printStackTrace\(\)|println\($var\.printStackTrace\(\)\)|Log\.d\(.*$var\.printStackTrace\(\)\)|Log\.e\(.*$var\.printStackTrace\(\)\)"
            if [ $? -eq 0 ]; then 
                if [ $ins_des -eq 0 ]; then
                    vuln="$vuln, Insecure Design"
                    let ins_des=ins_des+1
                fi
            fi
        fi

        #RULE 39: detection of debug mode enabled in Android
        echo $line | grep -E -q -i "\.setDebuggable\(true\)|\.debuggable *= *true|android:debuggable *= *[\"']true[\"']"
        if [ $? -eq 0 ]; then
            if [ $sec_mis -eq 0 ]; then
                vuln="$vuln, Security Misconfiguration"
                let sec_mis=sec_mis+1
            fi
        fi

        #RULE 40: detection of insecure HTTP protocol usage
        echo $line | grep -E -q -i "HttpURLConnection|http://|\.setAllowUnsafeConnections\(true\)"
        if [ $? -eq 0 ]; then
            echo $line | grep -v -q -i "HttpsURLConnection|https://"
            if [ $? -eq 0 ]; then
                if [ $crypto -eq 0 ]; then
                    vuln="$vuln, Cryptographic Failures"
                    let crypto=crypto+1
                fi
            fi
        fi
        
        #RULE NEW: detection of hardcoded sensitive information
        echo $line | grep -E -q -i "password *= *[\"'].*[\"']|apiKey *= *[\"'].*[\"']|secret *= *[\"'].*[\"']"
        if [ $? -eq 0 ]; then
            if [ $cred -eq 0 ]; then
                vuln="$vuln, Credential Exposure"
                let cred=cred+1
            fi
        fi

        #RULE 41: detection of javax.mail.Transport without SSL
echo $line | grep -E -q -i "javax\.mail\.Transport\.send\(|java\.mail\.Transport\.send\(|Properties\.put\(\"mail\.smtp\.starttls\.enable\", \"false\"\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q -i "mail\.smtp\.ssl\.enable.*true|mail\.smtp\.starttls\.enable.*true"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

#RULE 42: detection of MessageDigest with weak algorithms
echo $line | grep -E -q -i "MessageDigest\.getInstance\(\"SHA-256\"\)|DigestUtils\.sha256\("
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "\.update\(.*salt\)|\.update\(.*SALT\)"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

        #RULE 43: detection of weak key sizes in KeyPairGenerator
echo $line | grep -E -i -q "KeyPairGenerator\.initialize\((512|768|1024)\)|KeyPairGenerator\.getInstance\(\"DSA\"\)\.initialize\((512|768|1024)\)"
if [ $? -eq 0 ]; then
    value=$(echo $line | awk -F 'initialize\\(' '{print $2}' | awk -F ')' '{print $1}')
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

#RULE 44: detection of deprecated crypto algorithms
echo $line | grep -E -q -i "Cipher\.getInstance\(\"DES/|KeyGenerator\.getInstance\(\"DES\"\)|SecretKeySpec\(.*,\"DES\"\)"
if [ $? -eq 0 ]; then
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

#RULE 45: detection of insecure SSL/TLS configurations
echo $line | grep -E -q -i "SSLContext\.getInstance\(\"TLSv1\"\)|SSLSocketFactory\.getInsecure\(\)|setHostnameVerifier\(.*ALLOW_ALL_HOSTNAME_VERIFIER\)"
if [ $? -eq 0 ]; then
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

#RULE extra: detection of cleartext traffic allowed
echo $line | grep -q -i "android:usesCleartextTraffic=\"true\""
if [ $? -eq 0 ]; then
    echo $line | grep -v -q -i "networkSecurityConfig"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

        #RULE 47: detection of SHA-1 MessageDigest
echo $line | grep -E -q -i "MessageDigest\.getInstance\(\"SHA-1\"\)|DigestUtils\.sha1\("
if [ $? -eq 0 ]; then
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

        #RULE 48: detection of AES with ECB mode or without IV
echo $line | grep -E -q -i "Cipher\.getInstance\(\"AES/ECB\"\)|SecretKeySpec\(.*\"AES\"\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "IvParameterSpec"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

#RULE 49: detection of CBC mode with static IV
echo $line | grep -E -q -i "Cipher\.getInstance\(\"AES/CBC\"\)|Cipher\.getInstance\(\"DES/CBC\"\)"
if [ $? -eq 0 ]; then
    echo $line | grep -E -q -i "IvParameterSpec\(\"0000000000000000\"\)|IvParameterSpec\(new byte\[16\]\)"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

#RULE 50: detection of java.util.Random usage
echo $line | grep -E -q -i "new Random\(\)|Random\.next"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "SecureRandom"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

#RULE 51: detection of insecure random selection
echo $line | grep -E -q -i "Random\(\).nextInt\(|Random\(\).nextLong\(|Random\.next"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "SecureRandom"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

#RULE 52: detection of insecure random bit generation
echo $line | grep -E -q -i "Random\(\).nextBytes\(|Random\(\).nextInt\(.*\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "SecureRandom"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

#RULE 53: detection of insecure JWT processing
echo $line | grep -E -q -i "JWT\.decode\(|JWT\.parse\(|DefaultJwtParser\(\).parse\("
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "JWT\.require\(|Jwts\.parser\(\)\.setSigningKey"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

#RULE 54: detection of insecure temporary file creation
echo $line | grep -E -q -i "File\.createTempFile\(|\.createTempFile\("
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "\.deleteOnExit\(\)"
    if [ $? -eq 0 ]; then
        if [ $bac -eq 0 ]; then
            vuln="$vuln, Broken Access Control"
            let bac=bac+1
        fi
    fi
fi

#RULE 55: detection of System.currentTimeMillis() for security
echo $line | grep -E -q -i "System\.currentTimeMillis\(\)|System\.nanoTime\(\)"
if [ $? -eq 0 ]; then
    echo $line | grep -q -i "tokenExpiration|sessionTimeout"
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection"
            let inj=inj+1
        fi
    fi
fi

#RULE 56: detection of insecure ObjectInputStream usage
echo $line | grep -E -q -i "ObjectInputStream\(|ObjectOutputStream\("
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "readObject\(\)\.getClass\(\)\.getName\(\)"
    if [ $? -eq 0 ]; then
        if [ $soft_data -eq 0 ]; then
            vuln="$vuln, Software and Data Integrity Failures"
            let soft_data=soft_data+1
        fi
    fi
fi

#RULE 57: detection of insecure XML parsing
echo $line | grep -E -q -i "DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "setFeature\(\"http://xml.org/sax/features/external-general-entities\", false\)"
    if [ $? -eq 0 ]; then
        if [ $sec_mis -eq 0 ]; then
            vuln="$vuln, Security Misconfiguration"
            let sec_mis=sec_mis+1
        fi
    fi
fi

#RULE 58: detection of Java assertions
echo $line | grep -E -q -i "assert [a-zA-Z]"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
fi

#RULE 59: detection of weak MessageDigest algorithms
echo $line | grep -E -q -i "MessageDigest\.getInstance\(\"MD[245]\"\)|MessageDigest\.getInstance\(\"SHA-1\"\)"
if [ $? -eq 0 ]; then
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

#RULE 60: detection of weak PBKDF2 configurations
echo $line | grep -E -q -i "SecretKeyFactory\.getInstance\(\"PBKDF2WithHmac"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "PBKDF2WithHmacSHA512|PBKDF2WithHmacSHA384"
    if [ $? -eq 0 ]; then
        iterations=$(echo $line | grep -o "iterationCount = [0-9]*" | awk '{print $3}')
        if [ -z "$iterations" ] || [ $iterations -lt 10000 ]; then
            if [ $crypto -eq 0 ]; then
                vuln="$vuln, Cryptographic Failures"
                let crypto=crypto+1
            fi
        fi
    fi
fi

#RULE 61: detection of raw DatagramPacket processing
echo $line | grep -E -q -i "DatagramPacket\(|DatagramSocket\("
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "checkCallingOrSelfPermission\(\"android\.permission\.INTERNET\"\)"
    if [ $? -eq 0 ]; then
        if [ $bac -eq 0 ]; then
            vuln="$vuln, Broken Access Control"
            let bac=bac+1
        fi
    fi
fi

#RULE 62: detection of native binary execution
echo $line | grep -E -q -i "Runtime\.getRuntime\(\)\.exec\(.*\.bin\"\)|ProcessBuilder\(.*\.bin\"\)"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
fi

#RULE 63: detection of dangerous exec patterns
echo $line | grep -E -q -i "Runtime\.getRuntime\(\)\.exec\(.*\"su\"\)|Runtime\.getRuntime\(\)\.exec\(.*\"sh\"\)"
if [ $? -eq 0 ]; then
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection"
        let inj=inj+1
    fi
fi

#RULE 64: detection of insecure XML parsing
echo $line | grep -q -i "import javax\.xml\.parsers\.DocumentBuilderFactory|DocumentBuilderFactory\.newInstance\(\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "setFeature\(\"http://xml\.org/sax/features/external-general-entities\", false\)"
    if [ $? -eq 0 ]; then
        if [ $sec_mis -eq 0 ]; then
            vuln="$vuln, Security Misconfiguration"
            let sec_mis=sec_mis+1
        fi
    fi
fi

#RULE 65: detection of privilege escalation patterns
echo $line | grep -q -i "Runtime\.getRuntime\(\)\.exec\(.*\"su\"\)|checkCallingOrSelfPermission\(\".*\"\) == PackageManager\.PERMISSION_GRANTED"
if [ $? -eq 0 ]; then
    if [ $ins_des -eq 0 ]; then
        vuln="$vuln, Insecure Design"
        let ins_des=ins_des+1
    fi
fi

#RULE extra2: detection of insecure WebView JavaScript interface
echo $line | grep -E -q -i "\.addJavascriptInterface\(.*, *[\"'].*[\"']\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "@JavascriptInterface"
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection"
            let inj=inj+1
        fi
    fi
fi

#RULE 67: detection of insecure file permissions
echo $line | grep -E -q -i "File\.setReadable\(false\)|File\.setWritable\(false\)|File\.setExecutable\(false\)"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
fi

#RULE 68: detection of insecure cookie handling
echo $line | grep -E -q -i "CookieManager\.getInstance\(\)\.setCookie\(.*,.*\"|CookieManager\.getInstance\(\)\.setCookie\(.*,.*\""
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "Secure; HttpOnly"
    if [ $? -eq 0 ]; then
        if [ $sec_mis -eq 0 ]; then
            vuln="$vuln, Security Misconfiguration"
            let sec_mis=sec_mis+1
        fi
    fi
fi

#RULE 69: detection of disabled SSL hostname verification
echo $line | grep -E -q -i "HttpsURLConnection\.setDefaultHostnameVerifier\(.*ALLOW_ALL_HOSTNAME_VERIFIER\)|HostnameVerifier\.ALLOW_ALL_HOSTNAME_VERIFIER"
if [ $? -eq 0 ]; then
    if [ $id_auth -eq 0 ]; then
        vuln="$vuln, Identification and Authentication Failures"
        let id_auth=id_auth+1
    fi
fi

#RULE 70: detection of disabled SSL certificate verification
echo $line | grep -E -q -i "TrustManager\[\] trustAllCerts|X509TrustManager\.getAcceptedIssuers\(\) return null"
if [ $? -eq 0 ]; then
    if [ $id_auth -eq 0 ]; then
        vuln="$vuln, Identification and Authentication Failures"
        let id_auth=id_auth+1
    fi
fi

#RULE extra3: detection of debug flags in production
echo $line | grep -E -q -i "\.setDebuggable\(true\)|\.debuggable *= *true|android:debuggable *= *[\"']true[\"']"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
fi

#RULE 71: detection of insecure SSL context
echo $line | grep -q -i "SSLContext.getInstance\(\"TLS\"\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "SSLContext.getInstance\(\"TLSv1.2\"\)"
    if [ $? -eq 0 ]; then
        if [ $id_auth -eq 0 ]; then
            vuln="$vuln, Identification and Authentication Failures"
            let id_auth=id_auth+1
        fi
    fi
fi

#RULE 72: detection of disabled hostname verification
echo $line | grep -q -i "setHostnameVerifier\(.*ALLOW_ALL_HOSTNAME_VERIFIER\)"
if [ $? -eq 0 ]; then
    if [ $id_auth -eq 0 ]; then
        vuln="$vuln, Identification and Authentication Failures"
        let id_auth=id_auth+1
    fi
fi

#RULE 73: detection of weak TLS versions
echo $line | grep -q -i "SSLEngine.setEnabledProtocols\(\"TLSv1\"\)"
if [ $? -eq 0 ]; then
    if [ $id_auth -eq 0 ]; then
        vuln="$vuln, Identification and Authentication Failures"
        let id_auth=id_auth+1
    fi
fi

#RULE 74: detection of insecure random number generation
echo $line | grep -q -i "SecureRandom.getInstance\(\"SHA1PRNG\"\)|new Random\(\)"
if [ $? -eq 0 ]; then
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

#RULE 75: detection of weak key sizes
echo $line | grep -q -i "KeyPairGenerator.getInstance\(\"RSA\"\).initialize\(1024\)"
if [ $? -eq 0 ]; then
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

#RULE 76: detection of JWT verification bypass
echo $line | grep -q -i "JWT.parser\(\).setSigningKey\(\"\"\)|JWT.require\(\).build\(\).verify\(token\) == null"
if [ $? -eq 0 ]; then
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

#RULE 77: detection of unsigned JWT acceptance
echo $line | grep -q -i "JWT.decode\(token\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "JWT.require"
    if [ $? -eq 0 ]; then
        if [ $crypto -eq 0 ]; then
            vuln="$vuln, Cryptographic Failures"
            let crypto=crypto+1
        fi
    fi
fi

#RULE 78: detection of disabled JWT signature verification
echo $line | grep -q -i "JWT.parser\(\).setSkipSignatureVerification\(true\)"
if [ $? -eq 0 ]; then
    if [ $crypto -eq 0 ]; then
        vuln="$vuln, Cryptographic Failures"
        let crypto=crypto+1
    fi
fi

#RULE 79: detection of insecure network binding
echo $line | grep -q -i "ServerSocket\(0, -1, InetAddress.getByName\(\"0.0.0.0\"\)\)"
if [ $? -eq 0 ]; then
    if [ $bac -eq 0 ]; then
        vuln="$vuln, Broken Access Control"
        let bac=bac+1
    fi
fi

#RULE 80: detection of insecure XML parsing
echo $line | grep -q -i "DocumentBuilderFactory.newInstance\(\).setFeature\(\"http://xml.org/sax/features/external-general-entities\", true\)"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
fi

#RULE 81: detection of insecure XML/XSLT processing
echo $line | grep -q -i "TransformerFactory.newInstance\(\).setFeature\(\"http://javax.xml.XMLConstants/feature/secure-processing\", false\)"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
fi

#RULE 82: detection of insecure file permissions
echo $line | grep -q -i "File\(\".*\.bin\"\)\.setReadable\(true\)|File\(\".*\.bin\"\)\.setWritable\(true\)"
if [ $? -eq 0 ]; then
    if [ $sec_mis -eq 0 ]; then
        vuln="$vuln, Security Misconfiguration"
        let sec_mis=sec_mis+1
    fi
fi

#RULE 83: detection of potential infinite loops
echo $line | grep -q -i "while \(.* < .*\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "\+\+|\+= 1"
    if [ $? -eq 0 ]; then
        if [ $sec_log -eq 0 ]; then
            vuln="$vuln, Security Logging and Monitoring Failures"
            let sec_log=sec_log+1
        fi
    fi
fi

#RULE 84: detection of improper lock usage
echo $line | grep -q -i "ReentrantLock\(\).lock\(\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "tryLock\(\)|isLocked\(\)"
    if [ $? -eq 0 ]; then
        if [ $sec_log -eq 0 ]; then
            vuln="$vuln, Security Logging and Monitoring Failures"
            let sec_log=sec_log+1
        fi
    fi
fi

#RULE 85: detection of insecure file operations
echo $line | grep -q -i "FileInputStream\(\".*\"\)\.read\(\)|FileReader\(\".*\"\)\.read\(\)"
if [ $? -eq 0 ]; then
    echo $line | grep -v -q "File\(\".*\"\)\.exists\(\)"
    if [ $? -eq 0 ]; then
        if [ $bac -eq 0 ]; then
            vuln="$vuln, Broken Access Control"
            let bac=bac+1
        fi
    fi
fi

# SQL Injection patterns
rule1="(SELECT|DELETE|UPDATE|INSERT).*\\?.*\\(.*getParameter\\(.*\\)\\)"
rule2="(SELECT|DELETE|UPDATE|INSERT).*\\+.*\\(.*getParameter\\(.*\\)\\)"
rule3="rawQuery\\(.*\\+.*getParameter\\(.*\\).*\\)"
rule4="execSQL\\(.*\\+.*getParameter\\(.*\\).*\\)"
rule5="(orderBy|groupBy|having|limit)\\(.*\\.format\\(.*getParameter\\(.*\\)\\)\\)"
rule6="(orderBy|groupBy|having|limit)\\(.*%.*getParameter\\(.*\\)\\)"

sql_regex="($rule1|$rule2|$rule3|$rule4|$rule5|$rule6)"
if echo "$new_line" | grep -q -E "$sql_regex"; then
    if [ $inj -eq 0 ]; then
        vuln="$vuln, Injection (SQL)"
        let inj=inj+1
    fi
fi

#RULE: detection of insecure Velocity/FreeMarker configuration
echo "$line" | grep -q "VelocityEngine\\(|FreeMarkerConfigurationFactory\\("
if [ $? -eq 0 ]; then
    echo "$line" | grep -E -q -v "setProperty\\(.*RUNTIME_REFERENCES_STRICT.*true\\)|setTemplateLoaderPaths\\(.*secure\\)"
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection (Template)"
            let inj=inj+1
        fi
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

