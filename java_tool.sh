#!/bin/bash

input_file=$1
output_file=$2

if [ -z "$input_file" ] || [ -z "$output_file" ]; then
    echo "Usage: $0 <input_java_file> <output_report>"
    exit 1
fi

# OWASP Category Counters
inj_count=0              # A01 - Injection (includes XSS, SQLi, Cmd Inj, Open Redirect)
auth_fail_count=0        # A02 - Broken Authentication (hardcoded creds)
crypt_fail_count=0       # A03 - Cryptographic Failures (e.g., weak hashing)
insec_design_count=0     # A04 - Insecure Design (e.g., hardcoded secrets, insecure randomness)
sec_mis_count=0          # A05 - Security Misconfiguration (e.g., CSRF, file upload)
vuln_comp_count=0        # A06 - Vulnerable Components (e.g., old log4j)
id_auth_count=0          # A07 - Identification/Authentication Failures (e.g., weak session, passwords)
deser_count=0            # A08 - Insecure Deserialization
log_mon_count=0          # A09 - Logging Failures
ssrf_count=0             # A10 - SSRF

# Header
echo -e "==================> JAVA CODE VULNERABILITY ANALYSIS <==================" > "$output_file"
echo -e "| OWASP Top 10 (2021) Categories                                        |" >> "$output_file"
echo -e "========================================================================\n" >> "$output_file"

# Scan Line-by-Line
while IFS= read -r line; do
    vuln=""
    trimmed=$(echo "$line" | xargs)

    # ------------------ RULES ------------------

    # Rule 1: SQL Injection
    echo "$trimmed" | grep -qE 'Statement.*execute(Query|Update)\(.*"\s*\+\s*\w+'
    [ $? -eq 0 ] && vuln="$vuln, A01-Injection (SQLi)" && ((inj_count++))

    # Rule 2: Command Injection
    echo "$trimmed" | grep -qE 'Runtime\.getRuntime\(\)\.exec\(.*"\s*\+\s*\w+'
    [ $? -eq 0 ] && vuln="$vuln, A01-Injection (Cmd Inj)" && ((inj_count++))

    # Rule 3: Hardcoded Credentials
    echo "$trimmed" | grep -qE 'password\s*=\s*".+"'
    [ $? -eq 0 ] && vuln="$vuln, A02-Hardcoded Credentials" && ((auth_fail_count++))

    # Rule 4: Insecure SSL
    echo "$trimmed" | grep -qE 'TrustManager.*{.*checkClientTrusted.*'
    [ $? -eq 0 ] && vuln="$vuln, A05-Security Misconfiguration (SSL)" && ((sec_mis_count++))

    # Rule 5: Insecure Deserialization
    echo "$trimmed" | grep -qE 'ObjectInputStream.*readObject'
    [ $? -eq 0 ] && vuln="$vuln, A08-Insecure Deserialization" && ((deser_count++))

    # Rule 6: Weak Hashing
    echo "$trimmed" | grep -qE 'MessageDigest\.getInstance\("MD5"|"SHA1"'
    [ $? -eq 0 ] && vuln="$vuln, A03-Cryptographic Failures (Weak Hashing)" && ((crypt_fail_count++))

    # Rule 7: Hardcoded Secrets or Tokens
    echo "$trimmed" | grep -qE 'apiKey\s*=\s*".+"|secret\s*=\s*".+"|token\s*=\s*".+"'
    [ $? -eq 0 ] && vuln="$vuln, A04-Insecure Design (Secrets)" && ((insec_design_count++))

    # Rule 8: Insecure Library (e.g., Log4j)
    echo "$trimmed" | grep -qE 'import\s+org\.apache\.log4j'
    [ $? -eq 0 ] && vuln="$vuln, A06-Vulnerable Component (log4j)" && ((vuln_comp_count++))

    # Rule 9: Weak Session
    echo "$trimmed" | grep -qE 'HttpSession\s+\w+\s*=\s*request\.getSession\(\)'
    [ $? -eq 0 ] && vuln="$vuln, A07-Weak Session Mgmt" && ((id_auth_count++))

    # Rule 10: Missing Logging in Exception
    echo "$trimmed" | grep -qE 'catch\s*\(.*\)\s*\{[[:space:]]*\}'
    [ $? -eq 0 ] && vuln="$vuln, A09-Missing Logging" && ((log_mon_count++))

    # Rule 11: SSRF (Unvalidated user URL)
    echo "$trimmed" | grep -qE 'new\s+URL\s*\(.*"\s*\+\s*\w+'
    [ $? -eq 0 ] && vuln="$vuln, A10-SSRF" && ((ssrf_count++))

    # Rule 12: XSS (Reflected input in print)
    echo "$trimmed" | grep -qE 'out\.print.*request\.getParameter'
    [ $? -eq 0 ] && vuln="$vuln, A01-XSS" && ((inj_count++))

    # Rule 13: Insecure Random
    echo "$trimmed" | grep -qE 'new\s+Random\(\)'
    [ $? -eq 0 ] && vuln="$vuln, A04-Predictable Random" && ((insec_design_count++))

    # Rule 14: Missing CSRF Token
    echo "$trimmed" | grep -qE 'form\s+action=.*method="post"'
    if [ $? -eq 0 ]; then
        echo "$trimmed" | grep -vq 'csrf'
        [ $? -eq 0 ] && vuln="$vuln, A05-Missing CSRF Token" && ((sec_mis_count++))
    fi

    # Rule 15: Open Redirect
    echo "$trimmed" | grep -qE 'response\.sendRedirect\(.*"\s*\+\s*request\.getParameter'
    [ $? -eq 0 ] && vuln="$vuln, A01-Open Redirect" && ((inj_count++))

    # Rule 16: Unsafe File Upload
    echo "$trimmed" | grep -qE 'MultipartFile\s+\w+'
    if [ $? -eq 0 ]; then
        echo "$trimmed" | grep -vqE '\.getContentType\(\)|\.isEmpty\(\)'
        [ $? -eq 0 ] && vuln="$vuln, A05-Unvalidated Upload" && ((sec_mis_count++))
    fi

    # Rule 17: Weak Password Policy
    echo "$trimmed" | grep -qE 'password\.length\(\)\s*<\s*6'
    [ $? -eq 0 ] && vuln="$vuln, A07-Weak Password Policy" && ((id_auth_count++))

    # Rule 18: Hardcoded JDBC URL (Info Disclosure / Insecure Design)
    echo "$trimmed" | grep -qE 'jdbc:mysql://.+:.+@'
    [ $? -eq 0 ] && vuln="$vuln, A04-Insecure Design (Hardcoded JDBC URL)" && ((insec_design_count++))

    # Rule 19: Usage of System.exit() (Unexpected Termination)
    echo "$trimmed" | grep -q 'System\.exit('
    [ $? -eq 0 ] && vuln="$vuln, A04-Insecure Design (System.exit)" && ((insec_design_count++))

    # Rule 20: Use of eval() or ScriptEngine.eval() (Code Injection Risk)
    echo "$trimmed" | grep -qE 'eval\(|ScriptEngineManager.*eval\('
    [ $? -eq 0 ] && vuln="$vuln, A01-Injection (eval)" && ((inj_count++))

    # Rule 21: Use of Reflection (Dangerous Metaprogramming)
    echo "$trimmed" | grep -qE '\.getDeclaredMethod|\.\s*invoke\('
    [ $? -eq 0 ] && vuln="$vuln, A04-Insecure Design (Reflection Usage)" && ((insec_design_count++))

    # Rule 22: Catching Generic Exception (May Hide Critical Issues)
    echo "$trimmed" | grep -qE 'catch\s*\(\s*Exception\s*\w*\)'
    [ $? -eq 0 ] && vuln="$vuln, A09-Logging (Generic Exception Catch)" && ((log_mon_count++))

    # Rule 23: Use of Deprecated Cryptographic Algorithms (DES)
    echo "$trimmed" | grep -qE 'Cipher\.getInstance\("DES'
    [ $? -eq 0 ] && vuln="$vuln, A03-Cryptographic Failures (DES)" && ((crypt_fail_count++))

    # Rule 24: Disabling Certificate Validation (Trust All Certs)
    echo "$trimmed" | grep -qE 'X509TrustManager.*checkServerTrusted\s*\(\)\s*\{'
    [ $? -eq 0 ] && vuln="$vuln, A05-Security Misconfiguration (Trust All Certs)" && ((sec_mis_count++))

    # Rule 25: Hardcoded File Paths (Platform Dependency & Info Disclosure)
    echo "$trimmed" | grep -qE 'new\s+File\s*\(\s*"/[^"]+"'
    [ $? -eq 0 ] && vuln="$vuln, A04-Insecure Design (Hardcoded Path)" && ((insec_design_count++))

    # Rule 26: Insecure File Permissions
    echo "$trimmed" | grep -qE '\.setReadable\s*\(true\s*,\s*false\)'
    [ $? -eq 0 ] && vuln="$vuln, A05-Security Misconfiguration (File Permission)" && ((sec_mis_count++))

    # Rule 27: Use of getParameter Directly in Logic (Potential Logic Flaw or Injection)
    echo "$trimmed" | grep -qE 'if\s*\(.*request\.getParameter'
    [ $? -eq 0 ] && vuln="$vuln, A01-Injection (Unvalidated Logic Param)" && ((inj_count++))

        # Rule 28: Use of Serializable class without serialVersionUID
    echo "$trimmed" | grep -qE 'implements\s+Serializable'
    if [ $? -eq 0 ]; then
        echo "$trimmed" | grep -vq 'serialVersionUID'
        [ $? -eq 0 ] && vuln="$vuln, A04-Missing serialVersionUID" && ((insec_design_count++))
    fi

    # Rule 29: Storing Password in Plain Text File
    echo "$trimmed" | grep -qE 'new\s+FileWriter\s*\(.*password'
    [ $? -eq 0 ] && vuln="$vuln, A04-Storing Password in File" && ((insec_design_count++))

    # Rule 30: Weak Cipher (e.g., ECB mode)
    echo "$trimmed" | grep -qE 'Cipher\.getInstance\(".*ECB.*"\)'
    [ $? -eq 0 ] && vuln="$vuln, A03-Weak Cipher Mode (ECB)" && ((crypt_fail_count++))

    # Rule 31: Overly Permissive CORS
    echo "$trimmed" | grep -qE 'Access-Control-Allow-Origin\s*:\s*\*'
    [ $? -eq 0 ] && vuln="$vuln, A05-Permissive CORS" && ((sec_mis_count++))

    # Rule 32: Disabling X-Frame-Options
    echo "$trimmed" | grep -qE 'X-Frame-Options\s*:\s*ALLOWALL'
    [ $? -eq 0 ] && vuln="$vuln, A05-XFO Disabled" && ((sec_mis_count++))

    # Rule 33: Dangerous File Extensions Allowed
    echo "$trimmed" | grep -qE 'filename\.endsWith\(".*\.jsp"\)'
    [ $? -eq 0 ] && vuln="$vuln, A05-Upload of Executables" && ((sec_mis_count++))

    # Rule 34: HTTP instead of HTTPS
    echo "$trimmed" | grep -qE '"http://'
    [ $? -eq 0 ] && vuln="$vuln, A05-HTTP over HTTPS" && ((sec_mis_count++))

    # Rule 35: Exposing Stack Trace
    echo "$trimmed" | grep -qE 'e\.printStackTrace\('
    [ $? -eq 0 ] && vuln="$vuln, A09-Exposing Stack Trace" && ((log_mon_count++))

    # Rule 36: Use of insecure Protocols (FTP, Telnet)
    echo "$trimmed" | grep -qE '"ftp://|"telnet://'
    [ $? -eq 0 ] && vuln="$vuln, A05-Insecure Protocols" && ((sec_mis_count++))

    # Rule 37: Using static secrets
    echo "$trimmed" | grep -qE 'static\s+final\s+String\s+\w+\s*=\s*".*"'
    [ $? -eq 0 ] && vuln="$vuln, A04-Hardcoded Static Secret" && ((insec_design_count++))

    # Rule 38: Disabled CSRF Protection Annotation
    echo "$trimmed" | grep -q '@CsrfIgnore'
    [ $? -eq 0 ] && vuln="$vuln, A05-CSRF Disabled" && ((sec_mis_count++))

    # Rule 39: Use of sleep for synchronization
    echo "$trimmed" | grep -q '\.sleep('
    [ $? -eq 0 ] && vuln="$vuln, A04-Bad Sync (sleep)" && ((insec_design_count++))

    # Rule 40: Password in logs
    echo "$trimmed" | grep -qE 'log\.(info|debug|warn|error)\(.*password'
    [ $? -eq 0 ] && vuln="$vuln, A09-Password in Logs" && ((log_mon_count++))

    # Rule 41: Trust All HostnameVerifier
    echo "$trimmed" | grep -qE 'HostnameVerifier.*verify.*return\s+true'
    [ $? -eq 0 ] && vuln="$vuln, A05-Insecure HostnameVerifier" && ((sec_mis_count++))

    # Rule 42: URLConnection without timeouts
    echo "$trimmed" | grep -qE 'URLConnection.*openConnection'
    if [ $? -eq 0 ]; then
        echo "$trimmed" | grep -vqE 'setConnectTimeout|setReadTimeout'
        [ $? -eq 0 ] && vuln="$vuln, A04-Missing Timeouts" && ((insec_design_count++))
    fi

    # Rule 43: Using Runtime.loadLibrary without validation
    echo "$trimmed" | grep -q 'Runtime\.getRuntime\(\)\.loadLibrary'
    [ $? -eq 0 ] && vuln="$vuln, A01-Native Code Injection" && ((inj_count++))

    # Rule 44: Unsafe use of Object.clone()
    echo "$trimmed" | grep -q '\.clone()'
    [ $? -eq 0 ] && vuln="$vuln, A04-Insecure Object Copying" && ((insec_design_count++))

    # Rule 45: Use of base64 for "encryption"
    echo "$trimmed" | grep -q 'Base64\.encode|Base64\.decode'
    [ $? -eq 0 ] && vuln="$vuln, A03-Base64 Used as Encryption" && ((crypt_fail_count++))

    # Rule 46: Reflection by user input
    echo "$trimmed" | grep -qE 'Class\.forName\(.*request\.getParameter'
    [ $? -eq 0 ] && vuln="$vuln, A01-Reflection Injection" && ((inj_count++))

    # Rule 47: Command Injection via ProcessBuilder
    echo "$trimmed" | grep -qE 'ProcessBuilder\s*\(.*"\s*\+\s*\w+'
    [ $? -eq 0 ] && vuln="$vuln, A01-Cmd Injection (ProcessBuilder)" && ((inj_count++))

    # Rule 48: Manual session management
    echo "$trimmed" | grep -qE 'session\.setAttribute'
    [ $? -eq 0 ] && vuln="$vuln, A07-Manual Session Mgmt" && ((id_auth_count++))

    # # Rule 49: Missing CSP Header
    # echo "$trimmed" | grep -q 'Content-Security-Policy'
    # [ $? -ne 0 ] && vuln="$vuln, A05-Missing CSP Header" && ((sec_mis_count++))

    # Rule 50: Public exposure of debug endpoints
    echo "$trimmed" | grep -qE 'debug=true|endpoint/debug'
    [ $? -eq 0 ] && vuln="$vuln, A05-Exposed Debug Endpoint" && ((sec_mis_count++))

    # Rule 51: Use of deprecated API (e.g., Thread.stop)
    echo "$trimmed" | grep -q 'Thread\.stop'
    [ $? -eq 0 ] && vuln="$vuln, A06-Deprecated API Usage" && ((vuln_comp_count++))

    # Rule 52: Missing input validation
    echo "$trimmed" | grep -qE 'request\.getParameter'
    if [ $? -eq 0 ]; then
        echo "$trimmed" | grep -vqE 'matches\(|validate\('
        [ $? -eq 0 ] && vuln="$vuln, A01-Missing Input Validation" && ((inj_count++))
    fi

    # Rule 53: File deletion by user input
    echo "$trimmed" | grep -qE 'new\s+File\s*\(\s*.*request\.getParameter'
    [ $? -eq 0 ] && vuln="$vuln, A01-Arbitrary File Delete" && ((inj_count++))

    # Rule 54: Logger not using parameterized messages
    echo "$trimmed" | grep -qE 'logger\.(info|debug|warn|error)\(".*"\s*\+\s*'
    [ $? -eq 0 ] && vuln="$vuln, A09-Logger Concat (Unsafe)" && ((log_mon_count++))

    # Rule 55: Deserialization from untrusted source
    echo "$trimmed" | grep -qE 'readObject\s*\(.*request\.getParameter'
    [ $? -eq 0 ] && vuln="$vuln, A08-Deserialization from Input" && ((deser_count++))

    # Rule 56: Use of deprecated libraries
    echo "$trimmed" | grep -qE 'import\s+org\.apache\.commons\.collections'
    [ $? -eq 0 ] && vuln="$vuln, A06-Deprecated Library Usage" && ((vuln_comp_count++))


    # ------------------------------------------

    if [ -n "$vuln" ]; then
        echo -e "[!] VULNERABLE : $trimmed" >> "$output_file"
        echo -e "    -> Issues: $vuln\n" >> "$outpu t_file"
    else
        echo -e "[✓] SAFE : $trimmed\n" >> "$output_file"
    fi

done < "$input_file"

# Summary
echo -e "==================> SUMMARY OF OWASP DETECTIONS <==================" >> "$output_file"
echo -e "A01 - Injection (SQLi, Cmd, XSS, Open Redirect)   : $inj_count" >> "$output_file"
echo -e "A02 - Broken Authentication (Creds)               : $auth_fail_count" >> "$output_file"
echo -e "A03 - Cryptographic Failures                      : $crypt_fail_count" >> "$output_file"
echo -e "A04 - Insecure Design (Secrets, Random)           : $insec_design_count" >> "$output_file"
echo -e "A05 - Security Misconfiguration (SSL, CSRF, etc.) : $sec_mis_count" >> "$output_file"
echo -e "A06 - Vulnerable Components                       : $vuln_comp_count" >> "$output_file"
echo -e "A07 - ID/Auth Failures (Session, Password)        : $id_auth_count" >> "$output_file"
echo -e "A08 - Insecure Deserialization                    : $deser_count" >> "$output_file"
echo -e "A09 - Logging & Monitoring Failures               : $log_mon_count" >> "$output_file"
echo -e "A10 - Server-Side Request Forgery (SSRF)          : $ssrf_count" >> "$output_file"
echo -e "===================================================================\n" >> "$output_file"

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
{ echo "#Cryptographic Failures:"; echo $crypt_fail_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Security Misconfiguration:"; echo $sec_mis_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Broken Authentication:"; echo $auth_fail_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Identification and Authentication Failures:"; echo $id_auth_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Insecure Design:"; echo $insec_design_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Vulnerable Components:"; echo $vuln_comp_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Insecure Deserialization:"; echo $deser_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#Logging and Monitoring Failures:"; echo $log_mon_count; } | tr "\n" " ";
echo -e "\n"
{ echo "#SSRF:"; echo $ssrf_count; } | tr "\n" " ";
echo -e "\n\n"

echo -e "=================>        EXECUTION TIME        <=================\n"
{ echo "Runtime:"; echo $runtime; echo "s"; } | tr "\n" " ";
echo -e "\n"
{ echo "Average runtime per snippet:"; awk -v var1=$runtime -v var2=$dimtestset 'BEGIN {  if(var2!=0) { print  ( var1 / var2 ) } else {print 0} }'; echo "s"; } | tr "\n" " ";
echo -e "\n"
