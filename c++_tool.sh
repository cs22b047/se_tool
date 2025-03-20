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


        #RULE 1: if exists a the following pattern: = (..+request.args.get())
        echo $line | grep -E -q "\+request.args.get\(|\+ request.args.get\("
        if [ $? -eq 0 ]; then 
            if [ $inj -eq 0 ]; then # Toggle the category variable for the specific snippet
                vuln="$vuln, Injection"
                let inj=inj+1
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

        #RULE 3: if exists a the following pattern: = (request.POST.get())
        echo "$line" | grep -q "(request.POST.get(.*%"
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        #RULE 4: if exists a the following pattern: = (request.POST[])
        echo "$line" | grep -q "(request.POST\["
        if [ $? -eq 0 ]; then
            # Exclude lines that contain safe patterns (for example, conditional checks)
            echo "$line" | grep -E -v -q "if.*\.match\(|if obj_match\(|if os.path.isfile\(|args.send_static_file\("
            if [ $? -eq 0 ]; then
                if [ $bac -eq 0 ]; then
                    vuln="$vuln, Broken Access Control"
                    let bac=bac+1
                fi
            fi
        fi

        #RULE 5: if exists a the following pattern: = (request.GET.get())
        echo "$line" | grep -q "(request.GET.get(.*%"
        if [ $? -eq 0 ]; then
            if [ $inj -eq 0 ]; then
                vuln="$vuln, Injection"
                let inj=inj+1
            fi
        fi

        # RULE 6: Unsafe Integer Parsing - atoi(), atof() without validation; isdidgit(), strtol() are much safer alternatives
        echo "$line" | grep -q "atoi\(|atof\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -v -q "if.*isdigit\(|strtol\("
            if [ $? -eq 0 ]; then
                if [ $inj -eq 0 ]; then
                    vuln="$vuln, Unsafe Integer Parsing"
                    let inj=inj+1
                fi
            fi
        fi

        # RULE 7: Buffer Overflow - strcpy(), strcat() is unsafe as it copies/appends without checking size
        echo "$line" | grep -q "strcpy\(|strcat\("
        if [ $? -eq 0 ]; then
            echo "$line" | grep -E -v -q "strncpy\(|strncat\("
            if [ $? -eq 0 ]; then
                vuln="$vuln, Buffer Overflow"
                if [ $soft_data -eq 0 ]; then  # buffer overflow currently considered as a data integrity
                    let soft_data= soft_data + 1
                fi
            fi
        fi

        # RULE 8: Insecure Cryptography - MD5, SHA1, DES - these cryptography algorithms are weak - brtue-forced, collision attacks, etc
        echo "$line" | grep -q "md5\(|sha1\(|des\("
        if [ $? -eq 0 ]; then
            # SHA-256 SHA-512 are secure, so they will not count as vulnerabilities
            echo "$line" | grep -E -v -q "sha256\(|sha512\("
            if [ $? -eq 0 ]; then
                vuln="$vuln, Cryptographic Failure"
                if [ $crypto -eq 0 ]; then  
                    let crypto= crypto + 1
                fi
            fi
        fi


    fi
done < "$input"
