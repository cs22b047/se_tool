#!/bin/bash
# Initialize flags
inj=0
get_found=0

# Process the input file line by line.
while IFS= read -r line; do
    # Check if the line contains req.url_params.get(" which retrieves the query parameter
    echo "$line" | grep -E -q 'req\.url_params\.get\("'
    if [ $? -eq 0 ]; then
        get_found=1
    fi

    # Check if the line contains a pattern of unsanitized conversion from a query parameter.
    # This checks for both std::stoi and stoi (without std::).
    echo "$line" | grep -E -q "\+?(std::stoi|stoi)\("
    if [ $? -eq 0 ]; then
        if [ $inj -eq 0 ]; then
            vuln="$vuln, Injection"
            let inj=inj+1
        fi
    fi
done < "$1"

# Optional: Report if the parameter retrieval part was found
if [ $get_found -eq 1 ]; then
    echo "Found usage of req.url_params.get() in the code."
fi
