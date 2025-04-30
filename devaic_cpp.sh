#!/bin/bash

# Detection of Vulnerabilities in c++ Code

SRC_DIR=$PWD
INP_DIR=$SRC_DIR"/input"
RES_DIR=$SRC_DIR"/results"
GEN_DIR=$SRC_DIR"/generated_file_c++"
TOOL=$SRC_DIR/c++_tool.sh

name_os=$(uname)
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")


# ----------     ADJUSTING THE FILENAME      ----------
echo "$1" | grep -q "/"
if [ $? -eq 0 ]; then
    new_name=$(basename "$1")
else
    new_name=$1
fi

filename_res="$new_name"
type=$(echo $filename_res | awk -F '.' '{print $2}')

echo "$1" | grep -q ".txt"
if [ $? -eq 1 ]; then
    filename_res=$(echo $filename_res | sed "s/.$type/.txt/g")
fi

# Define the names of the generated files
input_file="INPUT_$filename_res"
det_file="DET_$filename_res"

# Define paths
input_path=$GEN_DIR/$input_file
det_path=$RES_DIR/$det_file

# ----------     PREPROCESSING      ----------
mkdir -p "$GEN_DIR" "$RES_DIR"

# Copy or transform input to generated directory
if [ $type == "json" ]; then
    echo "[!] JSON input not supported yet for c++. Provide .c++ or .txt files."
    exit 1
else
    cp "$1" "$input_path"
fi

# ----------     LAUNCHING THE TOOL     ----------
echo -e "[***] Running c++ Vulnerability Scanner...\n"

bash "$TOOL" "$input_path" "$det_path"

