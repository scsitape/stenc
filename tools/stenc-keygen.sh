#!/bin/bash

display_help()
{
   echo "Usage: $0 [-l <16|32>] [-d \"<string>\"] [-f \"<file name>\"] [-h]"
   echo "options:"
   echo "-l     key length in bytes <16|32>."
   echo "-d     key descriptor."
   echo "-f     key filename."
   echo "-h     this help."
   echo
}

command -v openssl >/dev/null 2>&1 || { echo >&2 "openssl command is required but it's not installed."; exit 1; }

while getopts "hl:f:d:" flag
do
    case "${flag}" in
        l) key_length=${OPTARG}
            if [ "$key_length" -ne 16 ] && [ "$key_length" -ne 32 ]; then
                echo "The key length must be 16 or 32 bytes."
                exit 1
            fi
            ;;
        d) descriptor=${OPTARG}
            ;;
        h)
            display_help
            exit 0
            ;;
        f) filename=${OPTARG}
            ;;
        \?) # Invalid option
            display_help
            exit 1
            ;;
    esac
done

#set default key length
[ -z "$key_length" ] && key_length="32"
#set default key descriptor
[ -z "$descriptor" ] && descriptor=$(LANG=C date +'TK%y%m%d%H%M%S')
#set default key filename
[ -z "$filename" ] && filename="${descriptor}.key"

umask 077
echo "Generating the key..."
openssl rand -hex $key_length > "$filename"
echo "$descriptor" >> "$filename"

echo "Key filename: $filename"
exit 0
