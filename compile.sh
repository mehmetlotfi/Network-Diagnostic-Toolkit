#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root privilege (use sudo)."
  exit 1
fi

if command -v apt &> /dev/null; then
  apt update
  apt install -y gcc
elif command -v yum &> /dev/null; then
  yum install -y gcc
elif command -v pacman &> /dev/null; then
  pacman -Sy --noconfirm gcc
else
  echo "Unsupported package manager. Please install dependencies manually. (gcc) then try manualy."
  exit 1
fi
clear
gcc net.c -o net -Wall -Wextra -Wpedantic -lc -lresolv

if [ $? -eq 0 ]; then
  echo "Compilation successful. Executable 'net' created."
else
  echo "Compilation failed."
  exit 1
fi
echo "For the ICMP Connection test and DNS Question sections to run correctly, the program must be run with root execution access level."
echo "mehmet lotfi"
echo "github.com/mehmetlotfi"