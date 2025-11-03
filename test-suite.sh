#!/bin/bash
# Test suite for concurrent and sequential executions of the program for linux systems
# MUST CHECK DEPENDENCIES MANUALLY

passwords=("passw" "senhas" "flamengo")

for pass in "${passwords[@]}"; do
  mkdir -p tests/"$pass"/concurrent
  mkdir -p tests/"$pass"/sequential
  for i in {1..5}; do
    echo "CONCURRENT TESTING PASSWORD $pass ITERATION $i"
    echo -n "$pass" | md5sum | cut -d ' ' -f1 | xargs ./md5crack >tests/"$pass"/concurrent/"$i".txt
  done
  for i in {1..5}; do
    echo "SEQUENCIAL TESTING PASSWORD $pass ITERATION $i"
    echo -n "$pass" | md5sum | cut -d ' ' -f1 | xargs -I {} ./md5crack {} -s >tests/"$pass"/sequential/"$i".txt
  done
done
