#!/bin/bash

#Create a backup copy if things get messed up
cp ../cobaltstrike/dumpFile.txt ../cobaltstrike/$(date +"%Y_%m_%d_%I_%M_%p").txt

#Remove Cobalt Strikes received output: strings from miniDump
sed -i -e 's/received output://g' ../cobaltstrike/dumpFile.txt

#Trim whitespaces from miniDump
cat ../cobaltstrike/dumpFile.txt | tr -d " \t\n\r" > ../cobaltstrike/dumpFile2.txt

#Base64 decode miniDump file and create final miniDump file 
base64 -d ../cobaltstrike/dumpFile2.txt > ../cobaltstrike/$(date +"%Y_%m_%d_%I_%M_%p").dmp

#Remove extra files
rm ../cobaltstrike/dumpFile.txt
rm ../cobaltstrike/dumpFile2.txt

