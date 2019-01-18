#!/usr/bin/env bash
sudo apt-get update;
sudo apt-get upgrade -y;

sudo apt-get install python-dev python-pip git libhdf5-dev python-tk libfuzzy-dev libffi-dev graphviz -y

sudo pip install numpy scipy sklearn keras theano tensorflow h5py matplotlib gevent requests ssdeep

git clone https://github.com/luweiwei1111/AI_Security.git

cd AI_Security

find . -type f -name \*.lzma -exec lzma -d {} \;