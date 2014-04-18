xptMiner
========

xptMiner is a multi-algorithm miner and reference implementation of the xpt protocol. It currently supports Protoshares, Metiscoin and Scrypt (slow)
For this project I tried to focus on clean code as well merging all the various algorithms into a single project. While performance is only secondary, I'll do speed optimizations if time allows.


Some instructions to get started


PREREQUISITES 
=============
CentOS:
sudo yum groupinstall "Development Tools"
sudo yum install openssl openssl-devel openssh-clients gmp gmp-devel gmp-static git wget

Ubuntu:
sudo apt-get -y install build-essential m4 openssl libssl-dev git libjson0 libjson0-dev libcurl4-openssl-dev wget

BUILDING
========
(Note: I have had issues compiling gmp on centos or amazon ec2 when not running 
as root, so i have added the sudo to the make command)

wget http://mirrors.kernel.org/gnu/gmp/gmp-5.1.3.tar.bz2
tar xjvf gmp-5.1.3.tar.bz2
cd gmp-5.1.3
./configure --enable-cxx
sudo make -j4 && sudo make install
cd
git clone https://github.com/clintar/xptMiner.git
cd xptMiner
LD_RUN_PATH=/usr/local/lib make -j4
./xptminer -u username.riecoinworkername -p workerpassword


if you get illegal instruction try this

make clean
LD_RUN_PATH=/usr/local/lib make -j4 -f Makefile_mtune

and run it again. If it still gets a segfault, (let me know, please) and try 
this:

make clean
LD_RUN_PATH=/usr/local/lib make -j4 -f Makefile_nomarch


This has a 0% donation which can be set using the -d option (-d 2.5 would be 
2.5% donation)

