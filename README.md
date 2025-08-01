![Build Pirated](https://github.com/PirateNetwork/pirate/actions/workflows/pirated_build.yml/badge.svg)
![Pirate Logo](https://i.ibb.co/F7Dgnxy/Pirate-Logo-Wordmark-Gold.png "Pirate Chain Logo")

## Pirate Chain

This is the official Pirate Chain sourcecode repository based on https://github.com/jl777/komodo.

## Development Resources

- Pirate Chain Website: [https://piratechain.com](https://piratechain.com/)
- Komodo Platform: [https://komodoplatform.com](https://komodoplatform.com/)
- Pirate Blockexplorer: [https://explorer.piratechain.com](https://piratechain.com/)
- Pirate Discord: [https://piratechain.com/discord](https://piratechain.com/discord)
- BTT ANN: [https://bitcointalk.org/index.php?topic=4979549.0](https://bitcointalk.org/index.php?topic=4979549.0/)
- Mail: [business@piratechain.com](mailto:business@piratechain.com)
- Support: [https://piratechain.com/discord](https://piratechain.com/discord)
- API references & Dev Documentation: [https://docs.piratechain.com](https://docs.piratechain.com/)
- Blog: [https://piratechain.com/blog](https://piratechain.com/blog/)
- Whitepaper: [Pirate Chain Whitepaper](https://piratechain.com/whitepaper)

## Komodo Platform Technologies Integrated In Pirate Chain

- Delayed Proof of Work (dPoW) - Additional security layer and Komodos own consensus algorithm  
- zk-SNARKs - Komodo Platform's privacy technology for shielded transactions  


## Tech Specification
- Max Supply: 200 million ARRR
- Block Time: 60s
- Block Reward: 256 ARRR
- Mining Algorithm: Equihash 200,9

## About this Project
Pirate Chain (ARRR) is a 100% private send cryptocurrency. It uses a privacy protocol that cannot be compromised by other users activity on the network. Most privacy coins are riddled with holes created by optional privacy. Pirate Chain uses zk-SNARKs to shield 100% of the peer to peer transactions on the blockchain making for highly anonymous and private transactions.

## Signed Releases
A Signature file is included in all releases designated as signed in the releases sections of this repository.

Verify the hashes specified in the signatures-vX.X.X.zip of each file by running:
```shell
sha256sum -c sha256sum-vX.Y.Z.txt
```

Verify the signatures specified in the signatures-vX.X.X.zip of each file by running:
```shell
1. First, import the public key (Available on GitHub at https://github.com/piratenetwork/pirate/blob/master/public_key.asc)
gpg --import public_key.asc

2. Verify signature
gpg --verify <filename.sig> <downloaded-filename-to-verify>
```

## Getting started
Build the code as described below. To see instructions on how to construct and send an offline transaction look
at README_offline_transaction_signing.md

A list of outstanding improvements is included in README_todo.md

## Dependencies Ubuntu

### Dependencies (Ubuntu 18.04) - End of life, will be removed in future updates.
```shell
#The following packages are needed:
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install build-essential pkg-config m4 g++-multilib autoconf libtool libncurses-dev unzip git python3 python3-zmq zlib1g-dev wget libcurl4-gnutls-dev bsdmainutils curl libsodium-dev bison

#gcc9 is also required
sudo apt-get update -y && apt-get upgrade -y
sudo apt-get install software-properties-common -y
sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
sudo apt-get update -y
sudo apt-get install gcc-9 g++-9 -y
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 60 --slave /usr/bin/g++ g++ /usr/bin/g++-9

```

### Dependencies (Ubuntu 20.04)
```shell
#The following packages are needed:
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install build-essential pkg-config m4 g++-multilib autoconf libtool libncurses-dev unzip git python3 python3-zmq zlib1g-dev wget libcurl4-gnutls-dev bsdmainutils curl libsodium-dev bison
```

### Dependencies (Ubuntu 22.04)
```shell
#The following packages are needed:
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install build-essential pkg-config m4 g++-multilib autoconf libtool libncurses-dev unzip git python3 python3-zmq zlib1g-dev wget libcurl4-gnutls-dev bsdmainutils curl libsodium-dev bison liblz4-dev
```

## Dependencies Other Linux

### Dependencies Manjaro
```shell
#The following packages are needed:
pacman -Syu base-devel pkg-config glibc m4 gcc autoconf libtool ncurses unzip git python python-pyzmq zlib wget libcurl-gnutls automake curl cmake mingw-w64
```

### Build Pirate

This software is based on zcash and considered experimental and is continuously undergoing heavy development.

The dev branch is considered the bleeding edge codebase while the master-branch is considered tested (unit tests, runtime tests, functionality). At no point of time do the Pirate developers take any responsibility for any damage out of the usage of this software.
Pirate builds for all operating systems out of the same codebase. Follow the OS specific instructions from below.

#### Linux
```shell
git clone https://github.com/PirateNetwork/pirate --branch master
cd pirate
# This step is not required for when using the Qt GUI
./zcutil/fetch-params.sh

# -j8 = using 8 threads for the compilation - replace 8 with number of threads you want to use; -j$(nproc) for all threads available

#For CLI binaries
./zcutil/build.sh -j8

#For qt GUI binaries
./zcutil/build-qt-linux.sh -j8

#If you get this compile error:
qt/moc_addressbookpage.cpp:142:1: error: ‘QT_INIT_METAOBJECT’ does not name a type
  142 | QT_INIT_METAOBJECT const QMetaObject AddressBookPage::staticMetaObject = { {
      | ^~~~~~~~~~~~~~~~~~
  146 | QT_INIT_METAOBJECT const QMetaObject ZAddressBookPage::staticMetaObject = { {
      | ^~~~~~~~~~~~~~~~~~

Qt is incompatible with the libgl library.
Remove library: sudo apt-get remove libgl-dev
Install libraries: sudo apt-get install mesa-common-dev libglu1-mesa-dev
```

#### OSX
Ensure you have [brew](https://brew.sh) and the command line tools installed (comes automatically with XCode) and run:
```shell
brew update
brew upgrade
brew tap discoteq/discoteq; brew install flock
brew install autoconf autogen automake gcc@9 binutilsprotobuf coreutils wget python3
git clone https://github.com/PirateNetwork/pirate --branch master
cd pirate
# This step is not required for when using the Qt GUI
./zcutil/fetch-params.sh

# -j8 = using 8 threads for the compilation - replace 8 with number of threads you want to use; -j$(nproc) for all threads available

#For CLI binaries
./zcutil/build-mac.sh -j8

#For qt GUI binaries
./zcutil/build-qt-mac.sh -j8
```

#### Windows
Use a debian cross-compilation setup with mingw for windows and run:

#### Dependencies (Ubuntu 20.04)
```shell
sudo apt-get install build-essential pkg-config m4 g++-multilib autoconf libtool libncurses-dev unzip git python3 python3-zmq zlib1g-dev wget libcurl4-gnutls-dev bsdmainutils curl libsodium-dev bison mingw-w64
```

#### Dependencies (Ubuntu 20.04)
```shell
sudo apt-get install build-essential pkg-config m4 g++-multilib autoconf libtool libncurses-dev unzip git python3 python3-zmq zlib1g-dev wget libcurl4-gnutls-dev bsdmainutils curl libsodium-dev bison liblz4-dev mingw-w64
```

```shell
sudo update-alternatives --config x86_64-w64-mingw32-gcc
# (configure to use POSIX variant)
sudo update-alternatives --config x86_64-w64-mingw32-g++
# (configure to use POSIX variant)

git clone https://github.com/PirateNetwork/pirate --branch master
cd pirate
# This step is not required for when using the Qt GUI
./zcutil/fetch-params.sh

# -j8 = using 8 threads for the compilation - replace 8 with number of threads you want to use; -j$(nproc) for all threads available

#For CLI binaries
./zcutil/build-win.sh -j8

#For qt GUI binaries
./zcutil/build-qt-win.sh -j8
```
**Pirate is experimental and a work-in-progress.** Use at your own risk.

To run the Pirate GUI wallet:

**Linux**
`pirate-qt-linux`

**OSX**
`pirate-qt-mac`

**Windows**
`pirate-qt-win.exe`


To run the daemon for Pirate Chain:  
`pirated`
both pirated and pirate-cli are located in the src directory after successfully building  

To reset the Pirate Chain blockchain change into the *~/.komodo/PIRATE* data directory and delete the corresponding files by running `rm -rf blocks chainstate debug.log komodostate db.log` and restart daemon

To initiate a bootstrap download on the GUI wallet add bootstrap=1 to the PIRATE.conf file.


**Pirate is based on Komodo which is unfinished and highly experimental.** Use at your own risk.

License
-------
For license information see the file [COPYING](COPYING).


Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
