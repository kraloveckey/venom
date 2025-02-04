# OpenVPN 3 Connect for Kali Linux

The following commands should install openvpn3 successfully on Kali Linux as of 2023-10-11.
Please check libssl1.1 version is newest at `https://packages.debian.org/bullseye/amd64/libssl1.1`.

Update packages:

```shell
sudo apt update
sudo apt full-upgrade
```

install secure apt transport over https:

```shell
sudo apt install apt-transport-https
```

Add sources.list, get the repo key for openvpn3 and install key:

```shell
sudo mkdir -p /etc/apt/keyrings && curl -fsSL https://packages.openvpn.net/packages-repo.gpg | sudo tee /etc/apt/keyrings/openvpn.asc
DISTRO=$(lsb_release -c | awk '{print $2}')
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/openvpn.asc] https://packages.openvpn.net/openvpn3/debian $DISTRO main" | sudo tee /etc/apt/sources.list.d/openvpn-packages.list
```

Get Debian Bullseye dependencies which are not in Kali from Debian repos:

```shell
wget http://ftp.us.debian.org/debian/pool/main/libj/libjsoncpp/libjsoncpp24_1.9.4-4_amd64.deb
wget http://ftp.us.debian.org/debian/pool/main/t/tinyxml2/libtinyxml2-8_8.0.0+dfsg-2_amd64.deb
```

Check this is the newest available `libssl1.1` when you install - updated 2023-10-11:

```shell
wget http://ftp.us.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.1w-0+deb11u1_amd64.deb
```

Install dependencies:

```shell
sudo dpkg -i libtinyxml2-8_8.0.0+dfsg-2_amd64.deb libjsoncpp24_1.9.4-4_amd64.deb libssl1.1_1.1.1w-0+deb11u1_amd64.deb
```

Update package slist and install `openvpn3`:

```shell
sudo apt update
sudo apt install openvpn3
```