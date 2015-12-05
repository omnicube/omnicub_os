OMNICUBE OS IN USER SPACE
===================================

The OMNICUBE OS (omnios) provides a set of tools
and libraries for writing high performance, scalable, user-mode storage
applications.
It achieves high performance by moving all of the necessary drivers into
userspace and operating in a polled mode instead of relying on interrupts,
which avoids kernel context switches and eliminates interrupt handling
overhead.

Documentation
=============

[Doxygen API documentation](https://omnios.github.io/omnios/doc/)

[Porting Guide](PORTING.md)

Prerequisites
=============

To build omnios, some dependencies must be installed.

Fedora/CentOS:

- gcc
- libpciaccess-devel
- CUnit-devel

Ubuntu/Debian:

- gcc
- libpciaccess-dev
- make
- libcunit1-dev

FreeBSD:

- gcc
- libpciaccess
- gmake
- cunit

Additionally, [DPDK](http://dpdk.org/doc/quick-start) is required.

    1) cd /path/to/spdk
    2) wget http://dpdk.org/browse/dpdk/snapshot/dpdk-2.1.0.tar.gz
    3) tar xfz dpdk-2.1.0.tar.gz
    4) cd dpdk-2.1.0

Linux:

    5) make install T=x86_64-native-linuxapp-gcc

FreeBSD:

    5) gmake install T=x86_64-native-bsdapp-clang

Building
========

Once the prerequisites are installed, run 'make' within the OMNIOS directory
to build the OMNIOS libraries and examples.

    make DPDK_DIR=/path/to/dpdk

If you followed the instructions above for building DPDK:

Linux:

    make DPDK_DIR=`pwd`/dpdk-2.1.0/x86_64-native-linuxapp-gcc

FreeBSD:

    gmake DPDK_DIR=`pwd`/dpdk-2.1.0/x86_64-native-bsdapp-clang

Hugepages and Device Binding
============================

Before running an OMNIOS application, some hugepages must be allocated and
any NVMe devices must be unbound from the native NVMe kernel driver.
SPDK includes scripts to automate this process on both Linux and FreeBSD.

    1) scripts/configure_hugepages.sh
    2) scripts/unbind_nvme.sh
