## Modified the nDPI example to support l3fwd with DPDK 18.11.2

This project has not been maintained for a while.

``` shell
export RTE_SDK=$(dpdk dir)
export RTE_TARGET=x86_64-native-linuxapp-gcc
export nDPI_src=$(nDPI dir)

make
sudo ./build/nDPIexe -c 0xf -n4 -- -L -p 0x3 --config="(0,0,0),(1,0,1)" --parse-ptype --eth-dest=0,68:b5:99:b6:d3:5d --eth-dest=1,b4:96:91:65:62:ab -- n4
```
- `-c 0xf -n4 -- -L -p 0x3 --config="(0,0,0),(1,0,1)" --parse-ptype --eth-dest=0,68:b5:99:b6:d3:5d --eth-dest=1,b4:96:91:65:62:ab` for DPDK
  * bind port_0 with lcore_0 and port_1 with lcore_1
  * Set destination MAC addr for each port.
- `-n4` for nDPI (used 4 thread)
- No support ARP cache in this project. Set static ARP manually.
- Forwarding packets by longest prefix IP which is usually uesd by router. 
  And almost all modified codes are in `l3fwd_lpm.c`, didn't change any of `l3fwd_em.c`.

