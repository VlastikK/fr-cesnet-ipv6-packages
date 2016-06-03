# fr-cesnet-ipv6-packages
Openwrt packages related to FR CESNET project Design of a system for testing security in IPv6 networks and processing incidents containing private addresses.

## Packages compilation
### Openwrt
Tested on TP-LINK WDR4300. Note, that routers with small internal flash (such as TP-LINK WDR4300) requires installation of some packages on external storage (USB, NFS, ...). 

   1. Download repository of latest stable Openwrt release (15.05): `git clone git://git.openwrt.org/15.05/openwrt.git`
   2. Download repository of the project:`git clone https://github.com/VlastikK/fr-cesnet-ipv6-packages.git`
   3. Copy configuration of package feeds: `cp openwrt/feeds.conf.default openwrt/feeds.conf`
   4. Add reference to directory with project specific packages acquired in previous step to file `openwrt/feeds.conf`. e.g.: `src-link cesnet /home/user/fr-cesnet-ipv6-packages`
   5. Change to directory `openwrt`
   6. Download/update all packages: `./scripts/feeds update -a`
   7. Install all packages: `./scripts/feeds install -a`
   8. Run `make menuconfig` and select following packages as modules and set architecture of CPU and router model (e.g. AR71xx and TP-LINK WDR4300):
        1. `Network->CESNET FR->ipv6-attacks`
        2. `LuCI->Applications->luci-app-ipv6-tests` (Only if LuCI WebGUI of the tool ipv6-attacks shall be used.)
        3. `Network->CESNET FR->tl-wdr4300-usb-opt` (Example how to use USB based storage for TP-LINK WDR4300 - mounts file with ext3 filesystem stored on USB flash disk to /opt.)
   9. Run `make`
  10. Created packages are stored in directory: `bin/ar71xx/packages/cesnet`
  
### Turris
The Turris OS is based on Openwrt so the compilation process is simillar.

#### Original Turris

Original Turris router has enough flash to install all packages.

   1. Download repository of TurrisOS: `git clone https://gitlab.labs.nic.cz/turris/openwrt.git`
   2. Download repository of the project:`git clone https://github.com/VlastikK/fr-cesnet-ipv6-packages.git`
   3. Copy configuration of package feeds: `cp openwrt/feeds.conf.default openwrt/feeds.conf`
   4. Add reference to directory with project specific packages acquired in previous step to file `openwrt/feeds.conf`. e.g.: `src-link cesnet /home/user/fr-cesnet-ipv6-packages`
   5. Change to directory `openwrt`
   6. Download/update all packages: `./scripts/feeds update -a`
   7. Install all packages: `./scripts/feeds install -a`
   8. Copy default configuration: `cp configs/config-turris-nand .config`
   9. Run: `make defconfig`
  10. Set environment variable: `export TARGET_BOARD=turris`
  11. Run `make menuconfig` and following packages as modules or alternatively those packages can be included in flash image:
        1. `Network->CESNET FR->ipv6-attacks`
        2. `LuCI->Applications->luci-app-ipv6-tests`  (Only if LuCI WebGUI of the tool ipv6-attacks shall be used.)
  12. Run `make`
  13. Created packages are stored in directory: `bin/mpc85xx/packages/cesnet`
  14. To add the packages persistently just copy the configuration bask to default configuration: `cp .config configs/config-turris-nand`

#### Omnia

Omnia router has enough flash to install all packages.

   1. Download repository of TurrisOS: `git clone https://gitlab.labs.nic.cz/turris/openwrt.git`
   2. Download repository of the project:`git clone https://github.com/VlastikK/fr-cesnet-ipv6-packages.git`
   3. Copy configuration of package feeds: `cp openwrt/feeds.conf.default openwrt/feeds.conf`
   4. Add reference to directory with project specific packages acquired in previous step to file `openwrt/feeds.conf`. e.g.: `src-link cesnet /home/user/fr-cesnet-ipv6-packages`
   5. Change to directory `openwrt`
   6. Download/update all packages: `./scripts/feeds update -a`
   7. Install all packages: `./scripts/feeds install -a`
   8. Copy default configuration: `cp configs/config-omnia .config`
   9. Run: `make defconfig`
  10. Set environment variable: `export TARGET_BOARD=omnia`
  11. Run `make menuconfig` and following packages as modules or alternatively those packages can be included in flash image:
        1. `Network->CESNET FR->ipv6-attacks`
        2. `LuCI->Applications->luci-app-ipv6-tests`  (Only if LuCI WebGUI of the tool ipv6-attacks shall be used.)
  12. Run `make`
  13. Created packages are stored in directory: `bin/mvebu-musl/packages/cesnet`
  14. To add the packages persistently just copy the configuration bask to default configuration: `cp .config configs/config-omnia`

