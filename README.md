# IPIP Direct (TC)

## Description
A program made to attach to the TC hook using the egress filter. This program makes it so any outgoing IPIP packets are sent directly back to the client instead of back through the IPIP tunnel. In cases where you don't need the end-application replies to go back through the forwarding server/IPIP tunnel, this is very useful and will result in less load on the forwarding server. With that said, in other cases it can result in less latency and more.

## Usage
Usage is as follows:

```
./IPIPDirect_Loader <Interface> [<Interface IP>]
```

You shouldn't need the second argument (Interface IP) since the program is supposed to get the interface's IP automatically.

Example:

```
./IPIPDirect_Loader ens18
```

## Installation
Use the MAKE file to install the program. These commands should do:

```
make
make install
```

You may also clean the installation by executing:

```
make clean
```

## Systemd File
A `systemd` file is located in the other/ directory and is installed via `make install`. You will need to edit the system file if you are using an interface other than `ens18`.

You may enable the service by executing so it'll start on bootup:

```
systemctl enable IPIPDirect
```

You may start/stop/restart the service by executing:

```
systemctl restart IPIPDirect # Restart service.
systemctl stop IPIPDirect # Stop service.
systemctl start IPIPDirect # Start service.
```

## Kernel Requirements
Kernel >= 5.3 is required for this. Newer kernels add the `BPF_ADJ_ROOM_MAC` mode to the `bpf_skb_adjust_room()` function which is needed for this program to work correctly.

## Notes
When compiling, you may need to copy `/usr/src/linux-headers-xxx/include/uapi/linux/bpf.h` to `/usr/include/linux/bpf.h`. For some reason, newer kernels don't have an up-to-date `/usr/include/linux/bpf.h` file. I'm unsure if this is intentional or a bug. However, I got the program to compile properly by copying that file.

**Update** - Apparently this is only a bug on Ubuntu.

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creator