# ACL Configuration Persistency

## How it works

After the system boots, `systemd` will load the `opx-acl-persistency.service`, which executes `acl-config` at startup, which reads the `acl-config.yaml` and loads the ACL rules defined in that file.

If a user makes changes to the `acl-config.yaml` file like adding/deleting/modifying a rule, they can run `acl-loader <filename>` to dynamically reload the ACL rules. The rules that were removed from the yaml file will get removed from the hardware and the rules that were modified or added will get programmed in the hardware.

## Relevant files

### `bin/acl-config.yaml`

This file contains ACL rules defined in an `iptables`-like format. Excerpt:

```
#ACL Configuration File

ACL Entries:
        - block-unicast -A INPUT -p tcp -i e101-025-1 -d 20.1.1.2/255.255.255.255 -j DROP
        - icmp-output -A INPUT -p icmp -i e101-011-0 -j DROP
        - drops-pkt -A OUTPUT -o e101-011-0 -d 30.1.1.2/255.255.255.255 -j DROP
        - block-syn -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j DROP
```

Each entry contains the following options:

- `ACL-Entry-Name`: A descriptive name for the ACL entry, such as `block-unicast`
- `-A {INPUT|OUTPUT}`: incoming and outgoing packet for the rule
- `-p {tcp|udp|icmp}`: protocol option -- tcp/udp/icmp
- `-i [interface-name]`: Interface
- `-d [ip-address/mask]`: Destination IP address/mask
- `-s [ip-address/mask]`: Source IP address/mask
- `-j {DROP|ACCEPT}`: This specifies the target of the rule; i.e., what to do if the packet matches it. 
- `--tcp-flags {SYN|RST|FIN|ACK}`: Specific TCP flags to match on
- `--sport [port-number]`: Source TCP/UDP port
- `--dport [port-number]`: Destination TCP/UDP port
- `--mac-source [mac-address]`: Source MAC address
- `--mac-destination [mac-address]`: Destination MAC address

---

### `bin/acl-loader`

If any changes are made to the `acl-config.yaml` file like adding, modifying, or deleting a rule, 
`acl-loader <filename>` is used to dynamically re-load the ACL rules defined in the file. 
The rules that are removed from the yaml file will get removed from the hardware and the 
rules that are modified or added will get programmed in the hardware.

--- 

### `bin/acl-config`

This script converts the `acl-config.yaml` rules to CPS API calls to program the hardware.

---

### `base_acl_cli.py`

This script performs operations on ACLs that are otherwise unavailable via `iptables`-like rules.

Below are the options present in the script:
- `show-table` Shows the ACL table with the filters
- `show-entry` Shows the entries of an ACL
- `delete-entry` Deletes an ACL entry
- `delete-table` Deletes the ACL table. (Delete the entry first to delete the ACL table)
- `create-counter` Creates a counter for the ACL table
- `append-counter` Append a counter for the particular ACL entry
- `delete-counter` Deletes an ACL counter
- `show-stats` Used to show the statistics for the ACL entry

---

### `bin/nas_acl.py`

This script is used internally by `base_acl_cli.py`.

---

### `init/opx-acl-persistency.service`

`systemd` service file used for running the acl-config file automatically on boot.

---

# Caveats

- `iptable`-like rules only support the targets ACCEPT and DROP.
- `OUTPUT` chains only match on the following filters: `'DST_IP'`, `'L4_SRC_PORT'`, `'L4_DST_PORT'`, `'IP_PROTOCOL'` and `'OUT_INTF'`.
- Parameters in `iptables` such as  `-g (--goto chain)` , `-f (--fragment)`, `-c (--set-counters)`, `-v(--verbose)`, `-n(--numeric)`,`-x(--exact)`,`--line-numbers` and `modprobe=command` are not supported
- `IPtable` match extensions with `'m'` option is not supported.
- If the user wants to specify multiple source ports and destination ports, multiple rules have to be specified.
-  `tcp-option` and `mss` are not supported for TCP.

