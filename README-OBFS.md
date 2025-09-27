# Tinc VPN with Traffic Obfuscation

This is a modified version of tinc 1.1pre18 that includes traffic obfuscation capabilities to make VPN traffic less detectable by DPI (Deep Packet Inspection) systems.

## Features

- **Header Junk**: Add random padding to packet headers to obscure packet structure
- **Magic Number Randomization**: Randomize protocol identifiers to avoid pattern detection
- **Handshake Tags**: Insert custom patterns into handshake packets
- **Junk Packets**: Send decoy packets to confuse traffic analysis
- **Runtime Configuration**: Control obfuscation settings via tinctl commands

## New Commands

### Check Obfuscation Status
```bash
tinctl -n <netname> obfs status
```

### Configure Obfuscation
```bash
# Enable basic obfuscation
tinctl -n <netname> obfs apply enabled=true

# Configure junk packets
tinctl -n <netname> obfs apply junk_count=5 junk_min=100 junk_max=500

# Add header junk for different message types
tinctl -n <netname> obfs apply header_junk_init=64 header_junk_transport=32

# Configure magic number randomization
tinctl -n <netname> obfs apply magic_init=1000-2000 magic_transport=3000-4000

# Add handshake tags (base64 encoded)
tinctl -n <netname> obfs apply add_tag_b64=aGVsbG8gd29ybGQ=

# Clear all tags and add new ones
tinctl -n <netname> obfs apply tags_clear=true add_tag_named_b64=mytag:ZXhhbXBsZQ==
```

## Implementation Details

The obfuscation system works at the network packet level, modifying UDP datagrams before transmission and stripping obfuscation data on receipt. Key components:

- `src/obfs.c` - Core obfuscation logic
- `src/obfs.h` - Obfuscation data structures and function declarations
- `src/control.c` - Control interface for runtime configuration
- `src/net_packet.c` - Packet processing with obfuscation integration
- `src/tincctl.c` - Command-line interface extensions

## Configuration Format

The obfuscation system supports various configuration parameters:

- `enabled` - Enable/disable obfuscation (boolean)
- `junk_count` - Number of junk packets to send (integer)
- `junk_min/junk_max` - Size range for junk packets (integers)
- `header_junk_<type>` - Header padding size for message types (init, response, cookie, transport)
- `magic_<type>` - Magic number ranges for message types
- `tags_clear` - Clear existing handshake tags (boolean)
- `add_tag_b64` - Add anonymous handshake tag (base64)
- `add_tag_named_b64` - Add named handshake tag (base64)

## Building

This version requires the same build dependencies as standard tinc:

```bash
autoreconf -fsi
./configure
make
```

## Android Integration

This modified tinc is also integrated into the Android tincapp client. The Android build automatically uses this obfuscated version through CMakeLists.txt configuration.

## Original Tinc

Based on tinc 1.1pre18 from https://tinc-vpn.org/

## License

Licensed under the GNU General Public License v2.0, same as the original tinc project.