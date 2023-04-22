# homeplug-av-dissector
A HomePlug AV protocol dissector plugin for Wireshark.

## Overview
The HomePlug AV<sup>[1]</sup> protocol is used by power line adapters that utilize HomePlug technology.
This dissector is an alternative to the HomePlug AV protocol dissector included with Wireshark.
It fully dissects the following Management Messages:

| MMTYPE | Interpretation |
| :---: | :--- |
| `0x0014` | CC\_DISCOVER\_LIST.REQ |
| `0x0015` | CC\_DISCOVER\_LIST.CNF |
| `0x6034` | CM\_STA\_CAP.REQ |
| `0x6035` | CM\_STA\_CAP.CNF |
| `0x6060` | CM\_STA\_IDENTIFY.REQ |
| `0x6061` | CM\_STA\_IDENTIFY.CNF |
| `0x6046` | CM\_MME\_ERROR.IND |

## Installation
Copy `homeplug-av.lua` into Wireshark's personal or global [plugin folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

---
<sup>[1]</sup> (2014). *HomePlug AV Specification Version 2.1*. Retrieved from <https://docbox.etsi.org/Reference/homeplug_av21/homeplug_av21_specification_final_public.pdf>.
