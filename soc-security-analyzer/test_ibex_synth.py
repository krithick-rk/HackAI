import re
import os

with open("/home/hackdac/opentitan/hw/vendor/lowrisc_ibex/rtl/ibex_pkg.sv", "r") as f:
    content = f.read()

# Comment out PmpCfgRst and PmpAddrRst
content = re.sub(r"parameter pmp_cfg_t PmpCfgRst.*?};", "", content, flags=re.DOTALL)
content = re.sub(r"parameter logic \[PMP_ADDR_MSB:0\] PmpAddrRst.*?};", "", content, flags=re.DOTALL)

with open("ibex_pkg_test.sv", "w") as f:
    f.write(content)

