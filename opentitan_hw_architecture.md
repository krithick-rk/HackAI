# OpenTitan `hw/` Directory Architecture — A Verified Deep Dive

*Compiled by directly cloning `lowRISC/opentitan` and inspecting file contents — not from memory. All directory listings and file counts below were verified against the live repository.*

---

## 1. The core mental model

Everything else in this document is a consequence of one design decision OpenTitan made early on:

> **Some IP blocks are the same no matter which chip you build. Others must be reconfigured per chip. OpenTitan physically separates these two categories into different folders, and uses a code generator (`topgen`) to bridge them.**

| | **Generic IPs** | **Templated ("Ipgen") IPs** |
|---|---|---|
| Example | `aes`, `hmac`, `uart`, `otbn` | `rv_core_ibex`, `gpio`, `pinmux`, `rv_plic`, `alert_handler` |
| Why they differ per top | They don't — one AES engine design works the same everywhere | Port counts, interrupt counts, address maps, and clock/reset connections genuinely change depending on which chip they're dropped into |
| Where the real RTL lives | `hw/ip/<name>/rtl/` — final, ready-to-build source | `hw/ip_templates/<name>/` — Mako **template** files (`.sv.tpl`), not compilable SystemVerilog |
| Where the *usable* RTL ends up | Same place — `hw/ip/<name>/rtl/` | Generated fresh per chip into `hw/top_<chipname>/ip_autogen/<name>/rtl/` |

This is confirmed directly by OpenTitan's own generator documentation (`util/topgen/README.md`):

> *"There are two kinds of peripherals: Generic peripherals, which are the same for any top configuration; Ipgen peripherals, which have a set of template files, and are expanded based on top-specific parameters."*

This split is directly visible when comparing the two directories:

```
Present in BOTH hw/ip/ and hw/ip_templates/:
  flash_ctrl, otp_ctrl, racl_ctrl, rv_core_ibex

Present ONLY in hw/ip_templates/ (no static copy in hw/ip/ at all):
  ac_range_check, alert_handler, clkmgr, gpio, pinmux, pwm, pwrmgr, rstmgr, rv_plic
```

The "both" group is special, not a contradiction — see §5.

---

## 2. Chip Variants: Earl Grey, Darjeeling, Chai, English Breakfast

Everything described in the rest of this document lives underneath one of several named top-level chip configurations ("tops"). Since later sections reference these constantly, it is worth establishing what each one actually is before covering directory mechanics.

| | **Earl Grey** | **Darjeeling** | **Chai** | **English Breakfast** | **`hw/vendor/`** |
|---|---|---|---|---|---|
| **Category** | Chip top-level | Chip top-level | Chip top-level (future) | Chip top-level | Directory, not a chip |
| **Status** | Fully implemented, silicon-proven; taped out in 2023 | Implemented; progressing toward full production release | Announced, not yet released — no public repository directory exists yet | Implemented; a reduced-resource variant | Always present; not a "release" |
| **Target use case** | Stand-alone SoC — its own discrete chip | Integrable implementation — designed to be embedded inside a larger host SoC | Integrated Secure Execution Environment (SEE) with support for external flash | Substantially reduced top level, sized to fit smaller/cheaper FPGA targets | N/A |
| **Key distinguishing feature** | On-die embedded flash; full standalone pad ring and analog sensor top | No dedicated pad ring of its own — the host SoC provides physical I/O; adds extra debug (`xbar_dbg`) and mailbox (`xbar_mbx`) crossbars for host interfacing | Uses external flash instead of embedded flash | Peripherals and crypto blocks trimmed (e.g. no KMAC, no OTBN) so the design fits on lower-resource FPGAs such as the Xilinx Artix-7 A100T | N/A |
| **Known real-world use** | Basis for Google/Nuvoton's hardware root-of-trust chip used in Chromebooks | Being incorporated by Rivos directly into a datacenter AI chip | No public deployment yet | Used with ChipWhisperer CW305-A100 capture boards for side-channel-analysis research; AES-only capture, since KMAC/OTBN are absent from this reduced top | N/A |
| **Repo location** | `hw/top_earlgrey/` | `hw/top_darjeeling/` | Not present in the public repository | `hw/top_englishbreakfast/` | `hw/vendor/` |

**Naming note:** no official technical rationale for the tea-themed codenames was found in lowRISC's public documentation. They appear to be an arbitrary branding convention rather than a scheme encoding any technical property.

---

## 3. `hw/ip/` — the generic IP library

**44 subdirectories.** This is the bulk of OpenTitan's actual, finished, buildable hardware. Full list (data/build files excluded):

```
adc_ctrl   aes        aon_timer   ascon      bkdr_loader  csrng
dma        edn        entropy_src flash_ctrl hmac         i2c
i3c        keymgr     keymgr_dpe  kmac       lc_ctrl      mbx
otbn       otp_ctrl   otp_macro   pattgen    prim         prim_asap7
prim_generic  prim_xilinx  prim_xilinx_ultrascale  racl_ctrl
rom_ctrl   rram_ctrl  rram_macro  rv_core_ibex  rv_dm     rv_timer
soc_dbg_ctrl  spi_device  spi_host  sram_ctrl  sysrst_ctrl  tlul
uart       usbdev
```

For a normal entry here (e.g. `aes/`), the standard structure applies: `rtl/` (the real `.sv` files, dozens of them for a complex block like `aes` or `otbn`), `dv/` (UVM testbench), `doc/` (spec + security countermeasure list). **These compile as-is** — no generation step needed. This is where the majority of per-IP security-audit effort would be spent.

Two entries deserve a special note:
- **`prim/`** — not a peripheral at all, but the shared primitives library (260 `.sv` files as of this check). Covered in more detail in §7 below.
- **`prim_generic/`, `prim_xilinx/`, `prim_xilinx_ultrascale/`, `prim_asap7/`** — these are the **technology-specific backends** for `prim/`'s abstract primitives (e.g. a generic RAM primitive maps to a Xilinx block-RAM primitive when targeting an FPGA, or an ASAP7-technology primitive when targeting that standard-cell library). `prim/` defines the interface; these four provide the concrete implementation per target technology.

---

## 4. `hw/ip_templates/` — the templates that generate per-chip variants

**13 subdirectories** (`ac_range_check`, `alert_handler`, `clkmgr`, `flash_ctrl`, `gpio`, `otp_ctrl`, `pinmux`, `pwm`, `pwrmgr`, `racl_ctrl`, `rv_core_ibex`, `rstmgr`, `rv_plic`).

Nothing in here is directly compilable. Instead of `.sv` files you find `.sv.tpl`, `.hjson.tpl`, `.core.tpl` — Mako template files with placeholders that get filled in per-chip. Confirmed directly: `hw/ip_templates/rv_core_ibex/` contains zero `.sv` files, only `.tpl` templates plus supporting docs (`theory_of_operation.md`, `boot-rom-patching.md`, etc.) and a `.tpldesc.hjson` describing what parameters the template expects.

**How generation actually happens**, per OpenTitan's own `topgen` documentation: each chip (top) has a top-level Hjson file (e.g. `hw/top_earlgrey/data/top_earlgrey.hjson`) describing things like fabric width, clock/reset sources, address maps, and the list of instantiated peripherals with their per-instance configuration. The `topgen.py` tool reads this file, and for every "Ipgen" peripheral, fills in the corresponding template from `hw/ip_templates/` and writes the expanded, real `.sv` file out to that chip's own directory. This explains why multiple `.sv` files exist for `rv_core_ibex` in `hw/top_earlgrey/`, `hw/top_darjeeling/`, and `hw/top_englishbreakfast/`, but effectively nothing in the shared `ip_templates/` copy — the templates aren't meant to be read as finished RTL at all.

---

## 5. The generated output: `hw/top_<name>/ip_autogen/`

Each of the three chip directories contains an `ip_autogen/` subfolder, which holds the **fully expanded, chip-specific, compilable RTL** produced by running the templates in §4 through `topgen`. Verified directly for `rv_core_ibex`:

```
hw/top_earlgrey/ip_autogen/rv_core_ibex/rtl/
  rv_core_ibex.sv              <- top-level wrapper for this chip
  rv_core_ibex_cfg_reg_top.sv  <- register interface (chip-specific address map)
  rv_core_ibex_reg_pkg.sv      <- register package
  rv_core_ibex_peri.sv         <- peripheral-side glue
  rv_core_ibex_addr_trans.sv   <- address translation
```

The identical five-file pattern exists independently under `hw/top_darjeeling/ip_autogen/rv_core_ibex/rtl/` and `hw/top_englishbreakfast/ip_autogen/rv_core_ibex/rtl/` — **three separate generated copies**, each expanded against that chip's own `ipconfig.hjson` (e.g. `top_earlgrey_rv_core_ibex.ipconfig.hjson`). This explains the file-count discrepancy across locations: only the generated, per-chip copies are the real wrapper RTL; the `ip_templates/` copy is template source, and the `hw/ip/rv_core_ibex/` copy (next section) is neither.

**Important — what `rv_core_ibex` actually is, and what it is *not*:** none of the files above are the CPU pipeline itself. They are OpenTitan-specific *integration/wrapper* logic — register interface, address translation, config plumbing — that sits between the real Ibex CPU core and the rest of the chip. The actual fetch/decode/execute pipeline lives entirely outside this generation system, in `hw/vendor/` (§6).

### Why `flash_ctrl`, `otp_ctrl`, `racl_ctrl`, `rv_core_ibex` appear in *both* `ip/` and `ip_templates/`

Checked directly — this is not duplication of the real RTL. The `hw/ip/<name>/` copy for these four contains only a thin, generic **package file** (types/constants) meant to be shared/imported by other, non-templated IPs that need to reference that block's types without depending on a specific chip's generated instance. Confirmed for two of them:

```
hw/ip/otp_ctrl/rtl/     →  otp_ctrl_pkg.sv   (1 file)
hw/ip/flash_ctrl/rtl/   →  flash_ctrl_pkg.sv (1 file)
```

The `otp_ctrl_pkg.sv` file's own header comment states its purpose directly: *"This package can be imported by generic IPs"* — i.e., it exists purely as a stable interface contract, not as the block's implementation. The real, chip-specific `otp_ctrl` RTL is generated the same way `rv_core_ibex` is, landing in each top's `ip_autogen/otp_ctrl/`. Verified counts: the template source in `hw/ip_templates/otp_ctrl/rtl/` has 13 files (mix of `.sv.tpl` and static `.sv`), which expands to 15 generated `.sv` files in `hw/top_earlgrey/ip_autogen/otp_ctrl/rtl/`.

`racl_ctrl`'s `hw/ip/racl_ctrl/` entry is slightly different again: it contains no RTL at all, only a **shared DV verification agent** (`racl_error_log_agent`) meant to be reused across every chip's generated `racl_ctrl` instance, so the testbench code for the error-logging interface doesn't need to be duplicated/regenerated per chip.

**Practical rule of thumb:** a `hw/ip/<name>/` directory containing only 1 file, or only `dv/` content with no `rtl/`, signals that the block is actually templated. The source-of-truth template lives in `hw/ip_templates/<name>/`, and the actual per-chip RTL to audit lives in each `hw/top_*/ip_autogen/<name>/`.

---

## 6. `hw/vendor/` — externally-developed code, Ibex included

This directory holds code whose primary development happens in a *different* repository entirely, and is periodically synced ("vendored") into OpenTitan's tree. Confirmed: `hw/vendor/lowrisc_ibex/` is the only Ibex-named entry here, and it's not a stub — it's the complete upstream `lowRISC/ibex` project, vendoring metadata included (`lowrisc_ibex.vendor.hjson`, `lowrisc_ibex.lock.hjson` — these record which upstream commit is currently vendored in, so updates are deliberate and pinned, not a moving target).

**This is where the actual CPU lives.** `hw/vendor/lowrisc_ibex/rtl/` contains the real pipeline — 30 `.sv` files including:

```
ibex_core.sv            <- top-level core, ties everything below together
ibex_if_stage.sv        <- instruction fetch stage
ibex_id_stage.sv        <- instruction decode stage
ibex_ex_block.sv        <- execute stage
ibex_alu.sv             <- arithmetic logic unit
ibex_controller.sv      <- control FSM
ibex_cs_registers.sv    <- control/status registers (CSRs) — PMP, shadow CSRs, cpuctrl live here
ibex_csr.sv             <- generic CSR primitive used by cs_registers
ibex_decoder.sv         <- instruction decoder
ibex_compressed_decoder.sv <- RVC (compressed instruction) decoder
ibex_branch_predict.sv  <- branch prediction
ibex_load_store_unit.sv <- memory access unit
ibex_multdiv_fast.sv / ibex_multdiv_slow.sv <- two selectable multiply/divide implementations (area/speed tradeoff)
ibex_icache.sv          <- instruction cache (supports optional ECC protection and scrambling)
ibex_fetch_fifo.sv      <- fetch buffering
ibex_lockstep.sv        <- the dual-core lockstep comparison logic itself
ibex_dummy_instr.sv     <- the dummy-instruction-insertion side-channel countermeasure
ibex_counter.sv         <- hardened counter used internally
ibex_pkg.sv             <- shared types/parameters for the whole core
ibex_top.sv (in ibex_top.core) <- outermost wrapper; core logic is split from the register file/RAM specifically to support the dual-core lockstep implementation
```

To be precise about terminology: **`hw/vendor/` is the one location where "ibex" refers to the actual CPU microarchitecture.** Every other "ibex" location (`hw/ip/rv_core_ibex`, `hw/ip_templates/rv_core_ibex`, `hw/top_*/ip_autogen/rv_core_ibex`) is OpenTitan-side wrapper/integration/register-interface code that connects to *this* core, not a copy of the core itself. Nothing under `hw/ip/` or any `top_*` directory duplicates `ibex_core.sv` or its pipeline stages — those exist in exactly one place.

**Audit implication:** an Ibex audit effort has two genuinely distinct scopes, not one — (a) auditing the actual pipeline/lockstep/countermeasure RTL in `hw/vendor/lowrisc_ibex/rtl/`, which is upstream code shared across all lowRISC projects, not OpenTitan-specific; and (b) auditing the three separate `rv_core_ibex` wrapper instantiations in each top's `ip_autogen/`, which *are* OpenTitan-specific and could easily diverge from each other in ways worth diffing (e.g. does Darjeeling's address translation logic have the same bug surface as Earl Grey's, given they're independently generated from the same template but different parameters?).

---

## 7. `hw/ip/prim/` and its technology-backend directories

Confirmed count: **260 `.sv` files** under `hw/ip/prim/` alone (not counting the technology-specific backend directories). It's a large, flat library of small hardened building blocks (`prim_lfsr`, `prim_prince`, `prim_count`, `prim_sparse_fsm_flop`, `prim_packer`, `prim_ram_1p_scr`, etc.), each reused across dozens of the "real" IPs in `hw/ip/`. The technology-specific implementations of the same abstract primitives live in the sibling directories `prim_generic/`, `prim_xilinx/`, `prim_xilinx_ultrascale/`, and `prim_asap7/` — same logical primitive, different concrete backend depending on build target (simulation, Xilinx FPGA, or a specific ASIC standard-cell library).

---

## 8. `hw/top/` — a newer, cross-chip infrastructure layer

`hw/top/` (no chip name suffix) holds infrastructure shared across *all* chip variants rather than belonging to any one of them — notably a `dt/` (device-table) subsystem generating chip-agnostic hardware description data, and a `tock/` subsystem related to Tock OS integration. This appears to be newer, still-evolving plumbing for describing chip configuration in a chip-independent way, separate from the older per-chip `top_<name>/data/top_<name>.hjson` approach. It warrants a light audit pass, but as tooling/description infrastructure rather than security-critical RTL, it is lower priority than the IP and top directories above.

---

## 9. Quick Reference: Locating Specific Content

| Looking for... | Location |
|---|---|
| Real, ready-to-build AES/HMAC/OTBN/etc. RTL | `hw/ip/<name>/rtl/` |
| The Ibex CPU pipeline itself (fetch/decode/execute, lockstep, PMP, CSRs) | `hw/vendor/lowrisc_ibex/rtl/` |
| OpenTitan's wrapper/glue around Ibex for a specific chip | `hw/top_<chip>/ip_autogen/rv_core_ibex/rtl/` |
| The *template* that generates that wrapper (parameterized, not compilable) | `hw/ip_templates/rv_core_ibex/` |
| GPIO / pinmux / alert_handler / clkmgr / pwrmgr / rstmgr / rv_plic RTL for a specific chip (these have no static `hw/ip/` copy at all) | `hw/top_<chip>/ip_autogen/<name>/rtl/` |
| Shared hardened primitives (LFSR, PRINCE cipher, hardened counters/FSMs) | `hw/ip/prim/` (behavioral) + `hw/ip/prim_<tech>/` (technology backend) |
| Chip-wide security countermeasure test automation (fault-injects every `prim_count`/`prim_sparse_fsm_flop`/`prim_double_lfsr` instance) | referenced from DV `cip_lib`, tied to each IP's `sec_cm_testplan.hjson` |
| The actual generator that turns templates into per-chip RTL | `util/topgen/` (`topgen.py`, `README.md` explains the whole pipeline) |
| Per-chip top-level configuration (address maps, peripheral list, clocks) | `hw/top_<chip>/data/top_<chip>.hjson` |

---

## 10. Implications for Security Audit Planning

Recommended worker-group structure based on this verified structural detail:

1. **Split the Ibex group's scope explicitly into two sub-scopes**, since they're genuinely different codebases with different provenance: upstream core RTL (`hw/vendor/lowrisc_ibex/`) vs. per-chip wrapper RTL (`hw/top_*/ip_autogen/rv_core_ibex/`). A bug class in one doesn't imply anything about the other.
2. **For every IP directory that looks suspiciously thin in `hw/ip/`** (1 file, or `dv/`-only with no `rtl/`) — that's a signal it's templated, not that the audit is done. Redirect that worker to `hw/ip_templates/<name>/` (design intent) *and* to each top's `ip_autogen/<name>/` (actual instantiated RTL) — the templated group (`ac_range_check`, `alert_handler`, `clkmgr`, `gpio`, `pinmux`, `pwm`, `pwrmgr`, `racl_ctrl`, `rstmgr`, `rv_plic`, plus `rv_core_ibex`/`otp_ctrl`/`flash_ctrl` for their generated portions) needs **per-chip re-review**, since three independently-generated copies (Earl Grey / Darjeeling / English Breakfast) can diverge even from an identical template if the per-chip parameters differ.
3. **`topgen.py` itself becomes an audit target**, not just a build tool — since it's the single point that expands every templated IP for every chip, a bug in the generator could introduce the same flaw into all three chips' instances simultaneously, which is a much bigger blast radius than a bug in any one hand-written IP. This should be handled by a cross-cutting integration-review pass, alongside analysis of the alert-handler/secure-boot trust chain, rather than by any single per-IP or per-chip group.
