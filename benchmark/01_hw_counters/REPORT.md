# HW Counters — ethtool -S Report

| | |
|:---|:---|
| **Suite** | `01_hw_counters` |
| **Status** | ✅ PASS |
| **Run** | 2026-05-28 19:33 UTC |

---


## Environment

| **Key** | **Value** |
|:---|:---|
| Timestamp | 2026-05-28T19:33:08.207046+00:00 |
| Kernel | 6.8.0-60-generic |
| Driver | mlx5_core |
| Driver Version | 25.07-0.9.7 |
| Fw Version | 22.41.1000 |
| Nic Pci | 0000:34:00.1 |
| Link Speed | 100000Mb/s |
| Numa Node | 0 |
| Cpu Model | Intel(R) Xeon(R) w5-3435X |
| Cpu Count | 8 |
| Hugepages 2M | 20 |
| Iface | enp52s0f1np1 |

## ℹ️ Baseline Run

No prior baseline was found. This run has been saved as the new baseline. Future runs will diff against it.

---

## Throughput

_No iperf3 data available._


---

## Zero → Non-Zero Counters

✅ No counters transitioned from zero.


---

## Counters — RX

✅ No counter changes in this group.


---

## Counters — TX

| **** | **Counter** | **T0** | **T1** | **Δ** | **Rate** | **Group** |
|:---|:---|:---|:---|:---|:---|:---|
| ⬆️ | `tx_bytes` | 6,585,589,446,806 | 6,585,620,914,326 | +31,467,520 | 3.15 M/s | tx |
| ⬆️ | `tx_bytes_phy` | 6,895,857,088,134 | 6,895,889,541,522 | +32,453,388 | 3.25 M/s | tx |
| ⬆️ | `tx_cqes` | 55,283,557,009 | 55,283,802,733 | +245,724 | 24.57 K/s | tx |
| ⬆️ | `tx_csum_none` | 55,273,971,886 | 55,274,217,726 | +245,840 | 24.58 K/s | tx |
| ⬆️ | `tx_mpwqe_blks` | 55,274,911,324 | 55,275,157,164 | +245,840 | 24.58 K/s | tx |
| ⬆️ | `tx_mpwqe_pkts` | 55,274,911,497 | 55,275,157,337 | +245,840 | 24.58 K/s | tx |
| ⬆️ | `tx_nop` | 15,477,816,326 | 15,477,885,164 | +68,838 | 6.88 K/s | tx |
| ⬆️ | `tx_packets` | 55,910,344,390 | 55,910,590,230 | +245,840 | 24.58 K/s | tx |
| ⬆️ | `tx_packets_phy` | 56,697,856,058 | 56,698,101,930 | +245,872 | 24.59 K/s | tx |
| ⬆️ | `tx_prio0_bytes` | 6,895,856,568,714 | 6,895,889,047,314 | +32,478,600 | 3.25 M/s | tx |
| ⬆️ | `tx_prio0_packets` | 56,697,852,175 | 56,698,098,227 | +246,052 | 24.61 K/s | tx |
| ⬆️ | `tx_vport_unicast_bytes` | 6,669,063,481,282 | 6,669,094,946,242 | +31,464,960 | 3.15 M/s | tx |
| ⬆️ | `tx_vport_unicast_packets` | 56,697,847,223 | 56,698,093,043 | +245,820 | 24.58 K/s | tx |

---

## Counters — ERROR

✅ No counter changes in this group.


---

## Counters — PFC

✅ No counter changes in this group.


---

## Counters — LINK

✅ No counter changes in this group.


## Regression Check

✅ No regressions detected against baseline.
