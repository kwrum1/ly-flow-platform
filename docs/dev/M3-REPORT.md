# M3 楠屾敹鎶ュ憡锛圓gent / RASP / 鍝嶅簲锛?
- 鏃ユ湡锛?026-10-19
- 鍒嗘敮锛歚feat/lyflow-v2`
- 娴嬭瘯 VM锛歚lyflow-test`锛圲buntu 24.04.5锛?C/8G/120G锛孌ocker 29.1.3 + Compose 2.40.3锛?
## 1. 鑼冨洿

- T3.1 `ly-agent` supervisor
- T3.2/T3.3 Elkeid/Wazuh 杩涚▼ Provider
- T3.4/T3.5 OpenRASP / Elkeid RASP 閰嶇疆鍔╂墜
- T3.6 Agent 缁熶竴闂ㄩ潰
- T3.7 瀹夎鍣?鑷/鍥炴粴
- T3.8 鍝嶅簲瀹℃壒/鏃堕棿绐?鍥涚溂
- T3.9 妯悜绉诲姩妫€娴?
## 2. 宸查€氳繃鐨勯獙璇?
| 楠岃瘉 | 鍛戒护 | 缁撴灉 |
|---|---|---|
| Supervisor/Provider | `cd agent && go test ./supervisor/... -count=1` | ok |
| RASP 閰嶇疆 | `cd agent && go test ./supervisor/rasp/... -count=1` | ok |
| Agent 闂ㄩ潰 | `cd server && go test ./agentfacade -count=1` | ok |
| 鍝嶅簲绛栫暐 | `cd server && go test ./response -count=1` | ok |
| 妯悜绉诲姩 | `cd server && go test ./correlation/lateral -count=1` | ok |
| 瀹夎鍓嶆鏌?| 娴嬭瘯 VM `preflight.sh` | exit 0锛屽叏閮?OK |
| 鑷 | 娴嬭瘯 VM `self-test.sh ssh /usr/sbin/sshd` | exit 0 |
| 蹇€熷叏閲?| `bash scripts/dev/test-all.sh fast` | all fast checks passed |

## 3. 娴嬭瘯 VM 鐘舵€?
- `lyflow-test` 宸插彲閫氳繃缂栬瘧鏈?SSH 璁块棶銆?- 闈欐€?IP銆佺綉鍏炽€丏NS銆丏ocker/Compose 宸插氨缁€?- `/opt/lyflow/{deploy,data,logs,reports,backups}` 宸插垱寤恒€?- ESXi 蹇収寰呰ˉ锛圓PI 鏆傛椂鎷掔粷杩炴帴锛夈€?
## 4. 灏氭湭瀹屾垚

1. 鐪熷疄 `ly-agent` 鍖呫€乻ystemd unit銆佹敞鍐?蹇冭烦/閰嶇疆涓嬪彂銆?2. Elkeid/Wazuh 杩涚▼瀹為檯鍚姩涓庝簨浠惰鑼冨寲銆?3. OpenRASP/Elkeid RASP 鐪熷疄娉ㄥ叆銆乤ttach銆佷簨浠朵笂鎶ャ€?4. 鍝嶅簲鎵ц鍣紙Wazuh active response/Elkeid task锛変笌鍥炴粴瀹¤銆?5. 妯悜绉诲姩妫€娴嬫帴鍏ュ疄鏃舵秷璐逛笌 Incident 闃舵鏈恒€?6. Agent 闂ㄩ潰 HTTP API 涓?UI銆?7. 娴嬭瘯 VM 涓婄殑鍏ㄦ爤闆嗘垚銆?
## 5. Gate G4 缁撹

**READY_FOR_REVIEW**锛欰gent/EDR/RASP/鍝嶅簲/妯悜妫€娴嬬殑楠ㄦ灦涓庡崟鍏冩祴璇曞畬鎴愶紱鐪熷疄绔笂鑱旇皟寰?Agent 鍖呬笌娴嬭瘯 VM 鍏ㄦ爤閮ㄧ讲銆傜户缁?M4锛堝唴瀹广€佹姄鍖呫€佹€ц兘銆佷氦浠橈級銆?
