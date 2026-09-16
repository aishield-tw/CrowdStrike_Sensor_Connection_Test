# CrowdStrike Sensor 部署前連線測試

[![Validate](https://github.com/aishield-tw/CrowdStrike_Sensor_Connection_Test/actions/workflows/validate.yml/badge.svg)](https://github.com/aishield-tw/CrowdStrike_Sensor_Connection_Test/actions/workflows/validate.yml)

在 Windows 安裝 Falcon Sensor 前，檢查指定 CrowdStrike 雲端區域的 DNS、TCP 443、TLS 1.2 與伺服器憑證，將失敗階段及憑證資訊保存為 JSON、CSV、TXT 報告。

工具不需要 CID、API Key 或管理員權限，不會安裝 Sensor，也不會修改 Proxy、登錄檔、Schannel、憑證存放區或防火牆。只有測試報告會寫入磁碟。`tests/` 是開發驗證程式，會暫時建立本機測試憑證，不需要在客戶端執行。

## 快速開始

1. 使用 GitHub 的 **Code → Download ZIP** 下載並完整解壓縮，保留 `src` 目錄。
2. 開啟 Windows PowerShell 5.1 或 Windows 上的 PowerShell 7，切換到解壓縮後的目錄。
3. 按照 Falcon Console 所在區域執行。以下使用 US-2：

```powershell
powershell.exe -NoProfile -File .\Test-CrowdStrikeConnection.ps1 -Cloud US-2
```

若檔案被 Windows 標記為下載檔，先檢視程式碼，再對已確認的檔案使用 `Unblock-File`。簽章或執行原則由組織管控時，請使用組織核准的方式執行。

| Falcon Console | `-Cloud` |
| --- | --- |
| `falcon.crowdstrike.com` | `US-1` |
| `falcon.us-2.crowdstrike.com` | `US-2` |
| `falcon.eu-1.crowdstrike.com` | `EU-1` |

Cloud 必須明確指定，未指定時 PowerShell 會提示輸入。政府雲、其他區域與特殊租戶端點未內建，請勿套用其他區域後據此判定通過。

## 測試內容

| 項目 | 判定方式 |
| --- | --- |
| DNS | 解析 A/AAAA，記錄所有回傳位址；直連逐一測試每個 IP |
| TCP | 連接目標的 443，或既有 HTTP Proxy 的監聽埠 |
| Proxy | Auto 使用目前執行身分的 .NET 系統 Proxy；HTTP CONNECT 必須回覆 200 |
| TLS | 使用原始 FQDN 做 SNI 與主機名稱驗證，指定 TLS 1.2，不降級 |
| 憑證 | 使用系統信任鏈、名稱及有效期驗證；不接受不受信任憑證 |
| 憑證證據 | 記錄 Subject、Issuer、Thumbprint、到期日、鏈驗證錯誤 |
| 撤銷檢查 | 加入 `-CheckRevocation` 才要求 .NET 撤銷驗證；系統快取與政策仍會影響結果 |

不對 Sensor 端點要求 HTTP 200；Sensor 服務不是一般網站，HTTP 403/404 無法直接代表網路中斷。本工具完成 TLS 握手後即關閉連線，不傳送 Sensor 資料、不模擬註冊。

## 端點清單

| 區域 | Sensor 通訊 | 檔案下載 | 檔案上傳 |
| --- | --- | --- | --- |
| US-1 | `ts01-b.cloudsink.net` | `lfodown01-b.cloudsink.net` | `lfoup01-b.cloudsink.net` |
| US-2 | `ts01-gyr-maverick.cloudsink.net` | `lfodown01-gyr-maverick.cloudsink.net` | `lfoup01-gyr-maverick.cloudsink.net` |
| EU-1 | `ts01-lanner-lion.cloudsink.net` | `lfodown01-lanner-lion.cloudsink.net` | `lfoup01-lanner-lion.cloudsink.net` |

上述 Sensor 端點使用對外 TCP 443。本清單為公開文件中的基礎端點，不保證涵蓋所有模組、租戶或後續變更。部署前仍應以該租戶 Falcon Console 的 **Sensor Deployment / Network Requirements** 為準。

`-IncludeConsole` 額外測試所選區域的 Console 與 API，列為選用項目。這不是完整的管理介面白名單，未包含 assets、firehose 等所有服務；管理介面連通也不代表 Sensor 連通。

## 使用範例

```powershell
# 預設：偵測並使用既有系統 Proxy，或按系統設定直連
.\Test-CrowdStrikeConnection.ps1 -Cloud US-2

# 僅測直連，供比較網路路徑
.\Test-CrowdStrikeConnection.ps1 -Cloud US-2 -ConnectionMode Direct

# 啟用憑證撤銷檢查，每個階段最多等待 15 秒
.\Test-CrowdStrikeConnection.ps1 -Cloud US-1 -CheckRevocation -TimeoutSeconds 15

# 同時檢查管理介面，指定報告目錄
.\Test-CrowdStrikeConnection.ps1 -Cloud EU-1 -IncludeConsole -OutputDirectory C:\Temp\FalconPreflight

# 加入租戶文件指定的其他主機；仍會測試原本區域的三個端點
.\Test-CrowdStrikeConnection.ps1 -Cloud US-2 -AdditionalHost 'tenant-endpoint.example.com'
```

最後一個範例是佔位主機，必須換成租戶文件的實際 FQDN。額外主機視為必要項目。參數僅接受完整 DNS 名稱，不接受 URL、萬用字元、IP、埠號或登入憑證。

## Proxy 的判讀

- `Auto` 使用 .NET `GetSystemWebProxy()`，依目標判斷目前身分的 Proxy/PAC 路徑。PowerShell 5.1 與 7 使用不同 .NET 版本，偵測結果可能不同。
- 同時記錄 `netsh winhttp show proxy` 與目前使用者的 Internet Settings，供人工對照；這些資訊不會自動套用成 Sensor 設定。
- 已偵測到 Proxy 但連線失敗時，不會悄悄切換直連。偵測逾時也會記錄失敗。
- 不提供自訂 Proxy 參數、不送出認證、不使用目前 Windows 登入憑證。Proxy 回覆 407 會明確失敗。
- 只支援 HTTP Proxy 的 CONNECT；HTTPS/SOCKS Proxy 或含帳密的 Proxy URI 會列為不支援。
- 經 Proxy 時，測試其所有解析位址，目標 DNS 可由 Proxy 解析；本機目標 DNS 失敗會記錄 `DNSError`，不會直接判定 Proxy 路徑失敗。
- Sensor 以服務身分執行，其 Proxy、憑證存放區及網路政策可能和互動登入使用者不同。應比對實際部署情境。

## 結果與報告

預設輸出至 `reports/`，檔名包含時間與隨機識別碼，避免重複執行覆蓋。JSON 保存完整逐 IP 測試結果與環境資料，CSV 供整理，TXT 供直接閱讀。報告含電腦名稱、Proxy/PAC 資訊、內部網路位址等環境資料，請按客戶資料規範分享；不會自動上傳報告。

| 狀態 | 意義 |
| --- | --- |
| PASS | 該主機所有測試位址的 TLS 1.2 與系統憑證驗證通過 |
| WARN | 至少一個位址成功，但另有失敗，例如 IPv4 可通、IPv6 不通 |
| FAIL | 無可成功完成測試的路徑，或 Proxy 偵測/DNS 階段失敗 |

| 程式退出碼 | 意義 |
| --- | --- |
| 0 | 所有已選測試項目通過 |
| 1 | 至少一個必要端點 FAIL |
| 2 | 有 WARN，或只有選用 Console/API 失敗，需人工確認 |
| 3 | 工具初始化、輸入驗證或報告寫入失敗 |

PowerShell 在腳本執行前拒絕參數或執行原則時，退出碼由 PowerShell 決定。用部署工具呼叫時，應以子程序退出碼判斷；不要將所有非零退出碼當成相同原因。

## 故障排查與界線

| 失敗階段／現象 | 檢查方向 |
| --- | --- |
| DNS | DNS 伺服器、分割 DNS、名稱過濾與 Proxy 端解析 |
| TCP | 出站 ACL、防火牆、Proxy 埠、路由與 IPv6 可達性 |
| ProxyCONNECT 407 | Proxy 要求認證，確認 Sensor 支援方式及必要的認證排除 |
| ProxyCONNECT 403 | Proxy 的目標主機／CONNECT 規則 |
| TLS 逾時或重設 | TLS 1.2、Schannel、加密套件、TLS 檢查設備或服務端拒絕一般用戶端 |
| 憑證名稱／信任鏈錯誤 | 系統時間、根憑證、攔截憑證、缺少中繼憑證 |
| 撤銷檢查失敗 | 實際憑證的 CRL/OCSP 連線與系統快取；本工具不把 CA 網站首頁 HTTP 狀態當作撤銷驗證 |

**PASS 只代表這次一般 TLS 用戶端的網路測試通過，不能保證 Sensor 能安裝、註冊或正常回報。** 本工具不模擬 Sensor 的憑證釘選、用戶端憑證或應用層通訊；合法的系統信任憑證也不等於符合 Sensor 的信任機制。若 TLS 檢查設備的 CA 已被系統信任，測試可能通過，仍須人工比對憑證與確認網路政策。

不檢查安裝套件簽章、OS 支援矩陣、舊版 Windows 必要 KB、CID、Provisioning Token、安裝權限或 Sensor 註冊。Windows 7／Server 2008 R2 等舊環境需要另外核對適用 Sensor 版本、WMF/.NET 與補丁；此工具的最低 PowerShell 版本不是 Sensor 的作業系統支援承諾。

`-TimeoutSeconds` 是各 DNS、Proxy 偵測、單 IP TCP、CONNECT、TLS 階段的等待上限，不是整次執行的總時間。系統 DNS/PAC 背景作業與憑證驗證的底層清理可能較久；多個端點／IP 會累加時間。

## 開發驗證

GitHub Actions 在 Windows runner 上，分別使用 Windows PowerShell 5.1 和 PowerShell 7，執行語法解析與本機網路測試。不依賴 CrowdStrike 網站是否回應。

```powershell
.\tests\Run-Tests.ps1
```

測試涵蓋：區域端點與選用項目、非法主機名稱、分層結果／退出碼、Proxy 407、TLS 逾時、不受信任憑證、正確 TLS 1.2、CONNECT 後的 TLS，以及憑證主機名稱不符。測試建立短效 localhost 憑證，暫存於目前使用者 My/Root store，並在 finally 移除；請在開發或 CI 環境執行。

## 資料來源

核對日期：2026-09-16。

- [Dell：CrowdStrike Falcon Sensor System Requirements](https://www.dell.com/support/kbdoc/en-us/000177899/crowdstrike-falcon-sensor-system-requirements)：三個區域的公開 Sensor 主機與 TCP 443 / TLS 1.2 要求。此文件的舊 OS 清單不作為現行版本支援判定。
- [CrowdStrike：Falcon Helm / Falcon Admission Controller](https://github.com/CrowdStrike/falcon-helm/blob/main/helm-charts/falcon-kac/README.md)：交叉核對通訊及下載端點；其產品部署範圍不同，不能直接當作 Windows Sensor 完整白名單。
- [Microsoft：SslStream.AuthenticateAsClientAsync](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream.authenticateasclientasync)：TLS 協定與憑證驗證 API。

本專案為 AIShield 的部署輔助工具，非 CrowdStrike 官方驗證工具。沿用 repository 既有 Apache-2.0 授權。
