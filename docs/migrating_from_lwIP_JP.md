# lwIP から wolfIP への移行

## 目次

- [1. 対象範囲](#1-対象範囲)
- [2. 設計モデル：lwIP と wolfIP の比較](#2-設計モデルlwip-と-wolfip-の比較)
- [3. 設定の移行：`lwipopts.h` から wolfIP `config.h` へ](#3-設定の移行lwipoptsh-から-wolfip-configh-へ)
- [4. 初期化とネットワークデバイスの接続](#4-初期化とネットワークデバイスの接続)
- [5. 既存の lwIP ネットワークドライバの移植](#5-既存の-lwip-ネットワークドライバの移植)
- [6. 乱数ソース](#6-乱数ソース)
- [7. ベアメタル向けソケット API の移行](#7-ベアメタル向けソケット-api-の移行)
- [8. lwIP raw/classic API からシンプルな TCP サーバーへの変換](#8-lwip-rawclassic-api-からシンプルな-tcp-サーバーへの変換)
- [9. lwIP ALTCP インターフェースからシンプルな TCP サーバーへの変換](#9-lwip-altcp-インターフェースからシンプルな-tcp-サーバーへの変換)
- [10. RTOS 統合](#10-rtos-統合)
- [11. 新しい RTOS への wolfIP の移植](#11-新しい-rtos-への-wolfip-の移植)
- [12. 移行チェックリスト](#12-移行チェックリスト)
- [13. よくある落とし穴](#13-よくある落とし穴)
- [14. クイック API マッピング](#14-クイック-api-マッピング)

## 1. 対象範囲

このガイドは、組み込みネットワークコードを lwIP から wolfIP に移行する開発者およびインテグレーター向けです。主に以下を対象とします：

- lwIP と wolfIP の設計上の違い；
- `lwipopts.h` の設定を wolfIP `config.h` で置き換える方法；
- 乱数ソースの設計；
- 既存の lwIP Ethernet/ネットワークドライバの移植；
- lwIP raw/classic および lwIP ALTCP スタイル API からのベアメタル TCP サーバーコードへの移行；
- 既存の FreeRTOS BSD ソケットラッパーをモデルとした、RTOS への wolfIP の統合。

サンプルコードは意図的に小さく作られています。これらは移行パターンを示すためのものであり、実践レベルのエラー処理、リソース管理、またはボード固有の Ethernet ドライバコードを示すものではありません。

---

## 2. 設計モデル：lwIP と wolfIP の比較

### 2.1 lwIP モデル

lwIP は高度に設定可能です。典型的な lwIP アプリケーションは、コールバック、Netconn、BSD ソケットの中から選択し、`lwipopts.h` を通じてメモリプール、pbuf プール、プロトコル制御ブロック、メールボックス/スレッドサポート、TCP/IP スレッドの動作、プロトコル機能を設定します。

例えば、lwIP は raw PCB、UDP PCB、アクティブな TCP PCB、待機中の TCP PCB、キュー済み TCP セグメント、Netconn オブジェクト、API メッセージ、DNS API メッセージ、ソケット/セレクトヘルパー、pbuf プール、ARP キューエントリ、タイムアウト用に個別のプール設定を提供しています。公式の lwIP オプションドキュメントでは、これらを `MEMP_NUM_TCP_PCB`、`MEMP_NUM_TCP_PCB_LISTEN`、`MEMP_NUM_UDP_PCB`、`MEMP_NUM_TCP_SEG`、`MEMP_NUM_NETCONN`、`MEMP_NUM_TCPIP_MSG_API`、`PBUF_POOL_SIZE` などの独立した設定項目として列挙しています。

### 2.2 wolfIP モデル

wolfIP はより直接的で静的です。スタックインスタンスはソケットの固定配列と固定サイズバッファを所有します。現在の `struct wolfIP` には以下のような配列が含まれます：

- `tcpsockets[MAX_TCPSOCKETS]`
- `udpsockets[MAX_UDPSOCKETS]`
- `icmpsockets[MAX_ICMPSOCKETS]`
- 機能が有効な場合の raw ソケットおよびパケットソケット配列

デフォルトの `config.h` では、`MAX_TCPSOCKETS` を 4、`MAX_UDPSOCKETS` を 2、`MAX_ICMPSOCKETS` を 2、`RXBUF_SIZE` を 20 KiB、`TXBUF_SIZE` を 32 KiB に設定しています。また、MTU、ネイバー、インターフェース、ループバック、raw ソケット、パケットソケット、転送、および静的 DNS のデフォルトも設定されています。

実際の移行は「lwIP の全プールを見つけてそのまま数値をコピーする」ということではありません。代わりに、製品が必要とする TCP、UDP、ICMP、raw、パケットソケットの最大同時接続数を決定し、トラフィックパターンに合わせて RX/TX バッファと MTU を調整します。

### 2.3 タイプ別の有限ソケット

wolfIP のソケットディスクリプタは、ソケットタイプとソケットインデックスの両方をエンコードします。公開ヘッダでは `MARK_TCP_SOCKET`、`MARK_UDP_SOCKET`、`MARK_ICMP_SOCKET`、`MARK_RAW_SOCKET`、`MARK_PACKET_SOCKET` などのソケットマーク、および `IS_SOCKET_TCP(fd)`、`SOCKET_UNMARK(fd)` などのヘルパーが定義されています。また、低位バイトがソケットインデックスとして使用されるため、各ソケット数が 256 未満に収まるよう強制されています。

移行時に注意すべき点：

- 待機中の TCP ソケットは TCP ソケットスロットを消費する；
- 各接続済み TCP コネクションもさらに TCP ソケットスロットを消費する；
- UDP ソケットは UDP ソケットプールから消費される；
- DNS や DHCP の使い方によって内部的にソケットを消費することがある；
- バックログを増やしても無制限の accept キューは作成されない。

1 つのリスナーと 3 つの同時クライアントを許可するシンプルな TCP サーバーの場合、最低限 `MAX_TCPSOCKETS 4` が必要です。1 つのリスナーと 8 つのクライアントを受け入れる必要がある場合は、`MAX_TCPSOCKETS` を少なくとも 9 に設定してください。

---

## 3. 設定の移行：`lwipopts.h` から wolfIP `config.h` へ

### 3.1 概念的な変更点

lwIP において、`lwipopts.h` は機能選択ファイルとリソースプール調整ファイルを兼ねます。以下のようなオプションが含まれる場合があります：

- OS モード：`NO_SYS`、`SYS_LIGHTWEIGHT_PROT`、`LWIP_NETCONN`、`LWIP_SOCKET`；
- メモリ：`MEM_SIZE`、`MEMP_NUM_*`、`PBUF_POOL_SIZE`、`PBUF_POOL_BUFSIZE`；
- TCP：`TCP_MSS`、`TCP_WND`、`TCP_SND_BUF`、`TCP_SND_QUEUELEN`、`MEMP_NUM_TCP_SEG`；
- プロトコル：`LWIP_TCP`、`LWIP_UDP`、`LWIP_ICMP`、`LWIP_DHCP`、`LWIP_DNS`、`LWIP_IPV4`、`LWIP_IPV6`；
- API モード：raw、Netconn、ソケット、ALTCP；
- ポート固有のシステム設定。

wolfIP では、`config.h` を用いて設定をシンプルに保ちます。重要なリソース設定は直接的です：タイプ別のソケット数、バッファサイズ、MTU、ネイバー数、インターフェース数、および raw ソケット、パケットソケット、転送、ループバック、HTTP サポートなどのオプション機能。

### 3.2 推奨移行テーブル

| lwIP 設定領域 | 典型的な lwIP オプション | wolfIP での移行方針 |
|---|---:|---|
| アクティブ TCP PCB | `MEMP_NUM_TCP_PCB` | `MAX_TCPSOCKETS` を使用。リスナーと受け入れ済み/クライアントソケットを合わせてカウント。 |
| TCP 待機 PCB | `MEMP_NUM_TCP_PCB_LISTEN` | wolfIP には個別のリスナープールはない。待機サーバーは TCP ソケットスロットを 1 つ使用。 |
| UDP PCB | `MEMP_NUM_UDP_PCB` | `MAX_UDPSOCKETS` を使用。アプリケーションの UDP ソケットと有効にした内部ユーザーを含める。 |
| ICMP/raw 処理 | `LWIP_RAW`、`MEMP_NUM_RAW_PCB` | ICMP ソケットには `MAX_ICMPSOCKETS` を使用。raw ソケットが必要な場合のみ `WOLFIP_RAWSOCKETS` を有効にして `WOLFIP_MAX_RAWSOCKETS` を設定。 |
| パケットソケット | 通常はポート/プラットフォーム固有 | Ethernet パケットソケットが必要な場合のみ `WOLFIP_PACKET_SOCKETS` を有効にして `WOLFIP_MAX_PACKETSOCKETS` を設定。 |
| pbuf プール | `PBUF_POOL_SIZE`、`PBUF_POOL_BUFSIZE` | `RXBUF_SIZE`、`TXBUF_SIZE`、`LINK_MTU` を調整。 |
| TCP セグメントキュー | `MEMP_NUM_TCP_SEG`、`TCP_SND_QUEUELEN` | `TXBUF_SIZE` と TCP ソケット数を調整。wolfIP は固定 TX メモリにキューイング。 |
| TCP ウィンドウ/送信バッファ | `TCP_WND`、`TCP_SND_BUF` | wolfIP の TCP バッファ動作を確認し、アプリケーションスループットが停滞する場合は `RXBUF_SIZE`/`TXBUF_SIZE` を増加。 |
| ARP ネイバーキャッシュ | `ARP_TABLE_SIZE`、`MEMP_NUM_ARP_QUEUE` | `MAX_NEIGHBORS` を使用。wolfIP には ARP 保留リクエストストレージもある。 |
| インターフェース | `LWIP_SINGLE_NETIF`、`netif` セットアップ | 複数インターフェースには `WOLFIP_MAX_INTERFACES` と `wolfIP_getdev_ex()` / `wolfIP_ipconfig_set_ex()` を使用。 |
| IPv6 | `LWIP_IPV6` | 直接的な設定マッピングを前提としない。wolfIP のバージョン/フォークが必要な IPv6 パスを明示的にサポートしている場合を除き、IPv4 コードのみ移行する。 |
| Netconn/BSD ソケット | `LWIP_NETCONN`、`LWIP_SOCKET` | ベアメタルは `wolfIP_sock_*` を直接使用。RTOS ポートは `wolfIP_sock_*` の周りに BSD スタイルラッパーを追加可能。 |
| ALTCP/TLS | `LWIP_ALTCP`、`LWIP_ALTCP_TLS` | ALTCP トランスポートコールバックを wolfIP ソケットで置き換える。TLS には wolfSSL を wolfIP ソケット上に配置し、有効な場合は wolfIP/wolfSSL 統合フックを使用。 |
| 静的 IP | `IP_ADDR`、`NETMASK`、`GW` またはボード設定 | `wolfIP_ipconfig_set()` または `wolfIP_ipconfig_set_ex()` を使用。 |
| 静的 DNS | ポート固有 | `WOLFIP_STATIC_DNS_IP` を使用するか、バージョンで利用可能なスタック API を通じて DNS 状態を設定。 |

### 3.3 最小限の `config.h`

```c
#ifndef WOLF_CONFIG_H
#define WOLF_CONFIG_H

#define ETHERNET

#define LINK_MTU 1536
#ifndef LINK_MTU_MIN
#define LINK_MTU_MIN 64U
#endif

#define MAX_TCPSOCKETS  5  /* 1 listener + 4 clients */
#define MAX_UDPSOCKETS  2
#define MAX_ICMPSOCKETS 1

#define RXBUF_SIZE (20 * 1024)
#define TXBUF_SIZE (32 * 1024)

#define MAX_NEIGHBORS 16

#ifndef WOLFIP_MAX_INTERFACES
#define WOLFIP_MAX_INTERFACES 1
#endif

#ifndef WOLFIP_RAWSOCKETS
#define WOLFIP_RAWSOCKETS 0
#endif

#ifndef WOLFIP_PACKET_SOCKETS
#define WOLFIP_PACKET_SOCKETS 0
#endif

#ifndef WOLFIP_ENABLE_FORWARDING
#define WOLFIP_ENABLE_FORWARDING 0
#endif

#ifndef WOLFIP_ENABLE_LOOPBACK
#define WOLFIP_ENABLE_LOOPBACK 0
#endif

#define WOLFIP_STATIC_DNS_IP "9.9.9.9"

#endif
```

サーバーの場合、`MAX_TCPSOCKETS` に待機ソケットを含めることを忘れないでください。例えば、1 つのリスナーと 4 つのクライアントを持つサーバーには、少なくとも 5 つの TCP ソケットが必要です。

---

## 4. 初期化とネットワークデバイスの接続

wolfIP は小さなリンク層ドライバインターフェースを公開しています：

```c
struct wolfIP_ll_dev {
    uint8_t mac[6];
    char ifname[16];
    uint8_t non_ethernet;
    uint32_t mtu;

    int (*poll)(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);
    int (*send)(struct wolfIP_ll_dev *ll, void *buf, uint32_t len);

    void *priv;
};
```

スタックは呼び出し元が提供したストレージで `wolfIP_init()` を使用して初期化することができます。静的スタックストレージが有効な場合は `wolfIP_init_static()` を使用します。`wolfIP_instance_size()` はスタックオブジェクトのサイズを返します。`WOLFIP_NOSTATIC` が定義されている場合、静的イニシャライザは無効になります。

典型的なベアメタルセットアップは以下の通りです：

```c
#include "config.h"
#include "wolfip.h"

static struct wolfIP *ipstack;

static int eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    /*
     * Return:
     *   >0 number of bytes received
     *    0 no packet available
     *   <0 driver error
     */
    return board_eth_poll(ll->priv, buf, len);
}

static int eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    /*
     * Return:
     *    0 or positive on success
     *   -WOLFIP_EAGAIN if the driver cannot accept the frame yet
     *   negative on hard error
     */
    return board_eth_send(ll->priv, buf, len);
}

void network_init(void)
{
    struct wolfIP_ll_dev *dev;

    wolfIP_init_static(&ipstack);

    dev = wolfIP_getdev(ipstack);
    dev->priv = board_eth_context();
    dev->poll = eth_poll;
    dev->send = eth_send;
    dev->mtu = LINK_MTU;
    dev->mac[0] = 0x02;
    dev->mac[1] = 0x00;
    dev->mac[2] = 0x00;
    dev->mac[3] = 0x00;
    dev->mac[4] = 0x00;
    dev->mac[5] = 0x01;

    wolfIP_ipconfig_set(
        ipstack,
        atoip4("192.168.1.50"),
        atoip4("255.255.255.0"),
        atoip4("192.168.1.1")
    );
}

void network_poll_forever(void)
{
    for (;;) {
        wolfIP_poll(ipstack, board_millis());
    }
}
```

`wolfIP_poll()` はコアの進行関数です。設定された各リンク層デバイスをポーリングし、受信パケットを処理し、タイマーを実行し、ソケットコールバックをディスパッチし、保留中の TCP/UDP/ICMP/raw/パケットデータの送信を試みます。

---

## 5. 既存の lwIP ネットワークドライバの移植

### 5.1 ドライバ境界での変更点

lwIP の Ethernet ドライバは通常 `struct netif` の後方に位置します。ドライバ初期化コールバックは MAC アドレス、MTU、インターフェースフラグ、`netif->state`、`netif->output`、`netif->linkoutput` などのフィールドを設定します。送信は通常 `netif->linkoutput` から `struct pbuf *` チェーンを受け取ります。受信は通常 `PBUF_RAW` pbuf または pbuf チェーンを割り当て、受信フレームをコピーし、`netif->input(p, netif)` を通じて上位に渡します。

wolfIP はその `netif`/`pbuf` 境界を取り除きます。ドライバはインターフェースごとに 1 つの `struct wolfIP_ll_dev` を公開します。スタックは `wolfIP_poll()` からドライバの `poll` 関数を呼び出して完全な受信フレームを要求し、ハードウェアに送信する完全なフレームの準備ができたらドライバの `send` 関数を呼び出します。`poll` または `send` に渡されるスタックバッファは線形です。ドライバは pbuf チェーンを受け取ったり返したりしません。

以下のメンタルマッピングを参考にしてください：

| lwIP ドライバの概念 | wolfIP ドライバの概念 |
|---|---|
| `struct netif` | `struct wolfIP_ll_dev` とドライバ状態用の `ll->priv` |
| `netif->state` | `ll->priv` |
| `netif->hwaddr[]` | `ll->mac[]` |
| `netif->mtu` | `ll->mtu` または `wolfIP_mtu_set()`；Ethernet の場合、これは wolfIP のフレームバジェットで、IPv4 ペイロード MTU はリンクオーバーヘッドを差し引いた後に導出される |
| `netif->linkoutput(netif, pbuf)` | `ll->send(ll, frame, len)` |
| pbuf を割り当てる `low_level_input()` | wolfIP のバッファにコピーする `ll->poll(ll, buf, len)` |
| `netif->input(p, netif)` | ドライバからは呼び出されない；wolfIP が `poll` でフレームを返した後に受信パスを呼び出す |
| `pbuf` チェーントラバーサル | 不要；wolfIP は単一の連続フレームバッファを渡す |
| `netif_add()` / `netif_set_default()` | `wolfIP_getdev()` / `wolfIP_getdev_ex()` と `wolfIP_ipconfig_set()` / `wolfIP_ipconfig_set_ex()` |

### 5.2 典型的な lwIP pbuf ベースの Ethernet ポート

以下は架空ですが代表的な lwIP Ethernet ドライバです。意図的に小さく作られており、ハードウェア関数はお使いの DMA ディスクリプタまたは MAC ドライバのプレースホルダーです。

```c
#include "lwip/err.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

struct my_lwip_eth {
    void *hw;
    uint8_t mac[6];
};

static err_t my_low_level_output(struct netif *netif, struct pbuf *p)
{
    struct my_lwip_eth *eth = (struct my_lwip_eth *)netif->state;
    struct pbuf *q;

    /* p can be a chain. The driver must transmit all fragments as one frame. */
    if (my_hw_tx_begin(eth->hw, p->tot_len) != 0) {
        return ERR_IF;
    }

    for (q = p; q != NULL; q = q->next) {
        if (my_hw_tx_write(eth->hw, q->payload, q->len) != 0) {
            my_hw_tx_abort(eth->hw);
            return ERR_IF;
        }
    }

    if (my_hw_tx_commit(eth->hw) != 0) {
        return ERR_IF;
    }

    return ERR_OK;
}

static struct pbuf *my_low_level_input(struct netif *netif)
{
    struct my_lwip_eth *eth = (struct my_lwip_eth *)netif->state;
    struct pbuf *p;
    struct pbuf *q;
    uint16_t frame_len;

    if (!my_hw_rx_ready(eth->hw)) {
        return NULL;
    }

    frame_len = my_hw_rx_frame_len(eth->hw);
    p = pbuf_alloc(PBUF_RAW, frame_len, PBUF_POOL);
    if (p == NULL) {
        my_hw_rx_drop(eth->hw);
        return NULL;
    }

    /* The incoming Ethernet frame is copied into the pbuf chain. */
    for (q = p; q != NULL; q = q->next) {
        if (my_hw_rx_read(eth->hw, q->payload, q->len) != 0) {
            pbuf_free(p);
            my_hw_rx_drop(eth->hw);
            return NULL;
        }
    }

    my_hw_rx_release(eth->hw);
    return p;
}

void my_ethernetif_input(struct netif *netif)
{
    struct pbuf *p = my_low_level_input(netif);

    if (p == NULL) {
        return;
    }

    if (netif->input(p, netif) != ERR_OK) {
        pbuf_free(p);
    }
}

err_t my_ethernetif_init(struct netif *netif)
{
    static struct my_lwip_eth eth0;

    eth0.hw = my_hw_open(0);
    my_hw_get_mac(eth0.hw, eth0.mac);

    netif->state = &eth0;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    memcpy(netif->hwaddr, eth0.mac, sizeof(eth0.mac));
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    netif->output = etharp_output;
    netif->linkoutput = my_low_level_output;

    return ERR_OK;
}
```

lwIPの振る舞いについて特に注意すべき点：

* 送信は 1 つの論理 Ethernet フレームを受け取るが、バイトは pbuf チェーンに分散している場合がある。
* 受信はパケットを lwIP に渡す前に pbuf ストレージを作成する。
* ドライバは多くの場合、メインループ、割り込みボトムハーフ、または RTOS タスクから呼び出さなければならない独立した `ethernetif_input()` パスを持つ。

### 5.3 `send` と `poll` を使用した等価 wolfIP ドライバ

wolfIP では、スタックが提供するリニアバッファに対してハードウェアドライバが 1 つの完全なフレームをコピーするようにします。ハードウェアレイヤがメモリの有効性を保証しない限り、`send` または `poll` が戻った後に `buf` ポインタを保持しないでください。ポータブルなドライバはこれを前提にすべきではありません。

```c
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "wolfip.h"

struct my_wolfip_eth {
    void *hw;
    uint8_t mac[6];
};

static int my_wolfip_eth_poll(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct my_wolfip_eth *eth = (struct my_wolfip_eth *)ll->priv;
    uint32_t frame_len;

    if (!my_hw_rx_ready(eth->hw)) {
        return 0; /* No frame available now. */
    }

    frame_len = my_hw_rx_frame_len(eth->hw);
    if (frame_len > len) {
        my_hw_rx_drop(eth->hw);
        return -WOLFIP_EINVAL;
    }

    if (my_hw_rx_read_frame(eth->hw, buf, frame_len) != 0) {
        my_hw_rx_drop(eth->hw);
        return -WOLFIP_EINVAL;
    }

    my_hw_rx_release(eth->hw);
    return (int)frame_len; /* One complete Ethernet frame, including header. */
}

static int my_wolfip_eth_send(struct wolfIP_ll_dev *ll, void *buf, uint32_t len)
{
    struct my_wolfip_eth *eth = (struct my_wolfip_eth *)ll->priv;

    if (len > LINK_MTU) {
        return -WOLFIP_EINVAL;
    }

    if (!my_hw_tx_has_free_desc(eth->hw)) {
        return -WOLFIP_EAGAIN;
    }

    /* The wolfIP buffer is linear. Queue or copy it into hardware-owned memory. */
    if (my_hw_tx_enqueue_copy(eth->hw, buf, len) != 0) {
        return -WOLFIP_EAGAIN;
    }

    return 0;
}
```

受信パスは lwIP バージョンと比べて逆転しています。pbuf を割り当てて `netif->input()` を呼び出す必要はありません。代わりに、`wolfIP_poll()` が `my_wolfip_eth_poll()` を呼び出します。`poll` が正のフレーム長を返すと、wolfIP はそのフレームを内部処理します。`0` を返す場合は処理するパケットがありません。負の値を返す場合、スタックはそのポール試行ではフレームを処理しません。

送信パスもスタック境界でシンプルです。pbuf チェーンを走査する必要はありません。wolfIP は連続した Ethernet フレームを `send` に渡します。戻り値が `0` の場合、ドライバがフレームを受け入れたことを意味します。`-WOLFIP_EAGAIN` は TX リングまたはハードウェアキューが一時的に満杯で、スタックが次の `wolfIP_poll()` サイクルで再試行すべきことを意味します。

### 5.4 wolfIP インターフェースの初期化

1 つの物理 Ethernet インターフェースの場合、スタックを初期化し、プライマリリンク層デバイスを取得し、ドライバコールバックとメタデータを設定し、IPv4 設定を行います。以下の例では、`LINK_MTU` は wolfIP のリンクフレームバジェットとして使用され、wolfIP はその値から Ethernet オーバーヘッドを差し引いた後に IPv4 ペイロード MTU を導出します。

```c
static struct wolfIP *ipstack;
static struct my_wolfip_eth eth0;

void my_wolfip_network_init(void)
{
    struct wolfIP_ll_dev *dev;

    wolfIP_init_static(&ipstack);

    eth0.hw = my_hw_open(0);
    my_hw_get_mac(eth0.hw, eth0.mac);

    dev = wolfIP_getdev(ipstack);
    memset(dev, 0, sizeof(*dev));

    memcpy(dev->mac, eth0.mac, sizeof(eth0.mac));
    strncpy(dev->ifname, "e0", sizeof(dev->ifname) - 1);
    dev->mtu = LINK_MTU;
    dev->poll = my_wolfip_eth_poll;
    dev->send = my_wolfip_eth_send;
    dev->priv = &eth0;

    wolfIP_ipconfig_set(
        ipstack,
        atoip4("192.168.1.50"),
        atoip4("255.255.255.0"),
        atoip4("192.168.1.1")
    );
}
```

複数の物理インターフェースの場合は、`config.h` で `WOLFIP_MAX_INTERFACES` を設定し、各ハードウェアインスタンスを初期化し、`wolfIP_getdev_ex()` で各デバイスを取得し、`wolfIP_ipconfig_set_ex()` で各インターフェースを設定します。

```c
#define MY_ETH_PORTS 2

static struct wolfIP *ipstack;
static struct my_wolfip_eth eth[MY_ETH_PORTS];

static void my_wolfip_init_one_if(unsigned int if_idx,
                                  const char *ifname,
                                  const char *ip,
                                  const char *mask,
                                  const char *gw)
{
    struct wolfIP_ll_dev *dev = wolfIP_getdev_ex(ipstack, if_idx);

    eth[if_idx].hw = my_hw_open(if_idx);
    my_hw_get_mac(eth[if_idx].hw, eth[if_idx].mac);

    memset(dev, 0, sizeof(*dev));
    memcpy(dev->mac, eth[if_idx].mac, sizeof(eth[if_idx].mac));
    strncpy(dev->ifname, ifname, sizeof(dev->ifname) - 1);
    dev->mtu = LINK_MTU;
    dev->poll = my_wolfip_eth_poll;
    dev->send = my_wolfip_eth_send;
    dev->priv = &eth[if_idx];

    wolfIP_ipconfig_set_ex(ipstack, if_idx, atoip4(ip), atoip4(mask), atoip4(gw));
}

void my_wolfip_network_init_two_ports(void)
{
    wolfIP_init_static(&ipstack);

    my_wolfip_init_one_if(0, "e0", "192.168.1.50", "255.255.255.0", "192.168.1.1");
    my_wolfip_init_one_if(1, "e1", "10.10.10.2",  "255.255.255.0", "10.10.10.1");
}
```

ビルドで wolfIP ループバックが有効な場合、インデックス 0のインターフェースを盲目的に上書きしないように注意してください。プライマリインターフェースには `wolfIP_getdev()` を使用し、インターフェースレイアウトを確認した場合にのみ明示的に `_ex()` インデックスを使用してください。

### 5.5 ポートの駆動

ベアメタルのメインループは通常以下のようになります：

```c
int main(void)
{
    board_init();
    my_wolfip_network_init();

    for (;;) {
        wolfIP_poll(ipstack, board_millis());
    }
}
```

割り込み駆動型 MAC の場合、ISR は小規模に設計してください。ISR はハードウェア割り込みを確認し、ネットワークループまたは RTOS ポールタスクを起動します。`poll` コールバックで RX ディスクリプタをドレインし、`send` で TX フレームをキューに入れてください。これにより、wolfIP スタックの全処理が同じ実行パス上に保たれ、割り込みからスタックに再入することを防ぎます。

### 5.6 ドライバ移行チェックリスト

* RX での pbuf 割り当てを、`ll->poll` に渡されるバッファへの 1 つの完全なフレームのコピーに置き換える。
* TX での pbuf チェーンの反復を、`ll->send` に渡される単一の連続フレームの送信に置き換える。
* `netif->state` の内容を `ll->priv` が参照するドライバプライベート構造体に移動する。
* MAC アドレスと MTU の設定を `netif` フィールドから `ll->mac` と `ll->mtu` に移動する。
* `netif_add()` と `netif_set_default()` を `wolfIP_getdev()` / `wolfIP_getdev_ex()` と `wolfIP_ipconfig_set()` / `wolfIP_ipconfig_set_ex()` に置き換える。
* 処理対象のフレームが存在しない場合は `poll` から `0` を、1 フレームがコピーされた場合は正のフレーム長を、ドライバエラーの場合は負のエラーを返す。
* ドライバがフレームを受け入れまたはコピーした後は `send` から `0` を、TX キューが一時的に満杯の場合は `-WOLFIP_EAGAIN` を返す。

---

## 6. 乱数ソース

wolfIP は、アプリケーションまたはプラットフォームポートが以下を提供することを要求します：

```c
uint32_t wolfIP_getrandom(void);
```

公開ヘッダはこれを外部要件として宣言しています。スタックは IP パケットカウンタシード、TCP シーケンス番号、エフェメラルポート、DNS ID、DNS リトライジッターなどの値にこれを使用します。

ハードウェア RNG、適切にシードされた TRNG/DRBG、またはプラットフォームの暗号乱数ソースを使用してください。製品版環境では定数、タイマーのみのシード、またはシードされていない `rand()` を使用しないでください。

ボードハードウェア RNG を使用した例：

```c
#include <stdint.h>
#include "wolfip.h"

uint32_t wolfIP_getrandom(void)
{
    uint32_t value;

    if (board_trng_read_u32(&value) == 0) {
        return value;
    }

    /*
     * Fallback should still be platform-specific and non-deterministic.
     * In production, prefer failing closed over returning predictable data.
     */
    return board_entropy_fallback_u32();
}
```

すでに wolfSSL/wolfCrypt を初期化している場合に wolfCrypt を使用した例：

```c
#include <stdint.h>
#include "wolfip.h"
#include <wolfssl/wolfcrypt/random.h>

uint32_t wolfIP_getrandom(void)
{
    static WC_RNG rng;
    static int rng_ready;
    uint32_t value = 0;

    if (!rng_ready) {
        if (wc_InitRng(&rng) != 0) {
            return 0; /* Replace with platform fail handling. */
        }
        rng_ready = 1;
    }

    if (wc_RNG_GenerateBlock(&rng, (byte *)&value, sizeof(value)) != 0) {
        return 0; /* Replace with platform fail handling. */
    }

    return value;
}
```

製品版環境では、製品が RNG の失敗をどのように処理するかを決定してください。ゼロを返すことでコードはシンプルになりますが、セキュリティが要求されるビルドには受け入れられない場合があります。

---

## 7. ベアメタル向けソケット API の移行

### 7.1 wolfIP ソケット API

wolfIP は明示的なスタックポインタを持つソケットスタイル API を公開しています：

```c
int wolfIP_sock_socket(struct wolfIP *s, int domain, int type, int protocol);
int wolfIP_sock_bind(struct wolfIP *s, int sockfd,
                     const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int wolfIP_sock_listen(struct wolfIP *s, int sockfd, int backlog);
int wolfIP_sock_accept(struct wolfIP *s, int sockfd,
                       struct wolfIP_sockaddr *addr, socklen_t *addrlen);
int wolfIP_sock_connect(struct wolfIP *s, int sockfd,
                        const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int wolfIP_sock_send(struct wolfIP *s, int sockfd,
                     const void *buf, size_t len, int flags);
int wolfIP_sock_recv(struct wolfIP *s, int sockfd,
                     void *buf, size_t len, int flags);
int wolfIP_sock_close(struct wolfIP *s, int sockfd);
```

同じヘッダには `sendto`、`recvfrom`、`sendmsg`、`recvmsg`、`setsockopt`、`getsockopt`、`getsockname`、`getpeername`、`wolfIP_sock_can_read()`、`wolfIP_sock_can_write()`、およびコールバック登録も含まれます。`CB_EVENT_READABLE`、`CB_EVENT_WRITABLE`、`CB_EVENT_TIMEOUT`、`CB_EVENT_CLOSED` がコアイベントビットです。

重要な動作上のポイント：

* ベアメタルでは、`wolfIP_poll()` を呼び出してwolfIPを駆動する。
* 操作がブロックされる場合、ソケット呼び出しは `-WOLFIP_EAGAIN` を返すことがある。
* `wolfIP_sock_connect()` は TCP 接続進行中に `-WOLFIP_EAGAIN` を返し、確立されると `0` を返す。
* `wolfIP_sock_accept()` は接続が準備できていない場合に `-WOLFIP_EAGAIN` を返す。
* `wolfIP_sock_send()` はソケット TX バッファにデータをキューし、TX スペースがない場合に `-WOLFIP_EAGAIN` を返すことがある。
* `wolfIP_sock_recv()` は利用可能なデータを返し、close-wait ケースでの正常クローズ時に `0`、データがないかソケット状態が無効な場合に負のエラーを返す。

### 7.2 アドレス設定

非 POSIX wolfIP ビルドでは `struct wolfIP_sockaddr_in` を使用します。ソケットアドレスのポートと IPv4 アドレスはネットワークバイトオーダーで格納されるため、適切な場所で `ee16()` と `ee32()` を使用してください。

```c
static void fill_bind_addr(struct wolfIP_sockaddr_in *addr, uint16_t port)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = ee16(port);
    addr->sin_addr.s_addr = ee32(0); /* INADDR_ANY */
}
```

---

## 8. lwIP raw/classic API からシンプルな TCP サーバーへの変換

### 8.1 オリジナル lwIP raw/classic サーバー

これは一般的なベアメタル lwIP コールバックスタイルです：TCP PCB を作成し、バインドし、待機し、accept コールバックを登録し、各受け入れ済み PCB に receive コールバックを登録し、データ消費後に `tcp_recved()` を呼び出し、`tcp_write()` と `tcp_output()` で送信します。通常のフローは `tcp_new()`、`tcp_bind()`、`tcp_listen()`、`tcp_accept()`、`tcp_recv()`、`tcp_recved()`、`tcp_write()`、`tcp_output()` です。

```c
#include "lwip/tcp.h"

#define ECHO_PORT 7

static err_t echo_recv(void *arg,
                       struct tcp_pcb *pcb,
                       struct pbuf *p,
                       err_t err)
{
    struct pbuf *q;

    if (p == NULL) {
        tcp_close(pcb);
        return ERR_OK;
    }

    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }

    tcp_recved(pcb, p->tot_len);

    for (q = p; q != NULL; q = q->next) {
        err_t wr = tcp_write(pcb, q->payload, q->len, TCP_WRITE_FLAG_COPY);
        if (wr != ERR_OK) {
            break;
        }
    }

    tcp_output(pcb);
    pbuf_free(p);

    return ERR_OK;
}

static err_t echo_accept(void *arg,
                         struct tcp_pcb *newpcb,
                         err_t err)
{
    if (err != ERR_OK || newpcb == NULL) {
        return err;
    }

    tcp_recv(newpcb, echo_recv);
    return ERR_OK;
}

void lwip_raw_echo_server_init(void)
{
    struct tcp_pcb *pcb;
    err_t err;

    pcb = tcp_new();
    if (pcb == NULL) {
        return;
    }

    err = tcp_bind(pcb, IP_ADDR_ANY, ECHO_PORT);
    if (err != ERR_OK) {
        tcp_abort(pcb);
        return;
    }

    pcb = tcp_listen(pcb);
    if (pcb == NULL) {
        return;
    }

    tcp_accept(pcb, echo_accept);
}
```

### 8.2 wolfIP ベアメタルバージョン

wolfIP バージョンは 1 つの待機ソケットと受け入れ済みソケットを使用します。ソケットコールバックを登録し、`wolfIP_poll()` を使用してネットワーク処理とイベントを提供します。

```c
#include <string.h>
#include "config.h"
#include "wolfip.h"

#define ECHO_PORT 7

static struct wolfIP *g_ip;
static int g_listen_fd = -1;

static void echo_socket_cb(int fd, uint16_t events, void *arg);

static void close_client(int fd)
{
    (void)wolfIP_sock_close(g_ip, fd);
    wolfIP_register_callback(g_ip, fd, NULL, NULL);
}

static void service_client_readable(int fd)
{
    uint8_t buf[512];

    for (;;) {
        int n = wolfIP_sock_recv(g_ip, fd, buf, sizeof(buf), 0);

        if (n > 0) {
            int off = 0;

            while (off < n) {
                int wr = wolfIP_sock_send(g_ip, fd, buf + off, (size_t)(n - off), 0);

                if (wr > 0) {
                    off += wr;
                    continue;
                }

                if (wr == -WOLFIP_EAGAIN) {
                    /*
                     * This minimal example does not keep a per-client
                     * pending-send queue. If TX space runs out before the
                     * echo is fully queued, close the client instead of
                     * silently dropping the remainder.
                     */
                    close_client(fd);
                    return;
                }

                close_client(fd);
                return;
            }

            continue;
        }

        if (n == 0) {
            close_client(fd);
            return;
        }

        if (n == -WOLFIP_EAGAIN) {
            return;
        }

        close_client(fd);
        return;
    }
}

static void accept_ready_clients(void)
{
    for (;;) {
        struct wolfIP_sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd;

        memset(&peer, 0, sizeof(peer));

        client_fd = wolfIP_sock_accept(
            g_ip,
            g_listen_fd,
            (struct wolfIP_sockaddr *)&peer,
            &peer_len
        );

        if (client_fd >= 0) {
            wolfIP_register_callback(g_ip, client_fd, echo_socket_cb, NULL);
            continue;
        }

        if (client_fd == -WOLFIP_EAGAIN) {
            return;
        }

        return;
    }
}

static void echo_socket_cb(int fd, uint16_t events, void *arg)
{
    (void)arg;

    if (fd == g_listen_fd) {
        if ((events & CB_EVENT_READABLE) != 0) {
            accept_ready_clients();
        }
        return;
    }

    if ((events & CB_EVENT_CLOSED) != 0) {
        close_client(fd);
        return;
    }

    if ((events & CB_EVENT_READABLE) != 0) {
        service_client_readable(fd);
    }

    if ((events & CB_EVENT_WRITABLE) != 0) {
        /*
         * If your application keeps a per-client pending-send queue,
         * resume it here. This minimal echo example sends immediately
         * from the receive path, so there may be nothing to do.
         */
    }
}

int wolfip_echo_server_init(struct wolfIP *ip)
{
    struct wolfIP_sockaddr_in local;
    int ret;

    g_ip = ip;

    g_listen_fd = wolfIP_sock_socket(
        g_ip,
        AF_INET,
        IPSTACK_SOCK_STREAM,
        0
    );

    if (g_listen_fd < 0) {
        return g_listen_fd;
    }

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = ee16(ECHO_PORT);
    local.sin_addr.s_addr = ee32(0); /* INADDR_ANY */

    ret = wolfIP_sock_bind(
        g_ip,
        g_listen_fd,
        (struct wolfIP_sockaddr *)&local,
        sizeof(local)
    );

    if (ret < 0) {
        wolfIP_sock_close(g_ip, g_listen_fd);
        return ret;
    }

    ret = wolfIP_sock_listen(g_ip, g_listen_fd, 1);
    if (ret < 0) {
        wolfIP_sock_close(g_ip, g_listen_fd);
        return ret;
    }

    wolfIP_register_callback(g_ip, g_listen_fd, echo_socket_cb, NULL);
    return 0;
}
```

メインループ：

```c
int main(void)
{
    network_init();

    if (wolfip_echo_server_init(ipstack) < 0) {
        board_fatal_error();
    }

    for (;;) {
        wolfIP_poll(ipstack, board_millis());
    }
}
```

動作の違いについて：

* lwIP raw API の受信コールバックは `pbuf` を渡す；wolfIP ソケットコールバックはソケットが読み取り可能であることを通知し、その後 `wolfIP_sock_recv()` を呼び出す。
* lwIP は受信ウィンドウを通知するために `tcp_recved()` を必要とする；wolfIP は `wolfIP_sock_recv()` 内でこれを処理する。
* lwIP は `tcp_write()` で送信し、次に `tcp_output()` を呼び出す；wolfIP は `wolfIP_sock_send()` で送信し、実際のフレーム出力は `wolfIP_poll()` から進行する。
* lwIP raw コールバックは PCB 中心；wolfIP コールバックはソケットディスクリプタ中心。
* lwIP の待機 PCB とアクティブ PCBは別のプールタイプ；wolfIP は両方に有限 TCP ソケット配列を使用する。

---

## 9. lwIP ALTCP インターフェースからシンプルな TCP サーバーへの変換

### 9.1 オリジナル lwIP ALTCP スタイルサーバー

lwIP ALTCP は TCP コールバック API の抽象化レイヤーです。アプリケーションを `altcp_*` 呼び出しに対して記述し、内部ではプレーン TCP、TLS、プロキシコネクト、または別のレイヤーを使用できるように設計されています。このインターフェースは TCP コールバック API を反映し、`struct tcp_pcb` を `struct altcp_pcb` で置き換え、関数のプレフィックスを `altcp_` にし、選択したトランスポートレイヤーが作成する PCB の種類を決定できるようにアロケーターオブジェクトを使用します。

プレーン TCP ALTCP エコーサーバーは次のようになります：

```c
#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"

#define ECHO_PORT 7

static err_t alt_echo_recv(void *arg,
                           struct altcp_pcb *conn,
                           struct pbuf *p,
                           err_t err)
{
    struct pbuf *q;

    if (p == NULL) {
        altcp_close(conn);
        return ERR_OK;
    }

    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }

    altcp_recved(conn, p->tot_len);

    for (q = p; q != NULL; q = q->next) {
        err_t wr = altcp_write(conn, q->payload, q->len, TCP_WRITE_FLAG_COPY);
        if (wr != ERR_OK) {
            break;
        }
    }

    altcp_output(conn);
    pbuf_free(p);

    return ERR_OK;
}

static err_t alt_echo_accept(void *arg,
                             struct altcp_pcb *new_conn,
                             err_t err)
{
    if (err != ERR_OK || new_conn == NULL) {
        return err;
    }

    altcp_recv(new_conn, alt_echo_recv);
    return ERR_OK;
}

void lwip_altcp_echo_server_init(void)
{
    struct altcp_pcb *listener;
    err_t err;

    listener = altcp_tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (listener == NULL) {
        return;
    }

    err = altcp_bind(listener, IP_ADDR_ANY, ECHO_PORT);
    if (err != ERR_OK) {
        altcp_abort(listener);
        return;
    }

    listener = altcp_listen(listener);
    if (listener == NULL) {
        return;
    }

    altcp_accept(listener, alt_echo_accept);
}
```

ALTCP 関数セットには `altcp_bind()`、`altcp_listen()`、`altcp_accept()`、`altcp_recv()`、`altcp_write()`、`altcp_output()`、`altcp_close()` が含まれ、raw TCP API を反映しています。

### 9.2 wolfIP バージョン

wolfIP はプレーンなTCP サーバーに ALTCP 抽象化レイヤーを必要としません。前のセクションで示した同じ `wolfIP_sock_*` パターンにサーバーを移行してください。

以下のマッピングを使用してください：

| lwIP ALTCP                                | wolfIP                                                               |
| ----------------------------------------- | -------------------------------------------------------------------- |
| `struct altcp_pcb *`                      | `int sockfd`                                                         |
| `altcp_tcp_new_ip_type()` / `altcp_new()` | `wolfIP_sock_socket()`                                               |
| `altcp_bind()`                            | `wolfIP_sock_bind()`                                                 |
| `altcp_listen()`                          | `wolfIP_sock_listen()`                                               |
| `altcp_accept()` コールバック             | 待機ソケットの `CB_EVENT_READABLE`、次に `wolfIP_sock_accept()`      |
| `altcp_recv()` コールバック               | `CB_EVENT_READABLE`、次に `wolfIP_sock_recv()`                       |
| `altcp_recved()`                          | 不要；受信ウィンドウ更新は `wolfIP_sock_recv()` が処理する           |
| `altcp_write()`                           | `wolfIP_sock_send()`                                                 |
| `altcp_output()`                          | 通常不要；送信プログレスは `wolfIP_poll()` で発生する                |
| `altcp_close()`                           | `wolfIP_sock_close()`                                                |
| `altcp_abort()`                           | `wolfIP_sock_close()` とアプリケーションクリーンアップ               |

プレーン TCP の場合、wolfIP の置き換えはセクション 8.2 のエコーサーバーです。

ALTCP-over-TLS 移行の場合、移行を 2 つのレイヤーに分けます：

1. まず TCP トランスポートを ALTCP から wolfIP ソケットに移行する。
2. 次に wolfIP ソケットの上に TLS を接続する。

wolfIP の公開ヘッダには、`WOLFSSL_WOLFIP` が有効な場合に wolfSSL 統合宣言が含まれており、`wolfSSL_SetIO_wolfIP()` と `wolfSSL_SetIO_wolfIP_CTX()` が含まれます。これが、以前に lwIP ALTCP TLS を使用していたアプリケーションの wolfIP 側置き換えポイントです。

TLS の概念的な形：

```c
/*
 * Pseudocode: exact wolfSSL setup depends on your product's wolfSSL config.
 */
WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
WOLFSSL *ssl = wolfSSL_new(ctx);

wolfSSL_SetIO_wolfIP_CTX(ctx, ipstack);
wolfSSL_SetIO_wolfIP(ssl, client_fd);

ret = wolfSSL_accept(ssl);
```

TLS ハンドシェイクもノンブロッキングプログレスを必要とすることに注意してください。ベアメタルでは、ソケットが読み取り可能または書き込み可能な場合に TLS の accept/read/write 関数を呼び出し、`wolfIP_poll()` を呼び続けてください。

---

## 10. RTOS 統合

### 10.1 FreeRTOS BSD ラッパーの動作

wolfIP には `src/port/freeRTOS/bsd_socket.c` に FreeRTOS POSIX スタイルのソケットラッパーと `src/port/freeRTOS/bsd_socket.h` に対応するヘッダが含まれています。

このラッパーは BSD ライクな関数を提供します：

```c
int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct wolfIP_sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct wolfIP_sockaddr *addr, socklen_t addrlen);
int send(int sockfd, const void *buf, size_t len, int flags);
int sendto(int sockfd, const void *buf, size_t len, int flags,
           const struct wolfIP_sockaddr *dest_addr, socklen_t addrlen);
int recv(int sockfd, void *buf, size_t len, int flags);
int recvfrom(int sockfd, void *buf, size_t len, int flags,
             struct wolfIP_sockaddr *src_addr, socklen_t *addrlen);
int close(int sockfd);
```

ヘッダは `SOCK_STREAM` を `IPSTACK_SOCK_STREAM` に、`SOCK_DGRAM` を `IPSTACK_SOCK_DGRAM` にマッピングし、`wolfip_freertos_socket_init()` を公開しています。

内部的に、FreeRTOS ポートは以下を使用します：

* グローバル `struct wolfIP *g_ipstack`；
* グローバルミューテックス `g_lock`；
* `internal_fd`、`ready_sem`、`wait_events` を含むエントリを持つ公開ファイルディスクリプタテーブル；
* 公開ソケットごとに 1 つのバイナリセマフォ；
* `wolfIP_poll()` を呼び出すポールタスク；
* ソケットのセマフォを与えることでブロックされたタスクを起動する wolfIP からのコールバック。

FreeRTOS ポールタスクはスタックをロックし、`wolfIP_poll(ipstack, now_ms)` を呼び出し、スタックをアンロックし、次のスリープを最小と最大の間に制限し、ミリ秒をティックに変換し、`vTaskDelay()` を呼び出します。デフォルトのラッパー定数には `WOLFIP_FREERTOS_BSD_MAX_FDS 16`、`WOLFIP_FREERTOS_POLL_MAX_MS 20`、`WOLFIP_FREERTOS_POLL_MIN_MS 5` が含まれます。

### 10.2 ラッパーのブロッキング動作

基礎となる wolfIP ソケット呼び出しはノンブロッキングスタイルで、`-WOLFIP_EAGAIN` を返すことがあります。FreeRTOS ラッパーはそれをブロッキング BSD ライクな動作に変換します：

1. wolfIP コアミューテックスをロックする。
2. 対応する `wolfIP_sock_*` 関数を呼び出す。
3. 成功した場合、アンロックして返す。
4. ハードエラーの場合、アンロックして `-1` を返す。
5. `-WOLFIP_EAGAIN` を返す場合、必要なイベントビットのコールバックを登録する。
6. ソケットセマフォをクリアする。
7. コアミューテックスをアンロックする。
8. セマフォでブロックする。
9. コールバックがタスクを起動したら操作を再試行する。

例えば：

* `accept()` は `CB_EVENT_READABLE` または `CB_EVENT_CLOSED` を待つ；
* `connect()` は `CB_EVENT_WRITABLE` または `CB_EVENT_CLOSED` を待つ；
* `send()` は `CB_EVENT_WRITABLE` または `CB_EVENT_CLOSED` を待つ；
* `recv()` は `CB_EVENT_READABLE` または `CB_EVENT_CLOSED` を待つ；
* `close()` は close が `-WOLFIP_EAGAIN` を返す場合に `CB_EVENT_CLOSED` を待つことがある。

ラッパーのコールバックはソケット I/O を実行しません。配信されたイベントが待機イベントマスクと交差するかどうかを確認し、ソケットのセマフォを与えます。

これは最も重要な RTOS 設計ルールです：wolfIP コアロックを保持したままセマフォでブロックしないこと、およびポールタスクがコールバックをディスパッチしている間にコアロックを保持している場合は、コールバックパスから BSD ラッパー関数を呼び出さないこと。

---

## 11. 新しい RTOS への wolfIP の移植

FreeRTOS ラッパーをテンプレートとして使用してください。必要な OS プリミティブはそう多くありません。

### 11.1 必要な OS プリミティブ

RTOS ポートに必要なもの：

| プリミティブ                              | 用途                                                                          |
| ----------------------------------------- | ----------------------------------------------------------------------------- |
| ミューテックス                            | wolfIP コアへの全呼び出しと `wolfIP_poll()` を保護する。                      |
| バイナリセマフォまたはイベントオブジェクト | ソケット準備完了を待つ間、アプリケーションタスクをスリープさせる。            |
| タスク/スレッド作成                        | wolfIP ポールタスクを実行する。                                               |
| ティック/タイム API                        | `wolfIP_poll()` に `now_ms` を提供する。                                      |
| ディレイ/スリープ API                      | ポールサイクル間でポールタスクをスリープさせる。                              |
| FD テーブル周りのクリティカルセクションまたはミューテックス | コアロックでカバーされていない場合、公開 FD の割り当て/解放を保護する。 |

### 11.2 推奨ポートアーキテクチャ

新しい OS には以下のアーキテクチャを使用してください：

```text
+-------------------------+
| Application task        |
| socket/send/recv/etc.   |
+------------+------------+
             |
             v
+-------------------------+
| OS BSD wrapper          |
| - public fd table       |
| - per-fd semaphore      |
| - core mutex            |
+------------+------------+
             |
             v
+-------------------------+
| wolfIP core             |
| wolfIP_sock_* APIs      |
| wolfIP_poll()           |
+------------+------------+
             |
             v
+-------------------------+
| Link-layer driver       |
| ll->poll(), ll->send()  |
+-------------------------+
```

### 11.3 移植手順

1. **グローバルポート状態を作成する**

```c
struct os_wolfip_fd {
    int in_use;
    int internal_fd;
    os_sem_t ready_sem;
    volatile uint16_t wait_events;
};

static struct wolfIP *g_ipstack;
static os_mutex_t g_core_lock;
static struct os_wolfip_fd g_fds[OS_WOLFIP_MAX_FDS];
```

2. **ポールタスクを作成する**

```c
static void wolfip_os_poll_task(void *arg)
{
    struct wolfIP *ipstack = (struct wolfIP *)arg;

    for (;;) {
        uint64_t now_ms = os_time_millis();
        uint32_t next_ms;

        os_mutex_lock(&g_core_lock);
        next_ms = (uint32_t)wolfIP_poll(ipstack, now_ms);
        os_mutex_unlock(&g_core_lock);

        if (next_ms < OS_WOLFIP_POLL_MIN_MS) {
            next_ms = OS_WOLFIP_POLL_MIN_MS;
        }

        if (next_ms > OS_WOLFIP_POLL_MAX_MS) {
            next_ms = OS_WOLFIP_POLL_MAX_MS;
        }

        os_sleep_ms(next_ms);
    }
}
```

3. **ラッパーを初期化する**

```c
int wolfip_os_socket_init(struct wolfIP *ipstack,
                          int poll_task_priority,
                          size_t poll_task_stack_size)
{
    int i;

    if (ipstack == NULL) {
        return -WOLFIP_EINVAL;
    }

    os_mutex_create(&g_core_lock);

    for (i = 0; i < OS_WOLFIP_MAX_FDS; i++) {
        g_fds[i].in_use = 0;
        g_fds[i].internal_fd = -1;
        g_fds[i].wait_events = 0;
        os_sem_create_binary(&g_fds[i].ready_sem);
    }

    g_ipstack = ipstack;

    if (os_task_create(wolfip_os_poll_task,
                       "wolfip_poll",
                       poll_task_stack_size,
                       ipstack,
                       poll_task_priority) != 0) {
        return -WOLFIP_ENOMEM;
    }

    return 0;
}
```

4. **wolfIP コールバックを OS ウェイクアップにブリッジする**

```c
static void wolfip_os_socket_cb(int internal_fd,
                                uint16_t events,
                                void *arg)
{
    struct os_wolfip_fd *entry = (struct os_wolfip_fd *)arg;

    (void)internal_fd;

    if (entry == NULL) {
        return;
    }

    if ((events & entry->wait_events) != 0) {
        os_sem_give(&entry->ready_sem);
    }
}
```

5. **コアがロックされている間に待機を準備する**

```c
static void prepare_wait_locked(struct os_wolfip_fd *entry,
                                uint16_t wait_events)
{
    entry->wait_events = wait_events;
    os_sem_drain(&entry->ready_sem);

    wolfIP_register_callback(
        g_ipstack,
        entry->internal_fd,
        wolfip_os_socket_cb,
        entry
    );
}
```

6. **各ソケット関数をラップする**

`recv()` ラッパーの例：

```c
int recv(int public_fd, void *buf, size_t len, int flags)
{
    struct os_wolfip_fd *entry;
    int ret;

    if (!fd_valid(public_fd)) {
        return -1;
    }

    entry = &g_fds[public_fd];

    for (;;) {
        os_mutex_lock(&g_core_lock);

        ret = wolfIP_sock_recv(
            g_ipstack,
            entry->internal_fd,
            buf,
            len,
            flags
        );

        if (ret >= 0) {
            os_mutex_unlock(&g_core_lock);
            return ret;
        }

        if (ret != -WOLFIP_EAGAIN) {
            os_mutex_unlock(&g_core_lock);
            os_set_errno_from_wolfip(ret);
            return -1;
        }

        prepare_wait_locked(
            entry,
            (uint16_t)(CB_EVENT_READABLE | CB_EVENT_CLOSED)
        );

        os_mutex_unlock(&g_core_lock);

        if (os_sem_take(&entry->ready_sem, OS_WAIT_FOREVER) != 0) {
            os_set_errno_from_wolfip(-WOLFIP_EAGAIN);
            return -1;
        }
    }
}
```

以下についても同じパターンを繰り返してください：

* `accept()` は `CB_EVENT_READABLE | CB_EVENT_CLOSED` を待つ；
* `connect()` は `CB_EVENT_WRITABLE | CB_EVENT_CLOSED` を待つ；
* `send()` は `CB_EVENT_WRITABLE | CB_EVENT_CLOSED` を待つ；
* `close()` が `-WOLFIP_EAGAIN` を返す場合は `CB_EVENT_CLOSED` を待つ。

### 11.4 RTOS ポーティングルール

新しい OS ポートでは以下のルールに従ってください：

* `wolfIP_sock_*` を呼び出す間はコアミューテックスを保持する。
* `wolfIP_poll()` を呼び出す間はコアミューテックスを保持する。
* セマフォでブロックしている間はコアミューテックスを保持しない。
* wolfIP コールバックを短く保つ；タスクの起動、フラグの設定、またはイベントの投稿のみ行う。
* コールバックの内部からブロッキングラッパー API を呼び出さない。
* 公開 FD テーブルを一貫して保護する。
* ソケットを閉じるときに FD ごとのセマフォを削除する。
* FD エントリを解放する前にコールバックをクリアする。
* ラッパーが BSD スタイルの `-1` プラス `errno` を返すか、wolfIP の負のエラーを直接返すかを決定する。一貫性を保つ。

### 11.5 ポールタスクのタイミング

FreeRTOS ラッパーはデフォルトでポール遅延を 5 ms から 20 ms の間に制限します。これは RTOS ポートの合理的な出発点です。ポールタスクがスピンするのを防ぎながら、TCP タイマー、ACK、再送信、キュー済み TX 作業に定期的なプログレスを与えるためです。

レイテンシが重要な製品では、最大遅延を小さくしてください。省電力が重要な製品では、再送信動作、DNS、DHCP、アプリケーションレイテンシが製品要件を満たすことを確認した後にのみ、より大きな最大遅延を許可してください。

---

## 12. 移行チェックリスト

### 12.1 コード変更前

* リスナーを含む最大同時 TCP ソケット数をカウントする。
* DNS/DHCP/アプリケーションの使用を含む UDP ソケット数をカウントする。
* ICMP、raw ソケット、パケットソケット、転送、ループバック、マルチキャスト、HTTP が必要かどうかを決定する。
* MTU と RX/TX バッファサイズを決定する。
* lwIP のすべての raw コールバック、Netconn タスク、ソケットユーザー、ALTCP/TLS ユーザーを特定する。
* ハードウェア RNG または暗号 RNG ソースを特定する。

### 12.2 設定

* `lwipopts.h` のプールチューニングを短い wolfIP `config.h` で置き換える。
* `MAX_TCPSOCKETS`、`MAX_UDPSOCKETS`、`MAX_ICMPSOCKETS` を設定する。
* `RXBUF_SIZE`、`TXBUF_SIZE`、`LINK_MTU`、`MAX_NEIGHBORS` を設定する。
* 必要なオプションのソケットファミリーとプロトコル機能のみを有効にする。
* 静的 IP の場合、ネットワーク初期化中に `wolfIP_ipconfig_set()` または `wolfIP_ipconfig_set_ex()` を呼び出す。

### 12.3 ネットワークドライバ

* ドライバ状態を `netif->state` から `wolfIP_ll_dev.priv` に移動する。
* MAC アドレスと MTU の設定を `netif` フィールドから `wolfIP_ll_dev` に移動する。
* RX pbuf 割り当てを、1 つの完全なフレームを wolfIP のバッファにコピーする `poll` 関数で置き換える。
* TX pbuf チェーントラバーサルを、1 つの連続フレームを受け入れる `send` 関数で置き換える。
* `wolfIP_getdev()` または `wolfIP_getdev_ex()` と `wolfIP_ipconfig_set()` または `wolfIP_ipconfig_set_ex()` で各インターフェースを初期化する。

### 12.4 ベアメタル

* `wolfIP_init_static()` または `wolfIP_init()` で wolfIP を初期化する。
* `wolfIP_ll_dev` に `poll`、`send`、MAC、MTU、ドライバコンテキストを設定する。
* `wolfIP_getrandom()` を提供する。
* `wolfIP_poll()` を定期的に呼び出す。
* lwIP PCB を wolfIP ソケットディスクリプタで置き換える。
* raw/ALTCP コールバックをソケットコールバックと `wolfIP_sock_recv()` / `wolfIP_sock_send()` で置き換える。

### 12.5 RTOS

* ポールタスクを 1 つ追加する。
* コアミューテックスを 1 つ追加する。
* BSD ライクなディスクリプタが必要な場合は公開 FD テーブルを追加する。
* FD ごとにセマフォ/イベントオブジェクトを 1 つ追加する。
* `-WOLFIP_EAGAIN` を待機と再試行の動作に変換する。
* `wolfIP_register_callback()` コールバックからブロックされたタスクを起動する。
* wolfIP コアミューテックスを保持したままブロックしない。

---

## 13. よくある落とし穴

### 13.1 リスナーが TCP ソケットを消費することを忘れる

`MAX_TCPSOCKETS` が 4 の場合、サーバーは 1 つのリスナーと最大 3 つの受け入れ済み TCP クライアントを同時に持つことができます。

### 13.2 lwIP スタイルの独立した待機プールとアクティブプールを期待する

lwIP には `MEMP_NUM_TCP_PCB` と `MEMP_NUM_TCP_PCB_LISTEN` があります。wolfIP には 1 つの TCP ソケット配列しかないため、両方の役割を考慮してサイズを設定してください。

### 13.3 `wolfIP_sock_accept()` を 1 回だけ呼び出す

コールバックはリスナーが読み取り可能であることを示す場合があります。`-WOLFIP_EAGAIN` になるまでループで accept し、すべての準備完了接続イベントをドレインしてください。

### 13.4 `wolfIP_sock_send()` を即時ワイヤ送信として扱う

`wolfIP_sock_send()` はデータをキューします。実際のフレーム送信は `wolfIP_poll()` から進行します。

### 13.5 弱い RNG を実装する

TCP シーケンス番号、DNS ID、ソースポート、その他のプロトコル値には予測不可能な乱数が必要です。本物の RNG を接続してください。

### 13.6 RTOS コールバック内でブロックする

FreeRTOS スタイルの設計では、コールバックはタスクを起動します。ブロッキングソケットラッパーを呼び出すべきではありません。

### 13.7 スリープ中にコアロックを保持する

wolfIP を呼び出す間はロックし、セマフォで待機する前にアンロックしてください。これによりデッドロックを防ぎ、ポールタスクがプログレスできるようになります。

---

## 14. クイック API マッピング

| タスク              | lwIP raw/classic                  | lwIP ALTCP                                | wolfIP ベアメタル                                        |
| ------------------- | --------------------------------- | ----------------------------------------- | -------------------------------------------------------- |
| TCP エンドポイント作成 | `tcp_new()`                    | `altcp_tcp_new_ip_type()` / `altcp_new()` | `wolfIP_sock_socket(s, AF_INET, IPSTACK_SOCK_STREAM, 0)` |
| バインド            | `tcp_bind()`                      | `altcp_bind()`                            | `wolfIP_sock_bind()`                                     |
| 待機               | `tcp_listen()`                    | `altcp_listen()`                          | `wolfIP_sock_listen()`                                   |
| 受け入れ            | `tcp_accept()` コールバック       | `altcp_accept()` コールバック             | コールバックイベント + `wolfIP_sock_accept()`             |
| 受信               | `tcp_recv()` コールバック（`pbuf`）| `altcp_recv()` コールバック（`pbuf`）     | コールバックイベント + `wolfIP_sock_recv()`               |
| 受信マーク          | `tcp_recved()`                    | `altcp_recved()`                          | アプリケーションでは不要                                 |
| 送信               | `tcp_write()`                     | `altcp_write()`                           | `wolfIP_sock_send()`                                     |
| 出力フラッシュ      | `tcp_output()`                    | `altcp_output()`                          | `wolfIP_poll()` が出力を進行させる                       |
| クローズ            | `tcp_close()`                     | `altcp_close()`                           | `wolfIP_sock_close()`                                    |
| アボート            | `tcp_abort()`                     | `altcp_abort()`                           | `wolfIP_sock_close()` とクリーンアップ                   |
| メインプログレス    | Ethernet 入力 + lwIP タイマー     | Ethernet 入力 + lwIP タイマー             | `wolfIP_poll()`                                          |
| TLS レイヤリング    | 通常 ALTCP TLS                    | ALTCP TLS                                 | wolfIP ソケット上の wolfSSL                              |
