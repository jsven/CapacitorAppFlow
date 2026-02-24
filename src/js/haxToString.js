/**
 * 超级解析器：自动识别 厂商块(UID) / NDEF数据 / 普通文本
 * @param {Array<string>} sectorBlocks - 包含4个十六进制字符串的数组
 * @returns {string} 解析后的人类可读内容
 */
function parseMifareSector(sectorBlocks) {
    if (!sectorBlocks || sectorBlocks.length < 3) return "数据不完整";

    let block0Hex = sectorBlocks[0];
    let streamHex = sectorBlocks[0] + sectorBlocks[1] + sectorBlocks[2];
    let bytes0 = hexToBytes(block0Hex);
    let allBytes = hexToBytes(streamHex);

    // === 策略 1: 识别厂商块 (Sector 0) ===
    // 特征：第5个字节(索引4) 等于 前4个字节的异或和 (BCC校验)
    // 且通常 Block 0 不会全是 0
    if (bytes0.length === 16 && bytes0[0] !== 0) {
        let bcc = bytes0[0] ^ bytes0[1] ^ bytes0[2] ^ bytes0[3];
        if (bcc === bytes0[4]) {
            // 提取 UID
            let uid = block0Hex.substring(0, 8);
            // 提取厂商数据 (后8个字节)
            let manuBytes = bytes0.slice(8, 16);
            let manuText = extractReadableASCII(manuBytes); // 尝试转文字

            return `[厂商块] UID:${uid} | 数据:${manuText}`;
        }
    }

    // === 策略 2: 识别 NDEF 格式 (上一组数据的格式) ===
    // 特征：寻找 0x03 (TLV Start)
    let msgStartIndex = -1;
    for (let i = 0; i < allBytes.length - 2; i++) {
        if (allBytes[i] === 0x03) {
            // 简单校验长度是否合理
            let len = allBytes[i+1];
            if (len > 0 && (i + 1 + len) < allBytes.length) {
                msgStartIndex = i;
                break;
            }
        }
    }

    if (msgStartIndex !== -1) {
        // ... (保留之前的 NDEF 解析逻辑) ...
        let len = allBytes[msgStartIndex+1];
        let recordHead = allBytes[msgStartIndex+2]; // D1 etc.
        let typeLen = allBytes[msgStartIndex+3];
        let payloadLen = allBytes[msgStartIndex+4];

        // 检查是否为文本记录 (Type 'T' = 0x54)
        let typePos = msgStartIndex + 5;
        if (allBytes[typePos] === 0x54) {
            let payloadPos = typePos + typeLen;
            let statusByte = allBytes[payloadPos];
            let langLen = statusByte & 0x3F;
            let textStart = payloadPos + 1 + langLen;
            let textLen = payloadLen - 1 - langLen;

            let textBytes = allBytes.slice(textStart, textStart + textLen);
            return "[NDEF信息] " + bytesToString(textBytes);
        }
    }

    // === 策略 3: 兜底 (暴力转文本) ===
    // 如果不是UID也不是NDEF，尝试直接显示可见字符
    let rawText = bytesToString(allBytes);
    // 如果转换出来的全是乱码或空，就返回原始 Hex
    if (rawText.replace(/\s/g, '').length < 3) {
        return "[原始数据] " + block0Hex + "...";
    }
    return "[纯文本] " + rawText;
}

// --- 辅助工具 (必须包含) ---

function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

function bytesToString(arr) {
    let str = "";
    for (let i = 0; i < arr.length; i++) {
        if (arr[i] >= 32 && arr[i] <= 126) str += String.fromCharCode(arr[i]);
    }
    return str;
}

function extractReadableASCII(arr) {
    let str = bytesToString(arr);
    return str.length > 0 ? str : "(Hex: " + bytesToHex(arr) + ")";
}

function bytesToHex(arr) {
    return arr.map(function(b) {
        return ("0" + (b & 0xFF).toString(16)).slice(-2);
    }).join("");
}

function initNFC() {
    // 监听任意标签（包括非 NDEF 格式的 M1 卡）
    nfc.addTagDiscoveredListener(
        function (nfcEvent) {
            console.log('收到卡片信息信息如下', nfcEvent)
            var tag = nfcEvent.tag;

            if (tag.mifareData) {
                console.log("=== 开始翻译 M1 卡数据 ===");

                // 遍历所有扇区
                for (var key in tag.mifareData) {
                    // key 类似 "sector_1"
                    var blocks = tag.mifareData[key];

                    // 检查是否是数组（如果是 "Auth Failed" 字符串则跳过）
                    if (Array.isArray(blocks)) {

                        const haxToStringRs = parseMifareSector(blocks)
                        console.warn("--- " + key + " ---" , haxToStringRs);
                    } else {
                        console.log(key + ": 密码验证失败 (Auth Failed)");
                    }
                }
            }
        },
        function () {
            console.log("NFC 监听启动成功");
        },
        function (error) {
            console.log("NFC 监听启动失败: " + JSON.stringify(error));
        }
    );
}