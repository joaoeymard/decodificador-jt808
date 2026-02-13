const input = document.getElementById("hexInput");
const statusEl = document.getElementById("status");
const summaryEl = document.getElementById("summary");
const tableBody = document.getElementById("partsTable");
const notesEl = document.getElementById("notes");
const escapedHexEl = document.getElementById("escapedHex");
const unescapedHexEl = document.getElementById("unescapedHex");
const loadSampleBtn = document.getElementById("loadSample");
const clearInputBtn = document.getElementById("clearInput");
const clearHistoryBtn = document.getElementById("clearHistory");
const historyListEl = document.getElementById("historyList");

const HISTORY_KEY = "jt808.history";
const HISTORY_LIMIT = 30;

const SAMPLE = "7E000200003440500493730104C77E";

function sanitizeHex(value) {
  return value.replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "");
}

function isValidHexString(hex) {
  return hex.length > 0 && hex.length % 2 === 0;
}

function loadHistory() {
  if (!historyListEl) return [];
  try {
    const stored = localStorage.getItem(HISTORY_KEY);
    const parsed = stored ? JSON.parse(stored) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    return [];
  }
}

function saveHistory(items) {
  if (!historyListEl) return;
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
  } catch (err) {
    // ignore
  }
}

function summarizeMessage(hex) {
  const bytes = hexToBytes(hex);
  const parsed = parseJT808(bytes);
  const idLabel = parsed.messageId !== null ? `0x${parsed.messageId.toString(16).padStart(4, "0").toUpperCase()}` : "Desconhecido";
  const length = bytes.length;
  const okLabel = parsed.errors?.length ? "Invalida" : "Valida";
  return { idLabel, length, okLabel };
}

function renderHistory(items) {
  if (!historyListEl) return;
  historyListEl.innerHTML = "";
  if (!items.length) {
    const empty = document.createElement("li");
    empty.className = "history-item history-empty";
    empty.textContent = "Sem mensagens salvas.";
    historyListEl.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    li.className = "history-item";
    li.dataset.hex = item.hex;

    const meta = document.createElement("div");
    meta.className = "history-meta";
    const info = summarizeMessage(item.hex);
    const time = new Date(item.ts || Date.now());
    const timeText = time.toLocaleString("pt-BR", { hour12: false });
    meta.textContent = `${info.okLabel} • ${info.idLabel} • ${info.length} bytes • ${timeText}`;

    const preview = document.createElement("div");
    preview.className = "history-hex";
    preview.textContent = item.hex.slice(0, 64) + (item.hex.length > 64 ? "..." : "");

    li.append(meta, preview);
    li.addEventListener("click", () => {
      input.value = item.hex;
      render();
    });

    historyListEl.appendChild(li);
  });
}

function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return bytes;
}

function bytesToHex(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function bytesToHexSpaced(bytes) {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ").toUpperCase();
}

function wordAt(bytes, index) {
  if (index + 1 >= bytes.length) return null;
  return (bytes[index] << 8) | bytes[index + 1];
}

function numberAt(bytes, index, length) {
  if (index + length > bytes.length) return null;
  let value = 0;
  for (let i = 0; i < length; i += 1) {
    value = value * 256 + bytes[index + i];
  }
  return value >>> 0;
}

function bcdToString(bytes) {
  let out = "";
  for (const byte of bytes) {
    const hi = (byte >> 4) & 0x0f;
    const lo = byte & 0x0f;
    out += hi <= 9 ? hi.toString() : "?";
    out += lo <= 9 ? lo.toString() : "?";
  }
  return out;
}

function bytesToAscii(bytes) {
  const chars = bytes.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ""));
  return chars.join("").replace(/\u0000/g, "").trim();
}

function formatBcdTime(bytes) {
  const digits = bcdToString(bytes);
  if (digits.length < 12) return digits;
  const yy = digits.slice(0, 2);
  const mm = digits.slice(2, 4);
  const dd = digits.slice(4, 6);
  const hh = digits.slice(6, 8);
  const mi = digits.slice(8, 10);
  const ss = digits.slice(10, 12);
  return `${yy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function unescapePayload(bytes) {
  const data = [];
  const errors = [];
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i];
    if (b === 0x7d) {
      const next = bytes[i + 1];
      if (next === 0x02) {
        data.push(0x7e);
        i += 1;
      } else if (next === 0x01) {
        data.push(0x7d);
        i += 1;
      } else {
        errors.push("Escape invalido encontrado: 0x7D sem 0x01/0x02.");
        data.push(b);
      }
    } else {
      data.push(b);
    }
  }
  return { data, errors };
}

function calcChecksum(bytes) {
  return bytes.reduce((acc, b) => acc ^ b, 0);
}

const RESULT_CODES = {
  0: "Sucesso",
  1: "Falha",
  2: "Mensagem incorreta",
  3: "Nao suportado",
  4: "Alarme confirmado",
};

const MESSAGE_ID_INFO = {
  0x0100: {
    name: "Device Registration",
    flow:
      "Dispositivo registra antes de operar; servidor responde com 0x8100 e retorna o authentication code.",
  },
  0x8100: {
    name: "Device Registration Response",
    flow: "Resposta do servidor ao registro (0x0100) com resultado e authentication code.",
  },
  0x0102: {
    name: "Device Authentication",
    flow: "Dispositivo autentica usando o authentication code; servidor responde 0x8001.",
  },
  0x8001: {
    name: "Server General Response",
    flow: "Resposta generica do servidor a mensagens que exigem confirmacao.",
  },
  0x0002: {
    name: "Device Heartbeat",
    flow: "Heartbeat do dispositivo; servidor responde 0x8001 para manter online.",
  },
  0x0200: {
    name: "Device Basic Information",
    flow: "Dados de posicao/sensores; servidor responde 0x8001 e persiste o bruto.",
  },
  0x0900: {
    name: "Additional Information",
    flow: "Dados adicionais de sensores; resposta nao obrigatoria pelo protocolo.",
  },
  0x0001: {
    name: "Device General Query Response",
    flow: "Resposta do dispositivo a consultas do servidor; nao exige resposta adicional.",
  },
  0x8103: {
    name: "Configuration Commands",
    flow: "Comando do servidor; dispositivo responde com 0x0104 ou 0x0001.",
  },
  0x8104: {
    name: "Query Commands",
    flow: "Consulta do servidor; dispositivo responde com 0x0104.",
  },
  0x0104: {
    name: "Device General Configuration Response",
    flow: "Resposta do dispositivo com parametros solicitados.",
  },
};

const PARAM_DEFS = {
  0x0001: { name: "Intervalo heartbeat", type: "DWORD", unit: "s" },
  0x0010: { name: "APN servidor", type: "STRING" },
  0x0011: { name: "APN usuario", type: "STRING" },
  0x0012: { name: "APN senha", type: "STRING" },
  0x0013: { name: "Servidor principal", type: "STRING" },
  0x0017: { name: "Servidor backup", type: "STRING" },
  0x0018: { name: "Porta servidor principal", type: "DWORD" },
  0x0027: { name: "Intervalo sleep", type: "DWORD", unit: "s" },
  0x0029: { name: "Intervalo run", type: "DWORD", unit: "s" },
  0x0030: { name: "Angulo de virada", type: "DWORD", unit: "graus" },
  0x0055: { name: "Velocidade maxima", type: "DWORD", unit: "km/h" },
  0x0056: { name: "Duracao overspeed", type: "DWORD", unit: "s" },
  0x0080: { name: "Odometro", type: "DWORD", unit: "0.1 km" },
  0xF000: { name: "Device ID", type: "STRING" },
  0xF001: { name: "Tensao em marcha", type: "DWORD", unit: "mV" },
  0xF002: { name: "Tensao parado", type: "DWORD", unit: "mV" },
  0xF003: { name: "Tensao sleep", type: "WORD", unit: "mV" },
  0xF004: { name: "Servidor NTP", type: "STRING" },
  0xF005: { name: "Porta NTP", type: "DWORD" },
  0xF006: { name: "Fuso horario", type: "BYTE" },
  0xF007: { name: "Tipo de protocolo", type: "BYTE", map: { 0: "JTT808", 1: "TAIP" } },
  0xF009: { name: "Criptografia", type: "BYTE", map: { 0: "NULL", 1: "RSA", 2: "AES", 3: "XTEA" } },
  0xF00A: { name: "GNSS", type: "BYTE", map: { 0: "GPS+BD", 1: "GPS+GLO", 2: "GPS+GAL" } },
  0xF00B: { name: "WiFi", type: "BYTE", map: { 0: "off", 1: "on" } },
  0xF00C: { name: "Modo WiFi", type: "BYTE", map: { 0: "AP", 1: "STA" } },
  0xF00F: { name: "Bluetooth", type: "BYTE", map: { 0: "off", 1: "on" } },
  0xF010: { name: "Modo Bluetooth", type: "BYTE", map: { 0: "host", 1: "slave" } },
  0xF011: { name: "Max nos Bluetooth", type: "BYTE" },
  0xF012: { name: "Timeout scan BT", type: "BYTE", unit: "min" },
  0xF014: { name: "Mascara BT sensor", type: "BYTE" },
  0xF015: { name: "Modo GPIO", type: "WORD" },
  0xF016: { name: "Direcao GPIO", type: "BYTE" },
  0xF017: { name: "Protocolo comunicacao", type: "BYTE", map: { 0: "TCP", 1: "UDP", 2: "MQTT" } },
  0xF018: { name: "Report mask", type: "DWORD" },
  0xF01A: { name: "Sensibilidade acelerometro", type: "BYTE" },
  0xF01B: { name: "Range acelerometro", type: "BYTE", map: { 0: "±2g", 1: "±4g", 2: "±8g", 3: "±16g" } },
  0xF01D: { name: "Motion acelerometro", type: "DWORD" },
  0xF01F: { name: "Mascara report acelerometro", type: "BYTE" },
  0xF02B: { name: "Porta servidor backup", type: "DWORD" },
  0xF02C: { name: "Buffer enable", type: "BYTE", map: { 0: "off", 1: "on" } },
  0xF02D: { name: "Server ack enable", type: "BYTE", map: { 0: "off", 1: "on" } },
  0xF030: { name: "AT command", type: "STRING" },
};

function formatParamValue(def, valueBytes) {
  if (!def) {
    return `Hex: ${bytesToHex(valueBytes)}`;
  }
  if (def.type === "STRING") {
    const ascii = bytesToAscii(valueBytes);
    return ascii ? `${ascii}` : `Hex: ${bytesToHex(valueBytes)}`;
  }
  const value = numberAt(valueBytes, 0, valueBytes.length);
  if (value === null) return `Hex: ${bytesToHex(valueBytes)}`;
  const mapped = def.map && Object.prototype.hasOwnProperty.call(def.map, value) ? def.map[value] : null;
  const unit = def.unit ? ` ${def.unit}` : "";
  return mapped ? `${value}${unit} (${mapped})` : `${value}${unit}`;
}

function makeLine(hex, meaning, start, end) {
  return { hex, meaning, start, end };
}

function fieldLine(bytes, start, length, label, value, options = {}) {
  const baseOffset = options.baseOffset ?? 0;
  const displayOffset = options.displayOffset ?? 0;
  if (length <= 0) {
    return makeLine("-", `${label}: ${value}`, null, null);
  }
  const slice = bytes.slice(start, start + length);
  const hex = bytesToHex(slice);
  const displayStart = start + displayOffset;
  const displayEnd = displayStart + length - 1;
  const range = length === 1 ? `${displayStart}` : `${displayStart}-${displayEnd}`;
  const absStart = start + baseOffset;
  const absEnd = absStart + length - 1;
  return makeLine(`Byte ${range}: ${hex}`, `${label}: ${value}`, absStart, absEnd);
}

function tailFieldLine(bytes, start, label, value, options = {}) {
  const baseOffset = options.baseOffset ?? 0;
  const displayOffset = options.displayOffset ?? 0;
  const slice = bytes.slice(start);
  const hex = bytesToHex(slice);
  const displayStart = start + displayOffset;
  const displayEnd = displayStart + slice.length - 1;
  const range = start >= bytes.length ? "-" : `${displayStart}-${displayEnd}`;
  const absStart = start + baseOffset;
  const absEnd = absStart + slice.length - 1;
  return makeLine(
    `Byte ${range}: ${hex || "-"}`,
    `${label}: ${value}`,
    slice.length ? absStart : null,
    slice.length ? absEnd : null
  );
}

function parseParamList(bytes, offset, count, baseOffset) {
  const lines = [];
  const warnings = [];
  let cursor = offset;
  for (let i = 0; i < count; i += 1) {
    if (cursor + 5 > bytes.length) {
      warnings.push("Lista de parametros incompleta.");
      break;
    }
    const idOffset = cursor;
    const paramId = numberAt(bytes, idOffset, 4);
    const lengthOffset = idOffset + 4;
    const length = bytes[lengthOffset];
    cursor += 5;
    if (cursor + length > bytes.length) {
      warnings.push(`Parametro 0x${paramId.toString(16).padStart(8, "0").toUpperCase()} truncado.`);
      break;
    }
    const valueOffset = cursor;
    const valueBytes = bytes.slice(valueOffset, valueOffset + length);
    cursor += length;

    const def = PARAM_DEFS[paramId];
    const name = def ? def.name : "Parametro";
    lines.push(
      fieldLine(
        bytes,
        idOffset,
        4,
        "Parametro ID",
        `0x${paramId.toString(16).padStart(8, "0").toUpperCase()} (${name})`,
        { baseOffset }
      )
    );
    lines.push(fieldLine(bytes, lengthOffset, 1, "Parametro length", length, { baseOffset }));
    lines.push(fieldLine(bytes, valueOffset, length, "Parametro value", formatParamValue(def, valueBytes), { baseOffset }));
  }
  return { lines, warnings, cursor };
}

function formatBody(messageId, bodyBytes, baseOffset) {
  const lines = [];
  const warnings = [];
  if (!bodyBytes) {
    return { lines, warnings };
  }

  switch (messageId) {
    case 0x0001: {
      const respSeq = wordAt(bodyBytes, 0);
      const respMsgId = wordAt(bodyBytes, 2);
      const result = bodyBytes[4];
      if (bodyBytes.length < 5) warnings.push("Body 0x0001 incompleto.");
      lines.push(fieldLine(bodyBytes, 0, 2, "Sequencia de resposta", respSeq ?? "-", { baseOffset }));
      lines.push(
        fieldLine(
          bodyBytes,
          2,
          2,
          "Message ID respondido",
          `0x${(respMsgId ?? 0).toString(16).padStart(4, "0").toUpperCase()}`,
          { baseOffset }
        )
      );
      lines.push(
        fieldLine(
          bodyBytes,
          4,
          1,
          "Resultado",
          `${result ?? "-"} ${RESULT_CODES[result] ? `(${RESULT_CODES[result]})` : ""}`,
          { baseOffset }
        )
      );
      break;
    }
    case 0x8001: {
      const respSeq = wordAt(bodyBytes, 0);
      const respMsgId = wordAt(bodyBytes, 2);
      const result = bodyBytes[4];
      if (bodyBytes.length < 5) warnings.push("Body 0x8001 incompleto.");
      lines.push(fieldLine(bodyBytes, 0, 2, "Sequencia de resposta", respSeq ?? "-", { baseOffset }));
      lines.push(
        fieldLine(
          bodyBytes,
          2,
          2,
          "Message ID respondido",
          `0x${(respMsgId ?? 0).toString(16).padStart(4, "0").toUpperCase()}`,
          { baseOffset }
        )
      );
      lines.push(
        fieldLine(
          bodyBytes,
          4,
          1,
          "Resultado",
          `${result ?? "-"} ${RESULT_CODES[result] ? `(${RESULT_CODES[result]})` : ""}`,
          { baseOffset }
        )
      );
      break;
    }
    case 0x0002:
      lines.push(makeLine("-", "Heartbeat sem payload.", null, null));
      break;
    case 0x0100: {
      const province = wordAt(bodyBytes, 0);
      const city = wordAt(bodyBytes, 2);
      const manufacturer = bytesToAscii(bodyBytes.slice(4, 9)) || bytesToHex(bodyBytes.slice(4, 9));
      const model = bytesToAscii(bodyBytes.slice(9, 29)) || bytesToHex(bodyBytes.slice(9, 29));
      const deviceId = bytesToAscii(bodyBytes.slice(29, 36)) || bytesToHex(bodyBytes.slice(29, 36));
      const licenseColor = bodyBytes[36];
      const vehicleId = bytesToAscii(bodyBytes.slice(37)) || bytesToHex(bodyBytes.slice(37));
      if (bodyBytes.length < 38) warnings.push("Body 0x0100 incompleto.");
      lines.push(fieldLine(bodyBytes, 0, 2, "Provincia ID", province ?? "-", { baseOffset }));
      lines.push(fieldLine(bodyBytes, 2, 2, "Cidade ID", city ?? "-", { baseOffset }));
      lines.push(fieldLine(bodyBytes, 4, 5, "Fabricante", manufacturer, { baseOffset }));
      lines.push(fieldLine(bodyBytes, 9, 20, "Modelo do dispositivo", model, { baseOffset }));
      lines.push(fieldLine(bodyBytes, 29, 7, "Device ID", deviceId, { baseOffset }));
      lines.push(fieldLine(bodyBytes, 36, 1, "Cor da placa", licenseColor ?? "-", { baseOffset }));
      lines.push(tailFieldLine(bodyBytes, 37, "Identificacao do veiculo", vehicleId || "-", { baseOffset }));
      break;
    }
    case 0x8100: {
      const respSeq = wordAt(bodyBytes, 0);
      const result = bodyBytes[2];
      const auth = bytesToAscii(bodyBytes.slice(3)) || bytesToHex(bodyBytes.slice(3));
      if (bodyBytes.length < 3) warnings.push("Body 0x8100 incompleto.");
      lines.push(fieldLine(bodyBytes, 0, 2, "Sequencia de resposta", respSeq ?? "-", { baseOffset }));
      lines.push(
        fieldLine(
          bodyBytes,
          2,
          1,
          "Resultado",
          `${result ?? "-"} ${RESULT_CODES[result] ? `(${RESULT_CODES[result]})` : ""}`,
          { baseOffset }
        )
      );
      lines.push(tailFieldLine(bodyBytes, 3, "Codigo de autenticacao", auth || "-", { baseOffset }));
      break;
    }
    case 0x0102: {
      const auth = bytesToAscii(bodyBytes) || bytesToHex(bodyBytes);
      lines.push(tailFieldLine(bodyBytes, 0, "Codigo de autenticacao", auth || "-", { baseOffset }));
      break;
    }
    case 0x8103: {
      const total = bodyBytes[0] ?? 0;
      lines.push(fieldLine(bodyBytes, 0, 1, "Total parametros", total, { baseOffset }));
      const parsed = parseParamList(bodyBytes, 1, total, baseOffset);
      parsed.lines.forEach((line) => lines.push(line));
      warnings.push(...parsed.warnings);
      break;
    }
    case 0x8104:
      lines.push(makeLine("-", "Query sem payload.", null, null));
      break;
    case 0x0104: {
      const respSeq = wordAt(bodyBytes, 0);
      const total = bodyBytes[2] ?? 0;
      lines.push(fieldLine(bodyBytes, 0, 2, "Sequencia de resposta", respSeq ?? "-", { baseOffset }));
      lines.push(fieldLine(bodyBytes, 2, 1, "Total parametros", total, { baseOffset }));
      const parsed = parseParamList(bodyBytes, 3, total, baseOffset);
      parsed.lines.forEach((line) => lines.push(line));
      warnings.push(...parsed.warnings);
      break;
    }
    case 0x0200: {
      if (bodyBytes.length < 28) {
        warnings.push("Body 0x0200 incompleto para info basica.");
      }
      const alarm = numberAt(bodyBytes, 0, 4);
      const status = numberAt(bodyBytes, 4, 4);
      const lat = numberAt(bodyBytes, 8, 4);
      const lon = numberAt(bodyBytes, 12, 4);
      const altitude = numberAt(bodyBytes, 16, 2);
      const speed = numberAt(bodyBytes, 18, 2);
      const direction = numberAt(bodyBytes, 20, 2);
      const time = formatBcdTime(bodyBytes.slice(22, 28));
      if (alarm !== null) {
        lines.push(
          fieldLine(
            bodyBytes,
            0,
            4,
            "Sinal de alarme",
            `0x${alarm.toString(16).padStart(8, "0").toUpperCase()}`,
            { baseOffset }
          )
        );
      }
      if (status !== null) {
        lines.push(
          fieldLine(
            bodyBytes,
            4,
            4,
            "Status",
            `0x${status.toString(16).padStart(8, "0").toUpperCase()}`,
            { baseOffset }
          )
        );
      }
      if (lat !== null) lines.push(fieldLine(bodyBytes, 8, 4, "Latitude", (lat / 1e6).toFixed(6), { baseOffset }));
      if (lon !== null) lines.push(fieldLine(bodyBytes, 12, 4, "Longitude", (lon / 1e6).toFixed(6), { baseOffset }));
      if (altitude !== null) lines.push(fieldLine(bodyBytes, 16, 2, "Altitude", `${altitude} m`, { baseOffset }));
      if (speed !== null)
        lines.push(fieldLine(bodyBytes, 18, 2, "Velocidade", `${(speed / 10).toFixed(1)} km/h`, { baseOffset }));
      if (direction !== null) lines.push(fieldLine(bodyBytes, 20, 2, "Direcao", `${direction}°`, { baseOffset }));
      lines.push(fieldLine(bodyBytes, 22, 6, "Horario (BCD)", time, { baseOffset }));

      const extStart = 28;
      if (bodyBytes.length > extStart) {
        lines.push(makeLine("-", "Extensoes:", null, null));
        let cursor = extStart;
        while (cursor + 2 <= bodyBytes.length) {
          const idOffset = cursor;
          const extId = bodyBytes[idOffset];
          const lenOffset = idOffset + 1;
          const len = bodyBytes[lenOffset];
          cursor += 2;
          if (cursor + len > bodyBytes.length) {
            warnings.push(`Extensao 0x${extId.toString(16).padStart(2, "0").toUpperCase()} truncada.`);
            break;
          }
          const valueOffset = cursor;
          const value = bodyBytes.slice(valueOffset, valueOffset + len);
          cursor += len;
          lines.push(
            fieldLine(
              bodyBytes,
              idOffset,
              1,
              "Ext ID",
              `0x${extId.toString(16).padStart(2, "0").toUpperCase()}`,
              { baseOffset }
            )
          );
          lines.push(fieldLine(bodyBytes, lenOffset, 1, "Ext length", len, { baseOffset }));
          lines.push(fieldLine(bodyBytes, valueOffset, len, "Ext value", bytesToHex(value), { baseOffset }));
        }
      }
      break;
    }
    default:
      lines.push(makeLine("-", "Sem interpretacao especifica para este Message ID.", null, null));
      break;
  }

  return { lines, warnings };
}

function parseJT808(bytes) {
  const errors = [];
  const warnings = [];

  if (!bytes.length) {
    errors.push("Mensagem vazia.");
    return { errors, warnings };
  }

  const hasStart = bytes[0] === 0x7e;
  const hasEnd = bytes[bytes.length - 1] === 0x7e;

  let escapedPayload = bytes;
  if (hasStart && hasEnd && bytes.length >= 2) {
    escapedPayload = bytes.slice(1, -1);
  } else {
    warnings.push("Flags 0x7E de inicio/fim nao encontradas. Parseando payload bruto.");
  }

  const unescaped = unescapePayload(escapedPayload);
  errors.push(...unescaped.errors);

  const payload = unescaped.data;
  if (payload.length < 13) {
    errors.push("Payload muito curto para conter header + checksum (minimo 13 bytes).");
  }

  const checksum = payload.length ? payload[payload.length - 1] : null;
  const content = payload.length ? payload.slice(0, -1) : [];

  if (content.length < 12) {
    errors.push("Header incompleto (minimo 12 bytes).");
  }

  const messageId = wordAt(content, 0);
  const props = wordAt(content, 2);
  const deviceIdBytes = content.slice(4, 10);
  const seq = wordAt(content, 10);

  const length = props !== null ? props & 0x03ff : null;
  const encMode = props !== null ? (props >> 10) & 0x07 : null;
  const subpackage = props !== null ? (props & 0x2000) !== 0 : null;
  const reserved14 = props !== null ? (props & 0x4000) !== 0 : null;
  const reserved15 = props !== null ? (props & 0x8000) !== 0 : null;

  let offset = 12;
  let subPkgTotal = null;
  let subPkgIndex = null;
  if (subpackage) {
    if (content.length >= offset + 4) {
      subPkgTotal = wordAt(content, offset);
      subPkgIndex = wordAt(content, offset + 2);
      offset += 4;
    } else {
      warnings.push("Sub-package habilitado, mas bytes de pacote ausentes.");
    }
  }

  let body = [];
  let extra = [];
  const bodyOffset = offset;
  if (length !== null) {
    body = content.slice(offset, offset + length);
    if (content.length < offset + length) {
      warnings.push("Body menor que o tamanho declarado nas properties.");
    }
    if (content.length > offset + length) {
      extra = content.slice(offset + length);
      if (extra.length) {
        warnings.push("Bytes extras encontrados apos o body declarado.");
      }
    }
  }

  const checksumCalc = content.length ? calcChecksum(content) : null;
  const checksumOk = checksum !== null && checksumCalc !== null && checksum === checksumCalc;

  return {
    errors,
    warnings,
    hasStart,
    hasEnd,
    escapedPayload,
    payload,
    messageId,
    props,
    deviceIdBytes,
    seq,
    length,
    encMode,
    subpackage,
    reserved14,
    reserved15,
    subPkgTotal,
    subPkgIndex,
    body,
    bodyOffset,
    extra,
    checksum,
    checksumCalc,
    checksumOk,
  };
}

function encryptionLabel(mode) {
  if (mode === 0) return "0 (none)";
  if (mode === 1) return "1 (RSA)";
  if (mode === null || mode === undefined) return "-";
  return `${mode} (desconhecido)`;
}

function setStatus(type, text) {
  statusEl.className = `status ${type || ""}`.trim();
  statusEl.textContent = text;
}

function addRow(rows, label, hex, meaning, range, hexIsHtml = false) {
  rows.push({ label, hex, meaning, range, hexIsHtml });
}

function renderRows(rows) {
  tableBody.innerHTML = "";
  rows.forEach((row, index) => {
    const tr = document.createElement("tr");
    tr.style.animationDelay = `${index * 0.04}s`;
    if (row.range && row.range.start !== null && row.range.end !== null) {
      tr.dataset.start = row.range.start;
      tr.dataset.end = row.range.end;
      tr.classList.add("range-row");
    }

    const tdLabel = document.createElement("td");
    tdLabel.textContent = row.label;

    const tdHex = document.createElement("td");
    if (row.hexIsHtml) {
      tdHex.innerHTML = row.hex || "-";
    } else {
      tdHex.textContent = row.hex || "-";
    }

    const tdMeaning = document.createElement("td");
    tdMeaning.innerHTML = row.meaning || "-";

    tr.append(tdLabel, tdHex, tdMeaning);
    tableBody.appendChild(tr);
  });
}

let hexByteSpans = [];
let rangeItems = [];

function renderHexBytes(bytes) {
  if (!bytes || !bytes.length) {
    unescapedHexEl.textContent = "-";
    hexByteSpans = [];
    rangeItems = [];
    return;
  }
  unescapedHexEl.innerHTML = bytes
    .map((b, index) => `<span class="hex-byte" data-index="${index}">${b.toString(16).padStart(2, "0").toUpperCase()}</span>`)
    .join(" ");
  hexByteSpans = Array.from(unescapedHexEl.querySelectorAll(".hex-byte"));
}

function clearHighlights() {
  hexByteSpans.forEach((span) => span.classList.remove("active"));
  rangeItems.forEach((item) => item.element.classList.remove("is-active"));
}

function highlightRange(start, end) {
  clearHighlights();
  if (start === null || end === null || start === undefined || end === undefined) return;
  for (let i = start; i <= end; i += 1) {
    const span = hexByteSpans[i];
    if (span) span.classList.add("active");
  }
  rangeItems.forEach((item) => {
    if (item.start === null || item.end === null) return;
    if (end < item.start || start > item.end) return;
    item.element.classList.add("is-active");
  });
}

function highlightIndex(index) {
  clearHighlights();
  const span = hexByteSpans[index];
  if (span) span.classList.add("active");
  rangeItems.forEach((item) => {
    if (item.start === null || item.end === null) return;
    if (index >= item.start && index <= item.end) {
      item.element.classList.add("is-active");
    }
  });
}

function setupHoverInteractions() {
  rangeItems = [];
  tableBody.querySelectorAll("tr[data-start][data-end]").forEach((row) => {
    const start = Number(row.dataset.start);
    const end = Number(row.dataset.end);
    rangeItems.push({ element: row, start, end });
  });

  tableBody.querySelectorAll(".body-line[data-start][data-end]").forEach((line) => {
    const start = Number(line.dataset.start);
    const end = Number(line.dataset.end);
    rangeItems.push({ element: line, start, end });
  });

  rangeItems.forEach((item) => {
    item.element.addEventListener("mouseenter", () => highlightRange(item.start, item.end));
    item.element.addEventListener("mouseleave", clearHighlights);
  });

  hexByteSpans.forEach((span) => {
    span.addEventListener("mouseenter", () => highlightIndex(Number(span.dataset.index)));
    span.addEventListener("mouseleave", clearHighlights);
  });
}

function renderNotes(errors, warnings) {
  if (!errors.length && !warnings.length) {
    notesEl.style.display = "none";
    notesEl.textContent = "";
    return;
  }

  notesEl.style.display = "block";
  const lines = [];
  errors.forEach((err) => lines.push(`Erro: ${err}`));
  warnings.forEach((warn) => lines.push(`Aviso: ${warn}`));
  notesEl.textContent = lines.join("\n");
}

function renderSummary(data) {
  if (!data || data.errors?.length) {
    summaryEl.textContent = "Mensagem nao valida para analise completa.";
    return;
  }

  const parts = [];
  if (data.messageId !== null) {
    parts.push(`Message ID: 0x${data.messageId.toString(16).padStart(4, "0").toUpperCase()}`);
  }
  if (data.length !== null) {
    parts.push(`Body length: ${data.length} bytes`);
  }
  if (data.encMode !== null) {
    parts.push(`Encryption mode: ${encryptionLabel(data.encMode)}`);
  }
  if (data.subpackage) {
    parts.push("Sub-package: sim");
  } else if (data.subpackage === false) {
    parts.push("Sub-package: nao");
  }
  if (data.checksumOk) {
    parts.push("Checksum: valido");
  } else if (data.checksum !== null) {
    parts.push("Checksum: invalido");
  }

  summaryEl.textContent = parts.join(" | ") || "Resumo indisponivel.";
}

function render() {
  const raw = input.value.trim();
  if (!raw) {
    setStatus("", "Aguardando entrada...");
    summaryEl.textContent = "Nenhuma mensagem analisada.";
    renderRows([]);
    renderNotes([], []);
    escapedHexEl.textContent = "-";
    renderHexBytes([]);
    return;
  }

  const sanitized = sanitizeHex(raw);
  if (!sanitized) {
    setStatus("error", "Nenhum hex valido encontrado.");
    renderRows([]);
    renderNotes(["Nao foi encontrado nenhum caractere hexadecimal valido."], []);
    summaryEl.textContent = "Mensagem nao valida para analise completa.";
    escapedHexEl.textContent = "-";
    renderHexBytes([]);
    return;
  }

  if (sanitized.length % 2 !== 0) {
    setStatus("error", "Quantidade de caracteres hex impar.");
    renderRows([]);
    renderNotes(["A quantidade de caracteres hex precisa ser par."], []);
    summaryEl.textContent = "Mensagem nao valida para analise completa.";
    escapedHexEl.textContent = "-";
    renderHexBytes([]);
    return;
  }

  const bytes = hexToBytes(sanitized);
  const parsed = parseJT808(bytes);
  const bodyInfo = formatBody(parsed.messageId, parsed.body || [], parsed.bodyOffset ?? 0);
  const allErrors = [...parsed.errors];
  const allWarnings = [...parsed.warnings, ...bodyInfo.warnings];

  if (allErrors.length) {
    setStatus("error", `Erros encontrados (${allErrors.length}).`);
  } else if (allWarnings.length) {
    setStatus("warn", `Avisos encontrados (${allWarnings.length}).`);
  } else {
    setStatus("ok", "Mensagem valida.");
  }

  escapedHexEl.textContent = bytesToHexSpaced(parsed.escapedPayload || []);
  renderHexBytes(parsed.payload || []);

  const rows = [];
  const payloadLength = parsed.payload?.length ?? 0;
  const checksumIndex = payloadLength ? payloadLength - 1 : null;
  const bodyStart = parsed.bodyOffset ?? null;
  const bodyEnd = bodyStart !== null && parsed.body?.length ? bodyStart + parsed.body.length - 1 : null;
  const extraStart =
    bodyStart !== null && parsed.body?.length !== undefined ? bodyStart + (parsed.body?.length || 0) : null;
  const extraEnd =
    extraStart !== null && parsed.extra?.length ? extraStart + parsed.extra.length - 1 : null;

  const msgInfo = parsed.messageId !== null ? MESSAGE_ID_INFO[parsed.messageId] : null;
  const msgInfoText = msgInfo
    ? `Tipo: ${msgInfo.name}<br>Fluxo: ${msgInfo.flow}`
    : "Descricao nao cadastrada para este Message ID.";
  addRow(rows, "Flag inicial", parsed.hasStart ? "7E" : "-", parsed.hasStart ? "Inicio do frame" : "Nao encontrado");
  addRow(
    rows,
    "Message ID",
    parsed.messageId !== null ? parsed.messageId.toString(16).padStart(4, "0").toUpperCase() : "-",
    `Identificador da mensagem.<br>${msgInfoText}`,
    parsed.messageId !== null ? { start: 0, end: 1 } : null
  );
  addRow(
    rows,
    "Message Body Properties",
    parsed.props !== null ? parsed.props.toString(16).padStart(4, "0").toUpperCase() : "-",
    parsed.props !== null
      ? `Length=${parsed.length} | Encryption=${encryptionLabel(parsed.encMode)} | Sub-package=${parsed.subpackage ? "1" : "0"} | Reserved14=${parsed.reserved14 ? "1" : "0"} | Reserved15=${parsed.reserved15 ? "1" : "0"}`
      : "-",
    parsed.props !== null ? { start: 2, end: 3 } : null
  );
  addRow(
    rows,
    "Device ID (BCD[6])",
    parsed.deviceIdBytes?.length ? bytesToHex(parsed.deviceIdBytes) : "-",
    parsed.deviceIdBytes?.length ? `Ultimos 12 digitos do IMEI: ${bcdToString(parsed.deviceIdBytes)}` : "-",
    parsed.deviceIdBytes?.length ? { start: 4, end: 9 } : null
  );
  addRow(
    rows,
    "Sequence Number",
    parsed.seq !== null ? parsed.seq.toString(10) : "-",
    "Numero sequencial da mensagem",
    parsed.seq !== null ? { start: 10, end: 11 } : null
  );

  if (parsed.subpackage) {
    addRow(
      rows,
      "Sub-package total",
      parsed.subPkgTotal !== null ? parsed.subPkgTotal.toString(10) : "-",
      "Total de pacotes",
      parsed.subPkgTotal !== null ? { start: 12, end: 13 } : null
    );
    addRow(
      rows,
      "Sub-package indice",
      parsed.subPkgIndex !== null ? parsed.subPkgIndex.toString(10) : "-",
      "Indice do pacote atual",
      parsed.subPkgIndex !== null ? { start: 14, end: 15 } : null
    );
  }

  addRow(
    rows,
    "Message Body",
    parsed.body?.length ? bytesToHex(parsed.body) : "-",
    `Payload (${parsed.body?.length || 0} bytes)`,
    bodyStart !== null && bodyEnd !== null && bodyEnd >= bodyStart ? { start: bodyStart, end: bodyEnd } : null
  );
  addRow(
    rows,
    "Message Body (interpretado)",
    bodyInfo.lines.length
      ? bodyInfo.lines
          .map((line) => {
            const safeHex = escapeHtml(line.hex || "-");
            if (line.start !== null && line.end !== null) {
              return `<span class="body-line" data-start="${line.start}" data-end="${line.end}">${safeHex}</span>`;
            }
            return `<span class="body-line">${safeHex}</span>`;
          })
          .join("<br>")
      : "-",
    bodyInfo.lines.length
      ? bodyInfo.lines
          .map((line) => {
            const safe = escapeHtml(line.meaning || "-");
            if (line.start !== null && line.end !== null) {
              return `<span class="body-line" data-start="${line.start}" data-end="${line.end}">${safe}</span>`;
            }
            return `<span class="body-line">${safe}</span>`;
          })
          .join("<br>")
      : "-",
    null,
    true
  );

  if (parsed.extra?.length) {
    addRow(
      rows,
      "Bytes extras",
      bytesToHex(parsed.extra),
      "Dados apos o body declarado",
      extraStart !== null && extraEnd !== null ? { start: extraStart, end: extraEnd } : null
    );
  }

  addRow(
    rows,
    "Checksum",
    parsed.checksum !== null ? parsed.checksum.toString(16).padStart(2, "0").toUpperCase() : "-",
    parsed.checksumCalc !== null
      ? `Calculado: ${parsed.checksumCalc.toString(16).padStart(2, "0").toUpperCase()} (${parsed.checksumOk ? "OK" : "Divergente"})`
      : "-",
    checksumIndex !== null ? { start: checksumIndex, end: checksumIndex } : null
  );
  addRow(rows, "Flag final", parsed.hasEnd ? "7E" : "-", parsed.hasEnd ? "Fim do frame" : "Nao encontrado");

  renderRows(rows);
  renderSummary(parsed);
  renderNotes(allErrors, allWarnings);
  setupHoverInteractions();

  if (!allErrors.length) {
    const sanitized = sanitizeHex(raw).toUpperCase();
    if (isValidHexString(sanitized)) {
      historyItems = historyItems.filter((item) => item.hex !== sanitized);
      historyItems.unshift({ hex: sanitized, ts: Date.now() });
      if (historyItems.length > HISTORY_LIMIT) {
        historyItems = historyItems.slice(0, HISTORY_LIMIT);
      }
      saveHistory(historyItems);
      renderHistory(historyItems);
    }
  }
}

let historyItems = loadHistory();
renderHistory(historyItems);

input.addEventListener("input", render);
loadSampleBtn.addEventListener("click", () => {
  input.value = SAMPLE;
  render();
});
clearInputBtn.addEventListener("click", () => {
  input.value = "";
  render();
});
if (clearHistoryBtn) {
  clearHistoryBtn.addEventListener("click", () => {
    historyItems = [];
    saveHistory(historyItems);
    renderHistory(historyItems);
  });
}

render();
