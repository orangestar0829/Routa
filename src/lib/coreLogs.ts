export type LogLevel = "error" | "warning" | "info" | "debug" | "unknown";
export type LogFilter = "all" | "problems" | LogLevel;
export type LogRouteLabels = Readonly<Partial<Record<string, string>>>;

export interface CoreLogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  message: string;
  raw: string;
}

export const LOG_LEVEL_LABELS: Record<LogLevel, string> = {
  error: "错误", warning: "警告", info: "信息", debug: "调试", unknown: "未知",
};

function levelOf(value: string): LogLevel {
  if (/^(error|fatal|panic)$/i.test(value)) return "error";
  if (/^warn(ing)?$/i.test(value)) return "warning";
  if (/^info$/i.test(value)) return "info";
  if (/^(debug|trace)$/i.test(value)) return "debug";
  return "unknown";
}

/** Logrus uses Go quoted strings, including escapes that JSON.parse doesn't accept. */
function unquote(value: string): string {
  if (!value.startsWith('"') || !value.endsWith('"')) return value;
  const escapes: Record<string, string> = {
    a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", '"': '"', "\\": "\\",
  };
  return value.slice(1, -1).replace(
    /\\(?:x([\da-fA-F]{2})|u([\da-fA-F]{4})|U([\da-fA-F]{8})|([0-7]{3})|([\s\S]))/g,
    (original, hex: string, unicode: string, wide: string, octal: string, char: string) => {
      if (char !== undefined) return escapes[char] ?? original;
      const point = parseInt(hex ?? unicode ?? wide ?? octal, octal ? 8 : 16);
      return point <= 0x10ffff ? String.fromCodePoint(point) : original;
    },
  );
}

function stripAnsi(text: string) {
  return text.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "");
}

function parseLine(raw: string): Omit<CoreLogEntry, "id"> {
  const clean = stripAnsi(raw);
  try {
    const json: unknown = JSON.parse(clean);
    if (json && typeof json === "object") {
      const fields = json as Record<string, unknown>;
      const message = fields.msg ?? fields.message ?? fields.payload;
      if (typeof message === "string") return {
        timestamp: String(fields.time ?? fields.timestamp ?? ""),
        level: levelOf(String(fields.level ?? fields.type ?? "")),
        message: stripAnsi(message), raw,
      };
    }
  } catch { /* Non-JSON logs are expected. */ }

  if (/^(?:time|level|msg)=/.test(clean)) {
    const fields = new Map([...clean.matchAll(/([\w.-]+)=("(?:\\.|[^"\\])*"|[^"\s]+)/g)]
      .map((match) => [match[1], unquote(match[2])]));
    if (fields.has("msg")) {
      const extra = [...fields].filter(([key]) => !["time", "level", "msg"].includes(key))
        .map(([key, value]) => `${key}=${value}`);
      return {
        timestamp: fields.get("time") ?? "", level: levelOf(fields.get("level") ?? ""),
        message: stripAnsi([fields.get("msg"), ...extra].join("\n")), raw,
      };
    }
  }
  const bracket = clean.match(/^(?:(\d{4}[-/]\d{2}[-/]\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:\d{2})?)\s+)?\[(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC)\]\s*(.*)$/i);
  if (bracket) return { timestamp: bracket[1] ?? "", level: levelOf(bracket[2]), message: bracket[3], raw };
  return { timestamp: "", level: "unknown", message: clean, raw };
}

/**
 * Mihomo 1.19 logs a failed dial's selected route and a successful dial's
 * resolved leaf (sometimes as `group[leaf]`). Replace only that field;
 * node names may contain spaces, slashes or brackets. Diagnostic text and
 * raw records must survive byte-for-byte.
 */
function labelRoutes(message: string, routes: ReadonlyMap<string, string>, leaves: ReadonlyMap<string, string>): string {
  const firstLineEnd = message.indexOf("\n");
  const firstLine = firstLineEnd < 0 ? message : message.slice(0, firstLineEnd);
  const rest = firstLineEnd < 0 ? "" : message.slice(firstLineEnd);
  const failure = firstLine.match(/^\[(?:TCP|UDP)\] dial /)?.[0];
  if (failure) {
    const afterPrefix = firstLine.slice(failure.length);
    // SourceDetail() is mihomo for internal traffic, otherwise IP:port
    // (possibly bracketed IPv6), with optional (process, uid=...) detail.
    const dialTail = /^ (?:\(match .*?\) )?(?:mihomo|(?:[\d.]+|\[[^\]]+\]):\d+(?:\(.*?\))?) --> \S+ error: /;
    let match: { end: number; label: string } | undefined;
    const boundary = afterPrefix.indexOf(" --> ");
    for (let end = afterPrefix.indexOf(" "); end >= 0 && end < boundary; end = afterPrefix.indexOf(" ", end + 1)) {
      const label = routes.get(afterPrefix.slice(0, end));
      if (!label || !dialTail.test(afterPrefix.slice(end))) continue;
      if (match) return message;
      match = { end, label };
    }
    if (match) return failure + match.label + afterPrefix.slice(match.end) + rest;
    return message;
  }

  const forwarded = firstLine.match(/^\[(?:TCP|UDP)\] (?:mihomo|(?:[\d.]+|\[[^\]]+\]):\d+(?:\(.*?\))?) --> \S+:\d+(?= )/)?.[0];
  if (!forwarded) return message;
  const matches: { offset: number; label: string }[] = [];
  for (let offset = firstLine.indexOf(" using ", forwarded.length);
    offset >= 0; offset = firstLine.indexOf(" using ", offset + 7)) {
    const qualifier = firstLine.slice(forwarded.length, offset);
    if (qualifier && !qualifier.startsWith(" match ") && qualifier !== " doesn't match any rule") continue;
    const start = offset + " using ".length;
    const route = firstLine.slice(start);
    const whole = leaves.get(route) ?? routes.get(route);
    if (whole) matches.push({ offset: start, label: whole });
    // Try exact split positions rather than assuming the first '[' belongs to
    // the group or the last one to the leaf. Both sides must resolve.
    if (route.endsWith("]")) {
      for (let bracket = route.indexOf("["); bracket >= 0; bracket = route.indexOf("[", bracket + 1)) {
        if (!routes.has(route.slice(0, bracket))) continue;
        const leaf = leaves.get(route.slice(bracket + 1, -1));
        if (leaf) matches.push({ offset: start, label: leaf });
      }
    }
  }
  // A literal proxy named "group[leaf]" is otherwise indistinguishable
  // from the Chain.String() form; don't attribute an ambiguous route.
  return matches.length === 1 ? firstLine.slice(0, matches[0].offset) + matches[0].label + rest : message;
}

/** File order is authoritative; don't invent timestamps for unstructured messages. */
export function parseCoreLogs(
  text: string,
  labels?: LogRouteLabels,
  labelsSince?: number | null,
  leafLabels?: LogRouteLabels,
): CoreLogEntry[] {
  if (!text.trim() || text.trim() === "暂无内核日志") return [];
  const entries: CoreLogEntry[] = [];
  const occurrences = new Map<string, number>();
  const validLabels = (values?: LogRouteLabels) =>
    new Map(Object.entries(values ?? {}).filter((entry): entry is [string, string] => {
      const [key, value] = entry;
      return !!key && !!value && !/[\r\n]/.test(key) && !/[\r\n]/.test(value);
    }));
  const routes = validLabels(labels);
  const leaves = validLabels(leafLabels);
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim()) continue;
    const parsed = parseLine(raw);
    const previous = entries[entries.length - 1];
    if (parsed.level === "unknown" && /^\s+/.test(raw) && previous) {
      previous.message += `\n${parsed.message}`;
      previous.raw += `\n${raw}`;
      continue;
    }
    // Use a complete ISO timestamp with timezone, and a strict second
    // boundary. The file may include a previous process or pre-reload rows.
    if (labelsSince != null && (routes.size || leaves.size) && /^(?:\d{4}-\d{2}-\d{2}[T ])\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(parsed.timestamp)
      && Math.floor(Date.parse(parsed.timestamp) / 1000) > labelsSince) {
      parsed.message = labelRoutes(parsed.message, routes, leaves);
    }
    const count = occurrences.get(raw) ?? 0;
    occurrences.set(raw, count + 1);
    entries.push({ ...parsed, id: `${raw}\0${count}` });
  }
  return entries;
}

export function filterCoreLogs(entries: CoreLogEntry[], filter: LogFilter, query: string) {
  const search = query.trim().toLocaleLowerCase();
  return entries.filter((entry) =>
    (filter === "all" || (filter === "problems" ? ["warning", "error"].includes(entry.level) : entry.level === filter)) &&
    (!search || `${entry.message}\n${entry.timestamp}\n${entry.raw}`.toLocaleLowerCase().includes(search)),
  );
}

export function logTime(timestamp: string) {
  if (!timestamp) return "时间未知";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
