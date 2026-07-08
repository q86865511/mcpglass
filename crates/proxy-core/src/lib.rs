//! Transport-level primitives shared by the proxy: newline framing of the MCP
//! stdio transport and best-effort JSON-RPC field extraction.
//!
//! Everything here is on the *tap* path, never the forwarding path. Callers must
//! forward bytes first and only then feed them here (fail-open): a bug in this
//! crate must never be able to corrupt or stall client<->server traffic.

/// Which leg of the conversation a framed line belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// client -> server (our stdin -> child stdin).
    C2s,
    /// server -> client (child stdout -> our stdout).
    S2c,
}

impl Direction {
    /// Stable on-disk token; matches the `messages.direction` CHECK values.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::C2s => "c2s",
            Direction::S2c => "s2c",
        }
    }
}

impl std::str::FromStr for Direction {
    type Err = ();

    /// Inverse of [`Direction::as_str`]; used when reading rows back out of storage.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "c2s" => Ok(Direction::C2s),
            "s2c" => Ok(Direction::S2c),
            _ => Err(()),
        }
    }
}

/// Incrementally splits a byte stream into newline-delimited frames.
///
/// The MCP stdio transport is one JSON-RPC message per `\n`-terminated line.
/// This handles the two things that break naive `split('\n')`: a frame straddling
/// a read boundary, and an over-long frame that must not be allowed to grow the
/// tap buffer without bound. Forwarding is unaffected either way — an over-long
/// frame is still forwarded byte-for-byte upstream; only its *recording* is dropped.
pub struct LineSplitter {
    buf: Vec<u8>,
    /// Cap on a single buffered frame. Beyond this we stop recording the current
    /// frame (memory guard against an unterminated stream) but keep forwarding.
    max_line_bytes: usize,
    /// True while we are inside a frame that already exceeded `max_line_bytes`.
    overflowed: bool,
}

impl LineSplitter {
    pub fn new(max_line_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_line_bytes,
            overflowed: false,
        }
    }

    /// Feed a chunk of freshly read bytes; return every complete frame it
    /// completes (without the trailing `\n`). A frame that overflowed
    /// `max_line_bytes` yields nothing and is silently dropped from the tap.
    pub fn push(&mut self, mut data: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(pos) = data.iter().position(|&b| b == b'\n') {
            let (head, rest) = data.split_at(pos);
            data = &rest[1..]; // drop the '\n' itself
            if self.overflowed {
                // Terminating newline of an over-long frame: reset, record nothing.
                self.overflowed = false;
                self.buf.clear();
            } else {
                self.buf.extend_from_slice(head);
                out.push(std::mem::take(&mut self.buf));
            }
        }
        // Trailing remainder has no newline yet; buffer it unless it overflows.
        if !self.overflowed && !data.is_empty() {
            self.buf.extend_from_slice(data);
            if self.buf.len() > self.max_line_bytes {
                self.overflowed = true;
                self.buf.clear();
            }
        }
        out
    }
}

/// JSON-RPC fields we index for querying. Absence of `method`/`rpc_id` is normal
/// (responses have no method; notifications have no id) — never an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMessage {
    pub method: Option<String>,
    pub rpc_id: Option<String>,
    pub is_valid_json: bool,
    /// A JSON-RPC error *response*: valid JSON travelling server->client whose top
    /// level carries an `error` member. Only meaningful for [`Direction::S2c`].
    pub is_error: bool,
}

/// Best-effort parse of a single framed line. A non-JSON line is not an error:
/// it is recorded verbatim with `is_valid_json = false` so nothing is ever lost.
///
/// `direction` gates the `is_error` classification: an `error` member only counts
/// as a failed response on the server->client leg.
pub fn parse_line(line: &[u8], direction: Direction) -> ParsedMessage {
    match serde_json::from_slice::<serde_json::Value>(line) {
        Ok(value) => {
            let method = value
                .get("method")
                .and_then(|m| m.as_str())
                .map(str::to_owned);
            // `id` may be a string or a number in JSON-RPC; normalise to text.
            let rpc_id = value.get("id").and_then(|id| match id {
                serde_json::Value::Null => None,
                serde_json::Value::String(s) => Some(s.clone()),
                other => Some(other.to_string()),
            });
            let is_error = direction == Direction::S2c && value.get("error").is_some();
            ParsedMessage {
                method,
                rpc_id,
                is_valid_json: true,
                is_error,
            }
        }
        Err(_) => ParsedMessage {
            method: None,
            rpc_id: None,
            is_valid_json: false,
            is_error: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_str(frames: &[Vec<u8>]) -> Vec<String> {
        frames
            .iter()
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect()
    }

    #[test]
    fn partial_line_across_reads_is_reassembled() {
        let mut s = LineSplitter::new(1024);
        // A frame split across three feeds emits nothing until the newline lands.
        assert!(s.push(b"{\"jsonrpc\"").is_empty());
        assert!(s.push(b":\"2.0\",\"id\":1}").is_empty());
        let frames = s.push(b"\n");
        assert_eq!(as_str(&frames), vec![r#"{"jsonrpc":"2.0","id":1}"#]);
    }

    #[test]
    fn multiple_frames_in_one_chunk() {
        let mut s = LineSplitter::new(1024);
        let frames = s.push(b"a\nbb\nccc\n");
        assert_eq!(as_str(&frames), vec!["a", "bb", "ccc"]);
        // Trailing bytes with no newline stay buffered.
        let frames = s.push(b"dd");
        assert!(frames.is_empty());
        let frames = s.push(b"\n");
        assert_eq!(as_str(&frames), vec!["dd"]);
    }

    #[test]
    fn oversized_line_is_dropped_but_stream_recovers() {
        // Cap of 8 bytes; a 20-byte frame overflows and records nothing...
        let mut s = LineSplitter::new(8);
        assert!(s.push(&[b'x'; 20]).is_empty());
        let frames = s.push(b"\nshort\n");
        // ...yet the following well-sized frame is still recovered.
        assert_eq!(as_str(&frames), vec!["short"]);
    }

    #[test]
    fn handles_ten_megabyte_line() {
        // 10 MiB payload fed in 64 KiB reads must reassemble into one frame.
        let cap = 64 * 1024 * 1024;
        let mut s = LineSplitter::new(cap);
        let payload = vec![b'z'; 10 * 1024 * 1024];
        let mut completed: Option<Vec<u8>> = None;
        for chunk in payload.chunks(64 * 1024) {
            for f in s.push(chunk) {
                completed = Some(f);
            }
        }
        assert!(completed.is_none());
        let frames = s.push(b"\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), 10 * 1024 * 1024);
    }

    #[test]
    fn parse_request_extracts_method_and_id() {
        let p = parse_line(
            br#"{"jsonrpc":"2.0","id":7,"method":"initialize"}"#,
            Direction::C2s,
        );
        assert_eq!(p.method.as_deref(), Some("initialize"));
        assert_eq!(p.rpc_id.as_deref(), Some("7"));
        assert!(p.is_valid_json);
        assert!(!p.is_error);
    }

    #[test]
    fn parse_notification_has_no_id() {
        let p = parse_line(
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            Direction::C2s,
        );
        assert_eq!(p.method.as_deref(), Some("notifications/initialized"));
        assert_eq!(p.rpc_id, None);
        assert!(p.is_valid_json);
    }

    #[test]
    fn parse_non_json_line_is_recorded_as_invalid() {
        let p = parse_line(b"this is not json", Direction::S2c);
        assert_eq!(p.method, None);
        assert_eq!(p.rpc_id, None);
        assert!(!p.is_valid_json);
        assert!(!p.is_error);
    }

    #[test]
    fn error_response_is_flagged_only_server_to_client() {
        let body = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}"#;
        // Same bytes: an error member counts only on the s2c leg.
        assert!(parse_line(body, Direction::S2c).is_error);
        assert!(!parse_line(body, Direction::C2s).is_error);
        // A plain result response is not an error.
        assert!(!parse_line(
            br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            Direction::S2c,
        )
        .is_error);
    }

    #[test]
    fn direction_round_trips_through_str() {
        for d in [Direction::C2s, Direction::S2c] {
            assert_eq!(d.as_str().parse::<Direction>(), Ok(d));
        }
        assert!("bogus".parse::<Direction>().is_err());
    }
}
