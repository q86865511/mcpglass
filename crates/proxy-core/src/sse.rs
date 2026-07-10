//! Server-Sent Events (SSE) event splitter for the tap path.
//!
//! The Streamable HTTP transport (MCP 2025-06-18) may answer a POST request, or a
//! GET stream, with `Content-Type: text/event-stream`. Each SSE event's `data`
//! payload is one JSON-RPC message. [`SseSplitter`] reassembles those payloads
//! from an arbitrarily-chunked byte stream so the storage thread can record and
//! fingerprint them — exactly like [`crate::LineSplitter`] does for stdio frames.
//!
//! It is strictly a *tap* helper: the gateway forwards every byte of the stream
//! to the client untouched and only feeds a copy here. A bug or overflow in this
//! splitter can therefore never corrupt or stall the wire — an over-long event is
//! silently skipped and the stream recovers on the next event boundary.

/// Incrementally splits an SSE byte stream into complete event `data` payloads.
///
/// Follows the [SSE stream-interpretation rules](https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation)
/// to the extent the tap needs them:
/// * a line is terminated by `\n` (a trailing `\r`, i.e. CRLF, is stripped);
/// * a blank line dispatches the buffered event;
/// * lines beginning with `:` are comments and ignored;
/// * a `data:` field appends its value (one optional leading space stripped);
///   multiple `data:` lines in one event are joined with `\n`;
/// * all other fields (`event`, `id`, `retry`, …) are irrelevant to the recorded
///   JSON-RPC payload and ignored.
///
/// An event whose accumulated data (or a single line) exceeds `max_event_bytes`
/// is dropped from the tap: the whole event is marked to be skipped and the
/// splitter resumes cleanly at the next blank line.
pub struct SseSplitter {
    max_event_bytes: usize,
    /// Bytes of the current, not-yet-terminated line (without its newline).
    line: Vec<u8>,
    /// Accumulated `data` payload for the current event.
    data: Vec<u8>,
    /// The current event has at least one `data` field (distinguishes an empty
    /// data payload, which is dispatched, from an event with no data at all,
    /// which is not).
    saw_data: bool,
    /// The current event overflowed `max_event_bytes` and will be skipped on
    /// dispatch rather than emitted.
    overflow: bool,
    /// The current line overflowed `max_event_bytes`; its buffered bytes were
    /// discarded, so at newline it must be treated as a (non-blank) skipped line
    /// rather than the blank dispatch line.
    line_dirty: bool,
}

impl SseSplitter {
    pub fn new(max_event_bytes: usize) -> Self {
        Self {
            max_event_bytes,
            line: Vec::new(),
            data: Vec::new(),
            saw_data: false,
            overflow: false,
            line_dirty: false,
        }
    }

    /// Feed freshly received bytes; return every complete event's `data` payload
    /// they finish (in order). Bytes that don't yet complete an event are
    /// buffered. An event that never terminates (no trailing blank line before
    /// EOF) is, per the SSE spec, simply never dispatched.
    pub fn push(&mut self, mut bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(pos) = bytes.iter().position(|&b| b == b'\n') {
            let (head, rest) = bytes.split_at(pos);
            bytes = &rest[1..]; // consume the '\n'
            self.buffer_line_bytes(head);
            let line = std::mem::take(&mut self.line);
            let dirty = std::mem::take(&mut self.line_dirty);
            if dirty {
                // An over-long line: uninspectable and definitely not blank. The
                // event is already marked `overflow`; skip and wait for the blank.
                continue;
            }
            if let Some(event) = self.handle_line(strip_cr(&line)) {
                out.push(event);
            }
        }
        // Trailing bytes with no newline yet: buffer them for the next feed.
        self.buffer_line_bytes(bytes);
        out
    }

    /// Append bytes to the current line, guarding against an unbounded single
    /// line. On overflow the line's bytes are dropped and the event is marked to
    /// be skipped; `line_dirty` records that this (now-empty) line is not blank.
    fn buffer_line_bytes(&mut self, chunk: &[u8]) {
        if self.line_dirty {
            return; // already over the cap for this line; drop the rest of it
        }
        self.line.extend_from_slice(chunk);
        if self.line.len() > self.max_event_bytes {
            self.overflow = true;
            self.line_dirty = true;
            self.line.clear();
        }
    }

    /// Process one complete line (already stripped of any trailing `\r`). Returns
    /// the event payload when the line is the blank line that dispatches it.
    fn handle_line(&mut self, line: &[u8]) -> Option<Vec<u8>> {
        if line.is_empty() {
            // Blank line: dispatch the buffered event (unless it overflowed or
            // carried no data at all), then reset for the next event.
            let event = if self.saw_data && !self.overflow {
                Some(std::mem::take(&mut self.data))
            } else {
                None
            };
            self.data.clear();
            self.saw_data = false;
            self.overflow = false;
            return event;
        }
        if line[0] == b':' {
            return None; // comment line
        }
        // Split "field:value"; a line with no colon is the field name with an
        // empty value (per the SSE spec).
        let (field, value) = match line.iter().position(|&b| b == b':') {
            Some(i) => {
                let mut v = &line[i + 1..];
                if v.first() == Some(&b' ') {
                    v = &v[1..]; // strip one leading space after the colon
                }
                (&line[..i], v)
            }
            None => (line, &b""[..]),
        };
        if field == b"data" && !self.overflow {
            if self.saw_data {
                self.data.push(b'\n'); // join multiple data lines with '\n'
            }
            self.saw_data = true;
            self.data.extend_from_slice(value);
            if self.data.len() > self.max_event_bytes {
                self.overflow = true;
                self.data.clear(); // free memory; the event will be skipped
            }
        }
        None
    }
}

/// Drop a single trailing `\r` so a CRLF-terminated line is handled like an
/// LF-terminated one.
fn strip_cr(line: &[u8]) -> &[u8] {
    match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(splitter: &mut SseSplitter, bytes: &[u8]) -> Vec<String> {
        splitter
            .push(bytes)
            .into_iter()
            .map(|e| String::from_utf8_lossy(&e).into_owned())
            .collect()
    }

    #[test]
    fn single_event_data_payload() {
        let mut s = SseSplitter::new(1024);
        assert_eq!(events(&mut s, b"data: hello\n\n"), vec!["hello"]);
    }

    #[test]
    fn reassembles_across_chunks() {
        let mut s = SseSplitter::new(1024);
        // The event is split across several feeds; nothing emits until the blank line.
        assert!(s.push(b"data: {\"jsonrpc\"").is_empty());
        assert!(s.push(b":\"2.0\",\"id\":1}").is_empty());
        assert!(s.push(b"\n").is_empty());
        assert_eq!(events(&mut s, b"\n"), vec![r#"{"jsonrpc":"2.0","id":1}"#]);
    }

    #[test]
    fn multi_line_data_joins_with_newline() {
        let mut s = SseSplitter::new(1024);
        // Two data lines in one event become one payload joined by '\n'.
        assert_eq!(events(&mut s, b"data: line one\ndata: line two\n\n"), vec!["line one\nline two"]);
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let mut s = SseSplitter::new(1024);
        assert_eq!(events(&mut s, b"data: hi\r\n\r\n"), vec!["hi"]);
    }

    #[test]
    fn non_data_fields_and_comments_are_ignored() {
        let mut s = SseSplitter::new(1024);
        // `event:`, `id:`, `retry:` and comment lines contribute nothing to the
        // recorded payload; only `data` does.
        let out = events(
            &mut s,
            b": keep-alive comment\nevent: message\nid: 42\ndata: payload\nretry: 3000\n\n",
        );
        assert_eq!(out, vec!["payload"]);
    }

    #[test]
    fn leading_space_after_colon_is_stripped_once() {
        let mut s = SseSplitter::new(1024);
        // "data:  x" -> one leading space stripped, so " x" (a second space kept).
        assert_eq!(events(&mut s, b"data:  x\n\n"), vec![" x"]);
        // "data:x" (no space) is kept verbatim.
        assert_eq!(events(&mut s, b"data:x\n\n"), vec!["x"]);
    }

    #[test]
    fn multiple_events_in_one_chunk() {
        let mut s = SseSplitter::new(1024);
        assert_eq!(
            events(&mut s, b"data: a\n\ndata: b\n\ndata: c\n\n"),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn oversized_event_is_skipped_and_stream_recovers() {
        // Cap 16: a 50-char data line far exceeds it and is dropped, yet the
        // following well-sized event (`data: small`, an 11-byte line) is still
        // emitted. (The cap bounds the raw line, so it sits above the small line.)
        let mut s = SseSplitter::new(16);
        let big = format!("data: {}\n\n", "x".repeat(50));
        assert!(s.push(big.as_bytes()).is_empty(), "oversized event must be skipped");
        assert_eq!(events(&mut s, b"data: small\n\n"), vec!["small"]);
    }

    #[test]
    fn oversized_multiline_data_is_skipped_then_recovers() {
        // Overflow accumulated across multiple data lines within one event.
        let mut s = SseSplitter::new(10);
        let ev = format!("data: {}\ndata: {}\n\n", "a".repeat(8), "b".repeat(8));
        assert!(s.push(ev.as_bytes()).is_empty());
        // A later normal event is unaffected.
        assert_eq!(events(&mut s, b"data: ok\n\n"), vec!["ok"]);
    }

    #[test]
    fn event_without_data_field_dispatches_nothing() {
        let mut s = SseSplitter::new(1024);
        // Only non-data fields, then a blank line: no payload to record.
        assert!(s.push(b"event: ping\nid: 1\n\n").is_empty());
        // The stream still works afterwards.
        assert_eq!(events(&mut s, b"data: after\n\n"), vec!["after"]);
    }

    // --- MCP 2025-11-25 SSE resumption (SEP-1699) ---------------------------

    #[test]
    fn retry_field_and_event_id_are_ignored_data_still_dispatched() {
        // The 2025-11-25 resumption model has the server emit `id:` (the resumption
        // token) and, before closing, a `retry:` field. Neither is part of the
        // recorded JSON-RPC payload: only `data` is, and it must still dispatch.
        let mut s = SseSplitter::new(1024);
        let out = events(
            &mut s,
            b"id: evt-42\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\nretry: 5000\n\n",
        );
        assert_eq!(out, vec![r#"{"jsonrpc":"2.0","id":1,"result":{}}"#]);
    }

    #[test]
    fn event_id_then_disconnect_before_blank_line_loses_no_prior_event() {
        // A server sends a complete event (with its resumption id), then starts a
        // second event and disconnects mid-way (no terminating blank line) — the
        // SEP-1699 "send an id, then drop the stream" pattern. The splitter must not
        // error and must not lose the already-completed first event; the truncated
        // second event is simply never dispatched (per the SSE spec), matching how a
        // resumed GET + Last-Event-ID would re-fetch it.
        let mut s = SseSplitter::new(1024);
        let out = events(
            &mut s,
            b"id: 1\ndata: {\"first\":true}\n\nid: 2\ndata: {\"second\"",
        );
        assert_eq!(out, vec![r#"{"first":true}"#]);
        // No blank line ever arrives for event 2: EOF (no further push) drops it,
        // exactly as the spec requires — nothing is emitted, nothing panics.
    }
}
