//! Test fixture: a trivial newline-echo "MCP server". Reads JSON-RPC lines from
//! stdin and writes each one straight back to stdout, unchanged, then exits on
//! EOF. Used by the integration tests to stand in for a real server.

use std::io::{BufRead, BufReader, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Echo verbatim (read_line keeps the trailing '\n').
                if out.write_all(line.as_bytes()).is_err() {
                    break;
                }
                let _ = out.flush();
            }
            Err(_) => break,
        }
    }
}
