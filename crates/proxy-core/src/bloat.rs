//! Context-bloat analysis: estimate how many LLM context tokens a server's
//! advertised tool catalog (`tools/list` response) would cost, using a
//! zero-dependency heuristic rather than a real tokenizer.
//!
//! The heuristic is [`CHARS_PER_TOKEN`] characters per token — a commonly
//! cited English/JSON approximation, not a measurement. Every number derived
//! from it is an estimate; callers (CLI, dashboard) must label it
//! `approximate` rather than presenting it as exact.

use serde_json::Value;

/// Heuristic characters-per-token ratio. English prose and compact JSON both
/// average close to 4 chars/token in practice; this crate takes no dependency
/// on a real tokenizer to get a closer number.
pub const CHARS_PER_TOKEN: usize = 4;

/// A tool whose `description` alone estimates to more than this many tokens
/// is flagged in [`BloatReport::fat_tools`] as a trimming candidate.
pub const FAT_DESCRIPTION_TOKENS: usize = 100;

/// Estimate a token count from a character count via [`CHARS_PER_TOKEN`],
/// rounding up (so any non-empty input estimates to at least 1 token).
pub fn estimate_tokens(chars: usize) -> usize {
    chars.div_ceil(CHARS_PER_TOKEN)
}

/// Per-tool breakdown of estimated context cost.
pub struct ToolBloat {
    pub name: String,
    /// `serde_json::to_string` length of the whole tool object.
    pub total_chars: usize,
    /// Length of the `description` string, or 0 if absent/non-string.
    pub description_chars: usize,
    /// `serde_json::to_string` length of `inputSchema`, or 0 if absent.
    pub schema_chars: usize,
    pub est_tokens: usize,
    pub description_tokens: usize,
}

/// Aggregate bloat report for one `tools/list` response.
pub struct BloatReport {
    pub tool_count: usize,
    pub total_chars: usize,
    pub est_total_tokens: usize,
    /// Sorted by `est_tokens` descending — heaviest tool first.
    pub tools: Vec<ToolBloat>,
    /// Names of tools whose `description_tokens` exceeds [`FAT_DESCRIPTION_TOKENS`].
    pub fat_tools: Vec<String>,
}

/// Analyze a raw `tools/list` JSON-RPC response body (the whole `{"jsonrpc":
/// ..., "result": {"tools": [...]}}` envelope). Returns `None` if
/// `result.tools` is missing or not an array — there is nothing to analyze,
/// as opposed to an empty catalog (`Some` with zeroed totals).
pub fn analyze_tools_list_response(value: &Value) -> Option<BloatReport> {
    let tools = value.get("result")?.get("tools")?.as_array()?;

    let mut breakdown: Vec<ToolBloat> = Vec::with_capacity(tools.len());
    let mut fat_tools = Vec::new();
    let mut total_chars = 0usize;

    for tool in tools {
        let name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_owned();
        let total = serde_json::to_string(tool).map(|s| s.len()).unwrap_or(0);
        let description_chars = tool
            .get("description")
            .and_then(|d| d.as_str())
            .map(str::len)
            .unwrap_or(0);
        let schema_chars = tool
            .get("inputSchema")
            .map(|s| serde_json::to_string(s).map(|s| s.len()).unwrap_or(0))
            .unwrap_or(0);
        let est_tokens = estimate_tokens(total);
        let description_tokens = estimate_tokens(description_chars);

        if description_tokens > FAT_DESCRIPTION_TOKENS {
            fat_tools.push(name.clone());
        }

        total_chars += total;
        breakdown.push(ToolBloat {
            name,
            total_chars: total,
            description_chars,
            schema_chars,
            est_tokens,
            description_tokens,
        });
    }

    // Heaviest tool first; ties keep their original tools[] order (`sort_by_key`
    // is stable).
    breakdown.sort_by_key(|t| std::cmp::Reverse(t.est_tokens));

    Some(BloatReport {
        tool_count: breakdown.len(),
        total_chars,
        est_total_tokens: estimate_tokens(total_chars),
        tools: breakdown,
        fat_tools,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn estimate_tokens_rounds_up_at_the_chars_per_token_boundary() {
        assert_eq!(estimate_tokens(0), 0);
        assert_eq!(estimate_tokens(1), 1);
        assert_eq!(estimate_tokens(4), 1);
        assert_eq!(estimate_tokens(5), 2);
        assert_eq!(estimate_tokens(8), 2);
    }

    #[test]
    fn missing_result_yields_none() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}});
        assert!(analyze_tools_list_response(&v).is_none());
    }

    #[test]
    fn result_without_tools_array_yields_none() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": "not-an-array"}});
        assert!(analyze_tools_list_response(&v).is_none());
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {}});
        assert!(analyze_tools_list_response(&v).is_none());
    }

    #[test]
    fn empty_tools_array_yields_zeroed_report_not_none() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}});
        let report = analyze_tools_list_response(&v).expect("empty array is still Some");
        assert_eq!(report.tool_count, 0);
        assert_eq!(report.total_chars, 0);
        assert_eq!(report.est_total_tokens, 0);
        assert!(report.tools.is_empty());
        assert!(report.fat_tools.is_empty());
    }

    #[test]
    fn description_missing_yields_zero_description_chars() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
            {"name": "no_desc", "inputSchema": {"type": "object"}}
        ]}});
        let report = analyze_tools_list_response(&v).unwrap();
        assert_eq!(report.tools[0].description_chars, 0);
        assert_eq!(report.tools[0].description_tokens, 0);
    }

    #[test]
    fn tools_are_sorted_by_estimated_tokens_descending() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
            {"name": "small", "description": "hi"},
            {"name": "big", "description": "x".repeat(400)},
            {"name": "medium", "description": "x".repeat(40)},
        ]}});
        let report = analyze_tools_list_response(&v).unwrap();
        let names: Vec<&str> = report.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["big", "medium", "small"]);
    }

    #[test]
    fn fat_tools_only_lists_tools_over_the_description_token_threshold() {
        // FAT_DESCRIPTION_TOKENS = 100 tokens = 400 chars at 4 chars/token.
        // Exactly at the threshold (400 chars -> 100 tokens) must NOT be fat
        // (the rule is strictly greater-than); one char over must be.
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
            {"name": "at_threshold", "description": "x".repeat(400)},
            {"name": "over_threshold", "description": "x".repeat(401)},
            {"name": "tiny", "description": "hi"},
        ]}});
        let report = analyze_tools_list_response(&v).unwrap();
        assert_eq!(report.fat_tools, vec!["over_threshold".to_string()]);
    }

    #[test]
    fn total_chars_and_schema_chars_reflect_serialized_json() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
            {"name": "t", "description": "d", "inputSchema": {"type": "object", "properties": {}}}
        ]}});
        let report = analyze_tools_list_response(&v).unwrap();
        let t = &report.tools[0];
        let expected_total = serde_json::to_string(&v["result"]["tools"][0]).unwrap().len();
        let expected_schema =
            serde_json::to_string(&v["result"]["tools"][0]["inputSchema"]).unwrap().len();
        assert_eq!(t.total_chars, expected_total);
        assert_eq!(t.schema_chars, expected_schema);
        assert_eq!(report.total_chars, expected_total);
    }
}
