//! Bounded source YAML normalization. Runtime still receives unambiguous, expanded YAML.
use super::{MAX_PROFILE_BYTES, PrepareError};
use std::collections::{HashMap, HashSet};
use yaml_rust2::{
    Yaml, YamlLoader,
    parser::{Event, Parser},
    scanner::TScalarStyle,
    yaml::Hash,
};

#[derive(Clone, Copy)]
struct Cost {
    nodes: usize,
    bytes: usize,
    depth: usize,
}
impl Cost {
    fn add(&mut self, child: Self) -> Result<(), PrepareError> {
        self.nodes = self.nodes.saturating_add(child.nodes);
        self.bytes = self.bytes.saturating_add(child.bytes);
        self.depth = self.depth.max(child.depth + 1);
        self.check()
    }
    fn check(self) -> Result<(), PrepareError> {
        if self.nodes > 50_000 || self.bytes > 8 * MAX_PROFILE_BYTES || self.depth > 64 {
            Err(PrepareError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}
struct Mapping {
    key: Option<String>,
    seen: HashSet<String>,
}
struct Frame {
    mapping: Option<Mapping>,
    anchor: usize,
    cost: Cost,
}

fn consume_value(stack: &mut [Frame]) -> Result<(), PrepareError> {
    if let Some(Mapping { key, .. }) = stack.last_mut().and_then(|f| f.mapping.as_mut())
        && key.take().is_none()
    {
        return Err(PrepareError::AmbiguousYaml); // Collection/alias mapping keys are unsupported.
    }
    Ok(())
}

fn account(stack: &mut [Frame], cost: Cost) -> Result<(), PrepareError> {
    cost.check()?;
    if stack.len() + cost.depth > 64 {
        return Err(PrepareError::LimitExceeded);
    }
    if let Some(parent) = stack.last_mut() {
        parent.cost.add(cost)?;
    }
    Ok(())
}

fn preflight(source: &str) -> Result<(), PrepareError> {
    if source.len() > MAX_PROFILE_BYTES {
        return Err(PrepareError::LimitExceeded);
    }
    let mut parser = Parser::new(source.chars());
    let mut stack: Vec<Frame> = Vec::new();
    let mut anchors = HashMap::new();
    let mut documents = 0;
    let mut source_nodes = 0;
    loop {
        let (event, _) = parser.next_token().map_err(|_| PrepareError::InvalidYaml)?;
        if matches!(
            event,
            Event::Scalar(..) | Event::Alias(_) | Event::MappingStart(..) | Event::SequenceStart(..)
        ) {
            source_nodes += 1;
            if source_nodes > 50_000 {
                return Err(PrepareError::LimitExceeded);
            }
        }
        match event {
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(PrepareError::InvalidYaml);
                }
            }
            Event::Alias(anchor) => {
                consume_value(&mut stack)?;
                // Only completed anchors: recursive/forward references cannot expand.
                let cost = *anchors.get(&anchor).ok_or(PrepareError::AmbiguousYaml)?;
                account(&mut stack, cost)?;
            }
            Event::Scalar(value, style, anchor, tag) => {
                let process_off = stack.len() == 1
                    && stack[0].mapping.as_ref().and_then(|m| m.key.as_deref()) == Some("find-process-mode")
                    && value == "off";
                if tag.is_some() || (style == TScalarStyle::Plain && ambiguous_scalar(&value) && !process_off) {
                    return Err(PrepareError::AmbiguousYaml);
                }
                if let Some(map) = stack.last_mut().and_then(|f| f.mapping.as_mut())
                    && map.key.take().is_none()
                {
                    if (style == TScalarStyle::Plain && !matches!(Yaml::from_str(&value), Yaml::String(_)))
                        || (value == "<<" && style != TScalarStyle::Plain)
                        || !map.seen.insert(value.clone())
                    {
                        return Err(PrepareError::AmbiguousYaml);
                    }
                    map.key = Some(value.clone());
                }
                let cost = Cost {
                    nodes: 1,
                    bytes: value.len().saturating_mul(6) + 2,
                    depth: 1,
                };
                account(&mut stack, cost)?;
                if anchor != 0 {
                    anchors.insert(anchor, cost);
                }
            }
            Event::MappingStart(anchor, ref tag) | Event::SequenceStart(anchor, ref tag) => {
                if tag.is_some() {
                    return Err(PrepareError::AmbiguousYaml);
                }
                consume_value(&mut stack)?;
                stack.push(Frame {
                    mapping: matches!(event, Event::MappingStart(..)).then(|| Mapping {
                        key: None,
                        seen: HashSet::new(),
                    }),
                    anchor,
                    cost: Cost {
                        nodes: 1,
                        bytes: 2,
                        depth: 1,
                    },
                });
                if stack.len() > 64 {
                    return Err(PrepareError::LimitExceeded);
                }
            }
            Event::MappingEnd | Event::SequenceEnd => {
                let frame = stack.pop().ok_or(PrepareError::InvalidYaml)?;
                account(&mut stack, frame.cost)?;
                if frame.anchor != 0 {
                    anchors.insert(frame.anchor, frame.cost);
                }
            }
            _ => (),
        }
    }
    Ok(())
}

fn merge_into(target: &mut Hash, value: Yaml) -> Result<(), PrepareError> {
    let Yaml::Hash(map) = value else {
        return Err(PrepareError::AmbiguousYaml);
    };
    for (key, value) in map {
        // YAML merge sequence: the first mapping wins. Explicit entries win afterwards.
        target.entry(key).or_insert(value);
    }
    Ok(())
}

fn expand_merges(value: Yaml) -> Result<Yaml, PrepareError> {
    match value {
        Yaml::Array(items) => items
            .into_iter()
            .map(expand_merges)
            .collect::<Result<_, _>>()
            .map(Yaml::Array),
        Yaml::Hash(items) => {
            let mut explicit = Hash::new();
            for (key, value) in items {
                explicit.insert(key, expand_merges(value)?);
            }
            let mut result = Hash::new();
            if let Some(merge) = explicit.remove(&Yaml::String("<<".into())) {
                match merge {
                    Yaml::Array(maps) => {
                        for map in maps {
                            merge_into(&mut result, map)?;
                        }
                    }
                    other => merge_into(&mut result, other)?,
                }
            }
            result.extend(explicit);
            Ok(Yaml::Hash(result))
        }
        other => Ok(other),
    }
}

pub(super) fn load(source: &str) -> Result<Yaml, PrepareError> {
    // Check expanded cost before YamlLoader clones any alias trees.
    preflight(source)?;
    let mut docs = YamlLoader::load_from_str(source).map_err(|_| PrepareError::InvalidYaml)?;
    if docs.len() != 1 {
        return Err(PrepareError::InvalidYaml);
    }
    expand_merges(docs.remove(0))
}
fn ambiguous_scalar(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if ["yes", "no", "on", "off", "y", "n"].contains(&lower.as_str()) || (lower == "null" && s != "null") {
        return true;
    }
    let n = s.strip_prefix(['+', '-']).unwrap_or(s);
    if n.is_empty() {
        return false;
    }
    if n.as_bytes()[0].is_ascii_digit() {
        // Permit canonical decimal integers only; reject other numeric syntax that
        // can resolve differently in the core's YAML implementation.
        if n.bytes().all(|b| b.is_ascii_digit()) {
            return (n.len() > 1 && n.starts_with('0')) || s.starts_with('+') || s.parse::<i64>().is_err();
        }
        if ["0x", "0o", "0b"]
            .iter()
            .any(|prefix| n.to_ascii_lowercase().starts_with(prefix))
            || (n.contains('_')
                && n.bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'+' | b'-' | b'e' | b'E')))
            || (n.len() >= 10
                && n.as_bytes().get(4) == Some(&b'-')
                && n.as_bytes().get(7) == Some(&b'-')
                && n.as_bytes()[..4].iter().all(u8::is_ascii_digit))
        {
            return true;
        }
    }
    if matches!(Yaml::from_str(s), Yaml::Real(_)) {
        static JSON_NUMBER: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
        return !JSON_NUMBER
            .get_or_init(|| regex_lite::Regex::new(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$").unwrap())
            .is_match(s);
    }
    false
}
