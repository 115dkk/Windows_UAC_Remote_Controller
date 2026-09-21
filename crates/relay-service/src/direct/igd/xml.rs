// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded XML tree for IGD descriptions and SOAP replies. No DTD/entity
//! expansion, remote references, unbounded depth or ambiguous duplicate fields.
use std::io;

use quick_xml::{Reader, events::Event};

use super::super::invalid_response;

pub(super) struct Node {
    pub(super) name: String,
    pub(super) text: String,
    pub(super) children: Vec<Node>,
}

impl Node {
    pub(super) fn child(&self, name: &str) -> io::Result<&Node> {
        let mut matches = self.children.iter().filter(|child| child.name == name);
        let child = matches.next().ok_or_else(invalid_response)?;
        if matches.next().is_some() {
            return Err(invalid_response());
        }
        Ok(child)
    }

    pub(super) fn value(&self, name: &str) -> io::Result<&str> {
        let child = self.child(name)?;
        if !child.children.is_empty() {
            return Err(invalid_response());
        }
        Ok(child.text.trim())
    }
}

pub(super) fn parse(text: &str) -> io::Result<Node> {
    if text.len() > 65536 {
        return Err(invalid_response());
    }
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut count = 0;
    loop {
        match reader.read_event().map_err(|_| invalid_response())? {
            Event::Start(start) => {
                count += 1;
                if count > 512 || stack.len() >= 32 {
                    return Err(invalid_response());
                }
                for attribute in start.attributes() {
                    attribute.map_err(|_| invalid_response())?;
                }
                let name = start.local_name().as_ref().to_owned();
                stack.push(Node {
                    name,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            Event::End(_) => {
                let node = stack.pop().ok_or_else(invalid_response)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return Err(invalid_response());
                }
            }
            Event::Text(text) => {
                let value = text.xml10_content();
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                } else if !value.trim().is_empty() {
                    return Err(invalid_response());
                }
            }
            Event::GeneralRef(reference) => {
                let value = match reference.as_ref() {
                    "amp" => "&",
                    "lt" => "<",
                    "gt" => ">",
                    "apos" => "'",
                    "quot" => "\"",
                    _ => return Err(invalid_response()),
                };
                stack
                    .last_mut()
                    .ok_or_else(invalid_response)?
                    .text
                    .push_str(value);
            }
            Event::Decl(_) | Event::Comment(_) => {}
            Event::Eof => break,
            // In particular DocType/CData/PI are not interpreted.
            _ => return Err(invalid_response()),
        }
    }
    if !stack.is_empty() {
        return Err(invalid_response());
    }
    root.ok_or_else(invalid_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_rejects_doctype_depth_duplicates_and_malformed_trees() {
        assert!(
            parse("<!DOCTYPE x [<!ENTITY bad SYSTEM 'http://127.0.0.1/'>]><x>&bad;</x>").is_err()
        );
        assert!(parse(&format!("{}{}", "<x>".repeat(33), "</x>".repeat(33))).is_err());
        assert!(
            parse("<x><a>one</a><a>two</a></x>")
                .unwrap()
                .value("a")
                .is_err()
        );
        assert!(parse("<x></y>").is_err());
        assert!(parse("<x/><y/>").is_err());
        assert!(
            parse("<x><a /></x>")
                .unwrap()
                .value("a")
                .unwrap()
                .is_empty()
        );
    }
}
