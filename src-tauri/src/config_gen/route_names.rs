//! Display-only metadata keyed by exactly the names written to mihomo YAML.
//! Never derive a node identity by splitting generated names (node names may
//! themselves contain slashes, brackets or reserved-looking fragments).
use std::collections::{hash_map::Entry, HashMap};

use crate::model::{ChainHop, Model, NodeRef};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteName {
    Node { name: String, path: Option<String> },
    Route(String),
    /// A confirmed non-node outbound, not merely a wrapper/group.
    Terminal(String),
}

impl RouteName {
    pub fn label(&self) -> &str {
        match self {
            Self::Node { name, path } => path.as_deref().unwrap_or(name),
            Self::Route(label) | Self::Terminal(label) => label,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RouteNames(HashMap<String, Option<RouteName>>);

impl RouteNames {
    pub fn builtins() -> Self {
        let mut out = Self::default();
        for (id, label) in [("DIRECT", "直连"), ("COMPATIBLE", "直连"), ("REJECT", "阻断"), ("REJECT-DROP", "阻断")] {
            out.terminal(id, label);
        }
        out
    }

    fn insert(&mut self, id: String, name: Option<RouteName>) {
        match self.0.entry(id) {
            Entry::Vacant(entry) => { entry.insert(name); }
            // Even a malformed/model-colliding alias must not pick the last
            // generated label and falsely attribute a connection.
            Entry::Occupied(mut entry) if entry.get() != &name => { entry.insert(None); }
            Entry::Occupied(_) => {}
        }
    }

    pub fn get(&self, id: &str) -> Option<&RouteName> {
        self.0.get(id)?.as_ref()
    }

    pub fn add(&mut self, id: &str, name: RouteName) {
        self.insert(id.to_owned(), Some(name));
    }

    pub fn node(&mut self, id: &str, label: &str) {
        self.add(id, RouteName::Node { name: label.into(), path: None });
    }

    pub fn route(&mut self, id: &str, label: impl Into<String>) {
        self.add(id, RouteName::Route(label.into()));
    }

    pub fn terminal(&mut self, id: &str, label: &str) {
        self.add(id, RouteName::Terminal(label.into()));
    }

    pub fn alias(&mut self, id: &str, target: &str) {
        if let Some(name) = self.get(target).cloned() {
            self.add(id, name);
        }
    }

    pub fn chain(&mut self, written: &[serde_yaml_ng::Value], name: &str, hops: &[ChainHop<'_>]) {
        let path = format!("{name} · 代理链：{}", hops.iter().map(|h| h.name).collect::<Vec<_>>().join(" → "));
        for (index, (proxy, hop)) in written.iter().zip(hops).enumerate() {
            if let Some(id) = proxy["name"].as_str() {
                self.add(id, RouteName::Node {
                    name: hop.name.into(),
                    path: (index + 1 == hops.len()).then(|| path.clone()),
                });
            }
        }
    }

    pub fn merge(&mut self, other: Self) {
        for (id, name) in other.0 { self.insert(id, name); }
    }

    /// Aliases can be reused on hot reload while an old flow or pending dial
    /// still refers to the original adapter. Omit aliases whose labels have
    /// changed in this core, including when a removed alias later reappears.
    pub fn unambiguous(&self, observed: &Self) -> Self {
        Self(self.0.iter()
            .filter(|(id, name)| name.is_some() && observed.0.get(*id) == Some(*name))
            .map(|(id, name)| (id.clone(), name.clone()))
            .collect())
    }

    pub fn logs(&self) -> (HashMap<String, String>, HashMap<String, String>) {
        let mut routes = HashMap::new();
        let mut leaves = HashMap::new();
        for (id, entry) in &self.0 {
            if let Some(entry) = entry {
                routes.insert(id.clone(), entry.label().into());
                match entry {
                    RouteName::Node { name, .. } | RouteName::Terminal(name) => {
                        leaves.insert(id.clone(), name.clone());
                    }
                    RouteName::Route(_) => {}
                }
            }
        }
        (routes, leaves)
    }
}

pub(super) fn node_name<'a>(model: &'a Model, node: &'a NodeRef) -> Option<&'a str> {
    match node {
        NodeRef::Subscription { name, .. } => Some(name),
        NodeRef::Manual { manual_id } => model.manual_nodes.iter().find(|n| &n.id == manual_id).map(|n| n.name.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflicting_internal_names_are_not_guessed() {
        let mut names = RouteNames::default();
        names.node("订阅/同名", "甲/乙");
        names.node("订阅/同名", "甲/乙");
        assert!(names.get("订阅/同名").is_some());
        names.node("订阅/同名", "另一个");
        names.node("订阅/同名", "甲/乙");
        assert!(names.get("订阅/同名").is_none());
        assert!(names.logs().0.is_empty());
        assert!(names.logs().1.is_empty());
    }
}
