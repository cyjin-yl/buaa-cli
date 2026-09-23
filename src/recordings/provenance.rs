use std::collections::{BTreeMap, BTreeSet};

use crate::net::Error;

use super::catalog::Catalog;
use super::model::{Asset, Provenance, ProvenanceIssue, ProvenanceLink, Relation};

const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 64;
const MAX_EDGES: usize = 128;

pub(crate) fn resolve(catalog: &Catalog, asset_id: &str) -> Result<Provenance, Error> {
    let mut resolver = Resolver {
        catalog,
        assets: BTreeMap::new(),
        parents: BTreeMap::new(),
        active: BTreeSet::new(),
        expanded_depth: BTreeMap::new(),
        originals: BTreeSet::new(),
        links: BTreeMap::new(),
        issues: BTreeSet::new(),
    };
    resolver.visit(asset_id, 0)?;
    if resolver.originals.is_empty() {
        resolver.issue("no_original", asset_id);
    }
    let segment_asset = resolver.assets.get(asset_id).cloned().flatten();
    let original_assets = resolver
        .originals
        .into_iter()
        .filter_map(|id| resolver.assets.remove(&id).flatten())
        .collect();
    Ok(Provenance {
        segment_asset,
        original_assets,
        links: resolver.links.into_values().collect(),
        complete: resolver.issues.is_empty(),
        issues: resolver
            .issues
            .into_iter()
            .map(|(asset_id, kind)| ProvenanceIssue { kind, asset_id })
            .collect(),
        hash_verification: "catalog_declared_not_blob_verified",
    })
}

struct Resolver<'a> {
    catalog: &'a Catalog,
    assets: BTreeMap<String, Option<Asset>>,
    parents: BTreeMap<String, Vec<Relation>>,
    active: BTreeSet<String>,
    expanded_depth: BTreeMap<String, usize>,
    originals: BTreeSet<String>,
    links: BTreeMap<(String, String, String), ProvenanceLink>,
    issues: BTreeSet<(String, &'static str)>,
}

impl Resolver<'_> {
    fn issue(&mut self, kind: &'static str, asset_id: &str) {
        self.issues.insert((asset_id.to_owned(), kind));
    }

    fn load(&mut self, asset_id: &str) -> Result<bool, Error> {
        if self.assets.contains_key(asset_id) {
            return Ok(true);
        }
        if self.assets.len() == MAX_NODES {
            self.issue("node_limit", asset_id);
            return Ok(false);
        }
        let asset = self.catalog.asset(asset_id)?;
        if asset.is_none() {
            self.issue("missing_asset", asset_id);
        }
        self.assets.insert(asset_id.to_owned(), asset);
        Ok(true)
    }

    fn visit(&mut self, asset_id: &str, depth: usize) -> Result<(), Error> {
        // Only a node on the current DFS path is a cycle: a completed shared
        // ancestor in a diamond is not one.
        if self.active.contains(asset_id) {
            self.issue("cycle_detected", asset_id);
            return Ok(());
        }
        if self
            .expanded_depth
            .get(asset_id)
            .is_some_and(|previous| *previous <= depth)
            || !self.load(asset_id)?
        {
            return Ok(());
        }
        let Some(asset) = self.assets.get(asset_id).and_then(Option::as_ref) else {
            self.expanded_depth.insert(asset_id.to_owned(), depth);
            return Ok(());
        };
        if !self.parents.contains_key(asset_id) {
            self.parents.insert(
                asset_id.to_owned(),
                self.catalog.parents(asset_id, MAX_EDGES + 1)?,
            );
        }
        let parent_count = self.parents[asset_id].len();
        if parent_count == 0 {
            if matches!(asset.kind.as_str(), "audio" | "video") {
                self.originals.insert(asset_id.to_owned());
            } else {
                self.issue("no_original", asset_id);
            }
            self.expanded_depth.insert(asset_id.to_owned(), depth);
            return Ok(());
        }
        // The root has depth zero; a terminal recording sixteen hops away is
        // allowed, but its parents would exceed the bound.
        if depth == MAX_DEPTH {
            self.issue("depth_limit", asset_id);
            return Ok(());
        }
        // A shorter path can recover ancestry that was cut off on an earlier
        // deeper traversal. Link deduplication must not suppress that work.
        self.issues.remove(&(asset_id.to_owned(), "depth_limit"));
        self.active.insert(asset_id.to_owned());
        for index in 0..parent_count {
            let parent = &self.parents[asset_id][index];
            let key = (
                parent.source_asset_id.clone(),
                parent.target_asset_id.clone(),
                parent.relation.clone(),
            );
            if self.links.contains_key(&key) {
                self.visit(&key.1, depth + 1)?;
                continue;
            }
            if self.links.len() == MAX_EDGES {
                self.issue("edge_limit", asset_id);
                break;
            }
            let created_at = parent.created_at.clone();
            let target_loaded = self.load(&key.1)?;
            let source_sha256 = self.assets[asset_id].as_ref().map(|a| a.sha256.clone());
            let target_sha256 = self
                .assets
                .get(&key.1)
                .and_then(Option::as_ref)
                .map(|a| a.sha256.clone());
            let link = ProvenanceLink {
                source_asset_id: key.0.clone(),
                target_asset_id: key.1.clone(),
                relation: key.2.clone(),
                created_at,
                source_sha256,
                target_sha256,
            };
            let target_id = link.target_asset_id.clone();
            self.links.insert(key, link);
            if target_loaded {
                self.visit(&target_id, depth + 1)?;
            }
        }
        self.active.remove(asset_id);
        self.expanded_depth.insert(asset_id.to_owned(), depth);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recordings::test_support::Fixture;

    const TRANSCRIPT_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DERIVED_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ORIGINAL_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn provenance(fixture: &Fixture, id: &str) -> Provenance {
        resolve(&Catalog::open(&fixture.path).unwrap(), id).unwrap()
    }

    fn original_ids(result: &Provenance) -> Vec<&str> {
        result
            .original_assets
            .iter()
            .map(|a| a.id.as_str())
            .collect()
    }

    fn issues(result: &Provenance) -> Vec<(&str, &str)> {
        result
            .issues
            .iter()
            .map(|i| (i.asset_id.as_str(), i.kind))
            .collect()
    }

    #[test]
    fn direct_recording_is_a_declared_original_not_verified_media() {
        let fixture = Fixture::new();
        fixture.asset("recording", "video", ORIGINAL_HASH);
        fixture.segment("recording", 0, "synthetic speech", None, None);
        let result = provenance(&fixture, "recording");
        assert!(result.complete);
        assert_eq!(original_ids(&result), ["recording"]);
        assert_eq!(result.segment_asset.as_ref().unwrap().id, "recording");
        assert_eq!(result.original_assets[0].sha256, ORIGINAL_HASH);
        assert_eq!(result.original_assets[0].captured_at, None);
        assert!(result.links.is_empty());
        assert!(result.issues.is_empty());
        assert_eq!(
            result.hash_verification,
            "catalog_declared_not_blob_verified"
        );
    }

    #[test]
    fn transcript_chain_keeps_each_hash_and_capture_time_separate() {
        let fixture = Fixture::new();
        fixture.asset("transcript", "transcript", TRANSCRIPT_HASH);
        fixture.asset("derived", "derived", DERIVED_HASH);
        fixture.asset("recording", "audio", ORIGINAL_HASH);
        fixture
            .db()
            .execute(
                "UPDATE asset SET captured_at='2023-06-07T08:09:10Z' WHERE id='recording'",
                [],
            )
            .unwrap();
        fixture.relate("transcript", "derived", "transcript_of");
        fixture.relate("derived", "recording", "derived_from");
        let result = provenance(&fixture, "transcript");
        assert!(result.complete);
        let segment_asset = result.segment_asset.as_ref().unwrap();
        assert_eq!(segment_asset.id, "transcript");
        assert_eq!(segment_asset.sha256, TRANSCRIPT_HASH);
        assert_eq!(segment_asset.captured_at, None);
        assert_eq!(original_ids(&result), ["recording"]);
        assert_eq!(result.original_assets[0].sha256, ORIGINAL_HASH);
        assert_eq!(
            result.original_assets[0].captured_at.as_deref(),
            Some("2023-06-07T08:09:10Z")
        );
        assert_eq!(result.links.len(), 2);
        assert_eq!(result.links[0].source_asset_id, "derived");
        assert_eq!(result.links[0].target_asset_id, "recording");
        assert_eq!(result.links[0].source_sha256.as_deref(), Some(DERIVED_HASH));
        assert_eq!(
            result.links[0].target_sha256.as_deref(),
            Some(ORIGINAL_HASH)
        );
        assert_eq!(
            result.links[1].source_sha256.as_deref(),
            Some(TRANSCRIPT_HASH)
        );
        assert_eq!(result.links[1].target_sha256.as_deref(), Some(DERIVED_HASH));
    }

    #[test]
    fn dangling_target_remains_a_link_without_a_fabricated_original() {
        let fixture = Fixture::new();
        fixture.asset("transcript", "transcript", TRANSCRIPT_HASH);
        fixture.relate("transcript", "absent", "transcript_of");
        let result = provenance(&fixture, "transcript");
        assert!(!result.complete);
        assert!(result.original_assets.is_empty());
        assert_eq!(result.links.len(), 1);
        assert_eq!(result.links[0].target_asset_id, "absent");
        assert_eq!(result.links[0].target_sha256, None);
        assert_eq!(
            result.links[0].source_sha256.as_deref(),
            Some(TRANSCRIPT_HASH)
        );
        assert_eq!(
            issues(&result),
            [("absent", "missing_asset"), ("transcript", "no_original")]
        );
        let missing = provenance(&fixture, "absent");
        assert!(!missing.complete);
        assert!(missing.segment_asset.is_none());
        assert_eq!(
            issues(&missing),
            [("absent", "missing_asset"), ("absent", "no_original")]
        );
    }

    #[test]
    fn cycle_is_incomplete_even_with_an_original_on_another_branch() {
        let fixture = Fixture::new();
        fixture.asset("a", "transcript", TRANSCRIPT_HASH);
        fixture.asset("b", "derived", DERIVED_HASH);
        fixture.asset("recording", "audio", ORIGINAL_HASH);
        fixture.relate("a", "b", "transcript_of");
        fixture.relate("b", "a", "derived_from");
        fixture.relate("a", "recording", "transcript_of");
        let result = provenance(&fixture, "a");
        assert!(!result.complete);
        assert_eq!(original_ids(&result), ["recording"]);
        assert_eq!(issues(&result), [("a", "cycle_detected")]);
        assert_eq!(result.links.len(), 3);
    }

    #[test]
    fn diamond_deduplicates_shared_ancestry_without_reporting_a_cycle() {
        let fixture = Fixture::new();
        for (id, kind) in [
            ("root", "transcript"),
            ("a", "derived"),
            ("b", "derived"),
            ("shared", "derived"),
            ("recording", "audio"),
        ] {
            fixture.asset(id, kind, ORIGINAL_HASH);
        }
        fixture.relate("root", "b", "derived_from");
        fixture.relate("root", "a", "derived_from");
        fixture.relate("a", "shared", "derived_from");
        fixture.relate("b", "shared", "derived_from");
        fixture.relate("shared", "recording", "derived_from");
        let result = provenance(&fixture, "root");
        assert!(result.complete);
        assert!(result.issues.is_empty());
        assert_eq!(original_ids(&result), ["recording"]);
        let links: Vec<_> = result
            .links
            .iter()
            .map(|l| (l.source_asset_id.as_str(), l.target_asset_id.as_str()))
            .collect();
        assert_eq!(
            links,
            [
                ("a", "shared"),
                ("b", "shared"),
                ("root", "a"),
                ("root", "b"),
                ("shared", "recording")
            ]
        );
    }

    #[test]
    fn multiple_originals_are_explicit_and_unrelated_edges_are_ignored() {
        let fixture = Fixture::new();
        fixture.asset("root", "transcript", TRANSCRIPT_HASH);
        for id in ["a", "b", "ignored"] {
            fixture.asset(id, "audio", ORIGINAL_HASH);
        }
        fixture.relate("root", "b", "transcript_of");
        fixture.relate("root", "a", "derived_from");
        for relation in ["alternate_of", "supersedes", "manifest_for"] {
            fixture.relate("root", "ignored", relation);
        }
        let result = provenance(&fixture, "root");
        assert!(result.complete);
        assert_eq!(original_ids(&result), ["a", "b"]);
        assert_eq!(result.links.len(), 2);
        assert_eq!(result.links[0].relation, "derived_from");
        assert_eq!(result.links[1].relation, "transcript_of");
    }

    #[test]
    fn a_terminal_nonrecording_does_not_become_an_original() {
        let fixture = Fixture::new();
        fixture.asset("root", "transcript", TRANSCRIPT_HASH);
        fixture.asset("manifest", "manifest", DERIVED_HASH);
        fixture.asset("recording", "audio", ORIGINAL_HASH);
        fixture.relate("root", "manifest", "derived_from");
        fixture.relate("manifest", "recording", "manifest_for");
        let result = provenance(&fixture, "root");
        assert!(!result.complete);
        assert!(result.original_assets.is_empty());
        assert_eq!(
            issues(&result),
            [("manifest", "no_original"), ("root", "no_original")]
        );
    }

    #[test]
    fn depth_boundary_allows_sixteen_hops_but_reports_truncation_beyond() {
        for terminal_depth in [16, 17] {
            let fixture = Fixture::new();
            for depth in 0..=terminal_depth {
                let id = format!("n{depth:02}");
                fixture.asset(
                    &id,
                    if depth == terminal_depth {
                        "audio"
                    } else {
                        "derived"
                    },
                    ORIGINAL_HASH,
                );
                if depth != 0 {
                    fixture.relate(&format!("n{:02}", depth - 1), &id, "derived_from");
                }
            }
            let result = provenance(&fixture, "n00");
            assert_eq!(result.links.len(), 16);
            if terminal_depth == 16 {
                assert!(result.complete);
                assert_eq!(original_ids(&result), ["n16"]);
            } else {
                assert!(!result.complete);
                assert!(result.original_assets.is_empty());
                assert_eq!(
                    issues(&result),
                    [("n00", "no_original"), ("n16", "depth_limit")]
                );
            }
        }
    }

    #[test]
    fn node_exhaustion_is_not_misreported_as_missing_catalog_data() {
        let fixture = Fixture::new();
        fixture.asset("root", "transcript", TRANSCRIPT_HASH);
        for index in 0..64 {
            let id = format!("recording{index:02}");
            fixture.asset(&id, "audio", ORIGINAL_HASH);
            fixture.relate("root", &id, "transcript_of");
        }
        let result = provenance(&fixture, "root");
        assert!(!result.complete);
        assert_eq!(result.original_assets.len(), 63);
        assert_eq!(result.links.len(), 64);
        assert_eq!(issues(&result), [("recording63", "node_limit")]);
        assert_eq!(result.links[63].target_sha256, None);
    }

    #[test]
    fn edge_exhaustion_is_incomplete_even_when_recordings_were_found() {
        let fixture = Fixture::new();
        fixture.asset("root", "transcript", TRANSCRIPT_HASH);
        for index in 0..11 {
            let id = format!("derived{index:02}");
            fixture.asset(&id, "derived", DERIVED_HASH);
            fixture.relate("root", &id, "derived_from");
            for recording in 0..11 {
                let target = format!("recording{recording:02}");
                if index == 0 {
                    fixture.asset(&target, "audio", ORIGINAL_HASH);
                }
                fixture.relate(&id, &target, "derived_from");
            }
        }
        let result = provenance(&fixture, "root");
        assert!(!result.complete);
        assert_eq!(result.links.len(), 128);
        assert_eq!(result.original_assets.len(), 11);
        assert_eq!(issues(&result), [("derived10", "edge_limit")]);
    }

    #[test]
    fn shorter_shared_path_recovers_original_after_deep_truncation() {
        let fixture = Fixture::new();
        fixture.asset("root", "transcript", TRANSCRIPT_HASH);
        let mut previous = "root".to_owned();
        for depth in 1..=14 {
            let id = format!("a{depth:02}");
            fixture.asset(&id, "derived", DERIVED_HASH);
            fixture.relate(&previous, &id, "derived_from");
            previous = id;
        }
        fixture.asset("shared", "derived", DERIVED_HASH);
        fixture.asset("middle", "derived", DERIVED_HASH);
        fixture.asset("original", "audio", ORIGINAL_HASH);
        fixture.relate(&previous, "shared", "derived_from");
        fixture.relate("root", "shared", "derived_from");
        fixture.relate("shared", "middle", "derived_from");
        fixture.relate("middle", "original", "derived_from");
        let result = provenance(&fixture, "root");
        assert_eq!(original_ids(&result), ["original"]);
        assert!(result.complete);
        assert!(result.issues.is_empty());
    }
}
