//! Agent-facing BUAA utilities and mandatory shared request-safety primitives.
//! Campus gateway code is explicit opt-in and live-unverified; archive access is also opt-in.
// The capability schemas are large literal objects; the default macro
// recursion budget cannot expand them.
#![recursion_limit = "512"]
pub mod announcements;
pub mod archive;
pub mod aerospace;
pub mod boya;
pub mod checkin;
pub mod credits;
pub mod contribution;
pub mod coursegrading;
pub mod departments;
pub mod drift;
pub mod drive;
pub mod electricity;
pub mod enrol;
pub mod evaluation;
pub mod fengrubei;
pub mod gateway;
mod git_tree;
pub mod governor;
pub mod ihome;
mod html;
pub mod marks;
pub mod net;
pub mod os_lab;
pub mod organizations;
pub mod physics;
pub mod physics_experiment;
pub mod recordings;
pub mod report;
pub mod shuttle;
pub mod smart;
pub mod spoc;
pub mod timed_input;
pub mod timetable;
pub mod timetable_pg;
pub mod welearn;
