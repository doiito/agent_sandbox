//! Independent, bounded filesystem subscriptions alongside the execution port.
mod inotify;
mod service;
pub(super) use service::Service;
