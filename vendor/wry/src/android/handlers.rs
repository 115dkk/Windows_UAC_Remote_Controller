// Copyright 2026 Windows-UAC-Remote-Controller contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! One coordinated publication/ownership domain. Callback cells are cloned out
//! before invocation; erased non-Sync Fn values remain mutex-serialized.
use super::{
  ActivityId, AndroidActivityOrigin, AndroidWebviewOrigin, CreateWebViewAttributes, UnsafeIpc,
  UnsafeOnPageLoadHandler, UnsafeRequestHandler, UnsafeTitleHandler, UnsafeUrlLoadingOverride,
  WebviewId,
};
use crate::{Error, Result};
use once_cell::sync::Lazy;
use std::{
  collections::HashMap,
  sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
  },
};

struct RegistrationInner {
  activity: AndroidActivityOrigin,
  label: String,
  live: AtomicBool,
}
#[derive(Clone)]
pub(crate) struct HandlerRegistration(Arc<RegistrationInner>);
impl HandlerRegistration {
  pub(crate) fn new(activity: AndroidActivityOrigin, label: String) -> Self {
    Self(Arc::new(RegistrationInner {
      activity,
      label,
      live: AtomicBool::new(true),
    }))
  }
  pub(crate) fn same(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
  }
  pub(crate) fn is_live(&self) -> bool {
    self.0.live.load(Ordering::Acquire) && self.0.activity.is_live()
  }
  pub(crate) fn retire(&self) {
    self.0.live.store(false, Ordering::Release);
  }
  pub(crate) fn activity(&self) -> &AndroidActivityOrigin {
    &self.0.activity
  }
  pub(crate) fn label(&self) -> &str {
    &self.0.label
  }
}

pub(crate) struct HandlerSet {
  pub request: Mutex<UnsafeRequestHandler>,
  pub ipc: Option<Mutex<UnsafeIpc>>,
  pub title: Option<Mutex<UnsafeTitleHandler>>,
  pub navigation: Option<Mutex<UnsafeUrlLoadingOverride>>,
  pub load: Option<Mutex<UnsafeOnPageLoadHandler>>,
  pub asset_loader: bool,
  pub asset_domain: Option<String>,
}
#[derive(Clone)]
pub(crate) struct RegisteredHandlers {
  pub registration: HandlerRegistration,
  pub handlers: Arc<HandlerSet>,
}
#[derive(Default)]
struct Registry {
  entries: HashMap<WebviewId, RegisteredHandlers>,
  definitions: HashMap<ActivityId, CreateWebViewAttributes>,
}
static REGISTRY: Lazy<Mutex<Registry>> = Lazy::new(Default::default);

impl Registry {
  fn remove_owned(
    &mut self,
    registration: &HandlerRegistration,
  ) -> (Option<RegisteredHandlers>, Option<CreateWebViewAttributes>) {
    let entry = if self
      .entries
      .get(registration.label())
      .is_some_and(|entry| entry.registration.same(registration))
    {
      self.entries.remove(registration.label())
    } else {
      None
    };
    let definition = if self
      .definitions
      .get(&registration.activity().id())
      .is_some_and(|entry| entry.registration.same(registration))
    {
      self.definitions.remove(&registration.activity().id())
    } else {
      None
    };
    (entry, definition)
  }
}

pub(crate) fn current(registration: &HandlerRegistration) -> bool {
  registration.is_live()
    && REGISTRY
      .lock()
      .unwrap()
      .entries
      .get(registration.label())
      .is_some_and(|entry| entry.registration.same(registration))
}
pub(crate) fn lookup(origin: &AndroidWebviewOrigin) -> Option<RegisteredHandlers> {
  let registration = origin.registration();
  if !origin.is_live() {
    return None;
  }
  REGISTRY
    .lock()
    .unwrap()
    .entries
    .get(registration.label())
    .filter(|entry| entry.registration.same(registration) && entry.registration.is_live())
    .cloned()
}
pub(crate) fn publish(attributes: CreateWebViewAttributes, handlers: HandlerSet) -> Result<()> {
  let registration = attributes.registration.clone();
  let replaced = {
    let mut registry = REGISTRY.lock().unwrap();
    if !registration.is_live()
      || (!registry.entries.contains_key(registration.label()) && registry.entries.len() >= 32)
      || (!registry
        .definitions
        .contains_key(&registration.activity().id())
        && registry.definitions.len() >= 32)
    {
      return Err(Error::ActivityNotFound);
    }
    let previous_definition = registry
      .definitions
      .get(&registration.activity().id())
      .cloned();
    let previous = previous_definition.map(|definition| {
      definition.registration.retire();
      registry.remove_owned(&definition.registration)
    });
    let old_owner = registry
      .entries
      .get(registration.label())
      .map(|entry| entry.registration.clone());
    let old_entry = old_owner.map(|owner| {
      owner.retire();
      registry.remove_owned(&owner)
    });
    registry.entries.insert(
      registration.label().to_owned(),
      RegisteredHandlers {
        registration: registration.clone(),
        handlers: Arc::new(handlers),
      },
    );
    registry
      .definitions
      .insert(registration.activity().id(), attributes);
    (previous, old_entry)
  };
  drop(replaced);
  Ok(())
}
pub(crate) fn rollback(registration: &HandlerRegistration) {
  registration.retire();
  let removed = REGISTRY.lock().unwrap().remove_owned(registration);
  drop(removed);
}

/// Mandatory retirement is synchronous metadata work, never a queued message.
/// It never waits for a callback cell or removes a newer same-label owner.
pub(crate) fn retire_activity(origin: &AndroidActivityOrigin, configuration: bool) {
  let removed = {
    let mut registry = REGISTRY.lock().unwrap();
    let matching = registry
      .definitions
      .get(&origin.id())
      .filter(|entry| entry.activity_origin.same(origin))
      .cloned();
    match matching {
      Some(mut definition) => {
        definition.registration.retire();
        if configuration {
          definition.configuration_recreate = true;
          registry.definitions.insert(origin.id(), definition);
          None
        } else {
          Some(registry.remove_owned(&definition.registration))
        }
      }
      None => None,
    }
  };
  drop(removed);
}

pub(crate) struct ConfigurationRollback {
  old_definition: CreateWebViewAttributes,
  old_handlers: RegisteredHandlers,
  candidate: HandlerRegistration,
}
pub(crate) fn prepare_configuration(
  origin: &AndroidActivityOrigin,
) -> Option<(CreateWebViewAttributes, ConfigurationRollback)> {
  let mut registry = REGISTRY.lock().unwrap();
  let old = registry.definitions.get(&origin.id())?.clone();
  if !old.configuration_recreate || old.registration.is_live() || !origin.is_live() {
    return None;
  }
  let old_handlers = registry.entries.get(&old.id)?.clone();
  if !old_handlers.registration.same(&old.registration) {
    return None;
  }
  let candidate = HandlerRegistration::new(origin.clone(), old.id.clone());
  let mut attributes = old.clone();
  attributes.activity_origin = origin.clone();
  attributes.registration = candidate.clone();
  attributes.configuration_recreate = false;
  registry.entries.insert(
    old.id.clone(),
    RegisteredHandlers {
      registration: candidate.clone(),
      handlers: Arc::clone(&old_handlers.handlers),
    },
  );
  registry.definitions.insert(origin.id(), attributes.clone());
  Some((
    attributes,
    ConfigurationRollback {
      old_definition: old,
      old_handlers,
      candidate,
    },
  ))
}
pub(crate) fn rollback_configuration(rollback: ConfigurationRollback) {
  rollback.candidate.retire();
  let removed = {
    let mut registry = REGISTRY.lock().unwrap();
    let removed = registry.remove_owned(&rollback.candidate);
    // Restore only a dormant definition, never revive the old physical origin.
    // A newer concurrent owner wins and is never overwritten by this rollback.
    if !registry.entries.contains_key(rollback.candidate.label())
      && !registry
        .definitions
        .contains_key(&rollback.candidate.activity().id())
    {
      registry
        .entries
        .insert(rollback.old_definition.id.clone(), rollback.old_handlers);
      registry.definitions.insert(
        rollback.old_definition.activity_origin.id(),
        rollback.old_definition,
      );
    }
    removed
  };
  drop(removed);
}
