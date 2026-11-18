use super::bool_var;
use crate::config::eloquent_config::EloquentConfigParser;
use crate::pass_registry::{EnvOverlay, FunctionAnnotationsOverlay};
use amice_llvm::inkwell2::ModuleExt;
use amice_plugin::inkwell::{module::Module, values::FunctionValue};
use log::warn;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AntiHookingConfig {
    /// Whether to attach anti-hooking prologue sequences to protected functions.
    pub enable: bool,
    /// Per-function selection probability in 0..=100.
    pub probability: u32,
}

impl Default for AntiHookingConfig {
    fn default() -> Self {
        Self {
            enable: false,
            probability: 100,
        }
    }
}

impl EnvOverlay for AntiHookingConfig {
    fn overlay_env(&mut self) {
        self.enable = bool_var("AMICE_ANTI_HOOKING", self.enable);
        if let Ok(value) = std::env::var("AMICE_ANTI_HOOKING_PROBABILITY") {
            match value.trim().parse::<u32>() {
                Ok(p) => self.probability = p.min(100),
                Err(_) => warn!("Invalid AMICE_ANTI_HOOKING_PROBABILITY: {value}"),
            }
        }
    }
}

impl FunctionAnnotationsOverlay for AntiHookingConfig {
    type Config = Self;

    fn overlay_annotations<'a>(&self, module: &mut Module<'a>, function: FunctionValue<'a>) -> anyhow::Result<Self> {
        let mut cfg = self.clone();
        let annotations = module
            .read_function_annotate(function)
            .map_err(|e| anyhow::anyhow!("read function annotations failed: {e}"))?
            .join(" ");
        let mut parser = EloquentConfigParser::new();
        parser
            .parse(&annotations)
            .map_err(|e| anyhow::anyhow!("parse function annotations failed: {e}"))?;

        if let Some(v) = parser
            .get_bool("anti_hooking")
            .or_else(|| parser.get_bool("anti_hook"))
            .or_else(|| parser.get_bool("antihook"))
        {
            cfg.enable = v;
        }
        if let Some(p) = parser
            .get_number::<u32>("anti_hooking_probability")
            .or_else(|| parser.get_number::<u32>("anti_hook_probability"))
        {
            cfg.probability = p.min(100);
        }

        Ok(cfg)
    }
}
