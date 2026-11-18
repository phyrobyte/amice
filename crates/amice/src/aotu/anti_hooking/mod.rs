use crate::config::{AntiHookingConfig, Config};
use crate::pass_registry::{AmiceFunctionPass, AmicePass, AmicePassFlag};
use amice_llvm::inkwell2::FunctionExt;
use amice_macro::amice;
use amice_plugin::inkwell::comdat::ComdatSelectionKind;
use amice_plugin::inkwell::module::{Linkage, Module};
use amice_plugin::PreservedAnalyses;
use rand::Rng;

// 16-byte AArch64 prologue (O-MVLL style):
//   mov x17, x17
//   mov x16, x16
//   mov x16, x16
//   mov x17, x17
// Uses IP0/IP1 scratch registers in the 16-byte entry window to disrupt
// inline relocators (e.g. Frida Gum) without clobbering ABI state.
const AARCH64_PROLOGUE: [u8; 16] = [
    0xf1, 0x03, 0x11, 0xaa, 0xf0, 0x03, 0x10, 0xaa, 0xf0, 0x03, 0x10, 0xaa, 0xf1, 0x03, 0x11, 0xaa,
];

// 16-byte x86_64 prologue (aligned so LLVM emits no zero padding before body):
//   movq %r10, %r10
//   movq %r11, %r11
//   movq %r10, %r10
//   movq %r11, %r11
//   nopl (%rax)
// Preserves Win64 & SysV argument registers, flags, and stack layout (SEH-safe).
const X86_64_PROLOGUE: [u8; 16] = [
    0x4d, 0x89, 0xd2, 0x4d, 0x89, 0xdb, 0x4d, 0x89, 0xd2, 0x4d, 0x89, 0xdb, 0x0f, 0x1f, 0x40, 0x00,
];

#[amice(
    priority = 10,
    name = "AntiHooking",
    flag = AmicePassFlag::OptimizerLast | AmicePassFlag::FullLtoLast | AmicePassFlag::FunctionLevel,
    config = AntiHookingConfig,
)]
#[derive(Default)]
pub struct AntiHooking {}

impl AmicePass for AntiHooking {
    fn init(&mut self, cfg: &Config, _flag: AmicePassFlag) {
        self.default_config = cfg.anti_hooking.clone();
    }

    fn do_pass(&self, module: &mut Module<'_>) -> anyhow::Result<PreservedAnalyses> {
        let triple = module.get_triple();
        let triple_str = triple.as_str().to_string_lossy();
        let arch = triple_str.split('-').next().unwrap_or("");

        let prologue: &'static [u8] = if arch.starts_with("aarch64") || arch.starts_with("arm64") {
            &AARCH64_PROLOGUE
        } else if arch == "x86_64" || arch == "amd64" {
            &X86_64_PROLOGUE
        } else {
            if self.default_config.enable {
                warn!("unsupported target architecture for AntiHooking: {triple_str}");
            }
            return Ok(PreservedAnalyses::All);
        };

        let has_annotations = module.get_global("llvm.global.annotations").is_some();
        let mut rng = rand::rng();
        let mut changed = false;
        let functions = module.get_functions().collect::<Vec<_>>();

        for function in functions {
            if function.is_llvm_function() || function.is_undef_function() || !function.is_anti_hook_safe() {
                continue;
            }
            if function.has_prologue_data() {
                continue;
            }
            if matches!(function.get_linkage(), Linkage::AvailableExternally) {
                continue;
            }
            if function.as_global_value().get_comdat().is_some_and(|comdat| {
                matches!(
                    comdat.get_selection_kind(),
                    ComdatSelectionKind::ExactMatch | ComdatSelectionKind::SameSize
                )
            }) {
                continue;
            }

            let cfg = if has_annotations {
                self.parse_function_annotations(module, function)?
            } else {
                self.default_config.clone()
            };
            if !cfg.enable || cfg.probability == 0 {
                continue;
            }
            if cfg.probability < 100 && rng.random_range(0..100) >= cfg.probability {
                continue;
            }

            unsafe {
                function.set_prologue_bytes(prologue);
            }
            changed = true;
        }

        if changed {
            Ok(PreservedAnalyses::None)
        } else {
            Ok(PreservedAnalyses::All)
        }
    }
}
