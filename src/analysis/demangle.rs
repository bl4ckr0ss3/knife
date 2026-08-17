//! Bounded cross-toolchain symbol demangling for analyst-facing names.

/// Turn a linker symbol into a readable name while leaving ordinary C names
/// untouched. Inputs are bounded because symbol tables are attacker-controlled.
pub fn display_name(raw: &str) -> String {
    const MAX_INPUT: usize = 16 * 1024;
    const MAX_OUTPUT: usize = 64 * 1024;
    if raw.len() > MAX_INPUT || raw.is_empty() {
        return raw.to_string();
    }

    let result = std::panic::catch_unwind(|| {
        if raw.starts_with('?') {
            return msvc_demangler::demangle(raw, msvc_demangler::DemangleFlags::llvm()).ok();
        }
        if let Ok(symbol) = rustc_demangle::try_demangle(raw) {
            return Some(format!("{symbol:#}"));
        }
        cpp_demangle::Symbol::new(raw).ok().and_then(|symbol| {
            symbol
                .demangle_with_options(
                    &cpp_demangle::DemangleOptions::new()
                        .recursion_limit(64)
                        .no_return_type(),
                )
                .ok()
        })
    })
    .ok()
    .flatten()
    .filter(|name| !name.is_empty() && name.len() <= MAX_OUTPUT);

    result.unwrap_or_else(|| raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_itanium_msvc_and_rust_without_touching_c_names() {
        assert_eq!(display_name("_ZN5space3fooEii"), "space::foo(int, int)");
        assert!(display_name("?answer@@YAHH@Z").contains("answer"));
        assert_eq!(display_name("_ZN3foo3bar17h05af221e174051e9E"), "foo::bar");
        assert_eq!(display_name("memcpy"), "memcpy");
    }

    #[test]
    fn pathological_symbol_input_is_bounded_and_preserved() {
        let oversized = format!("_ZN{}E", "9".repeat(20_000));
        assert_eq!(display_name(&oversized), oversized);
        assert_eq!(
            display_name("_ZN999999999999999999xE"),
            "_ZN999999999999999999xE"
        );
    }
}
