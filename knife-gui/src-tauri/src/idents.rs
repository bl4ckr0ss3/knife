//! What the analyst can act on in a line of pseudocode.
//!
//! `ir::Line` is `{ label, text }` — the decompiler renders to a string, so a
//! front end that wants to offer "bind a type to this pointer" or "name this
//! field" has to find those identifiers in the rendered text itself.
//!
//! The terminal interface already does this, in `parse_field_ref` and
//! `selected_variable_ref` (`src/tui/mod.rs`). Those rules are mirrored here
//! rather than reimplemented from scratch, and the tests below pin the parts
//! that are easy to get subtly wrong: `field_m18` is a *negative* offset, an
//! alias the analyst already set maps back to the recovered base, and a bare
//! substring is not an identifier match.

use reknife::db::Db;
use serde::Serialize;

/// A `base->member` reference the analyst can name or retype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldRef {
    /// Recovered pointer base (`rcx`, `var_8`), after undoing any alias.
    pub base: String,
    /// Signed byte offset of the member within the bound type.
    pub offset: i64,
    /// The type currently bound to `base`, if any. Naming a field needs one.
    pub type_name: Option<String>,
    /// The member exactly as it is rendered (`field_28`, or a name you gave).
    pub member: String,
}

/// Everything actionable found in one line.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LineActions {
    pub field: Option<FieldRef>,
    /// Recovered identity of the variable on this line, if there is one.
    pub variable: Option<String>,
}

fn ident_tail(text: &str) -> String {
    text.chars()
        .rev()
        .take_while(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

fn ident_head(text: &str) -> String {
    text.chars()
        .take_while(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        .collect()
}

/// Whether `identifier` appears in `text` as a whole word.
fn contains_identifier(text: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }
    text.match_indices(identifier).any(|(start, matched)| {
        let before = text[..start].chars().next_back();
        let after = text[start + matched.len()..].chars().next();
        !before.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            && !after.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    })
}

/// Parse `base->member` out of a rendered pseudocode line.
///
/// `function` is base-relative, matching how `Db` stores things.
pub fn parse_field_ref(text: &str, function: u64, db: &Db) -> Option<FieldRef> {
    let arrow = text.find("->")?;
    let shown_base = ident_tail(&text[..arrow]);

    // The analyst may have renamed the base; the database keys off the
    // recovered identity, so map the displayed alias back to it.
    let base = db
        .variables
        .iter()
        .find_map(|((owner, recovered), alias)| {
            (*owner == function && alias == &shown_base).then_some(recovered.clone())
        })
        .unwrap_or(shown_base);
    if !reknife::db::valid_base(&base) {
        return None;
    }

    let member = ident_head(&text[arrow + 2..]);
    let type_name = db.bound_type(function, &base).map(str::to_string);

    // `field_18` is +0x18 and `field_m18` is -0x18. Anything else is already a
    // name the analyst gave, so its offset comes from the bound type.
    let offset = if let Some(hex) = member.strip_prefix("field_m") {
        i64::from_str_radix(hex, 16).ok()?.checked_neg()?
    } else if let Some(hex) = member.strip_prefix("field_") {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        let type_name = type_name.as_ref()?;
        db.fields
            .get(type_name)?
            .iter()
            .find_map(|(&offset, field)| (field.name == member).then_some(offset))?
    };

    Some(FieldRef {
        base,
        offset,
        type_name,
        member,
    })
}

/// What can be acted on in this line: a field reference, and/or a variable.
pub fn line_actions(text: &str, function: u64, db: &Db) -> LineActions {
    let field = parse_field_ref(text, function, db);
    // A field's base is itself a variable worth renaming.
    let variable = field.as_ref().map(|f| f.base.clone()).or_else(|| {
        db.variables
            .iter()
            .find(|((owner, _), alias)| *owner == function && contains_identifier(text, alias))
            .map(|((_, base), _)| base.clone())
    });
    LineActions { field, variable }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_offset_reads_as_hex_and_m_means_negative() {
        let db = Db::default();
        let plus = parse_field_ref("rcx->field_28 = 0x0;", 0x1000, &db).expect("field");
        assert_eq!(plus.base, "rcx");
        assert_eq!(plus.offset, 0x28);

        let minus = parse_field_ref("var_8->field_m18 = 0x0;", 0x1000, &db).expect("field");
        assert_eq!(minus.base, "var_8");
        assert_eq!(minus.offset, -0x18, "field_m18 is a negative offset");
    }

    #[test]
    fn a_renamed_base_maps_back_to_its_recovered_identity() {
        // The analyst renamed `rcx` to `hdr`; the database still keys on `rcx`,
        // so a line rendered with the alias must resolve to the real base or
        // the next edit would be written against a base that does not exist.
        let mut db = Db::default();
        db.set_variable(0x1000, "rcx", "hdr").unwrap();
        let field = parse_field_ref("hdr->field_10;", 0x1000, &db).expect("field");
        assert_eq!(field.base, "rcx");
    }

    #[test]
    fn a_named_field_resolves_through_the_bound_type() {
        let mut db = Db::default();
        db.bind_type(0x1000, "rcx", "HEADER").unwrap();
        db.set_typed_field("HEADER", 0x28, "length", None).unwrap();
        let field = parse_field_ref("rcx->length = 0x0;", 0x1000, &db).expect("field");
        assert_eq!(field.offset, 0x28);
        assert_eq!(field.type_name.as_deref(), Some("HEADER"));
        assert_eq!(field.member, "length");
    }

    #[test]
    fn a_line_without_an_arrow_offers_nothing_to_retype() {
        let db = Db::default();
        assert!(parse_field_ref("return rax;", 0x1000, &db).is_none());
    }

    #[test]
    fn an_identifier_match_respects_word_boundaries() {
        assert!(contains_identifier("rax = rcx;", "rcx"));
        assert!(
            !contains_identifier("rcx_saved = 0x0;", "rcx"),
            "a prefix of a longer identifier is not a match"
        );
        assert!(!contains_identifier("", "rcx"));
    }
}
