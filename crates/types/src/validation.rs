use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use nonempty::NonEmpty;

#[doc(hidden)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn validate_nonempty_unique<T, K>(
    mut items: Vec<T>,
    sort_key: impl Fn(&T) -> K,
    dup_msg: impl Fn(&T) -> String,
) -> Result<NonEmpty<T>, String>
where
    K: Ord,
{
    if items.is_empty() {
        return Err("must have at least one item".to_string());
    }

    items.sort_by_key(|item| sort_key(item));

    for window in items.windows(2) {
        let (prev, next) = (&window[0], &window[1]);
        if sort_key(prev) == sort_key(next) {
            return Err(dup_msg(next));
        }
    }

    Ok(NonEmpty::from_vec(items).unwrap())
}
