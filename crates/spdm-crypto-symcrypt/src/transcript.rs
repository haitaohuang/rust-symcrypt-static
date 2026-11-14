use alloc::{collections::BTreeMap, vec::Vec};
use spdmlib::{
    crypto::SpdmHash,
    error::{SpdmResult, SPDM_STATUS_INVALID_STATE_LOCAL},
    protocol::{SpdmBaseHashAlgo, SpdmDigestStruct},
};
use symcrypt_core::hash::Context;

struct Registry {
    next: usize,
    contexts: BTreeMap<usize, Context>,
}

// Public SPDM callbacks accept arbitrary usize handles. Never interpret those as pointers.
static CONTEXTS: spin::Mutex<Registry> = spin::Mutex::new(Registry {
    next: 1,
    contexts: BTreeMap::new(),
});

fn insert(context: Context) -> Option<usize> {
    let mut registry = CONTEXTS.lock();
    let handle = registry.next;
    registry.next = handle.checked_add(1)?;
    registry.contexts.insert(handle, context);
    Some(handle)
}

pub static HASH: SpdmHash = SpdmHash {
    hash_all_cb: hash_all,
    hash_ctx_init_cb: |algorithm| insert(Context::new(crate::hash_algorithm(algorithm)?).ok()?),
    hash_ctx_update_cb: update,
    hash_ctx_finalize_cb: finish,
    hash_ctx_dup_cb: duplicate,
    hash_ctx_serialize_cb: serialize,
    hash_ctx_deserialize_cb: |bytes| insert(Context::import(bytes).ok()?),
};

fn hash_all(algorithm: SpdmBaseHashAlgo, input: &[u8]) -> Option<SpdmDigestStruct> {
    Some(SpdmDigestStruct::from(
        crate::hash_algorithm(algorithm)?
            .digest(input)
            .ok()?
            .as_slice(),
    ))
}

fn update(handle: usize, input: &[u8]) -> SpdmResult {
    CONTEXTS
        .lock()
        .contexts
        .get_mut(&handle)
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .update(input);
    Ok(())
}

fn finish(handle: usize) -> Option<SpdmDigestStruct> {
    let context = CONTEXTS.lock().contexts.remove(&handle)?;
    Some(SpdmDigestStruct::from(context.finish().as_slice()))
}

fn duplicate(handle: usize) -> Option<usize> {
    let copy = CONTEXTS.lock().contexts.get(&handle)?.try_clone().ok()?;
    insert(copy)
}

fn serialize(handle: usize) -> Option<Vec<u8>> {
    Some(CONTEXTS.lock().contexts.get(&handle)?.export())
}
