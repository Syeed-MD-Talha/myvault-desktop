//! Canonical binary encoding for authenticated associated data (AAD).
//!
//! Every AAD blob is built with this module so that two different logical
//! contexts can never encode to the same bytes. Lengths are fixed-width
//! little-endian and every variable-length field is length-prefixed, which
//! removes the ambiguity of string concatenation.

/// Object types bound into the AAD.
pub const OBJ_VAULT_KEY: u8 = 1;
pub const OBJ_MANIFEST: u8 = 2;
pub const OBJ_CHUNK: u8 = 3;

const AAD_DOMAIN: &[u8; 8] = b"MYVAAD\x00\x01";

/// The associated data that binds a ciphertext to its logical context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aad {
    pub context: u8,
    pub vault_id: [u8; 16],
    pub object_id: [u8; 16],
    pub chunk_index: u64,
}

impl Aad {
    pub fn new(context: u8, vault_id: [u8; 16], object_id: [u8; 16], chunk_index: u64) -> Self {
        Aad {
            context,
            vault_id,
            object_id,
            chunk_index,
        }
    }

    /// Canonical encoding:
    /// `domain(8) || format_version(u16) || context(u8) || vault_id(16) ||
    ///  object_id(16) || chunk_index(u64)`
    ///
    /// `format_version` is the container format version, so a ciphertext from
    /// a future format can never be accepted by an older reader.
    pub fn encode(&self, format_version: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 2 + 1 + 16 + 16 + 8);
        out.extend_from_slice(AAD_DOMAIN);
        out.extend_from_slice(&format_version.to_le_bytes());
        out.push(self.context);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.object_id);
        out.extend_from_slice(&self.chunk_index.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: [u8; 16] = [7u8; 16];
    const OBJ: [u8; 16] = [9u8; 16];

    #[test]
    fn encoding_is_stable_and_distinct() {
        let base = Aad::new(OBJ_CHUNK, VAULT, OBJ, 3).encode(1);
        assert_eq!(base.len(), 8 + 2 + 1 + 16 + 16 + 8);

        // Chunk index is part of the AAD: replaying a chunk under a different
        // index must produce different associated data.
        assert_ne!(base, Aad::new(OBJ_CHUNK, VAULT, OBJ, 4).encode(1));
        // Object id binding prevents chunk substitution between files.
        let other = Aad::new(OBJ_CHUNK, VAULT, [8u8; 16], 3).encode(1);
        assert_ne!(base, other);
        // Context binding prevents cross-purpose substitution.
        assert_ne!(base, Aad::new(OBJ_MANIFEST, VAULT, OBJ, 3).encode(1));
        // Format version binding.
        assert_ne!(base, Aad::new(OBJ_CHUNK, VAULT, OBJ, 3).encode(2));
    }

    #[test]
    fn encoding_has_no_ambiguity_from_concatenation() {
        // Two adjacent 16-byte ids must not be swappable into an equal blob.
        let a = Aad::new(OBJ_CHUNK, [1u8; 16], [2u8; 16], 0).encode(1);
        let b = Aad::new(OBJ_CHUNK, [2u8; 16], [1u8; 16], 0).encode(1);
        assert_ne!(a, b);
    }
}
