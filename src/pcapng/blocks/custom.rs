//! Custom Block.

use std::any::Any;
use std::io::Write;

use byteorder_slice::byteorder::{ReadBytesExt, WriteBytesExt};

use byteorder_slice::ByteOrder;

use super::block_common::{Block, PcapNgBlock};
use crate::PcapError;
use crate::pcapng::PcapNgState;

/// Custom block
#[derive(Debug)]
pub struct CustomBlock<const COPIABLE: bool> {
    /// Private Enterprise Number of the entity which defined this block.
    pub pen: u32,
    /// Payload of this block.
    pub payload: Box<dyn PcapNgCustom>,
}

impl<const COPIABLE: bool> CustomBlock<COPIABLE> {
    /// Create a new custom block from a PEN, and a payload.
    pub fn new<T: PcapNgCustom + 'static>(pen: u32, payload: T) -> Result<Self, PcapError> {
        Ok(CustomBlock { pen, payload: Box::new(payload) })
    }

    // The into_owned method must be implemented manually,
    // since derive_into_owned can't handle the const generic.
    /// Returns a version of self with all fields converted to owning versions.
    pub fn into_owned(self) -> CustomBlock<COPIABLE> {
        self
    }
}

// Manual implementation of Clone
impl<const COPIABLE: bool> Clone for CustomBlock<COPIABLE> {
    fn clone(&self) -> Self {
        CustomBlock { pen: self.pen, payload: self.payload.clone() }
    }
}
// Manual implementation of PartialEq
impl<const COPIABLE: bool> PartialEq for CustomBlock<COPIABLE> {
    fn eq(&self, other: &Self) -> bool {
        self.pen == other.pen && self.payload.eq(&other.payload)
    }
}
impl<const COPIABLE: bool> Eq for CustomBlock<COPIABLE> {}

/// Common interface for custom block payloads
pub trait PcapNgCustom: std::fmt::Debug + Any {
    /// Returns this trait object as a `dyn Any`.
    fn as_any(&self) -> &dyn Any;

    /// Returns a clone of the underlying object into a Box.
    fn clone_to_box(&self) -> Box<dyn PcapNgCustom>;

    /// Compares the underlying object with another.
    fn eq_payload(&self, other: &dyn PcapNgCustom) -> bool;

    /// Returns the Private Enterprise Number (PEN) that identifies this payload type.
    fn pen(&self) -> u32;

    /// Write this payload into a writer.
    fn write_to(&self, state: &PcapNgState, writer: &mut dyn Write) -> Result<usize, PcapError>;
}

impl Clone for Box<dyn PcapNgCustom> {
    fn clone(&self) -> Self {
        self.clone_to_box()
    }
}

impl PartialEq for Box<dyn PcapNgCustom> {
    fn eq(&self, other: &Self) -> bool {
        // Defer to our new helper method
        self.eq_payload(other.as_ref())
    }
}
impl Eq for Box<dyn PcapNgCustom> {}

/// Trait generate a (sized) PcapNgCustom from a slice of bytes and a PcapNgState.
pub trait PcapNgCustomReader: Sized + PcapNgCustom {
    /// Tries to parse a payload from a slice. Does not keep a reference to the underlying slice!
    fn from_slice<'a, B: ByteOrder>(state: &PcapNgState, slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError>;
}

impl<'a, const COPIABLE: bool> PcapNgBlock<'a> for CustomBlock<COPIABLE> {
    fn from_slice<B: ByteOrder>(state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError>
    where
        Self: Sized,
    {
        let pen = slice.read_u32::<B>()?;
        let parser = state.custom_parsers.get(&pen).ok_or_else(|| PcapError::UnknownPEN(pen))?;

        let (rem, payload) = parser(state, slice)?;
        Ok((rem, CustomBlock { pen, payload }))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapError> {
        writer.write_u32::<B>(self.pen)?;
        let payload_len = self.payload.write_to(state, writer)?;
        Ok(4 + payload_len)
    }

    fn into_block(self) -> Block<'a> {
        if COPIABLE {
            Block::CustomCopiable(CustomBlock { pen: self.pen, payload: self.payload })
        } else {
            Block::CustomNonCopiable(CustomBlock { pen: self.pen, payload: self.payload })
        }
    }
}
