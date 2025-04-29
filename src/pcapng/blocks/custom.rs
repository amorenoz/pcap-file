//! Custom Block.

use std::borrow::Cow;
use std::io::Write;

use byteorder_slice::{ByteOrder, BigEndian, LittleEndian};
use byteorder_slice::byteorder::{ReadBytesExt, WriteBytesExt};

use super::block_common::{Block, PcapNgBlock};
use crate::pcapng::PcapNgState;
use crate::{Endianness, PcapError};

/// Custom block
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomBlock<'a, const COPIABLE: bool> {
    /// Private Enterprise Number of the entity which defined this block.
    pub pen: u32,
    /// Payload of this block.
    pub payload: Cow<'a, [u8]>,
}

impl<'a, const COPIABLE: bool> CustomBlock<'a, COPIABLE> {
    /// Converts this block's payload into a type that implements [`PcapNgCustom`].
    pub fn interpret<'b: 'a, T: PcapNgCustom<'a>>(&'b self, state: &PcapNgState) -> Result<Option<T>, PcapError> {
        Ok(match state.section.endianness {
            Endianness::Big => T::from_slice::<BigEndian>(state, &self.payload)?,
            Endianness::Little => T::from_slice::<LittleEndian>(state, &self.payload)?,
        })
    }

    /// Create a new custom block from a PEN, a payload and a [`PcapNgState`].
    pub fn new<T: PcapNgCustom<'a>>(pen: u32, payload: &T, state: &PcapNgState) -> Result<Self, PcapError> {
        Ok(CustomBlock {
            pen,
            payload: Cow::Owned(payload.to_bytes(state)?),
        })
    }

    // The into_owned method must be implemented manually,
    // since derive_into_owned can't handle the const generic.

    /// Returns a version of self with all fields converted to owning versions.
    pub fn into_owned(self) -> CustomBlock<'static, COPIABLE> {
        CustomBlock {
            pen: self.pen,
            payload: Cow::Owned(self.payload.into_owned())
        }
    }
}

/// Common interface for custom block payloads
pub trait PcapNgCustom<'a> {
    /// Try to parse this payload from a slice.
    fn from_slice<B: ByteOrder>(state: &PcapNgState, slice: &'a [u8]) -> Result<Option<Self>, PcapError>
        where Self: Sized;

    /// Write this payload into a writer.
    fn write_to<B: ByteOrder, W: Write>(&self, state: &PcapNgState, writer: &mut W) -> Result<usize, PcapError>;

    /// Convert this payload into its raw bytes.
    fn to_bytes(&self, state: &PcapNgState) -> Result<Vec<u8>, PcapError> {
        let mut buf = Vec::new();
        match state.section.endianness {
            Endianness::Big => self.write_to::<BigEndian, _>(state, &mut buf)?,
            Endianness::Little => self.write_to::<LittleEndian, _>(state, &mut buf)?,
        };
        Ok(buf)
    }
}

impl<'a, const COPIABLE: bool> PcapNgBlock<'a> for CustomBlock<'a, COPIABLE> {
    fn from_slice<B: ByteOrder>(_state: &PcapNgState, mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError>
    where
        Self: Sized,
    {
        let pen = slice.read_u32::<B>()?;
        Ok((&[], CustomBlock { pen, payload: Cow::Borrowed(slice) }))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, _state: &PcapNgState, writer: &mut W) -> Result<usize, PcapError> {
        writer.write_u32::<B>(self.pen)?;
        writer.write_all(&self.payload)?;
        Ok(4 + self.payload.len())
    }

    fn into_block(self) -> Block<'a> {
        if COPIABLE {
            Block::CustomCopiable(CustomBlock { pen: self.pen, payload: self.payload })
        } else {
            Block::CustomNonCopiable(CustomBlock { pen: self.pen, payload: self.payload })
        }
    }
}
