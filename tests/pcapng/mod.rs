use std::fs::File;
use std::io::Read;

use glob::glob;
use pcap_file::pcapng::{PcapNgParser, PcapNgReader, PcapNgWriter};

#[test]
fn reader() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let file = File::open(&entry).unwrap();
        let mut pcapng_reader = PcapNgReader::new(file).unwrap();

        let mut i = 0;
        while let Some(block) = pcapng_reader.next_block() {
            let _block = block.unwrap_or_else(|_| panic!("Error on block {i} on file: {entry:?}"));
            i += 1;
        }
    }
}

#[test]
fn parser() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let mut file = File::open(&entry).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut src = &data[..];
        let (rem, mut pcapng_parser) = PcapNgParser::new(src).unwrap();
        src = rem;

        let mut i = 0;
        loop {
            if src.is_empty() {
                break;
            }

            let (rem, _) = pcapng_parser.next_block(src).unwrap_or_else(|_| panic!("Error on block {i} on file: {entry:?}"));
            src = rem;

            i += 1;
        }
    }
}

#[test]
fn writer() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let pcapng_in = std::fs::read(&entry).unwrap();
        let mut pcapng_reader = PcapNgReader::new(&pcapng_in[..]).unwrap();
        let mut pcapng_writer = PcapNgWriter::with_section_header(Vec::new(), pcapng_reader.section().clone()).unwrap();

        let mut idx = 0;
        while let Some(block) = pcapng_reader.next_block() {
            let block = block.unwrap();
            pcapng_writer
                .write_block(&block)
                .unwrap_or_else(|_| panic!("Error writing block, file: {entry:?}, block n°{idx}, block: {block:?}"));
            idx += 1;
        }

        let expected = &pcapng_in;
        let actual = pcapng_writer.get_ref();

        if expected != actual {
            let mut expected_reader = PcapNgReader::new(&expected[..]).unwrap();
            let mut actual_reader = PcapNgReader::new(&actual[..]).unwrap();

            let mut idx = 0;
            while let (Some(expected), Some(actual)) = (expected_reader.next_block(), actual_reader.next_block()) {
                let expected = expected.unwrap();
                let actual = actual.unwrap();

                if expected != actual {
                    assert_eq!(expected, actual, "Pcap written != pcap read, file: {entry:?}, block n°{idx}")
                }

                idx += 1;
            }

            panic!("Pcap written != pcap read  but blocks are equal, file: {entry:?}");
        }
    }
}

#[test]
fn test_custom_block() {
    use byteorder_slice::{
        ByteOrder,
        byteorder::{ReadBytesExt, WriteBytesExt},
    };
    use pcap_file::PcapError;
    use pcap_file::pcapng::PcapNgState;
    use pcap_file::pcapng::blocks::{custom::*, *};
    use std::any::Any;
    use std::io::Write;

    // A unique PEN for our test block
    const MY_CUSTOM_PEN: u32 = 70000;

    // 1. Define a new custom block payload
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MyCustomPayload {
        magic_number: u64,
    }

    // 2. Implement the required traits for the custom payload
    impl PcapNgCustom for MyCustomPayload {
        fn pen(&self) -> u32 {
            MY_CUSTOM_PEN
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn clone_to_box(&self) -> Box<dyn PcapNgCustom> {
            Box::new(self.clone())
        }

        fn eq_payload(&self, other: &dyn PcapNgCustom) -> bool {
            // Downcast 'other' to our concrete type and compare
            if let Some(other_concrete) = other.as_any().downcast_ref::<Self>() {
                self == other_concrete
            } else {
                false
            }
        }

        fn write_to(&self, _state: &PcapNgState, writer: &mut dyn Write) -> Result<usize, PcapError> {
            // For this test, we'll just write in native endian, but a real
            // implementation should respect the state's endianness.
            writer.write_u64::<byteorder_slice::NativeEndian>(self.magic_number)?;
            Ok(8)
        }
    }

    impl PcapNgCustomReader for MyCustomPayload {
        fn from_slice<'a, B: ByteOrder>(_state: &PcapNgState, slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
            let mut cursor = std::io::Cursor::new(slice);
            let magic_number = cursor.read_u64::<B>()?;
            Ok((slice, MyCustomPayload { magic_number }))
        }
    }

    let original_payload = MyCustomPayload { magic_number: 0xDEADBEEFCAFED00D };
    let original_block = CustomBlock::<true>::new(MY_CUSTOM_PEN, original_payload.clone()).unwrap();

    let mut buffer = Vec::new();
    let mut pcapng_writer = PcapNgWriter::new(&mut buffer).expect("Failed to create writer");
    pcapng_writer.write_block(&original_block.into_block()).expect("Failed to write custom block");

    // --- READING ---
    let (rem, mut pcapng_parser) = PcapNgParser::new(&buffer).expect("Failed to create parser");
    let mut remaining_data = rem;

    // Payload parser registration
    pcapng_parser.register::<MyCustomPayload>(MY_CUSTOM_PEN);

    // Read the next block, which should be our custom block
    let (rem, read_block_enum) = pcapng_parser.next_block(remaining_data).expect("Failed to read next block");
    remaining_data = rem;

    // --- VERIFICATION ---
    // Extract the CustomBlock from the enum
    let read_block = match read_block_enum {
        Block::CustomCopiable(block) => block,
        // In a real scenario, you might handle both, but we know we wrote a copiable one.
        _ => panic!("Expected a CustomCopiable block, but got something else."),
    };

    // Assert that the PEN is correct
    assert_eq!(read_block.pen, MY_CUSTOM_PEN, "PEN did not match");

    // Downcast the `dyn PcapNgCustom` payload back to our concrete type
    let read_payload = read_block.payload.as_any().downcast_ref::<MyCustomPayload>().expect("Failed to downcast payload");

    // Assert that the inner data is correct
    assert_eq!(read_payload, &original_payload, "Payload data did not match");

    // We can also test the full block equality thanks to our manual PartialEq impl
    // First, recreate the original block for a fair comparison, as it was consumed
    let original_block_for_comparison = CustomBlock::<true>::new(MY_CUSTOM_PEN, original_payload).unwrap();
    assert_eq!(read_block, original_block_for_comparison, "Full blocks did not match");

    // Verify there is no more data left to parse
    assert!(remaining_data.is_empty(), "Expected all data to be consumed");
}
