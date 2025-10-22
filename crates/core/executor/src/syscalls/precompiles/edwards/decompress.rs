use sp1_curves::{
    curve25519_dalek::CompressedEdwardsY,
    edwards::{ed25519::decompress, WORDS_FIELD_ELEMENT},
    COMPRESSED_POINT_BYTES,
};
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le};

use crate::{
    events::{
        EdDecompressEvent, EdwardsPageProtRecords, MemoryReadRecord, MemoryWriteRecord,
        PrecompileEvent,
    },
    syscalls::{SyscallCode, SyscallContext},
    ExecutorConfig,
};

pub fn edwards_decompress_syscall<Ex: ExecutorConfig>(
    rt: &mut SyscallContext<Ex>,
    syscall_code: SyscallCode,
    arg1: u64,
    sign: u64,
) -> Option<u64> {
    let start_clk = rt.clk;
    let slice_ptr = arg1;
    assert!(slice_ptr.is_multiple_of(8), "slice_ptr must be 8-byte aligned.");
    assert!(sign <= 1, "Sign bit must be 0 or 1.");

    let (y_memory_records_vec, y_vec, read_page_prot_records) =
        rt.mr_slice(slice_ptr + (COMPRESSED_POINT_BYTES as u64), WORDS_FIELD_ELEMENT);
    let y_memory_records: [MemoryReadRecord; WORDS_FIELD_ELEMENT] =
        y_memory_records_vec.try_into().unwrap();

    let sign_bool = sign != 0;

    let y_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(&y_vec);

    // Copy bytes into another array so we can modify the last byte and make CompressedEdwardsY,
    // which we'll use to compute the expected X.
    // Re-insert sign bit into last bit of Y for CompressedEdwardsY format
    let mut compressed_edwards_y: [u8; COMPRESSED_POINT_BYTES] = y_bytes;
    compressed_edwards_y[compressed_edwards_y.len() - 1] &= 0b0111_1111;
    compressed_edwards_y[compressed_edwards_y.len() - 1] |= (sign as u8) << 7;

    // Compute actual decompressed X
    let compressed_y = CompressedEdwardsY(compressed_edwards_y);
    let decompressed = decompress(&compressed_y).expect("curve25519 Decompression failed");

    let mut decompressed_x_bytes = decompressed.x.to_bytes_le();
    decompressed_x_bytes.resize(32, 0u8);
    let decompressed_x_words: [u64; WORDS_FIELD_ELEMENT] = bytes_to_words_le(&decompressed_x_bytes);

    rt.clk += 1;

    // Write decompressed X into slice
    let (x_memory_records_vec, write_page_prot_records) =
        rt.mw_slice(slice_ptr, &decompressed_x_words, false);
    let x_memory_records: [MemoryWriteRecord; WORDS_FIELD_ELEMENT] =
        x_memory_records_vec.try_into().unwrap();

    let (local_mem_access, page_prot_local_events) = rt.postprocess();

    let event = EdDecompressEvent {
        clk: start_clk,
        ptr: slice_ptr,
        sign: sign_bool,
        y_bytes,
        decompressed_x_bytes: decompressed_x_bytes.try_into().unwrap(),
        x_memory_records,
        y_memory_records,
        local_mem_access,
        page_prot_records: EdwardsPageProtRecords {
            read_page_prot_records,
            write_page_prot_records,
        },
        local_page_prot_access: page_prot_local_events,
    };
    let syscall_event =
        rt.rt.syscall_event(start_clk, syscall_code, arg1, sign, false, rt.next_pc, rt.exit_code);
    rt.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::EdDecompress(event));
    None
}
