// SPDX-License-Identifier: MIT OR Apache-2.0

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ldap_client_ber::tag::Tag;
use ldap_client_ber::{BerReader, BerWriter};

fn bench_write_integer(c: &mut Criterion) {
    c.bench_function("write_integer", |b| {
        b.iter(|| {
            let mut w = BerWriter::new();
            for i in 0..100 {
                w.write_integer(black_box(i));
            }
            black_box(w.into_bytes());
        });
    });
}

fn bench_write_sequence(c: &mut Criterion) {
    c.bench_function("write_sequence_nested", |b| {
        b.iter(|| {
            let mut w = BerWriter::new();
            w.write_sequence(Tag::sequence(), |outer| {
                for _ in 0..10 {
                    outer.write_sequence(Tag::sequence(), |inner| {
                        inner.write_bytes(b"cn");
                        inner.write_sequence(Tag::set(), |vals| {
                            vals.write_bytes(b"admin");
                        });
                    });
                }
            });
            black_box(w.into_bytes());
        });
    });
}

fn bench_read_sequence(c: &mut Criterion) {
    // Pre-encode a message to decode
    let mut w = BerWriter::new();
    w.write_sequence(Tag::sequence(), |outer| {
        for _ in 0..10 {
            outer.write_sequence(Tag::sequence(), |inner| {
                inner.write_bytes(b"cn=admin,dc=example,dc=com");
                inner.write_integer(42);
                inner.write_boolean(true);
            });
        }
    });
    let data = w.into_bytes();

    c.bench_function("read_sequence_nested", |b| {
        b.iter(|| {
            let mut r = BerReader::new(black_box(&data));
            r.read_sequence(Tag::sequence(), |outer| {
                while !outer.is_empty() {
                    outer.read_sequence(Tag::sequence(), |inner| {
                        let _ = inner.read_octet_string()?;
                        let _ = inner.read_integer()?;
                        let _ = inner.read_boolean()?;
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap();
        });
    });
}

fn bench_octet_string_roundtrip(c: &mut Criterion) {
    let payload = vec![0xAB_u8; 1024];

    c.bench_function("octet_string_1k_roundtrip", |b| {
        b.iter(|| {
            let mut w = BerWriter::new();
            w.write_bytes(black_box(&payload));
            let encoded = w.into_bytes();
            let mut r = BerReader::new(&encoded);
            let _ = r.read_octet_string().unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_write_integer,
    bench_write_sequence,
    bench_read_sequence,
    bench_octet_string_roundtrip
);
criterion_main!(benches);
